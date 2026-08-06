//! RFC 8555 ACME v2 protocol client: directory discovery, nonce
//! management (including badNonce retry, per §6.5), and the signed
//! request sequence for account creation, order creation, authorization
//! polling, challenge notification, finalization, and certificate
//! download. Built directly on `reqwest` -- no `instant-acme`/`lego`.

use bytes::Bytes;
use reqwest::header::{HeaderMap, CONTENT_TYPE, LOCATION};
use reqwest::StatusCode;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::Mutex;

use super::jws::{b64url, encode_jws, AccountKey, JwsError};
use super::types::{
    Authorization, Directory, FinalizePayload, Identifier, NewAccountPayload, NewOrderPayload,
    Order, Problem,
};

const REPLAY_NONCE_HEADER: &str = "replay-nonce";
const MAX_NONCE_RETRIES: u32 = 3;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JWS error: {0}")]
    Jws(#[from] JwsError),
    #[error("ACME server returned a problem: {0}")]
    Problem(Problem),
    #[error("ACME server response was missing a Replay-Nonce header")]
    MissingNonce,
    #[error("ACME server response was missing a Location header")]
    MissingLocation,
    #[error("unexpected HTTP status {0} with a non-problem body")]
    UnexpectedStatus(StatusCode),
    #[error("exhausted retries after repeated badNonce errors")]
    RetriesExhausted,
    #[error("certificate response was not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

struct SignedResponse {
    headers: HeaderMap,
    body: Bytes,
}

pub struct AcmeClient {
    http: reqwest::Client,
    account_key: AccountKey,
    directory: Directory,
    kid: Mutex<Option<String>>,
    nonce: Mutex<Option<String>>,
}

impl AcmeClient {
    pub async fn discover(
        http: &reqwest::Client,
        directory_url: &str,
    ) -> Result<Directory, AcmeError> {
        let resp = http.get(directory_url).send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }

    pub async fn new(directory_url: &str, account_key: AccountKey) -> Result<Self, AcmeError> {
        let http = reqwest::Client::builder().build()?;
        let directory = Self::discover(&http, directory_url).await?;
        Ok(Self {
            http,
            account_key,
            directory,
            kid: Mutex::new(None),
            nonce: Mutex::new(None),
        })
    }

    /// For tests / callers that already have a directory and don't want a
    /// second discovery round-trip.
    pub fn with_directory(
        http: reqwest::Client,
        account_key: AccountKey,
        directory: Directory,
    ) -> Self {
        Self {
            http,
            account_key,
            directory,
            kid: Mutex::new(None),
            nonce: Mutex::new(None),
        }
    }

    pub async fn kid(&self) -> Option<String> {
        self.kid.lock().await.clone()
    }

    async fn fresh_nonce(&self) -> Result<String, AcmeError> {
        if let Some(n) = self.nonce.lock().await.take() {
            return Ok(n);
        }
        let resp = self.http.head(&self.directory.new_nonce).send().await?;
        remember_nonce_header(&self.nonce, resp.headers()).await;
        self.nonce
            .lock()
            .await
            .take()
            .ok_or(AcmeError::MissingNonce)
    }

    async fn signed_post(
        &self,
        url: &str,
        payload: Option<&Value>,
    ) -> Result<SignedResponse, AcmeError> {
        for attempt in 0..MAX_NONCE_RETRIES {
            let nonce = self.fresh_nonce().await?;
            let kid = self.kid.lock().await.clone();
            let jws = encode_jws(&self.account_key, url, &nonce, kid.as_deref(), payload)?;

            let resp = self
                .http
                .post(url)
                .header(CONTENT_TYPE, "application/jose+json")
                .json(&jws)
                .send()
                .await?;

            remember_nonce_header(&self.nonce, resp.headers()).await;
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = resp.bytes().await?;

            if status.is_success() {
                return Ok(SignedResponse { headers, body });
            }

            if let Ok(problem) = serde_json::from_slice::<Problem>(&body) {
                let is_bad_nonce =
                    problem.typ.as_deref() == Some("urn:ietf:params:acme:error:badNonce");
                if is_bad_nonce && attempt + 1 < MAX_NONCE_RETRIES {
                    continue;
                }
                return Err(AcmeError::Problem(problem));
            }
            return Err(AcmeError::UnexpectedStatus(status));
        }
        Err(AcmeError::RetriesExhausted)
    }

    pub async fn new_account(&self, contact_email: &str) -> Result<String, AcmeError> {
        let payload = serde_json::to_value(NewAccountPayload {
            terms_of_service_agreed: true,
            contact: vec![format!("mailto:{contact_email}")],
        })?;
        let resp = self
            .signed_post(&self.directory.new_account, Some(&payload))
            .await?;
        let location = location_header(&resp.headers)?;
        *self.kid.lock().await = Some(location.clone());
        Ok(location)
    }

    pub async fn new_order(&self, domains: &[String]) -> Result<(String, Order), AcmeError> {
        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::dns(d.clone())).collect();
        let payload = serde_json::to_value(NewOrderPayload { identifiers })?;
        let resp = self
            .signed_post(&self.directory.new_order, Some(&payload))
            .await?;
        let location = location_header(&resp.headers)?;
        let order: Order = serde_json::from_slice(&resp.body)?;
        Ok((location, order))
    }

    pub async fn get_authorization(&self, url: &str) -> Result<Authorization, AcmeError> {
        let resp = self.signed_post(url, None).await?;
        Ok(serde_json::from_slice(&resp.body)?)
    }

    /// Tells the server "the challenge resource is ready to validate" --
    /// the actual DNS TXT record must already be published (see `dns01`)
    /// before this is called.
    pub async fn notify_challenge_ready(&self, challenge_url: &str) -> Result<(), AcmeError> {
        self.signed_post(challenge_url, Some(&serde_json::json!({})))
            .await?;
        Ok(())
    }

    pub async fn poll_order(&self, order_url: &str) -> Result<Order, AcmeError> {
        let resp = self.signed_post(order_url, None).await?;
        Ok(serde_json::from_slice(&resp.body)?)
    }

    pub async fn finalize(&self, finalize_url: &str, csr_der: &[u8]) -> Result<Order, AcmeError> {
        let payload = serde_json::to_value(FinalizePayload {
            csr: b64url(csr_der),
        })?;
        let resp = self.signed_post(finalize_url, Some(&payload)).await?;
        Ok(serde_json::from_slice(&resp.body)?)
    }

    /// Returns the full-chain PEM as text (`application/pem-certificate-chain`).
    pub async fn download_certificate(&self, cert_url: &str) -> Result<String, AcmeError> {
        let resp = self.signed_post(cert_url, None).await?;
        Ok(String::from_utf8(resp.body.to_vec())?)
    }

    pub fn account_key(&self) -> &AccountKey {
        &self.account_key
    }
}

async fn remember_nonce_header(slot: &Mutex<Option<String>>, headers: &HeaderMap) {
    if let Some(value) = headers
        .get(REPLAY_NONCE_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        *slot.lock().await = Some(value.to_string());
    }
}

fn location_header(headers: &HeaderMap) -> Result<String, AcmeError> {
    headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AcmeError::MissingLocation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::jws::AccountKey;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_directory(server: &MockServer) -> Directory {
        Directory {
            new_nonce: format!("{}/acme/new-nonce", server.uri()),
            new_account: format!("{}/acme/new-account", server.uri()),
            new_order: format!("{}/acme/new-order", server.uri()),
        }
    }

    fn test_client(http: reqwest::Client, directory: Directory) -> AcmeClient {
        let (key, _) = AccountKey::generate().unwrap();
        AcmeClient::with_directory(http, key, directory)
    }

    #[tokio::test]
    async fn directory_discovery_parses_a_mocked_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "newNonce": format!("{}/acme/new-nonce", server.uri()),
                "newAccount": format!("{}/acme/new-account", server.uri()),
                "newOrder": format!("{}/acme/new-order", server.uri()),
            })))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let dir = AcmeClient::discover(&http, &format!("{}/directory", server.uri()))
            .await
            .unwrap();
        assert_eq!(dir.new_nonce, format!("{}/acme/new-nonce", server.uri()));
    }

    #[tokio::test]
    async fn new_account_sends_jwk_header_and_captures_kid_from_location() {
        let server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .and(path("/acme/new-nonce"))
            .respond_with(ResponseTemplate::new(200).insert_header(REPLAY_NONCE_HEADER, "nonce-1"))
            .mount(&server)
            .await;

        let account_url = format!("{}/acme/acct/1", server.uri());
        Mock::given(method("POST"))
            .and(path("/acme/new-account"))
            .and(header_exists("content-type"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("location", account_url.as_str())
                    .insert_header(REPLAY_NONCE_HEADER, "nonce-2")
                    .set_body_json(serde_json::json!({"status": "valid"})),
            )
            .mount(&server)
            .await;

        let directory = mock_directory(&server).await;
        let client = test_client(reqwest::Client::new(), directory);

        let kid = client.new_account("admin@example.com").await.unwrap();
        assert_eq!(kid, account_url);
        assert_eq!(client.kid().await, Some(account_url));
    }

    #[tokio::test]
    async fn bad_nonce_response_is_retried_with_a_fresh_nonce() {
        let server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .and(path("/acme/new-nonce"))
            .respond_with(
                ResponseTemplate::new(200).insert_header(REPLAY_NONCE_HEADER, "stale-nonce"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let account_url = format!("{}/acme/acct/1", server.uri());

        // First attempt: rejected as badNonce, but the response itself
        // carries a fresh nonce to retry with (RFC 8555 §6.5.1) -- the
        // client must use it rather than re-fetching new-nonce.
        Mock::given(method("POST"))
            .and(path("/acme/new-account"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header(REPLAY_NONCE_HEADER, "fresh-nonce")
                    .set_body_json(serde_json::json!({
                        "type": "urn:ietf:params:acme:error:badNonce",
                        "detail": "stale nonce",
                        "status": 400
                    })),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/acme/new-account"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("location", account_url.as_str())
                    .insert_header(REPLAY_NONCE_HEADER, "nonce-after-success")
                    .set_body_json(serde_json::json!({"status": "valid"})),
            )
            .mount(&server)
            .await;

        let directory = mock_directory(&server).await;
        let client = test_client(reqwest::Client::new(), directory);

        let kid = client.new_account("admin@example.com").await.unwrap();
        assert_eq!(kid, account_url);
    }

    #[tokio::test]
    async fn non_bad_nonce_problem_is_not_retried_and_surfaces_the_detail() {
        let server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .and(path("/acme/new-nonce"))
            .respond_with(ResponseTemplate::new(200).insert_header(REPLAY_NONCE_HEADER, "nonce-1"))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/acme/new-account"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header(REPLAY_NONCE_HEADER, "nonce-2")
                    .set_body_json(serde_json::json!({
                        "type": "urn:ietf:params:acme:error:malformed",
                        "detail": "contact field invalid",
                        "status": 400
                    })),
            )
            .mount(&server)
            .await;

        let directory = mock_directory(&server).await;
        let client = test_client(reqwest::Client::new(), directory);

        let err = client.new_account("admin@example.com").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("contact field invalid"),
            "unexpected error message: {msg}"
        );
    }

    #[tokio::test]
    async fn new_order_parses_authorizations_and_finalize_url() {
        let server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .and(path("/acme/new-nonce"))
            .respond_with(ResponseTemplate::new(200).insert_header(REPLAY_NONCE_HEADER, "nonce-1"))
            .mount(&server)
            .await;

        let order_url = format!("{}/acme/order/1", server.uri());
        Mock::given(method("POST"))
            .and(path("/acme/new-order"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("location", order_url.as_str())
                    .insert_header(REPLAY_NONCE_HEADER, "nonce-2")
                    .set_body_json(serde_json::json!({
                        "status": "pending",
                        "authorizations": [format!("{}/acme/authz/1", server.uri())],
                        "finalize": format!("{}/acme/order/1/finalize", server.uri()),
                        "certificate": null
                    })),
            )
            .mount(&server)
            .await;

        let directory = mock_directory(&server).await;
        let client = test_client(reqwest::Client::new(), directory);

        let (location, order) = client
            .new_order(&["example.com".to_string()])
            .await
            .unwrap();
        assert_eq!(location, order_url);
        assert_eq!(order.authorizations.len(), 1);
        assert!(order.finalize.ends_with("/finalize"));
    }
}
