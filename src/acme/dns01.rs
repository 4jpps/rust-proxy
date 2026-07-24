//! dns-01 challenge fulfillment via direct Cloudflare API v4 calls (no
//! `cloudflare` crate) -- create/clean up the `_acme-challenge` TXT
//! record, and compute the RFC 8555 §8.4 key-authorization digest that
//! becomes the record's content.

use serde::Deserialize;
use thiserror::Error;

use super::jws::{b64url, AccountKey};

const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Error)]
pub enum Dns01Error {
    #[error("HTTP error talking to Cloudflare: {0}")]
    Http(#[from] reqwest::Error),
    #[error("no Cloudflare zone found for {0} or any parent domain")]
    ZoneNotFound(String),
    #[error("Cloudflare API call failed: {0}")]
    Api(String),
    #[error("Cloudflare response was missing an expected result")]
    MissingResult,
}

/// RFC 8555 §8.4: `keyAuthorization = token || "." || jwkThumbprint`;
/// the TXT record content is base64url(SHA-256(keyAuthorization)).
pub fn dns01_txt_value(token: &str, account_key: &AccountKey) -> String {
    let key_authorization = format!("{token}.{}", account_key.jwk_thumbprint());
    let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
    b64url(digest.as_ref())
}

pub fn acme_challenge_record_name(domain: &str) -> String {
    format!("_acme-challenge.{domain}")
}

#[derive(Debug, Deserialize)]
struct CfListResponse<T> {
    #[allow(dead_code)]
    success: bool,
    result: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct CfSingleResponse<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<CfError>,
}

#[derive(Debug, Deserialize)]
struct CfZone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CfDnsRecord {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CfError {
    message: String,
}

pub struct CloudflareDns01 {
    http: reqwest::Client,
    api_token: String,
    base_url: String,
}

impl CloudflareDns01 {
    pub fn new(http: reqwest::Client, api_token: String) -> Self {
        Self {
            http,
            api_token,
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(http: reqwest::Client, api_token: String, base_url: String) -> Self {
        Self { http, api_token, base_url }
    }

    /// Cloudflare zones are usually the registrable/apex domain, not the
    /// exact challenge hostname (e.g. a challenge for `foo.bar.example.com`
    /// lives in the `example.com` zone). Walk from the full name up
    /// through each parent label until one matches a zone in the account.
    pub async fn find_zone_id(&self, domain: &str) -> Result<String, Dns01Error> {
        let labels: Vec<&str> = domain.split('.').collect();
        // Stop one short of the TLD itself (e.g. never query for "com").
        for i in 0..labels.len().saturating_sub(1) {
            let candidate = labels[i..].join(".");
            if let Some(id) = self.query_zone(&candidate).await? {
                return Ok(id);
            }
        }
        Err(Dns01Error::ZoneNotFound(domain.to_string()))
    }

    async fn query_zone(&self, name: &str) -> Result<Option<String>, Dns01Error> {
        let resp = self
            .http
            .get(format!("{}/zones", self.base_url))
            .bearer_auth(&self.api_token)
            .query(&[("name", name)])
            .send()
            .await?;
        let body: CfListResponse<CfZone> = resp.json().await?;
        Ok(body.result.into_iter().next().map(|z| z.id))
    }

    /// Creates the TXT record and returns its Cloudflare record ID, needed
    /// later to clean it up.
    pub async fn create_txt_record(&self, zone_id: &str, name: &str, content: &str) -> Result<String, Dns01Error> {
        let resp = self
            .http
            .post(format!("{}/zones/{zone_id}/dns_records", self.base_url))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": name,
                "content": content,
                "ttl": 60,
            }))
            .send()
            .await?;
        let body: CfSingleResponse<CfDnsRecord> = resp.json().await?;
        if !body.success {
            return Err(Dns01Error::Api(join_errors(&body.errors)));
        }
        body.result.map(|r| r.id).ok_or(Dns01Error::MissingResult)
    }

    pub async fn delete_txt_record(&self, zone_id: &str, record_id: &str) -> Result<(), Dns01Error> {
        let resp = self
            .http
            .delete(format!("{}/zones/{zone_id}/dns_records/{record_id}", self.base_url))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        let body: CfSingleResponse<CfDnsRecord> = resp.json().await?;
        if !body.success {
            return Err(Dns01Error::Api(join_errors(&body.errors)));
        }
        Ok(())
    }
}

fn join_errors(errors: &[CfError]) -> String {
    if errors.is_empty() {
        "unknown error".to_string()
    } else {
        errors.iter().map(|e| e.message.as_str()).collect::<Vec<_>>().join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::jws::AccountKey;
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn txt_value_is_deterministic_for_the_same_token_and_key() {
        let (key, _) = AccountKey::generate().unwrap();
        let a = dns01_txt_value("token-abc", &key);
        let b = dns01_txt_value("token-abc", &key);
        assert_eq!(a, b);
        // 32-byte SHA-256 digest, unpadded base64url -> 43 chars.
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn txt_value_differs_for_different_tokens() {
        let (key, _) = AccountKey::generate().unwrap();
        let a = dns01_txt_value("token-one", &key);
        let b = dns01_txt_value("token-two", &key);
        assert_ne!(a, b);
    }

    #[test]
    fn record_name_is_prefixed_correctly() {
        assert_eq!(acme_challenge_record_name("example.com"), "_acme-challenge.example.com");
        assert_eq!(
            acme_challenge_record_name("foo.bar.example.com"),
            "_acme-challenge.foo.bar.example.com"
        );
    }

    #[tokio::test]
    async fn zone_lookup_falls_back_to_the_apex_when_the_subdomain_has_no_zone() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "foo.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"success": true, "result": []})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": [{"id": "zone-abc123"}]
            })))
            .mount(&server)
            .await;

        let client = CloudflareDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone_id = client.find_zone_id("foo.example.com").await.unwrap();
        assert_eq!(zone_id, "zone-abc123");
    }

    #[tokio::test]
    async fn zone_lookup_errors_when_no_zone_matches_any_parent_domain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"success": true, "result": []})))
            .mount(&server)
            .await;

        let client = CloudflareDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let err = client.find_zone_id("foo.example.com").await.unwrap_err();
        assert!(matches!(err, Dns01Error::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn create_txt_record_returns_the_new_record_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/zones/zone-1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": {"id": "record-42"},
                "errors": []
            })))
            .mount(&server)
            .await;

        let client = CloudflareDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let id = client
            .create_txt_record("zone-1", "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap();
        assert_eq!(id, "record-42");
    }

    #[tokio::test]
    async fn create_txt_record_surfaces_cloudflare_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/zones/zone-1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "result": null,
                "errors": [{"code": 9109, "message": "Invalid access token"}]
            })))
            .mount(&server)
            .await;

        let client = CloudflareDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let err = client
            .create_txt_record("zone-1", "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid access token"));
    }

    #[tokio::test]
    async fn delete_txt_record_succeeds_on_a_successful_response() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path_regex(r"^/zones/zone-1/dns_records/record-42$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": {"id": "record-42"},
                "errors": []
            })))
            .mount(&server)
            .await;

        let client = CloudflareDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        client.delete_txt_record("zone-1", "record-42").await.unwrap();
    }
}
