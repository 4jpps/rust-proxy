//! DigitalOcean DNS-01 provider -- direct calls against the DigitalOcean
//! API v2 (`https://api.digitalocean.com/v2`), Bearer-token auth.
//! Verified against DigitalOcean's own published OpenAPI spec
//! (api-engineering.nyc3.cdn.digitaloceanspaces.com/spec-ci/DigitalOcean-public.v2.yaml)
//! before writing this, not guessed.
//!
//! DigitalOcean has no separate numeric zone ID the way Cloudflare/Hetzner
//! do -- domain records live directly under `/v2/domains/{domain_name}`,
//! so the "zone ID" [`DnsZone::id`] this provider returns is just the
//! domain name string itself. Its record `name` field is also always
//! relative to that domain, never fully-qualified, so every write here
//! goes through [`super::relative_record_name`] first.

use async_trait::async_trait;
use serde::Deserialize;

use super::{
    join_api_errors, relative_record_name, ApiErrorMessage, Dns01Error, DnsProvider, DnsZone,
};

const DEFAULT_BASE_URL: &str = "https://api.digitalocean.com/v2";

#[derive(Debug, Deserialize)]
struct DoRecordResponse {
    domain_record: DoRecord,
}

#[derive(Debug, Deserialize)]
struct DoRecord {
    id: u64,
}

pub struct DigitalOceanDns01 {
    http: reqwest::Client,
    api_token: String,
    base_url: String,
}

impl DigitalOceanDns01 {
    pub fn new(http: reqwest::Client, api_token: String) -> Self {
        Self {
            http,
            api_token,
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(http: reqwest::Client, api_token: String, base_url: String) -> Self {
        Self {
            http,
            api_token,
            base_url,
        }
    }

    /// `GET /v2/domains/{name}` returns 200 with the domain resource if
    /// DigitalOcean manages it, 404 otherwise -- there's no list-by-name
    /// filter to query instead, so existence is the only signal.
    async fn domain_exists(&self, name: &str) -> Result<bool, Dns01Error> {
        let resp = self
            .http
            .get(format!("{}/domains/{name}", self.base_url))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        Ok(resp.status().is_success())
    }
}

#[async_trait]
impl DnsProvider for DigitalOceanDns01 {
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error> {
        let labels: Vec<&str> = domain.split('.').collect();
        for i in 0..labels.len().saturating_sub(1) {
            let candidate = labels[i..].join(".");
            if self.domain_exists(&candidate).await? {
                return Ok(DnsZone {
                    id: candidate.clone(),
                    name: candidate,
                });
            }
        }
        Err(Dns01Error::ZoneNotFound(domain.to_string()))
    }

    async fn create_txt_record(
        &self,
        zone: &DnsZone,
        name: &str,
        content: &str,
    ) -> Result<String, Dns01Error> {
        let relative_name = relative_record_name(name, &zone.name);
        let resp = self
            .http
            .post(format!("{}/domains/{}/records", self.base_url, zone.id))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": relative_name,
                "data": content,
                "ttl": 30,
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Dns01Error::Api(response_error_message(resp).await));
        }
        let body: DoRecordResponse = resp.json().await?;
        Ok(body.domain_record.id.to_string())
    }

    async fn delete_txt_record(&self, zone: &DnsZone, record_id: &str) -> Result<(), Dns01Error> {
        let resp = self
            .http
            .delete(format!(
                "{}/domains/{}/records/{record_id}",
                self.base_url, zone.id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Dns01Error::Api(response_error_message(resp).await));
        }
        Ok(())
    }
}

/// DigitalOcean error responses are `{"id": "...", "message": "..."}`,
/// not Cloudflare's `{"errors": [...]}` array shape -- reuses
/// [`ApiErrorMessage`] for the one field both shapes have in common
/// rather than a DO-specific struct for a single string.
async fn response_error_message(resp: reqwest::Response) -> String {
    match resp.json::<ApiErrorMessage>().await {
        Ok(err) => join_api_errors([err.message.as_str()]),
        Err(_) => join_api_errors([]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn zone_lookup_falls_back_to_the_apex_when_the_subdomain_is_not_a_registered_domain() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/domains/foo.example.com"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/domains/example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "domain": {"name": "example.com"}
            })))
            .mount(&server)
            .await;

        let client = DigitalOceanDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let zone = client.find_zone("foo.example.com").await.unwrap();
        assert_eq!(zone.id, "example.com");
        assert_eq!(zone.name, "example.com");
    }

    #[tokio::test]
    async fn zone_lookup_errors_when_no_parent_domain_is_registered() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = DigitalOceanDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let err = client.find_zone("foo.example.com").await.unwrap_err();
        assert!(matches!(err, Dns01Error::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn create_txt_record_sends_a_zone_relative_name_and_returns_the_new_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/domains/example.com/records"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "domain_record": {"id": 3352896, "type": "TXT", "name": "_acme-challenge", "data": "digest-value"}
            })))
            .mount(&server)
            .await;

        let client = DigitalOceanDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let zone = DnsZone {
            id: "example.com".into(),
            name: "example.com".into(),
        };
        let id = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap();
        assert_eq!(id, "3352896");
    }

    #[tokio::test]
    async fn create_txt_record_surfaces_digitalocean_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/domains/example.com/records"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "id": "unauthorized",
                "message": "Unable to authenticate you"
            })))
            .mount(&server)
            .await;

        let client = DigitalOceanDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let zone = DnsZone {
            id: "example.com".into(),
            name: "example.com".into(),
        };
        let err = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Unable to authenticate you"));
    }

    #[tokio::test]
    async fn delete_txt_record_succeeds_on_a_204() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/domains/example.com/records/3352896"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = DigitalOceanDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let zone = DnsZone {
            id: "example.com".into(),
            name: "example.com".into(),
        };
        client.delete_txt_record(&zone, "3352896").await.unwrap();
    }
}
