//! GoDaddy dns-01 provider -- the v3 Domains API
//! (`https://api.godaddy.com/v3/domains/zones/{zone}/dns-records`),
//! confirmed against GoDaddy's own published OpenAPI spec
//! (`developer.godaddy.com/openapi/domains-v3.json`) before writing
//! this, not guessed.
//!
//! Auth is a Personal Access Token as `Authorization: Bearer <token>` --
//! deliberately *not* the older `sso-key {key}:{secret}` v1 scheme most
//! existing ACME clients/tutorials still document. GoDaddy's own docs
//! say that scheme is being phased out and PATs are already required
//! for every v3 endpoint, so building against it now would mean
//! shipping something already headed for deprecation. This also keeps
//! `dns_api_token` a single opaque string, same as every other provider
//! here -- no "pack two credentials into one field" convention needed.
//!
//! `zone` here is just the registered domain name (GoDaddy manages
//! exactly one zone per domain on the account, no separate zone ID), so
//! [`find_zone`](DnsProvider::find_zone) walks up through parent labels
//! the same way Cloudflare/Hetzner do, using a fetch's 200-vs-404 as the
//! exists check (GoDaddy has no separate "does this zone exist" call).
//! Record `name` is zone-relative, so writes go through
//! [`super::relative_record_name`].

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{ApiErrorMessage, Dns01Error, DnsProvider, DnsZone, relative_record_name};

const DEFAULT_BASE_URL: &str = "https://api.godaddy.com/v3/domains/zones";

pub struct GoDaddyDns01 {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl GoDaddyDns01 {
    pub fn new(http: reqwest::Client, token: String) -> Self {
        Self {
            http,
            token,
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(http: reqwest::Client, token: String, base_url: String) -> Self {
        Self {
            http,
            token,
            base_url,
        }
    }

    async fn zone_exists(&self, zone: &str) -> Result<bool, Dns01Error> {
        let resp = self
            .http
            .get(format!("{}/{zone}/dns-records", self.base_url))
            .bearer_auth(&self.token)
            .query(&[("limit", "1")])
            .send()
            .await?;
        Ok(resp.status().is_success())
    }
}

#[derive(Serialize)]
struct NewTxtRecord<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    typ: &'static str,
    data: &'a str,
    ttl: u32,
}

#[derive(Deserialize)]
struct CreatedRecord {
    #[serde(rename = "recordId")]
    record_id: String,
}

#[async_trait]
impl DnsProvider for GoDaddyDns01 {
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error> {
        let labels: Vec<&str> = domain.split('.').collect();
        for i in 0..labels.len().saturating_sub(1) {
            let candidate = labels[i..].join(".");
            if self.zone_exists(&candidate).await? {
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
        // 600s is GoDaddy's documented minimum TTL -- there's no reason
        // to ask for anything longer for a value that gets deleted
        // again within minutes.
        let resp = self
            .http
            .post(format!("{}/{}/dns-records", self.base_url, zone.id))
            .bearer_auth(&self.token)
            .json(&NewTxtRecord {
                name: &relative_name,
                typ: "TXT",
                data: content,
                ttl: 600,
            })
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Dns01Error::Api(response_error_message(resp).await));
        }
        let created: CreatedRecord = resp.json().await?;
        Ok(created.record_id)
    }

    async fn delete_txt_record(&self, zone: &DnsZone, record_id: &str) -> Result<(), Dns01Error> {
        let resp = self
            .http
            .delete(format!(
                "{}/{}/dns-records/{record_id}",
                self.base_url, zone.id
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Dns01Error::Api(response_error_message(resp).await));
        }
        Ok(())
    }
}

/// GoDaddy's error envelope is `{"name","message","details":[...],...}`
/// (confirmed against the OpenAPI spec's error schema) -- `message` is
/// the human-readable summary; `details` (per-field validation issues)
/// isn't surfaced here to keep this consistent with the other
/// providers' single-string error messages.
async fn response_error_message(resp: reqwest::Response) -> String {
    match resp.json::<ApiErrorMessage>().await {
        Ok(env) => super::join_api_errors([env.message.as_str()]),
        Err(_) => super::join_api_errors([]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn zone_lookup_falls_back_to_the_apex_when_the_subdomain_has_no_zone() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/foo.example.com/dns-records"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(
                    serde_json::json!({"name": "NOT_FOUND", "message": "not found"}),
                ),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/example.com/dns-records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"items": []})),
            )
            .mount(&server)
            .await;

        let client =
            GoDaddyDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = client.find_zone("foo.example.com").await.unwrap();
        assert_eq!(zone.id, "example.com");
        assert_eq!(zone.name, "example.com");
    }

    #[tokio::test]
    async fn zone_lookup_errors_when_no_zone_matches_any_parent_domain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(
                    serde_json::json!({"name": "NOT_FOUND", "message": "not found"}),
                ),
            )
            .mount(&server)
            .await;

        let client =
            GoDaddyDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let err = client.find_zone("foo.example.com").await.unwrap_err();
        assert!(matches!(err, Dns01Error::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn create_txt_record_sends_a_bearer_token_and_zone_relative_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/example.com/dns-records"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "recordId": "record-id-1", "name": "_acme-challenge", "type": "TXT", "data": "digest-value", "ttl": 600
            })))
            .mount(&server)
            .await;

        let client =
            GoDaddyDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = DnsZone {
            id: "example.com".into(),
            name: "example.com".into(),
        };
        let id = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap();
        assert_eq!(id, "record-id-1");
    }

    #[tokio::test]
    async fn create_txt_record_surfaces_godaddy_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/example.com/dns-records"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "name": "INVALID_BODY", "message": "data is required"
            })))
            .mount(&server)
            .await;

        let client =
            GoDaddyDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = DnsZone {
            id: "example.com".into(),
            name: "example.com".into(),
        };
        let err = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("data is required"));
    }

    #[tokio::test]
    async fn delete_txt_record_succeeds_on_a_successful_response() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/example.com/dns-records/record-id-1"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client =
            GoDaddyDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = DnsZone {
            id: "example.com".into(),
            name: "example.com".into(),
        };
        client
            .delete_txt_record(&zone, "record-id-1")
            .await
            .unwrap();
    }
}
