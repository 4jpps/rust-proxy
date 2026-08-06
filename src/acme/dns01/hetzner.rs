//! Hetzner DNS-01 provider -- direct calls against the Hetzner DNS API
//! (`https://dns.hetzner.com/api/v1`). Auth is a custom `Auth-API-Token`
//! header, not `Authorization: Bearer` -- confirmed via Hetzner's own DNS
//! API docs before writing this (not guessed; this is the one header
//! shape that genuinely differs from the other two providers here).
//!
//! Like DigitalOcean, Hetzner's record `name` field is zone-relative, not
//! fully-qualified, so writes go through [`super::relative_record_name`].
//! Unlike DigitalOcean, Hetzner does have its own opaque numeric-ish zone
//! ID (returned by `GET /zones?name=`), so [`DnsZone::id`] here is a real
//! provider-assigned ID, not just the domain name repeated.

use async_trait::async_trait;
use serde::Deserialize;

use super::{join_api_errors, relative_record_name, Dns01Error, DnsProvider, DnsZone};

const DEFAULT_BASE_URL: &str = "https://dns.hetzner.com/api/v1";
const AUTH_HEADER: &str = "Auth-API-Token";

#[derive(Debug, Deserialize)]
struct HetznerZoneListResponse {
    zones: Vec<HetznerZone>,
}

#[derive(Debug, Deserialize)]
struct HetznerZone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct HetznerRecordResponse {
    record: HetznerRecord,
}

#[derive(Debug, Deserialize)]
struct HetznerRecord {
    id: String,
}

pub struct HetznerDns01 {
    http: reqwest::Client,
    api_token: String,
    base_url: String,
}

impl HetznerDns01 {
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

    async fn query_zone(&self, name: &str) -> Result<Option<DnsZone>, Dns01Error> {
        let resp = self
            .http
            .get(format!("{}/zones", self.base_url))
            .header(AUTH_HEADER, &self.api_token)
            .query(&[("name", name)])
            .send()
            .await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body: HetznerZoneListResponse = resp.json().await?;
        Ok(body.zones.into_iter().next().map(|z| DnsZone {
            id: z.id,
            name: z.name,
        }))
    }
}

#[async_trait]
impl DnsProvider for HetznerDns01 {
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error> {
        let labels: Vec<&str> = domain.split('.').collect();
        for i in 0..labels.len().saturating_sub(1) {
            let candidate = labels[i..].join(".");
            if let Some(zone) = self.query_zone(&candidate).await? {
                return Ok(zone);
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
            .post(format!("{}/records", self.base_url))
            .header(AUTH_HEADER, &self.api_token)
            .json(&serde_json::json!({
                "zone_id": zone.id,
                "type": "TXT",
                "name": relative_name,
                "value": content,
                "ttl": 300,
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Dns01Error::Api(response_error_message(resp).await));
        }
        let body: HetznerRecordResponse = resp.json().await?;
        Ok(body.record.id)
    }

    async fn delete_txt_record(&self, _zone: &DnsZone, record_id: &str) -> Result<(), Dns01Error> {
        let resp = self
            .http
            .delete(format!("{}/records/{record_id}", self.base_url))
            .header(AUTH_HEADER, &self.api_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Dns01Error::Api(response_error_message(resp).await));
        }
        Ok(())
    }
}

/// Hetzner's error body shape (`{"error": {"message": "...", "code": N}}`)
/// wasn't independently confirmed against live docs the way the
/// zone/record success shapes above were, so this deliberately falls back
/// to a generic message on any parse failure rather than asserting a
/// specific field layout it isn't sure of.
async fn response_error_message(resp: reqwest::Response) -> String {
    #[derive(Deserialize)]
    struct ErrorEnvelope {
        error: ErrorDetail,
    }
    #[derive(Deserialize)]
    struct ErrorDetail {
        message: String,
    }

    match resp.json::<ErrorEnvelope>().await {
        Ok(env) => join_api_errors([env.error.message.as_str()]),
        Err(_) => join_api_errors([]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn zone_lookup_falls_back_to_the_apex_when_the_subdomain_has_no_zone() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "foo.example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"zones": [], "meta": {}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "zones": [{"id": "zone-xyz", "name": "example.com"}],
                "meta": {}
            })))
            .mount(&server)
            .await;

        let client =
            HetznerDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = client.find_zone("foo.example.com").await.unwrap();
        assert_eq!(zone.id, "zone-xyz");
        assert_eq!(zone.name, "example.com");
    }

    #[tokio::test]
    async fn zone_lookup_errors_when_no_zone_matches_any_parent_domain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"zones": [], "meta": {}})),
            )
            .mount(&server)
            .await;

        let client =
            HetznerDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let err = client.find_zone("foo.example.com").await.unwrap_err();
        assert!(matches!(err, Dns01Error::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn create_txt_record_sends_a_zone_relative_name_and_returns_the_new_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "record": {"id": "record-id-1", "type": "TXT", "name": "_acme-challenge", "value": "digest-value", "zone_id": "zone-xyz", "ttl": 300}
            })))
            .mount(&server)
            .await;

        let client =
            HetznerDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = DnsZone {
            id: "zone-xyz".into(),
            name: "example.com".into(),
        };
        let id = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap();
        assert_eq!(id, "record-id-1");
    }

    #[tokio::test]
    async fn create_txt_record_surfaces_hetzner_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {"message": "invalid auth token", "code": 401}
            })))
            .mount(&server)
            .await;

        let client =
            HetznerDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = DnsZone {
            id: "zone-xyz".into(),
            name: "example.com".into(),
        };
        let err = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid auth token"));
    }

    #[tokio::test]
    async fn delete_txt_record_succeeds_on_a_successful_response() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/records/record-id-1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client =
            HetznerDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = DnsZone {
            id: "zone-xyz".into(),
            name: "example.com".into(),
        };
        client
            .delete_txt_record(&zone, "record-id-1")
            .await
            .unwrap();
    }
}
