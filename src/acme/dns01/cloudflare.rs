//! Cloudflare DNS-01 provider -- direct calls against the Cloudflare API
//! v4 (`https://api.cloudflare.com/client/v4`), Bearer-token auth. Record
//! names are fully-qualified (Cloudflare accepts and returns them that
//! way), so unlike [`super::digitalocean`]/[`super::hetzner`] this
//! provider never needs [`super::relative_record_name`].

use async_trait::async_trait;
use serde::Deserialize;

use super::{ApiErrorMessage, Dns01Error, DnsProvider, DnsZone, join_api_errors};

const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";

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
    errors: Vec<ApiErrorMessage>,
}

#[derive(Debug, Deserialize)]
struct CfZone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CfDnsRecord {
    id: String,
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
            .bearer_auth(&self.api_token)
            .query(&[("name", name)])
            .send()
            .await?;
        let body: CfListResponse<CfZone> = resp.json().await?;
        Ok(body.result.into_iter().next().map(|z| DnsZone {
            id: z.id,
            name: z.name,
        }))
    }
}

#[async_trait]
impl DnsProvider for CloudflareDns01 {
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error> {
        let labels: Vec<&str> = domain.split('.').collect();
        // Stop one short of the TLD itself (e.g. never query for "com").
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
        let resp = self
            .http
            .post(format!("{}/zones/{}/dns_records", self.base_url, zone.id))
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
            return Err(Dns01Error::Api(join_api_errors(
                body.errors.iter().map(|e| e.message.as_str()),
            )));
        }
        body.result.map(|r| r.id).ok_or(Dns01Error::MissingResult)
    }

    async fn delete_txt_record(&self, zone: &DnsZone, record_id: &str) -> Result<(), Dns01Error> {
        let resp = self
            .http
            .delete(format!(
                "{}/zones/{}/dns_records/{record_id}",
                self.base_url, zone.id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        let body: CfSingleResponse<CfDnsRecord> = resp.json().await?;
        if !body.success {
            return Err(Dns01Error::Api(join_api_errors(
                body.errors.iter().map(|e| e.message.as_str()),
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn zone_lookup_falls_back_to_the_apex_when_the_subdomain_has_no_zone() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "foo.example.com"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"success": true, "result": []})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": [{"id": "zone-abc123", "name": "example.com"}]
            })))
            .mount(&server)
            .await;

        let client = CloudflareDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let zone = client.find_zone("foo.example.com").await.unwrap();
        assert_eq!(zone.id, "zone-abc123");
        assert_eq!(zone.name, "example.com");
    }

    #[tokio::test]
    async fn zone_lookup_errors_when_no_zone_matches_any_parent_domain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"success": true, "result": []})),
            )
            .mount(&server)
            .await;

        let client = CloudflareDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let err = client.find_zone("foo.example.com").await.unwrap_err();
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

        let client = CloudflareDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let zone = DnsZone {
            id: "zone-1".into(),
            name: "example.com".into(),
        };
        let id = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
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

        let client = CloudflareDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let zone = DnsZone {
            id: "zone-1".into(),
            name: "example.com".into(),
        };
        let err = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
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

        let client = CloudflareDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            server.uri(),
        );
        let zone = DnsZone {
            id: "zone-1".into(),
            name: "example.com".into(),
        };
        client.delete_txt_record(&zone, "record-42").await.unwrap();
    }
}
