//! DuckDNS dns-01 provider -- a single `GET` request against
//! `https://www.duckdns.org/update`, confirmed via DuckDNS's own spec
//! (`duckdns.org/spec.jsp`) and cross-checked against `go-acme/lego`'s
//! well-established DuckDNS provider for the parts the spec leaves
//! implicit (the exact `clear`/`txt` combination for set vs. clear, and
//! reducing a deeper hostname down to the actual registered subdomain).
//!
//! DuckDNS genuinely has no zone/record-ID concept at all -- an account
//! owns exactly one subdomain, and that subdomain has exactly one TXT
//! value shared across it and everything under it (lego's own comment:
//! "In DuckDNS you only have one TXT record shared with the domain and
//! all subdomains"). So unlike Cloudflare/DigitalOcean/Hetzner,
//! [`find_zone`](DnsProvider::find_zone) makes no API call -- there's
//! nothing to look up, only string surgery to find which label is the
//! registered subdomain -- and the "record ID" `create_txt_record`
//! returns is a placeholder; `delete_txt_record` doesn't need one; the
//! subdomain name alone is enough to clear it.

use async_trait::async_trait;

use super::{Dns01Error, DnsProvider, DnsZone};

const DEFAULT_BASE_URL: &str = "https://www.duckdns.org/update";
const APEX: &str = "duckdns.org";

pub struct DuckDnsDns01 {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl DuckDnsDns01 {
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

    async fn update(&self, subdomain: &str, txt: &str, clear: bool) -> Result<(), Dns01Error> {
        let resp = self
            .http
            .get(&self.base_url)
            .query(&[
                ("domains", subdomain),
                ("token", self.token.as_str()),
                ("txt", txt),
                ("clear", if clear { "true" } else { "false" }),
            ])
            .send()
            .await?;
        let body = resp.text().await?;
        // DuckDNS's entire response contract is the literal text "OK" or
        // "KO" (optionally with extra lines if `verbose=true`, which
        // this client doesn't set) -- there's no structured error body
        // to extract a message from.
        if body.trim() != "OK" {
            return Err(Dns01Error::Api(format!(
                "DuckDNS update returned \"{}\" (expected OK)",
                body.trim()
            )));
        }
        Ok(())
    }
}

/// DuckDNS only lets you manage the one subdomain your account
/// registered -- `sub.duckdns.org`, never anything deeper. A host
/// configured at `app.sub.duckdns.org` (or a wildcard `*.sub.duckdns.org`)
/// still needs its dns-01 challenge published against that same
/// `sub.duckdns.org` slot, so this always reduces to exactly the label
/// immediately before `duckdns.org`, discarding everything deeper --
/// the same "top 3 levels" rule `go-acme/lego`'s DuckDNS provider uses.
fn registered_subdomain(domain: &str) -> Option<String> {
    let lower = domain.to_ascii_lowercase();
    if !lower.ends_with(&format!(".{APEX}")) {
        return None;
    }
    let without_apex = lower.strip_suffix(&format!(".{APEX}"))?;
    let subdomain = without_apex.rsplit('.').next()?;
    (!subdomain.is_empty()).then(|| subdomain.to_string())
}

#[async_trait]
impl DnsProvider for DuckDnsDns01 {
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error> {
        let subdomain = registered_subdomain(domain)
            .ok_or_else(|| Dns01Error::ZoneNotFound(domain.to_string()))?;
        Ok(DnsZone {
            id: subdomain.clone(),
            name: subdomain,
        })
    }

    /// `name` (the fully-qualified `_acme-challenge...` record name) is
    /// unused -- DuckDNS has no concept of a record name to target, only
    /// the one TXT slot for the whole subdomain.
    async fn create_txt_record(
        &self,
        zone: &DnsZone,
        _name: &str,
        content: &str,
    ) -> Result<String, Dns01Error> {
        self.update(&zone.id, content, false).await?;
        Ok(zone.id.clone())
    }

    /// `record_id` is unused for the same reason -- clearing just needs
    /// the subdomain, already in `zone.id`.
    async fn delete_txt_record(&self, zone: &DnsZone, _record_id: &str) -> Result<(), Dns01Error> {
        self.update(&zone.id, "", true).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn registered_subdomain_strips_the_duckdns_org_suffix() {
        assert_eq!(
            registered_subdomain("myhost.duckdns.org").as_deref(),
            Some("myhost")
        );
    }

    #[test]
    fn registered_subdomain_reduces_a_deeper_hostname_to_the_registered_label() {
        assert_eq!(
            registered_subdomain("app.myhost.duckdns.org").as_deref(),
            Some("myhost")
        );
    }

    #[test]
    fn registered_subdomain_is_case_insensitive() {
        assert_eq!(
            registered_subdomain("MyHost.DuckDNS.org").as_deref(),
            Some("myhost")
        );
    }

    #[test]
    fn registered_subdomain_rejects_a_non_duckdns_domain() {
        assert_eq!(registered_subdomain("example.com"), None);
    }

    #[tokio::test]
    async fn find_zone_makes_no_http_call_and_returns_the_registered_subdomain() {
        // No mock mounted at all -- if find_zone made any HTTP request
        // this would fail with a connection error, proving it doesn't.
        let server = MockServer::start().await;
        let client =
            DuckDnsDns01::with_base_url(reqwest::Client::new(), "test-token".into(), server.uri());
        let zone = client.find_zone("app.myhost.duckdns.org").await.unwrap();
        assert_eq!(zone.id, "myhost");
        assert_eq!(zone.name, "myhost");
    }

    #[tokio::test]
    async fn find_zone_errors_for_a_non_duckdns_domain() {
        let client = DuckDnsDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            "http://unused.invalid".into(),
        );
        let err = client.find_zone("example.com").await.unwrap_err();
        assert!(matches!(err, Dns01Error::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn create_txt_record_sends_clear_false_and_the_txt_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/update"))
            .and(query_param("domains", "myhost"))
            .and(query_param("token", "test-token"))
            .and(query_param("txt", "digest-value"))
            .and(query_param("clear", "false"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&server)
            .await;

        let client = DuckDnsDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            format!("{}/update", server.uri()),
        );
        let zone = DnsZone {
            id: "myhost".into(),
            name: "myhost".into(),
        };
        let record_id = client
            .create_txt_record(&zone, "_acme-challenge.myhost.duckdns.org", "digest-value")
            .await
            .unwrap();
        assert_eq!(record_id, "myhost");
    }

    #[tokio::test]
    async fn create_txt_record_surfaces_a_ko_response_as_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/update"))
            .respond_with(ResponseTemplate::new(200).set_body_string("KO"))
            .mount(&server)
            .await;

        let client = DuckDnsDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            format!("{}/update", server.uri()),
        );
        let zone = DnsZone {
            id: "myhost".into(),
            name: "myhost".into(),
        };
        let err = client
            .create_txt_record(&zone, "_acme-challenge.myhost.duckdns.org", "digest-value")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("KO"));
    }

    #[tokio::test]
    async fn delete_txt_record_sends_clear_true_and_an_empty_txt_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/update"))
            .and(query_param("domains", "myhost"))
            .and(query_param("token", "test-token"))
            .and(query_param("txt", ""))
            .and(query_param("clear", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&server)
            .await;

        let client = DuckDnsDns01::with_base_url(
            reqwest::Client::new(),
            "test-token".into(),
            format!("{}/update", server.uri()),
        );
        let zone = DnsZone {
            id: "myhost".into(),
            name: "myhost".into(),
        };
        client.delete_txt_record(&zone, "myhost").await.unwrap();
    }
}
