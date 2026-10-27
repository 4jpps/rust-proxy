//! Route53 DNS-01 provider -- direct REST-XML calls against Route53's
//! global/legacy endpoint (`https://route53.amazonaws.com`), authenticated
//! with AWS Signature Version 4 implemented from scratch in `sigv4`
//! (no aws-sdk-* crate, same "thin direct reqwest client" philosophy as
//! every other provider here).
//!
//! Route53 is a global service with no regional API endpoints -- but
//! SigV4 signing still needs *a* region in its credential scope. AWS's
//! own documentation (https://docs.aws.amazon.com/general/latest/gr/r53.html,
//! "Service endpoints" section) says explicitly: "Route 53 in AWS
//! Regions other than the Beijing and Ningxia Regions: specify
//! us-east-1 as the Region... When you use the Route 53 API to submit
//! requests, use the same Regions as above to sign requests." So the
//! signing region is always `"us-east-1"` here, regardless of what
//! region (if any) the operator's own AWS account otherwise uses --
//! confirmed against AWS's own documentation, not assumed.
//!
//! Auth needs two pieces packed into `token` as
//! `"access_key_id:secret_access_key"` (no region in the token itself --
//! see above), same multi-field-credential convention `namecheap.rs`
//! established.
//!
//! `create_txt_record`'s returned "record ID" packs the record's fully-
//! qualified name and its exact TXT value as `"{name}|{content}"` --
//! Route53's `ChangeResourceRecordSets` API has no separate record-ID
//! concept at all; deleting a record set means resubmitting the exact
//! same Name/Type/TTL/Value with `Action=DELETE`. `|` is a safe
//! separator: it can never appear in a DNS name, and the TXT content
//! here is always this crate's own base64url ACME digest
//! (`[A-Za-z0-9_-]`, see `dns01::dns01_txt_value`).

use async_trait::async_trait;
use quick_xml::Reader;
use quick_xml::events::Event;

use super::sigv4::SigV4Signer;
use super::{Dns01Error, DnsProvider, DnsZone};

const BASE_URL: &str = "https://route53.amazonaws.com";
const API_VERSION: &str = "2013-04-01";
const SIGNING_REGION: &str = "us-east-1";
const SIGNING_SERVICE: &str = "route53";
const TXT_TTL: i64 = 300;

pub struct Route53Dns01 {
    http: reqwest::Client,
    signer: SigV4Signer,
    base_url: String,
}

impl Route53Dns01 {
    /// `token` is `"access_key_id:secret_access_key"`.
    pub fn new(http: reqwest::Client, token: String) -> Self {
        let mut parts = token.splitn(2, ':');
        let access_key_id = parts.next().unwrap_or_default().to_string();
        let secret_access_key = parts.next().unwrap_or_default().to_string();
        Self {
            http,
            signer: SigV4Signer::new(
                access_key_id,
                secret_access_key,
                SIGNING_REGION.to_string(),
                SIGNING_SERVICE.to_string(),
            ),
            base_url: BASE_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(http: reqwest::Client, token: String, base_url: String) -> Self {
        let mut client = Self::new(http, token);
        client.base_url = base_url;
        client
    }

    /// The SigV4 canonical `host` header is always the real service
    /// host, even in tests where `base_url` points at a local mock
    /// server -- Route53 itself never sees these test requests, so
    /// there's nothing to validate the signed host against; this
    /// mirrors the `with_base_url` test seam every other provider here
    /// already uses.
    fn host_header(&self) -> &'static str {
        "route53.amazonaws.com"
    }

    async fn list_hosted_zones_by_name(
        &self,
        dns_name: &str,
    ) -> Result<Option<DnsZone>, Dns01Error> {
        let path = format!("/{API_VERSION}/hostedzonesbyname");
        let dns_name = dns_name.trim_end_matches('.');
        let query = [("dnsname", dns_name), ("maxitems", "1")];
        let signed = self.signer.sign(
            "GET",
            self.host_header(),
            &path,
            &query,
            b"",
            chrono::Utc::now(),
        );

        let resp = self
            .http
            .get(format!("{}{path}", self.base_url))
            .query(&query)
            .header("x-amz-date", &signed.x_amz_date)
            .header("Authorization", &signed.authorization)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(Dns01Error::Api(route53_error_message(&body)));
        }
        parse_list_hosted_zones_response(&body, dns_name)
    }

    async fn change_resource_record_sets(
        &self,
        zone_id: &str,
        action: &str,
        name: &str,
        content: &str,
    ) -> Result<(), Dns01Error> {
        let path = format!("/{API_VERSION}/hostedzone/{zone_id}/rrset");
        let body = change_batch_xml(action, name, content);
        let signed = self.signer.sign(
            "POST",
            self.host_header(),
            &path,
            &[],
            body.as_bytes(),
            chrono::Utc::now(),
        );

        let resp = self
            .http
            .post(format!("{}{path}", self.base_url))
            .header("x-amz-date", &signed.x_amz_date)
            .header("Authorization", &signed.authorization)
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(Dns01Error::Api(route53_error_message(&body)));
        }
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for Route53Dns01 {
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error> {
        let labels: Vec<&str> = domain.split('.').collect();
        for i in 0..labels.len().saturating_sub(1) {
            let candidate = labels[i..].join(".");
            if let Some(zone) = self.list_hosted_zones_by_name(&candidate).await? {
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
        self.change_resource_record_sets(&zone.id, "UPSERT", name, content)
            .await?;
        Ok(format!("{name}|{content}"))
    }

    async fn delete_txt_record(&self, zone: &DnsZone, record_id: &str) -> Result<(), Dns01Error> {
        let (name, content) = record_id
            .split_once('|')
            .ok_or_else(|| Dns01Error::Api(format!("malformed Route53 record id: {record_id}")))?;
        self.change_resource_record_sets(&zone.id, "DELETE", name, content)
            .await
    }
}

fn change_batch_xml(action: &str, name: &str, content: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>
      <Change>
        <Action>{action}</Action>
        <ResourceRecordSet>
          <Name>{}</Name>
          <Type>TXT</Type>
          <TTL>{TXT_TTL}</TTL>
          <ResourceRecords>
            <ResourceRecord>
              <Value>{}</Value>
            </ResourceRecord>
          </ResourceRecords>
        </ResourceRecordSet>
      </Change>
    </Changes>
  </ChangeBatch>
</ChangeResourceRecordSetsRequest>"#,
        xml_escape(name),
        // Route53 TXT record values must be wrapped in literal double
        // quotes in the API request itself (this is Route53's own
        // convention, distinct from the outer XML element quoting).
        xml_escape(&format!("\"{content}\"")),
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Walks `<ListHostedZonesByNameResponse><HostedZones><HostedZone>
/// <Id>/hostedzone/Z123</Id><Name>example.com.</Name>...`, returning the
/// first zone whose `Name` (trailing dot stripped) case-insensitively
/// matches `dns_name`. An exact-name check is required here -- unlike
/// every other provider's zone-list API in this module, Route53's
/// `ListHostedZonesByName` returns the *closest* match sorted near the
/// requested name even when there's no exact match, so a naive
/// "first result" read would silently pick the wrong zone.
fn parse_list_hosted_zones_response(
    body: &str,
    dns_name: &str,
) -> Result<Option<DnsZone>, Dns01Error> {
    let wanted = dns_name.trim_end_matches('.').to_ascii_lowercase();
    let mut reader = Reader::from_str(body);
    let mut buf = Vec::new();
    let (mut current_id, mut current_name) = (None::<String>, None::<String>);
    let (mut in_id, mut in_name) = (false, false);
    let mut found: Option<DnsZone> = None;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref() == "Id" => {
                in_id = true;
                current_id = Some(String::new());
            }
            Ok(Event::End(e)) if e.name().as_ref() == "Id" => in_id = false,
            Ok(Event::Start(e)) if e.name().as_ref() == "Name" => {
                in_name = true;
                current_name = Some(String::new());
            }
            Ok(Event::End(e)) if e.name().as_ref() == "Name" => in_name = false,
            Ok(ev) if in_id || in_name => {
                let target = if in_id {
                    &mut current_id
                } else {
                    &mut current_name
                };
                if let (Some(text), Some(piece)) = (target.as_mut(), super::xml_text_piece(&ev)) {
                    text.push_str(&piece);
                }
            }
            Ok(Event::End(e)) if e.name().as_ref() == "HostedZone" => {
                if let (Some(id), Some(name)) = (current_id.take(), current_name.take()) {
                    let stripped_name = name.trim_end_matches('.').to_ascii_lowercase();
                    if found.is_none() && stripped_name == wanted {
                        found = Some(DnsZone {
                            id: id.trim_start_matches("/hostedzone/").to_string(),
                            name: stripped_name,
                        });
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => {
                return Err(Dns01Error::Api(format!(
                    "failed to parse Route53 response: {err}"
                )));
            }
        }
        buf.clear();
    }
    Ok(found)
}

/// Route53 error bodies are XML (`<ErrorResponse><Error><Message>...`),
/// not JSON like most of the other providers here -- a tiny dedicated
/// walk, not worth a struct given the shallow shape.
fn route53_error_message(body: &str) -> String {
    let mut reader = Reader::from_str(body);
    let mut buf = Vec::new();
    let mut in_message = false;
    let mut message = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref() == "Message" => in_message = true,
            Ok(Event::End(e)) if e.name().as_ref() == "Message" => in_message = false,
            Ok(ev) if in_message => message.extend(super::xml_text_piece(&ev)),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        buf.clear();
    }
    if message.is_empty() {
        format!("Route53 API error (unparsed body): {body}")
    } else {
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn list_zones_xml(zones: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
            <ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
              <HostedZones>{zones}</HostedZones>
              <IsTruncated>false</IsTruncated>
            </ListHostedZonesByNameResponse>"#
        )
    }

    fn hosted_zone_xml(id: &str, name: &str) -> String {
        format!(
            "<HostedZone><Id>{id}</Id><Name>{name}</Name><CallerReference>x</CallerReference></HostedZone>"
        )
    }

    #[tokio::test]
    async fn zone_lookup_falls_back_to_the_apex_when_the_subdomain_has_no_zone() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2013-04-01/hostedzonesbyname"))
            .and(query_param("dnsname", "foo.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_string(list_zones_xml("")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/2013-04-01/hostedzonesbyname"))
            .and(query_param("dnsname", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_string(list_zones_xml(
                &hosted_zone_xml("/hostedzone/Z123", "example.com."),
            )))
            .mount(&server)
            .await;

        let client =
            Route53Dns01::with_base_url(reqwest::Client::new(), "AKID:SECRET".into(), server.uri());
        let zone = client.find_zone("foo.example.com").await.unwrap();
        assert_eq!(zone.id, "Z123");
        assert_eq!(zone.name, "example.com");
    }

    #[tokio::test]
    async fn zone_lookup_errors_when_no_zone_matches_any_parent_domain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(list_zones_xml("")))
            .mount(&server)
            .await;

        let client =
            Route53Dns01::with_base_url(reqwest::Client::new(), "AKID:SECRET".into(), server.uri());
        let err = client.find_zone("foo.example.com").await.unwrap_err();
        assert!(matches!(err, Dns01Error::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn zone_lookup_ignores_a_non_exact_closest_match() {
        // Route53's ListHostedZonesByName returns the *closest* zone even
        // when there's no exact match -- this must not be mistaken for a
        // real match.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("dnsname", "foo.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_string(list_zones_xml(
                &hosted_zone_xml("/hostedzone/Z999", "other.com."),
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("dnsname", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_string(list_zones_xml(
                &hosted_zone_xml("/hostedzone/Z123", "example.com."),
            )))
            .mount(&server)
            .await;

        let client =
            Route53Dns01::with_base_url(reqwest::Client::new(), "AKID:SECRET".into(), server.uri());
        let zone = client.find_zone("foo.example.com").await.unwrap();
        assert_eq!(zone.id, "Z123");
    }

    #[tokio::test]
    async fn create_txt_record_sends_upsert_and_returns_a_name_content_record_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/2013-04-01/hostedzone/Z123/rrset"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status><SubmittedAt>2026-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>"#,
            ))
            .mount(&server)
            .await;

        let client =
            Route53Dns01::with_base_url(reqwest::Client::new(), "AKID:SECRET".into(), server.uri());
        let zone = DnsZone {
            id: "Z123".into(),
            name: "example.com".into(),
        };
        let record_id = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap();
        assert_eq!(record_id, "_acme-challenge.example.com|digest-value");
    }

    #[tokio::test]
    async fn create_txt_record_surfaces_route53_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                r#"<ErrorResponse><Error><Type>Sender</Type><Code>InvalidChangeBatch</Code><Message>bad request</Message></Error></ErrorResponse>"#,
            ))
            .mount(&server)
            .await;

        let client =
            Route53Dns01::with_base_url(reqwest::Client::new(), "AKID:SECRET".into(), server.uri());
        let zone = DnsZone {
            id: "Z123".into(),
            name: "example.com".into(),
        };
        let err = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad request"));
    }

    #[tokio::test]
    async fn delete_txt_record_sends_delete_with_the_same_name_and_content() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/2013-04-01/hostedzone/Z123/rrset"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status><SubmittedAt>2026-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>"#,
            ))
            .mount(&server)
            .await;

        let client =
            Route53Dns01::with_base_url(reqwest::Client::new(), "AKID:SECRET".into(), server.uri());
        let zone = DnsZone {
            id: "Z123".into(),
            name: "example.com".into(),
        };
        client
            .delete_txt_record(&zone, "_acme-challenge.example.com|digest-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_txt_record_rejects_a_malformed_record_id() {
        let client = Route53Dns01::with_base_url(
            reqwest::Client::new(),
            "AKID:SECRET".into(),
            "http://localhost".into(),
        );
        let zone = DnsZone {
            id: "Z123".into(),
            name: "example.com".into(),
        };
        let err = client
            .delete_txt_record(&zone, "no-separator-here")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }

    #[test]
    fn error_message_keeps_entities() {
        let body = "<ErrorResponse><Error><Message>Invalid &quot;name&quot; &amp; value</Message></Error></ErrorResponse>";
        assert_eq!(route53_error_message(body), r#"Invalid "name" & value"#);
    }
}
