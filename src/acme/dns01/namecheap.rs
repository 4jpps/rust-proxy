//! Namecheap dns-01 provider -- the XML `namecheap.domains.dns.*` API
//! (`https://api.namecheap.com/xml.response`). Confirmed against
//! `go-acme/lego`'s well-established Namecheap provider (its exact
//! request params and XML response shapes), since Namecheap's own docs
//! site blocks generic fetches; lego's implementation is real, widely
//! used, production code, not a guess.
//!
//! Three things make this provider a genuinely different shape from
//! Cloudflare/DigitalOcean/Hetzner/GoDaddy:
//!
//! - **XML, not JSON.** The only reason this crate depends on `quick-xml`
//!   at all.
//! - **No per-record write API.** `getHosts`/`setHosts` read and replace
//!   *the entire* host record list for a domain in one shot -- there's
//!   no add/delete-one-record call. `create_txt_record` reads the
//!   current list, appends the challenge TXT record, and writes the
//!   whole list back; `delete_txt_record` does the same in reverse. This
//!   is exactly what real ACME clients against Namecheap have to do
//!   (see lego's own comment: "There is no API to add or modify a single
//!   DNS record... (Yuck.)").
//! - **No record IDs.** Host records are identified only by
//!   `(Name, Type)`, not an opaque ID, so unlike the ID-based providers,
//!   [`create_txt_record`](DnsProvider::create_txt_record) returns the
//!   relative record *name* as its "ID" -- `delete_txt_record` uses it
//!   to find and drop the matching `Name`+`TXT` entry from a fresh
//!   `getHosts` read.
//!
//! Auth needs three pieces Namecheap requires on every call -- `ApiUser`,
//! `ApiKey`, and `ClientIp` (an IP the account has allowlisted in its
//! Namecheap API settings; not a secret, but still required on every
//! request) -- packed into `dns_api_token` as `"user:key:clientip"`,
//! following the same "one opaque config field" convention this crate
//! already uses when a provider needs more than one credential part.
//!
//! Zone lookup splits a candidate domain as `sld.tld` using the *last
//! label only* as the TLD (e.g. `example.com` -> SLD `example`, TLD
//! `com`) -- correct for the common single-label TLDs Namecheap mostly
//! sells (`.com`/`.net`/`.org`/`.io`/...), but not a full public-suffix-
//! list lookup, so a genuine multi-label TLD (`.co.uk`, `.com.au`) would
//! split wrong. Not attempting a full PSL implementation here; flagged
//! plainly rather than silently mishandled.

use async_trait::async_trait;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use super::{Dns01Error, DnsProvider, DnsZone, join_api_errors, relative_record_name};

const DEFAULT_BASE_URL: &str = "https://api.namecheap.com/xml.response";
/// Namecheap requires this field on every `setHosts` write for every
/// record type, TXT included, even though it's semantically meaningless
/// outside MX records -- `10` is what lego's own provider sends.
const PLACEHOLDER_MX_PREF: &str = "10";
const TXT_TTL: &str = "1800";

#[derive(Debug, Clone)]
struct HostRecord {
    typ: String,
    name: String,
    address: String,
    mx_pref: String,
    ttl: String,
}

pub struct NamecheapDns01 {
    http: reqwest::Client,
    api_user: String,
    api_key: String,
    client_ip: String,
    base_url: String,
}

impl NamecheapDns01 {
    /// `token` is `"api_user:api_key:client_ip"` -- see the module doc
    /// for why three credential parts get packed into the one config
    /// field every other provider here also uses.
    pub fn new(http: reqwest::Client, token: String) -> Self {
        let mut parts = token.splitn(3, ':');
        let api_user = parts.next().unwrap_or_default().to_string();
        let api_key = parts.next().unwrap_or_default().to_string();
        let client_ip = parts.next().unwrap_or_default().to_string();
        Self {
            http,
            api_user,
            api_key,
            client_ip,
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(http: reqwest::Client, token: String, base_url: String) -> Self {
        let mut client = Self::new(http, token);
        client.base_url = base_url;
        client
    }

    fn base_params(&self, command: &str) -> Vec<(String, String)> {
        vec![
            ("ApiUser".to_string(), self.api_user.clone()),
            ("ApiKey".to_string(), self.api_key.clone()),
            ("UserName".to_string(), self.api_user.clone()),
            ("Command".to_string(), command.to_string()),
            ("ClientIp".to_string(), self.client_ip.clone()),
        ]
    }

    async fn get_hosts(&self, sld: &str, tld: &str) -> Result<Vec<HostRecord>, Dns01Error> {
        let mut params = self.base_params("namecheap.domains.dns.getHosts");
        params.push(("SLD".to_string(), sld.to_string()));
        params.push(("TLD".to_string(), tld.to_string()));

        let resp = self.http.get(&self.base_url).query(&params).send().await?;
        let body = resp.text().await?;
        parse_get_hosts_response(&body)
    }

    async fn set_hosts(
        &self,
        sld: &str,
        tld: &str,
        hosts: &[HostRecord],
    ) -> Result<(), Dns01Error> {
        let mut params = self.base_params("namecheap.domains.dns.setHosts");
        params.push(("SLD".to_string(), sld.to_string()));
        params.push(("TLD".to_string(), tld.to_string()));
        for (i, host) in hosts.iter().enumerate() {
            let n = i + 1;
            params.push((format!("HostName{n}"), host.name.clone()));
            params.push((format!("RecordType{n}"), host.typ.clone()));
            params.push((format!("Address{n}"), host.address.clone()));
            params.push((format!("MXPref{n}"), host.mx_pref.clone()));
            params.push((format!("TTL{n}"), host.ttl.clone()));
        }

        // setHosts is a POST with the params as a form-urlencoded body --
        // confirmed against go-acme/lego's Namecheap provider
        // (internal/client.go's newRequestPost: `strings.NewReader(query.Encode())`
        // with `Content-Type: application/x-www-form-urlencoded`), not a
        // query string like getHosts uses.
        let resp = self.http.post(&self.base_url).form(&params).send().await?;
        let body = resp.text().await?;
        parse_set_hosts_response(&body)
    }

    /// Single-label-TLD split -- see the module doc's caveat about
    /// multi-label TLDs.
    fn split_sld_tld(candidate: &str) -> Option<(String, String)> {
        let (sld, tld) = candidate.rsplit_once('.')?;
        (!sld.is_empty() && !tld.is_empty()).then(|| (sld.to_string(), tld.to_string()))
    }

    /// The last two labels of `domain`, regardless of how many precede
    /// them -- a Namecheap zone is always exactly `sld.tld` (no nested
    /// zones to walk through the way Cloudflare/Hetzner/GoDaddy's real
    /// zone-list APIs support), so `app.example.com` and
    /// `*.example.com` both reduce to the same `example.com` zone
    /// candidate. `split_sld_tld` must only ever be called on this
    /// reduced form, never on the original (possibly deeper) domain --
    /// applying it directly to `app.example.com` would misparse `app.example`
    /// as the SLD.
    fn zone_candidate(domain: &str) -> Option<String> {
        let labels: Vec<&str> = domain.split('.').collect();
        (labels.len() >= 2).then(|| labels[labels.len() - 2..].join("."))
    }
}

#[async_trait]
impl DnsProvider for NamecheapDns01 {
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error> {
        let candidate = Self::zone_candidate(domain)
            .ok_or_else(|| Dns01Error::ZoneNotFound(domain.to_string()))?;
        let (sld, tld) = Self::split_sld_tld(&candidate)
            .ok_or_else(|| Dns01Error::ZoneNotFound(domain.to_string()))?;
        self.get_hosts(&sld, &tld)
            .await
            .map_err(|_| Dns01Error::ZoneNotFound(domain.to_string()))?;
        Ok(DnsZone {
            id: candidate.clone(),
            name: candidate,
        })
    }

    async fn create_txt_record(
        &self,
        zone: &DnsZone,
        name: &str,
        content: &str,
    ) -> Result<String, Dns01Error> {
        let (sld, tld) = Self::split_sld_tld(&zone.name)
            .ok_or_else(|| Dns01Error::ZoneNotFound(zone.name.clone()))?;
        let relative_name = relative_record_name(name, &zone.name);

        let mut hosts = self.get_hosts(&sld, &tld).await?;
        hosts.push(HostRecord {
            typ: "TXT".to_string(),
            name: relative_name.clone(),
            address: content.to_string(),
            mx_pref: PLACEHOLDER_MX_PREF.to_string(),
            ttl: TXT_TTL.to_string(),
        });
        self.set_hosts(&sld, &tld, &hosts).await?;
        Ok(relative_name)
    }

    /// `record_id` here is the relative record *name* `create_txt_record`
    /// returned (Namecheap has no real record IDs -- see the module
    /// doc). Matches by `(Name, Type=TXT)` only, same as lego's own
    /// cleanup, and rewrites the full host list without it.
    async fn delete_txt_record(&self, zone: &DnsZone, record_id: &str) -> Result<(), Dns01Error> {
        let (sld, tld) = Self::split_sld_tld(&zone.name)
            .ok_or_else(|| Dns01Error::ZoneNotFound(zone.name.clone()))?;
        let hosts = self.get_hosts(&sld, &tld).await?;
        let remaining: Vec<HostRecord> = hosts
            .into_iter()
            .filter(|h| !(h.typ == "TXT" && h.name == record_id))
            .collect();
        self.set_hosts(&sld, &tld, &remaining).await
    }
}

fn xml_attr(e: &BytesStart, name: &str) -> String {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name.as_bytes())
        .map(|a| String::from_utf8_lossy(&a.value).into_owned())
        .unwrap_or_default()
}

/// Walks `<ApiResponse><Errors><Error>msg</Error></Errors>
/// <CommandResponse><DomainDNSGetHostsResult><host .../>...
/// </DomainDNSGetHostsResult></CommandResponse></ApiResponse>` (the
/// exact shape lego's `getHostsResponse` type decodes) collecting every
/// `<host>`'s attributes and every `<Error>`'s text.
fn parse_get_hosts_response(body: &str) -> Result<Vec<HostRecord>, Dns01Error> {
    let mut reader = Reader::from_str(body);
    let mut hosts = Vec::new();
    let mut errors = Vec::new();
    let mut in_error = false;
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) if e.name().as_ref() == b"host" => hosts.push(HostRecord {
                typ: xml_attr(&e, "Type"),
                name: xml_attr(&e, "Name"),
                address: xml_attr(&e, "Address"),
                mx_pref: xml_attr(&e, "MXPref"),
                ttl: xml_attr(&e, "TTL"),
            }),
            Ok(Event::Start(e)) if e.name().as_ref() == b"Error" => in_error = true,
            Ok(Event::End(e)) if e.name().as_ref() == b"Error" => in_error = false,
            Ok(Event::Text(t)) if in_error => {
                if let Ok(text) = t.unescape() {
                    errors.push(text.into_owned());
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => {
                return Err(Dns01Error::Api(format!(
                    "failed to parse Namecheap response: {err}"
                )));
            }
        }
        buf.clear();
    }
    if !errors.is_empty() {
        return Err(Dns01Error::Api(join_api_errors(
            errors.iter().map(String::as_str),
        )));
    }
    Ok(hosts)
}

/// Same `<Errors>` handling as [`parse_get_hosts_response`], plus
/// `<CommandResponse><DomainDNSSetHostsResult IsSuccess="true"/>
/// </CommandResponse>` -- a response with no errors but
/// `IsSuccess != "true"` is still a failure (matches lego's own check).
fn parse_set_hosts_response(body: &str) -> Result<(), Dns01Error> {
    let mut reader = Reader::from_str(body);
    let mut errors = Vec::new();
    let mut in_error = false;
    let mut is_success = false;
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) if e.name().as_ref() == b"DomainDNSSetHostsResult" => {
                is_success = xml_attr(&e, "IsSuccess").eq_ignore_ascii_case("true");
            }
            Ok(Event::Start(e)) if e.name().as_ref() == b"Error" => in_error = true,
            Ok(Event::End(e)) if e.name().as_ref() == b"Error" => in_error = false,
            Ok(Event::Text(t)) if in_error => {
                if let Ok(text) = t.unescape() {
                    errors.push(text.into_owned());
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => {
                return Err(Dns01Error::Api(format!(
                    "failed to parse Namecheap response: {err}"
                )));
            }
        }
        buf.clear();
    }
    if !errors.is_empty() {
        return Err(Dns01Error::Api(join_api_errors(
            errors.iter().map(String::as_str),
        )));
    }
    if !is_success {
        return Err(Dns01Error::Api(
            "Namecheap setHosts did not report success".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn get_hosts_xml(hosts: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <ApiResponse Status="OK">
              <Errors />
              <CommandResponse Type="namecheap.domains.dns.getHosts">
                <DomainDNSGetHostsResult>{hosts}</DomainDNSGetHostsResult>
              </CommandResponse>
            </ApiResponse>"#
        )
    }

    fn error_xml() -> String {
        r#"<?xml version="1.0" encoding="UTF-8"?>
        <ApiResponse Status="ERROR">
          <Errors><Error Number="1011150">Domain not found</Error></Errors>
        </ApiResponse>"#
            .to_string()
    }

    fn set_hosts_success_xml() -> String {
        r#"<?xml version="1.0" encoding="UTF-8"?>
        <ApiResponse Status="OK">
          <Errors />
          <CommandResponse Type="namecheap.domains.dns.setHosts">
            <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />
          </CommandResponse>
        </ApiResponse>"#
            .to_string()
    }

    #[test]
    fn parses_host_records_from_a_real_shaped_response() {
        let xml = get_hosts_xml(
            r#"<host HostId="1" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" /><host HostId="2" Name="_acme-challenge" Type="TXT" Address="digest" MXPref="10" TTL="1800" />"#,
        );
        let hosts = parse_get_hosts_response(&xml).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[1].typ, "TXT");
        assert_eq!(hosts[1].name, "_acme-challenge");
        assert_eq!(hosts[1].address, "digest");
    }

    #[test]
    fn parses_an_empty_host_list() {
        let xml = get_hosts_xml("");
        assert!(parse_get_hosts_response(&xml).unwrap().is_empty());
    }

    #[test]
    fn surfaces_an_error_element_as_an_error() {
        let err = parse_get_hosts_response(&error_xml()).unwrap_err();
        assert!(err.to_string().contains("Domain not found"));
    }

    #[test]
    fn set_hosts_response_reports_success() {
        parse_set_hosts_response(&set_hosts_success_xml()).unwrap();
    }

    #[test]
    fn set_hosts_response_without_is_success_true_is_an_error() {
        let xml = r#"<ApiResponse Status="OK"><Errors /><CommandResponse><DomainDNSSetHostsResult IsSuccess="false" /></CommandResponse></ApiResponse>"#;
        assert!(parse_set_hosts_response(xml).is_err());
    }

    #[tokio::test]
    async fn find_zone_reduces_a_deeper_hostname_to_its_two_label_zone() {
        // Namecheap has no nested-zone concept to walk through -- any
        // depth of hostname under example.com must resolve straight to
        // the single example.com zone, with exactly one getHosts call
        // (SLD=example, TLD=com), not a multi-candidate walk.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("SLD", "example"))
            .and(query_param("TLD", "com"))
            .respond_with(ResponseTemplate::new(200).set_body_string(get_hosts_xml("")))
            .mount(&server)
            .await;

        let client = NamecheapDns01::with_base_url(
            reqwest::Client::new(),
            "user:key:1.2.3.4".into(),
            server.uri(),
        );
        let zone = client.find_zone("foo.example.com").await.unwrap();
        assert_eq!(zone.name, "example.com");
    }

    #[tokio::test]
    async fn find_zone_errors_when_the_zone_is_not_reachable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(error_xml()))
            .mount(&server)
            .await;

        let client = NamecheapDns01::with_base_url(
            reqwest::Client::new(),
            "user:key:1.2.3.4".into(),
            server.uri(),
        );
        let err = client.find_zone("foo.example.com").await.unwrap_err();
        assert!(matches!(err, Dns01Error::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn create_txt_record_reads_then_writes_the_full_host_list() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("Command", "namecheap.domains.dns.getHosts"))
            .respond_with(ResponseTemplate::new(200).set_body_string(get_hosts_xml(
                r#"<host HostId="1" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" />"#,
            )))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains(
                "Command=namecheap.domains.dns.setHosts",
            ))
            .and(body_string_contains("HostName1=%40"))
            .and(body_string_contains("HostName2=_acme-challenge"))
            .and(body_string_contains("RecordType2=TXT"))
            .and(body_string_contains("Address2=digest-value"))
            .respond_with(ResponseTemplate::new(200).set_body_string(set_hosts_success_xml()))
            .mount(&server)
            .await;

        let client = NamecheapDns01::with_base_url(
            reqwest::Client::new(),
            "user:key:1.2.3.4".into(),
            server.uri(),
        );
        let zone = DnsZone {
            id: "example.com".into(),
            name: "example.com".into(),
        };
        let record_id = client
            .create_txt_record(&zone, "_acme-challenge.example.com", "digest-value")
            .await
            .unwrap();
        assert_eq!(record_id, "_acme-challenge");
    }

    #[tokio::test]
    async fn delete_txt_record_removes_only_the_matching_txt_record() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("Command", "namecheap.domains.dns.getHosts"))
            .respond_with(ResponseTemplate::new(200).set_body_string(get_hosts_xml(
                r#"<host HostId="1" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" /><host HostId="2" Name="_acme-challenge" Type="TXT" Address="digest-value" MXPref="10" TTL="1800" />"#,
            )))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains(
                "Command=namecheap.domains.dns.setHosts",
            ))
            .and(body_string_contains("HostName1=%40"))
            .respond_with(ResponseTemplate::new(200).set_body_string(set_hosts_success_xml()))
            .mount(&server)
            .await;

        let client = NamecheapDns01::with_base_url(
            reqwest::Client::new(),
            "user:key:1.2.3.4".into(),
            server.uri(),
        );
        let zone = DnsZone {
            id: "example.com".into(),
            name: "example.com".into(),
        };
        client
            .delete_txt_record(&zone, "_acme-challenge")
            .await
            .unwrap();
    }
}
