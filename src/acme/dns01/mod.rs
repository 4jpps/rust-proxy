//! dns-01 challenge fulfillment behind a pluggable `DnsProvider` trait --
//! create/clean up the `_acme-challenge` TXT record with whichever DNS
//! host actually manages the zone, plus the RFC 8555 §8.4
//! key-authorization digest that becomes the record's content (provider-
//! agnostic, lives here rather than in any one provider module).
//!
//! Providers: [`cloudflare`], [`digitalocean`], [`duckdns`], [`godaddy`],
//! [`hetzner`], [`namecheap`]. Each is a thin, direct-`reqwest` client
//! against that provider's own REST API (no provider SDK crates)
//! implementing the same three-call shape: find the zone that owns a
//! domain, create a TXT record in it, delete a TXT record from it.

pub mod cloudflare;
pub mod digitalocean;
pub mod duckdns;
pub mod godaddy;
pub mod hetzner;
pub mod namecheap;
pub mod route53;
mod sigv4;

use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;

use super::jws::{AccountKey, b64url};

pub use cloudflare::CloudflareDns01;
pub use digitalocean::DigitalOceanDns01;
pub use duckdns::DuckDnsDns01;
pub use godaddy::GoDaddyDns01;
pub use hetzner::HetznerDns01;
pub use namecheap::NamecheapDns01;
pub use route53::Route53Dns01;

#[derive(Debug, Error)]
pub enum Dns01Error {
    #[error("HTTP error talking to the DNS provider: {0}")]
    Http(#[from] reqwest::Error),
    #[error("no DNS zone found for {0} or any parent domain")]
    ZoneNotFound(String),
    #[error("DNS provider API call failed: {0}")]
    Api(String),
    #[error("DNS provider response was missing an expected result")]
    MissingResult,
}

/// A zone as located by [`DnsProvider::find_zone`]. `id` is whatever
/// opaque handle the provider's create/delete calls need back (a numeric
/// zone ID for Cloudflare/Hetzner, or just the domain name itself for
/// DigitalOcean, which has no separate zone ID). `name` is always the
/// zone's own registrable domain (e.g. "example.com") -- providers whose
/// record-`name` field is relative to the zone, not fully-qualified
/// (DigitalOcean, Hetzner), need it to compute that relative name; see
/// [`relative_record_name`].
#[derive(Debug, Clone)]
pub struct DnsZone {
    pub id: String,
    pub name: String,
}

/// Every provider implements the same three RFC 8555 §8.4 dns-01 primitives
/// against its own API. `Send + Sync` (and dyn-safety via `async-trait`)
/// so `acme::run_renewal_loop` can hold one `Box<dyn DnsProvider>` chosen
/// at startup from `AcmeConfig.dns_provider` and use it across every host's
/// renewal check without knowing which concrete provider it is.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Cloudflare/DigitalOcean/Hetzner zones are the registrable/apex
    /// domain, not the exact challenge hostname (e.g. a challenge for
    /// `foo.bar.example.com` lives in the `example.com` zone) -- every
    /// provider implementation walks from the full name up through each
    /// parent label until one matches a real zone.
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error>;

    /// Creates the TXT record and returns its provider-assigned record
    /// ID, needed later to clean it up. `name` is always the fully-
    /// qualified record name (e.g. `_acme-challenge.foo.example.com`);
    /// providers that need a zone-relative name convert it internally.
    async fn create_txt_record(
        &self,
        zone: &DnsZone,
        name: &str,
        content: &str,
    ) -> Result<String, Dns01Error>;

    async fn delete_txt_record(&self, zone: &DnsZone, record_id: &str) -> Result<(), Dns01Error>;
}

/// RFC 8555 §8.4: `keyAuthorization = token || "." || jwkThumbprint`;
/// the TXT record content is base64url(SHA-256(keyAuthorization)).
pub fn dns01_txt_value(token: &str, account_key: &AccountKey) -> String {
    let key_authorization = format!("{token}.{}", account_key.jwk_thumbprint());
    let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
    b64url(digest.as_ref())
}

/// For a wildcard identifier (`*.example.com`), RFC 8555 §8.4 validates
/// dns-01 at `_acme-challenge.example.com` -- the wildcard label itself is
/// never part of the record name.
pub fn acme_challenge_record_name(domain: &str) -> String {
    let base = domain.strip_prefix("*.").unwrap_or(domain);
    format!("_acme-challenge.{base}")
}

/// DigitalOcean and Hetzner both want a record `name` relative to the
/// zone apex, not the fully-qualified name Cloudflare's API expects --
/// e.g. `_acme-challenge` inside the `example.com` zone, rather than
/// `_acme-challenge.example.com`. dns-01 record names always carry the
/// `_acme-challenge.` prefix, so they're never exactly equal to the zone
/// apex itself; the apex/"@" case a general-purpose relative-name helper
/// would otherwise need to handle can't come up here.
pub(crate) fn relative_record_name(fqdn: &str, zone_name: &str) -> String {
    fqdn.strip_suffix(zone_name)
        .and_then(|s| s.strip_suffix('.'))
        .unwrap_or(fqdn)
        .to_string()
}

pub(crate) fn join_api_errors<'a>(messages: impl IntoIterator<Item = &'a str>) -> String {
    let joined = messages.into_iter().collect::<Vec<_>>().join("; ");
    if joined.is_empty() {
        "unknown error".to_string()
    } else {
        joined
    }
}

/// Constructs the right `DnsProvider` for `kind`, given an already-built
/// `reqwest::Client` and a credential's `token` string (whatever shape
/// that provider's own `new()` expects -- see each provider module's
/// doc comment). Used by `acme::resolve_dns_credential` to build a
/// provider per host at issuance/renewal time, since credentials are
/// now DB-backed and multi-row rather than one global startup value.
pub fn build_provider(
    kind: crate::config::DnsProviderKind,
    http: reqwest::Client,
    token: String,
) -> Box<dyn DnsProvider> {
    use crate::config::DnsProviderKind;
    match kind {
        DnsProviderKind::Cloudflare => Box::new(CloudflareDns01::new(http, token)),
        DnsProviderKind::DigitalOcean => Box::new(DigitalOceanDns01::new(http, token)),
        DnsProviderKind::Hetzner => Box::new(HetznerDns01::new(http, token)),
        DnsProviderKind::DuckDns => Box::new(DuckDnsDns01::new(http, token)),
        DnsProviderKind::GoDaddy => Box::new(GoDaddyDns01::new(http, token)),
        DnsProviderKind::Namecheap => Box::new(NamecheapDns01::new(http, token)),
        DnsProviderKind::Route53 => Box::new(Route53Dns01::new(http, token)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::jws::AccountKey;

    #[test]
    fn build_provider_dispatches_every_provider_kind_without_panicking() {
        use crate::config::DnsProviderKind::*;
        let http = reqwest::Client::new();
        for kind in [
            Cloudflare,
            DigitalOcean,
            Hetzner,
            DuckDns,
            GoDaddy,
            Namecheap,
            Route53,
        ] {
            let _: Box<dyn DnsProvider> = build_provider(kind, http.clone(), "token".to_string());
        }
    }

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
        assert_eq!(
            acme_challenge_record_name("example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            acme_challenge_record_name("foo.bar.example.com"),
            "_acme-challenge.foo.bar.example.com"
        );
    }

    #[test]
    fn wildcard_record_name_strips_the_wildcard_label() {
        // RFC 8555 8.4: dns-01 for `*.example.com` validates at
        // `_acme-challenge.example.com`, not `_acme-challenge.*.example.com`.
        assert_eq!(
            acme_challenge_record_name("*.pages.example.com"),
            "_acme-challenge.pages.example.com"
        );
    }

    #[test]
    fn relative_record_name_strips_the_zone_suffix() {
        assert_eq!(
            relative_record_name("_acme-challenge.example.com", "example.com"),
            "_acme-challenge"
        );
        assert_eq!(
            relative_record_name("_acme-challenge.foo.example.com", "example.com"),
            "_acme-challenge.foo"
        );
    }

    #[test]
    fn relative_record_name_falls_back_to_the_input_if_the_suffix_does_not_match() {
        assert_eq!(
            relative_record_name("_acme-challenge.example.com", "other.com"),
            "_acme-challenge.example.com"
        );
    }
}

// Shared response envelope shapes reused by more than one provider module
// live here to avoid duplicating `#[derive(Deserialize)]` boilerplate;
// providers with a genuinely different envelope (DigitalOcean's
// `{"domain_record": ...}` wrapper) define their own instead of forcing a
// generic shape that doesn't fit.
#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorMessage {
    pub message: String,
}
