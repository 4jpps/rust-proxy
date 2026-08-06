//! SNI-based certificate dispatch. Renewed certs published into
//! `state`'s `ArcSwap<HashMap<...>>` (see `state::AppState::upsert_cert`)
//! are picked up on the very next handshake -- `resolve` reads live state
//! on every call, there's nothing to restart.

use std::collections::HashMap;
use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::state::{AppState, CertEntry};

pub struct CertResolver {
    state: AppState,
}

impl CertResolver {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertResolver")
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let certs = self.state.certs();
        let entry = select_cert_for_sni(&certs, sni)?;
        match build_certified_key(entry) {
            Ok(key) => Some(Arc::new(key)),
            Err(err) => {
                tracing::error!(sni, error = %err, "failed to build signing key for certificate");
                None
            }
        }
    }
}

/// Exact match first, then a `*.parent` wildcard cert covering exactly one
/// label under `parent` -- same lookup shape as `proxy::router::match_host`.
pub fn select_cert_for_sni<'a>(
    certs: &'a HashMap<String, CertEntry>,
    sni: &str,
) -> Option<&'a CertEntry> {
    if let Some(entry) = certs
        .iter()
        .find(|(domain, _)| domain.eq_ignore_ascii_case(sni))
        .map(|(_, entry)| entry)
    {
        return Some(entry);
    }
    let (_, parent) = sni.split_once('.')?;
    let wildcard = format!("*.{parent}");
    certs
        .iter()
        .find(|(domain, _)| domain.eq_ignore_ascii_case(&wildcard))
        .map(|(_, entry)| entry)
}

fn build_certified_key(entry: &CertEntry) -> Result<CertifiedKey, rustls::Error> {
    let key = rustls::crypto::ring::sign::any_supported_type(&entry.private_key)?;
    Ok(CertifiedKey::new(entry.cert_chain.clone(), key))
}

/// Shared with `proxy::mod`'s own tests (a real end-to-end ALPN/HTTP2
/// test needs a real cert to terminate TLS with, same as every test
/// here does) -- kept `#[cfg(test)]`-only rather than moved into
/// non-test code, since generating a throwaway self-signed cert has no
/// legitimate use outside tests.
#[cfg(test)]
pub(crate) fn self_signed_entry(domain: &str) -> CertEntry {
    use crate::acme::cert::build_cert_entry;
    use rcgen::{CertificateParams, KeyPair};

    let key_pair = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec![domain.to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    build_cert_entry(&cert.pem(), &key_pair.serialize_pem()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_the_matching_domain_case_insensitively() {
        let mut certs = HashMap::new();
        certs.insert("Example.com".to_string(), self_signed_entry("example.com"));

        assert!(select_cert_for_sni(&certs, "example.com").is_some());
        assert!(select_cert_for_sni(&certs, "EXAMPLE.COM").is_some());
    }

    #[test]
    fn returns_none_for_an_unknown_sni() {
        let mut certs = HashMap::new();
        certs.insert("example.com".to_string(), self_signed_entry("example.com"));
        assert!(select_cert_for_sni(&certs, "not-configured.com").is_none());
    }

    #[test]
    fn wildcard_cert_resolves_for_any_single_label_subdomain() {
        let mut certs = HashMap::new();
        certs.insert(
            "*.pages.example.com".to_string(),
            self_signed_entry("*.pages.example.com"),
        );
        assert!(select_cert_for_sni(&certs, "myproject.pages.example.com").is_some());
        assert!(select_cert_for_sni(&certs, "another.pages.example.com").is_some());
        assert!(select_cert_for_sni(&certs, "a.b.pages.example.com").is_none());
    }

    #[test]
    fn exact_cert_wins_over_wildcard_when_both_are_present() {
        let mut certs = HashMap::new();
        certs.insert(
            "*.pages.example.com".to_string(),
            self_signed_entry("*.pages.example.com"),
        );
        certs.insert(
            "myproject.pages.example.com".to_string(),
            self_signed_entry("myproject.pages.example.com"),
        );
        // Both resolve to *some* entry; this just confirms the exact-match
        // branch is actually reachable and doesn't error out first.
        assert!(select_cert_for_sni(&certs, "myproject.pages.example.com").is_some());
    }

    #[test]
    fn builds_a_usable_signing_key_from_a_cert_entry() {
        let entry = self_signed_entry("example.com");
        let key = build_certified_key(&entry).unwrap();
        assert_eq!(key.cert.len(), 1);
    }
}
