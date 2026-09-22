//! Optional mTLS client-certificate support, trusting TrustBridge's own
//! root (see jpps/pki) -- built for two consumers:
//!
//!   1. A `ClientCert`-kind ACL (see `config::AclKind`), letting a host
//!      skip its `Login` gate when a valid TrustBridge-issued client
//!      cert was presented, falling back to the normal login page
//!      otherwise (Jeff's own words: "#2 but fallback with user/pass as
//!      is now").
//!   2. `ProxyHost::pass_client_cert_header`, which forwards a trusted
//!      `X-Client-Cert-Subject` header to the upstream for apps (store,
//!      wiki, ...) to consume for their own admin-login bypass.
//!
//! Deliberately uses `rustls::server::WebPkiClientVerifier` --
//! `allow_unauthenticated()` makes client-cert presentation optional at
//! the TLS layer (a connection with no cert still completes normally),
//! while chain validation for any cert that *is* offered is rustls's
//! own well-tested verifier, not hand-rolled here. A cert that fails
//! verification aborts the handshake entirely (standard TLS behavior,
//! not something this module controls) -- in practice this only
//! affects a client that actually has *some* client cert installed and
//! chose to offer it, since `root_hint_subjects()` only advertises
//! TrustBridge's root, so a browser with no TrustBridge cert simply
//! won't offer one at all.
//!
//! Known limitation: chain + expiry validation only -- this does not
//! check TrustBridge's CRL/OCSP, so a *revoked-but-not-yet-expired*
//! client cert is still accepted here. Acceptable for a first version;
//! revisit if this ever protects something high-value enough to need
//! live revocation checking on every handshake.

use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;

const TRUSTBRIDGE_ROOT_PEM: &str = include_str!("trustbridge_root.crt");

/// Builds the optional client-cert verifier, trusting only TrustBridge's
/// root. Called once at startup (see `build_https_server_config`) --
/// the embedded PEM is fixed at compile time, so this can't fail at
/// runtime from a missing/misconfigured file the way a path-based
/// config option could.
pub fn build_optional_client_cert_verifier() -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
    let mut roots = RootCertStore::empty();
    let mut reader = std::io::Cursor::new(TRUSTBRIDGE_ROOT_PEM.as_bytes());
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.expect("embedded trustbridge_root.crt must parse as valid PEM/DER");
        roots.add(cert).expect("embedded TrustBridge root must be a valid trust anchor");
    }
    WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .expect("failed to build optional client-cert verifier")
}

/// Extracts the leaf client certificate's Subject Common Name, if the
/// connection presented one. By the time this is called (after a
/// successful handshake), any cert present has already passed
/// `WebPkiClientVerifier`'s chain/expiry check -- rustls aborts the
/// handshake for an invalid one rather than exposing it here.
pub fn client_cert_subject(peer_certs: Option<&[rustls_pki_types::CertificateDer<'static>]>) -> Option<String> {
    let leaf = peer_certs?.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());
    cn
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_without_panicking() {
        // Same one-time setup every other rustls-touching test in this
        // crate does (see e.g. proxy::mod's tests) -- idempotent if
        // another test in the same process already installed one.
        let _ = rustls::crypto::ring::default_provider().install_default();
        // The real assertion here is "the embedded PEM parses and
        // WebPkiClientVerifier::build() succeeds" -- both `.expect()`
        // calls in build_optional_client_cert_verifier would panic
        // otherwise, which is exactly what should fail loudly at
        // startup (not silently disable client-cert support).
        let _ = build_optional_client_cert_verifier();
    }

    #[test]
    fn client_cert_subject_is_none_when_no_cert_presented() {
        assert_eq!(client_cert_subject(None), None);
    }
}
