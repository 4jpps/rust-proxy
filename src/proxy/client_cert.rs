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
//! Revocation is not part of the handshake: `proxy::revocation` asks
//! TrustBridge's OCSP responder about each presented certificate per
//! request and treats a revoked one as "no certificate".

use std::sync::Arc;

use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;

const TRUSTBRIDGE_ROOT_PEM: &str = include_str!("trustbridge_root.crt");
// Trusted directly (not just chained through the root) so that a
// client presenting only its leaf cert -- no intermediate in the
// handshake -- still validates. Real, hit-in-practice gap: iOS's own
// PKCS#12 import doesn't reliably keep a bundled intermediate
// associated with an identity for TLS presentation, and every OS's
// plain `openssl s_client`-style client auth only ever sends what's
// actually in the identity/keystore it was given -- requiring every
// client to always assemble and present a full chain is fragile in a
// way trusting the intermediate as its own anchor here isn't. A leaf
// cert genuinely issued by TrustBridge's intermediate still has to
// pass full chain/expiry validation either way; this only removes the
// client's burden of also sending the intermediate along with it.
const TRUSTBRIDGE_INTERMEDIATE_PEM: &str = include_str!("trustbridge_intermediate.crt");

/// Builds the optional client-cert verifier, trusting TrustBridge's
/// root and intermediate (see `TRUSTBRIDGE_INTERMEDIATE_PEM`'s doc
/// comment for why both). Called once at startup (see
/// `build_https_server_config`) -- the embedded PEMs are fixed at
/// compile time, so this can't fail at runtime from a missing/
/// misconfigured file the way a path-based config option could.
pub fn build_optional_client_cert_verifier() -> Arc<dyn rustls::server::danger::ClientCertVerifier>
{
    let mut roots = RootCertStore::empty();
    for pem in [TRUSTBRIDGE_ROOT_PEM, TRUSTBRIDGE_INTERMEDIATE_PEM] {
        let mut reader = std::io::Cursor::new(pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert
                .expect("embedded TrustBridge root/intermediate PEM must parse as valid PEM/DER");
            roots
                .add(cert)
                .expect("embedded TrustBridge root/intermediate must be a valid trust anchor");
        }
    }
    WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .expect("failed to build optional client-cert verifier")
}

/// Who a presented client certificate says its holder is.
///
/// ACL matching (`ClientCert` entries, `admin.client_cert_subjects`) is on
/// `cn`. `org` and `org_id` are forwarded to upstreams (`X-Client-Cert-Org`,
/// `X-Client-Cert-Org-Id`). When an org lock is set (`org_allowed`), a cert
/// whose org-id differs is dropped before any of that happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertIdentity {
    pub cn: String,
    pub org: Option<String>,
    pub org_id: Option<String>,
}

#[cfg(test)]
impl ClientCertIdentity {
    pub fn cn_only(cn: impl Into<String>) -> Self {
        Self {
            cn: cn.into(),
            org: None,
            org_id: None,
        }
    }
}

/// X.509 `organizationIdentifier` (2.5.4.97).
const OID_ORGANIZATION_IDENTIFIER: &[u64] = &[2, 5, 4, 97];
/// Whether `id` may be honored given the required org-id (`None` = no lock).
/// A cert without an org-id never passes a lock.
pub fn org_allowed(id: &ClientCertIdentity, required: Option<&str>) -> bool {
    match required {
        None => true,
        Some(req) => id.org_id.as_deref() == Some(req),
    }
}

/// Fallback carrier for the org-id: an OU of the form `org-id:XXXX`.
const OU_ORG_ID_PREFIX: &str = "org-id:";

/// Parses the leaf's CN, Organization and org-id. Requires a CN (as
/// before); `org`/`org_id` are `None` when absent or empty.
pub fn identity_from_der(der: &[u8]) -> Option<ClientCertIdentity> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let subject = cert.subject();
    let cn = subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())?;
    let org = subject
        .iter_organization()
        .next()
        .and_then(|o| o.as_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let from_attr = subject
        .iter_attributes()
        .find(|a| {
            a.attr_type()
                .iter()
                .map(|it| it.collect::<Vec<u64>>())
                .is_some_and(|v| v == OID_ORGANIZATION_IDENTIFIER)
        })
        .and_then(|a| a.as_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let org_id = from_attr.or_else(|| {
        subject
            .iter_organizational_unit()
            .filter_map(|ou| ou.as_str().ok())
            .find_map(|ou| ou.strip_prefix(OU_ORG_ID_PREFIX))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    });
    Some(ClientCertIdentity { cn, org, org_id })
}

/// Extracts the leaf client certificate's identity, if the connection
/// presented one. By the time this is called (after a successful
/// handshake), any cert present has already passed
/// `WebPkiClientVerifier`'s chain/expiry check -- rustls aborts the
/// handshake for an invalid one rather than exposing it here.
pub fn client_cert_identity(
    peer_certs: Option<&[rustls_pki_types::CertificateDer<'static>]>,
) -> Option<ClientCertIdentity> {
    identity_from_der(peer_certs?.first()?.as_ref())
}

/// Removes every identity header a client could have supplied itself.
/// Run unconditionally (even for hosts that never forward them) so a
/// client can't probe the difference between "stripped" and "never set".
pub fn strip_identity_headers(headers: &mut hyper::HeaderMap) {
    for name in [
        "x-client-cert-subject",
        "x-client-cert-org",
        "x-client-cert-org-id",
        "x-rustproxy-client-cert-token",
    ] {
        headers.remove(name);
    }
}

/// Sets the identity headers for a verified certificate. `org`/`org_id`
/// are only set when present and plain ASCII (a non-ASCII organization
/// name is simply not forwarded rather than sent as raw UTF-8 bytes).
pub fn set_identity_headers(headers: &mut hyper::HeaderMap, id: &ClientCertIdentity, token: &str) {
    use hyper::header::HeaderValue;
    let (Ok(subject), Ok(token)) = (HeaderValue::from_str(&id.cn), HeaderValue::from_str(token))
    else {
        return;
    };
    headers.insert("x-client-cert-subject", subject);
    headers.insert("x-rustproxy-client-cert-token", token);
    let ascii = |v: &Option<String>| {
        v.as_deref()
            .filter(|v| v.is_ascii())
            .and_then(|v| HeaderValue::from_str(v).ok())
    };
    if let Some(v) = ascii(&id.org) {
        headers.insert("x-client-cert-org", v);
    }
    if let Some(v) = ascii(&id.org_id) {
        headers.insert("x-client-cert-org-id", v);
    }
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
    fn identity_is_none_when_no_cert_presented() {
        assert_eq!(client_cert_identity(None), None);
    }

    fn leaf(build: impl FnOnce(&mut rcgen::DistinguishedName)) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        build(&mut params.distinguished_name);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn org_id_type() -> rcgen::DnType {
        rcgen::DnType::CustomDnType(OID_ORGANIZATION_IDENTIFIER.to_vec())
    }

    #[test]
    fn cn_only_cert_has_no_org_data() {
        let der = leaf(|dn| dn.push(rcgen::DnType::CommonName, "Jeff Parrish"));
        assert_eq!(
            identity_from_der(&der),
            Some(ClientCertIdentity::cn_only("Jeff Parrish"))
        );
    }

    #[test]
    fn extracts_org_and_organization_identifier() {
        let der = leaf(|dn| {
            dn.push(rcgen::DnType::CommonName, "Jeff Parrish");
            dn.push(
                rcgen::DnType::OrganizationName,
                "Jeff Parrish PC Services LLC",
            );
            dn.push(org_id_type(), rcgen::DnValue::Utf8String("TB-1234".into()));
        });
        let id = identity_from_der(&der).unwrap();
        assert_eq!(id.cn, "Jeff Parrish");
        assert_eq!(id.org.as_deref(), Some("Jeff Parrish PC Services LLC"));
        assert_eq!(id.org_id.as_deref(), Some("TB-1234"));
    }

    #[test]
    fn org_id_falls_back_to_ou_prefix() {
        let der = leaf(|dn| {
            dn.push(rcgen::DnType::CommonName, "Jeff Parrish");
            dn.push(rcgen::DnType::OrganizationName, "Acme");
            dn.push(rcgen::DnType::OrganizationalUnitName, "Engineering");
            dn.push(rcgen::DnType::OrganizationalUnitName, "org-id:ACME-9");
        });
        assert_eq!(
            identity_from_der(&der).unwrap().org_id.as_deref(),
            Some("ACME-9")
        );
    }

    #[test]
    fn organization_identifier_wins_over_ou_fallback() {
        let der = leaf(|dn| {
            dn.push(rcgen::DnType::CommonName, "x");
            dn.push(rcgen::DnType::OrganizationalUnitName, "org-id:FROM-OU");
            dn.push(
                org_id_type(),
                rcgen::DnValue::Utf8String("FROM-ATTR".into()),
            );
        });
        assert_eq!(
            identity_from_der(&der).unwrap().org_id.as_deref(),
            Some("FROM-ATTR")
        );
    }

    #[test]
    fn a_cert_without_a_cn_yields_no_identity() {
        let der = leaf(|dn| dn.push(rcgen::DnType::OrganizationName, "Acme"));
        assert_eq!(identity_from_der(&der), None);
    }

    #[test]
    fn strip_removes_every_client_supplied_identity_header() {
        let mut h = hyper::HeaderMap::new();
        for n in [
            "x-client-cert-subject",
            "x-client-cert-org",
            "x-client-cert-org-id",
            "x-rustproxy-client-cert-token",
        ] {
            h.insert(n, "forged".parse().unwrap());
        }
        h.insert("x-other", "keep".parse().unwrap());
        strip_identity_headers(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-other"));
    }

    #[test]
    fn set_headers_forwards_org_data_only_when_present() {
        let mut h = hyper::HeaderMap::new();
        set_identity_headers(&mut h, &ClientCertIdentity::cn_only("Jeff"), "tok");
        assert_eq!(h["x-client-cert-subject"], "Jeff");
        assert_eq!(h["x-rustproxy-client-cert-token"], "tok");
        assert!(!h.contains_key("x-client-cert-org"));
        assert!(!h.contains_key("x-client-cert-org-id"));

        let mut h = hyper::HeaderMap::new();
        let id = ClientCertIdentity {
            cn: "Jeff".into(),
            org: Some("Acme".into()),
            org_id: Some("A-1".into()),
        };
        set_identity_headers(&mut h, &id, "tok");
        assert_eq!(h["x-client-cert-org"], "Acme");
        assert_eq!(h["x-client-cert-org-id"], "A-1");

        // A non-ASCII org name can't be a header value; the rest still goes.
        let mut h = hyper::HeaderMap::new();
        let id = ClientCertIdentity {
            cn: "Jeff".into(),
            org: Some("Caf\u{e9}".into()),
            org_id: Some("A-1".into()),
        };
        set_identity_headers(&mut h, &id, "tok");
        assert!(!h.contains_key("x-client-cert-org"));
        assert_eq!(h["x-client-cert-org-id"], "A-1");
    }
}
