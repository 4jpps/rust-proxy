//! CSR generation (PKCS#10, via `rcgen`) and turning a downloaded
//! full-chain PEM + its matching private key into the in-memory form
//! `state::CertEntry` needs for SNI dispatch.

use std::io::Cursor;
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

use crate::state::CertEntry;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("CSR generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("failed to parse PEM: {0}")]
    Pem(std::io::Error),
    #[error("no certificate found in the downloaded chain")]
    EmptyChain,
    #[error("no private key found for the generated CSR")]
    MissingKey,
    #[error("failed to parse the leaf certificate's X.509 fields: {0}")]
    X509(String),
}

pub struct GeneratedCsr {
    pub der: Vec<u8>,
    pub key_pair_pem: String,
}

/// One fresh key pair + CSR per issuance -- the leaf key is never reused
/// across renewals. `organization`/`organizational_unit` (from
/// `AcmeConfig`) are included in the CSR's Subject when set -- purely a
/// *request*, not a guarantee: Let's Encrypt and virtually every public
/// CA issue Domain Validated certs, which by definition can't vouch for
/// organizational identity, so Subject fields beyond CN are silently
/// discarded by their CAs (boulder, LE's issuer, does this
/// unconditionally). This only actually lands in the issued certificate
/// against a CA that performs real organization vetting (a private/
/// enterprise ACME CA such as step-ca configured for OV) -- worth
/// sending regardless, since it costs nothing against a CA that ignores
/// it and is exactly what's needed against one that doesn't.
pub fn generate_csr(
    domains: &[String],
    organization: Option<&str>,
    organizational_unit: Option<&str>,
) -> Result<GeneratedCsr, CertError> {
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(domains.to_vec())?;
    // `CertificateParams::new` (via its `Default` impl) hard-codes the
    // Subject Common Name to the literal string "rcgen self signed
    // cert" -- harmless for the self-signed test certs rcgen is mostly
    // used for, but fatal here: that string ends up as the CSR's
    // Subject when serialized, and Let's Encrypt's finalize-order
    // validation rejects it outright ("Cannot issue for \"rcgen self
    // signed cert\": Domain name contains an invalid character" --
    // rejectedIdentifier, confirmed against a real production
    // failure). Clearing the DN entirely first is standard ACME CSR
    // practice anyway: the SAN extension (already set from `domains`
    // above) is what CAs actually validate against; a Subject CN is
    // optional and, per current CA/Browser Forum guidance, increasingly
    // expected to be absent or to exactly match a SAN entry rather than
    // carry a placeholder -- so this never sets one, only O/OU when
    // configured.
    let mut dn = rcgen::DistinguishedName::new();
    if let Some(organization) = organization {
        dn.push(rcgen::DnType::OrganizationName, organization);
    }
    if let Some(organizational_unit) = organizational_unit {
        dn.push(rcgen::DnType::OrganizationalUnitName, organizational_unit);
    }
    params.distinguished_name = dn;
    let csr = params.serialize_request(&key_pair)?;
    Ok(GeneratedCsr {
        der: csr.der().as_ref().to_vec(),
        key_pair_pem: key_pair.serialize_pem(),
    })
}

/// Parses a downloaded full-chain PEM (leaf + intermediates) alongside the
/// PEM-encoded leaf private key rcgen produced, and computes the leaf
/// certificate's expiry -- everything `CertEntry` needs for SNI dispatch
/// and renewal scheduling.
pub fn build_cert_entry(chain_pem: &str, key_pem: &str) -> Result<CertEntry, CertError> {
    let mut chain_reader = Cursor::new(chain_pem.as_bytes());
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut chain_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(CertError::Pem)?;
    if cert_chain.is_empty() {
        return Err(CertError::EmptyChain);
    }

    let mut key_reader = Cursor::new(key_pem.as_bytes());
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(CertError::Pem)?
        .ok_or(CertError::MissingKey)?;

    let not_after = leaf_expiry(&cert_chain[0])?;

    Ok(CertEntry {
        cert_chain,
        private_key: Arc::new(private_key),
        not_after,
    })
}

/// Reads the real `notAfter` field out of the leaf certificate's DER --
/// this is what the renewal loop compares against `renew_before_days`, so
/// it has to reflect the certificate the CA actually issued, not a guess.
fn leaf_expiry(leaf: &CertificateDer<'static>) -> Result<chrono::DateTime<chrono::Utc>, CertError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| CertError::X509(e.to_string()))?;
    let not_after_unix = parsed.validity().not_after.timestamp();
    chrono::DateTime::from_timestamp(not_after_unix, 0)
        .ok_or_else(|| CertError::X509(format!("notAfter timestamp {not_after_unix} out of range")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_der_csr_for_a_single_domain() {
        let csr = generate_csr(&["example.com".to_string()], None, None).unwrap();
        assert!(!csr.der.is_empty());
        assert!(
            csr.key_pair_pem.contains("BEGIN PRIVATE KEY")
                || csr.key_pair_pem.contains("BEGIN EC PRIVATE KEY")
        );
    }

    /// Regression test for a real production failure: `rcgen`'s default
    /// Subject Common Name ("rcgen self signed cert") was leaking into
    /// the CSR sent to Let's Encrypt, which rejected the whole order
    /// with `rejectedIdentifier` ("Cannot issue for \"rcgen self signed
    /// cert\": Domain name contains an invalid character"). Checks the
    /// raw DER for the placeholder string directly -- simpler and just
    /// as effective as parsing the ASN.1 Subject field, and fails
    /// loudly if a future rcgen upgrade reintroduces a default CN.
    #[test]
    fn csr_never_contains_rcgens_placeholder_common_name() {
        let csr = generate_csr(&["example.com".to_string()], None, None).unwrap();
        let placeholder = b"rcgen self signed cert";
        assert!(
            !csr.der.windows(placeholder.len()).any(|w| w == placeholder),
            "CSR DER must not contain rcgen's default Subject CN -- it gets rejected by Let's Encrypt as an invalid identifier"
        );
    }

    #[test]
    fn organization_and_organizational_unit_are_absent_from_the_csr_when_not_set() {
        let csr = generate_csr(&["example.com".to_string()], None, None).unwrap();
        // ASN.1 for these two -- if they're not requested at all,
        // neither string should appear anywhere in the DER, regardless
        // of encoding position.
        assert!(!csr
            .der
            .windows(b"Acme Corp".len())
            .any(|w| w == b"Acme Corp"));
    }

    #[test]
    fn organization_and_organizational_unit_are_embedded_in_the_csr_when_set() {
        let csr = generate_csr(
            &["example.com".to_string()],
            Some("Acme Corp"),
            Some("Platform Engineering"),
        )
        .unwrap();
        assert!(
            csr.der
                .windows(b"Acme Corp".len())
                .any(|w| w == b"Acme Corp"),
            "organization must actually be present in the CSR's Subject DN"
        );
        assert!(
            csr.der
                .windows(b"Platform Engineering".len())
                .any(|w| w == b"Platform Engineering"),
            "organizational_unit must actually be present in the CSR's Subject DN"
        );
    }

    #[test]
    fn generates_a_csr_covering_multiple_sans() {
        let csr = generate_csr(
            &["example.com".to_string(), "www.example.com".to_string()],
            None,
            None,
        )
        .unwrap();
        assert!(!csr.der.is_empty());
    }

    #[test]
    fn build_cert_entry_rejects_empty_chain() {
        let csr = generate_csr(&["example.com".to_string()], None, None).unwrap();
        let err = build_cert_entry("", &csr.key_pair_pem).unwrap_err();
        assert!(matches!(err, CertError::EmptyChain));
    }

    #[test]
    fn build_cert_entry_reads_the_real_notafter_from_the_certificate() {
        use chrono::Datelike;

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 6, 15);
        let cert = params.self_signed(&key_pair).unwrap();

        let entry = build_cert_entry(&cert.pem(), &key_pair.serialize_pem()).unwrap();
        assert_eq!(entry.not_after.year(), 2031);
        assert_eq!(entry.not_after.month(), 6);
    }
}
