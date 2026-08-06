//! TLS client configs for connecting to an HTTPS upstream (`proxy::http`'s
//! `forward_http`, when a host's `upstream_https` is set) -- distinct from
//! `proxy::tls`, which is the *server*-side config this daemon presents to
//! visitors. Built once and reused (rustls configs are cheap to clone --
//! an `Arc` internally -- but not free to build) rather than per-request.

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// Verifies the upstream's certificate chain against the bundled Mozilla
/// root store (`webpki-roots`) -- same trust model any normal HTTPS
/// client uses, no OpenSSL/system cert store dependency.
pub fn verified_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// Accepts any certificate the upstream presents, self-signed included --
/// the connection is still encrypted, it just isn't authenticated. Only
/// ever used when a host's `upstream_tls_verify` is explicitly `false`
/// (see `config::ProxyHost::upstream_tls_verify`'s doc comment for when
/// that's an appropriate choice).
pub fn insecure_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            Arc::new(
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoServerCertVerification))
                    .with_no_client_auth(),
            )
        })
        .clone()
}

#[derive(Debug)]
struct NoServerCertVerification;

impl ServerCertVerifier for NoServerCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Verification itself is a no-op above, so every scheme rustls/ring
    /// knows about is "supported" -- this list only needs to be
    /// exhaustive enough that a real handshake never gets rejected for
    /// offering a signature scheme this verifier claims not to
    /// recognize.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_and_insecure_configs_build_without_panicking() {
        let _ = verified_client_config();
        let _ = insecure_client_config();
    }

    #[test]
    fn configs_are_cheap_to_fetch_repeatedly() {
        // Both are OnceLock-cached -- a second call must return the same
        // underlying Arc's data, not rebuild from scratch.
        let a = verified_client_config();
        let b = verified_client_config();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
