//! RFC 7515 JSON Web Signature framing for ACME (RFC 8555 §6.2): ES256
//! (ECDSA P-256 + SHA-256) signatures over a `protected.payload` input,
//! using unpadded base64url throughout. No JOSE/JWT crate -- ACME's JWS
//! usage is narrow enough (one alg, two header shapes) that hand-rolling
//! it is less risk than pulling in a general-purpose implementation and
//! only using a sliver of it.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwsError {
    #[error("key generation failed: {0}")]
    KeyGen(String),
    #[error("signing failed")]
    Sign,
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("I/O error persisting account key: {0}")]
    Io(#[from] std::io::Error),
}

/// Unpadded base64url, per RFC 7515 §2 ("Base64url Encoding") -- ACME
/// (and JWS generally) never uses the padded alphabet.
pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_json<T: Serialize>(value: &T) -> Result<String, JwsError> {
    Ok(b64url(&serde_json::to_vec(value)?))
}

/// An ACME account's ECDSA P-256 signing key. `EcdsaKeyPair` from `ring`
/// doesn't implement `Clone`/`Debug` and can't be reconstructed cheaply,
/// so callers hold this behind an `Arc` (see `state.rs`-style usage in
/// `acme::mod`).
pub struct AccountKey {
    key_pair: EcdsaKeyPair,
}

impl AccountKey {
    pub fn generate() -> Result<(Self, Vec<u8>), JwsError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| JwsError::KeyGen(format!("{e:?}")))?;
        let key = Self::from_pkcs8(pkcs8.as_ref())?;
        Ok((key, pkcs8.as_ref().to_vec()))
    }

    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, JwsError> {
        let rng = SystemRandom::new();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes, &rng)
                .map_err(|e| JwsError::KeyGen(format!("{e:?}")))?;
        Ok(Self { key_pair })
    }

    /// Loads the persisted account key at `path`, generating and saving a
    /// new one (mode 0600) if none exists yet.
    pub fn load_or_generate(path: &std::path::Path) -> Result<Self, JwsError> {
        if let Ok(existing) = std::fs::read(path) {
            return Self::from_pkcs8(&existing);
        }
        let (key, pkcs8) = Self::generate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &pkcs8)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(key)
    }

    /// The public key as a JWK (RFC 7518 §6.2.1), field order is
    /// intentionally `crv, kty, x, y` -- callers that need the RFC 7638
    /// thumbprint depend on this exact canonical ordering.
    pub fn jwk(&self) -> Value {
        let (x, y) = self.public_point_xy();
        json!({
            "crv": "P-256",
            "kty": "EC",
            "x": b64url(&x),
            "y": b64url(&y),
        })
    }

    /// RFC 8555 §8.1 / RFC 7638 JWK thumbprint: base64url(SHA-256(canonical
    /// JSON of the public JWK, lexicographic key order, no whitespace)).
    /// Used to build `keyAuthorization` for challenge validation.
    pub fn jwk_thumbprint(&self) -> String {
        let (x, y) = self.public_point_xy();
        // Field order is fixed to already be lexicographic (crv < kty < x < y),
        // so this literal *is* RFC 7638 canonical form -- no generic JSON
        // canonicalizer needed for a shape this small and fixed.
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            b64url(&x),
            b64url(&y)
        );
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        b64url(digest.as_ref())
    }

    fn public_point_xy(&self) -> ([u8; 32], [u8; 32]) {
        // Uncompressed SEC1 point: 0x04 || X (32 bytes) || Y (32 bytes).
        let public = self.key_pair.public_key().as_ref();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&public[1..33]);
        y.copy_from_slice(&public[33..65]);
        (x, y)
    }

    /// Raw ES256 signature (r || s, 64 bytes) over `signing_input`, per
    /// RFC 7518 §3.4 -- *not* the ASN.1 DER form some other ECDSA APIs
    /// default to.
    fn sign_raw(&self, signing_input: &[u8]) -> Result<Vec<u8>, JwsError> {
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, signing_input)
            .map_err(|_| JwsError::Sign)?;
        Ok(sig.as_ref().to_vec())
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }
}

/// Builds a full ACME JWS request body per RFC 8555 §6.2: either
/// `{"alg":"ES256","jwk":...,"nonce":...,"url":...}` for the very first
/// request (new-account, before a `kid` exists) or
/// `{"alg":"ES256","kid":...,"nonce":...,"url":...}` for every request
/// after. `payload` is `None` for POST-as-GET requests (empty string
/// payload, per RFC 8555 §6.3).
pub fn encode_jws(
    account_key: &AccountKey,
    url: &str,
    nonce: &str,
    kid: Option<&str>,
    payload: Option<&Value>,
) -> Result<Value, JwsError> {
    let mut protected = json!({
        "alg": "ES256",
        "nonce": nonce,
        "url": url,
    });
    match kid {
        Some(kid) => {
            protected["kid"] = json!(kid);
        }
        None => {
            protected["jwk"] = account_key.jwk();
        }
    }

    let protected_b64 = b64url_json(&protected)?;
    let payload_b64 = match payload {
        Some(p) => b64url_json(p)?,
        None => String::new(),
    };

    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = account_key.sign_raw(signing_input.as_bytes())?;

    Ok(json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url(&signature),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    #[test]
    fn b64url_matches_rfc4648_test_vectors_unpadded() {
        // RFC 4648 §10's standard test vectors, minus the padding
        // characters unpadded base64url must never emit.
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foob"), "Zm9vYg");
        assert_eq!(b64url(b"fooba"), "Zm9vYmE");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn generated_jws_signature_self_verifies() {
        let (key, _) = AccountKey::generate().unwrap();
        let payload = json!({"termsOfServiceAgreed": true});
        let jws = encode_jws(
            &key,
            "https://example.invalid/acme/new-account",
            "test-nonce-123",
            None,
            Some(&payload),
        )
        .unwrap();

        let protected_b64 = jws["protected"].as_str().unwrap();
        let payload_b64 = jws["payload"].as_str().unwrap();
        let sig_b64 = jws["signature"].as_str().unwrap();

        // Unpadded base64url, per RFC 7515 -- never a trailing '='.
        assert!(!protected_b64.contains('='));
        assert!(!payload_b64.contains('='));
        assert!(!sig_b64.contains('='));

        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        let public_key_bytes = key.public_key_der();
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public_key_bytes);
        assert!(
            public_key
                .verify(signing_input.as_bytes(), &sig_bytes)
                .is_ok()
        );
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let (key, _) = AccountKey::generate().unwrap();
        let payload = json!({"termsOfServiceAgreed": true});
        let jws = encode_jws(
            &key,
            "https://example.invalid/acme/new-account",
            "nonce",
            None,
            Some(&payload),
        )
        .unwrap();

        let protected_b64 = jws["protected"].as_str().unwrap();
        let sig_b64 = jws["signature"].as_str().unwrap();
        let tampered_payload_b64 = b64url_json(&json!({"termsOfServiceAgreed": false})).unwrap();

        let signing_input = format!("{protected_b64}.{tampered_payload_b64}");
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        let public_key_bytes = key.public_key_der();
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public_key_bytes);
        assert!(
            public_key
                .verify(signing_input.as_bytes(), &sig_bytes)
                .is_err()
        );
    }

    #[test]
    fn protected_header_uses_jwk_before_kid_is_known() {
        let (key, _) = AccountKey::generate().unwrap();
        let jws = encode_jws(
            &key,
            "https://example.invalid/acme/new-account",
            "nonce",
            None,
            None,
        )
        .unwrap();
        let protected: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jws["protected"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(protected.get("jwk").is_some());
        assert!(protected.get("kid").is_none());
    }

    #[test]
    fn protected_header_uses_kid_once_account_exists() {
        let (key, _) = AccountKey::generate().unwrap();
        let jws = encode_jws(
            &key,
            "https://example.invalid/acme/new-order",
            "nonce",
            Some("https://example.invalid/acme/acct/1"),
            None,
        )
        .unwrap();
        let protected: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jws["protected"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(protected["kid"], "https://example.invalid/acme/acct/1");
        assert!(protected.get("jwk").is_none());
    }

    #[test]
    fn post_as_get_has_empty_string_payload() {
        let (key, _) = AccountKey::generate().unwrap();
        let jws = encode_jws(
            &key,
            "https://example.invalid/acme/order/1",
            "nonce",
            Some("kid"),
            None,
        )
        .unwrap();
        assert_eq!(jws["payload"], "");
    }

    #[test]
    fn jwk_thumbprint_is_deterministic_and_correct_length() {
        let (key, _) = AccountKey::generate().unwrap();
        assert_eq!(key.jwk_thumbprint(), key.jwk_thumbprint());
        // Unpadded base64url of a 32-byte SHA-256 digest is always 43 chars.
        assert_eq!(key.jwk_thumbprint().len(), 43);
    }

    #[test]
    fn different_keys_produce_different_thumbprints() {
        let (key_a, _) = AccountKey::generate().unwrap();
        let (key_b, _) = AccountKey::generate().unwrap();
        assert_ne!(key_a.jwk_thumbprint(), key_b.jwk_thumbprint());
    }

    #[test]
    fn load_or_generate_persists_and_reuses_the_same_key() {
        let dir = std::env::temp_dir().join(format!("acme-jws-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("account.key");

        let key1 = AccountKey::load_or_generate(&path).unwrap();
        let thumb1 = key1.jwk_thumbprint();
        let key2 = AccountKey::load_or_generate(&path).unwrap();
        let thumb2 = key2.jwk_thumbprint();

        assert_eq!(thumb1, thumb2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
