//! Admin session authentication: argon2 password verification (never a
//! plaintext comparison) plus a stateless HMAC-signed session cookie --
//! same "no server-side session table" shape as jpps-store's `token.rs`,
//! just scoped to this daemon's one admin account instead of many.

use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const SESSION_COOKIE: &str = "rust_proxy_session";
const SESSION_LIFETIME_SECS: i64 = 12 * 3600;

#[derive(Debug, Serialize, Deserialize)]
struct SessionPayload {
    username: String,
    exp: i64,
}

pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc_hash) else {
        return false;
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// `payload.signature`, both unpadded base64url -- same framing style as
/// the ACME JWS module, minus the JOSE header (there's only ever one
/// algorithm/purpose here, so it isn't worth the ceremony).
pub fn sign_session(secret: &str, username: &str) -> String {
    let payload = SessionPayload {
        username: username.to_string(),
        exp: chrono::Utc::now().timestamp() + SESSION_LIFETIME_SECS,
    };
    let payload_json = serde_json::to_vec(&payload).expect("SessionPayload always serializes");
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let sig = hmac_sign(secret, payload_b64.as_bytes());
    format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(sig))
}

/// Returns the signed-in username if `token` has a valid signature and
/// hasn't expired.
pub fn verify_session(secret: &str, token: &str) -> Option<String> {
    let (payload_b64, sig_b64) = token.split_once('.')?;
    let given_sig = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let expected_sig = hmac_sign(secret, payload_b64.as_bytes());
    if given_sig.ct_eq(&expected_sig).unwrap_u8() != 1 {
        return None;
    }
    let payload_json = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let payload: SessionPayload = serde_json::from_slice(&payload_json).ok()?;
    if payload.exp < chrono::Utc::now().timestamp() {
        return None;
    }
    Some(payload.username)
}

fn hmac_sign(secret: &str, data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trips() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn session_token_round_trips_the_username() {
        let token = sign_session("secret-key", "admin");
        assert_eq!(verify_session("secret-key", &token), Some("admin".to_string()));
    }

    #[test]
    fn session_token_rejected_with_wrong_secret() {
        let token = sign_session("secret-key", "admin");
        assert_eq!(verify_session("different-secret", &token), None);
    }

    #[test]
    fn tampered_session_token_is_rejected() {
        let token = sign_session("secret-key", "admin");
        let (payload, sig) = token.split_once('.').unwrap();
        let tampered_payload = URL_SAFE_NO_PAD.encode(br#"{"username":"root","exp":9999999999}"#);
        let tampered = format!("{tampered_payload}.{sig}");
        assert_eq!(verify_session("secret-key", &tampered), None);
        let _ = payload;
    }

    #[test]
    fn malformed_token_is_rejected_not_panicking() {
        assert_eq!(verify_session("secret-key", "not-a-valid-token"), None);
        assert_eq!(verify_session("secret-key", ""), None);
        assert_eq!(verify_session("secret-key", "a.b.c"), None);
    }

    #[test]
    fn expired_token_is_rejected() {
        let payload = SessionPayload {
            username: "admin".to_string(),
            exp: chrono::Utc::now().timestamp() - 10,
        };
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig = hmac_sign("secret-key", payload_b64.as_bytes());
        let token = format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(sig));
        assert_eq!(verify_session("secret-key", &token), None);
    }
}
