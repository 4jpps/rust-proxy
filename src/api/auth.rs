//! Admin authentication, two independent mechanisms:
//! - Session: argon2 password verification (never a plaintext comparison)
//!   plus a stateless HMAC-signed cookie -- same "no server-side session
//!   table" shape as jpps-store's `token.rs`, just scoped to this
//!   daemon's one admin account instead of many. For the web UI.
//! - API tokens: opaque random bearer credentials, hashed at rest in
//!   sqlite (see `db::api_tokens`) and looked up by hash on every
//!   request. For programmatic/CI use -- see `routes::require_admin`,
//!   which accepts either mechanism on every protected endpoint.

use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const SESSION_COOKIE: &str = "rust_proxy_session";
const SESSION_LIFETIME_SECS: i64 = 12 * 3600;

/// Prefixed like GitHub/Stripe/GitLab tokens (`ghp_`, `sk_`, `glpat-`) so
/// a token is recognizable at a glance (in logs, in a secrets scanner,
/// in a config file) instead of looking like an arbitrary random string.
pub const API_TOKEN_PREFIX: &str = "rpx_";

/// Generates a new random API token and returns `(plaintext, hash)`. The
/// plaintext is returned to the caller exactly once, at creation time,
/// and is never persisted anywhere -- only the hash goes to sqlite (see
/// `db::create_api_token`), so losing the plaintext means generating a
/// new token, not a support request to recover it.
pub fn generate_api_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = format!("{API_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = hash_api_token(&token);
    (token, hash)
}

/// SHA-256, deliberately not argon2 -- API tokens are already a 256-bit
/// random secret, not a low-entropy human password, so there's no
/// offline-guessing risk a slow KDF would defend against, and a fast
/// hash keyed by a DB lookup is the standard approach for this kind of
/// credential (GitHub, GitLab, and Stripe all hash PATs/API keys this
/// way, not with bcrypt/argon2).
pub fn hash_api_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionPayload {
    username: String,
    exp: i64,
}

pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
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
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
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
        assert_eq!(
            verify_session("secret-key", &token),
            Some("admin".to_string())
        );
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
    fn generated_api_tokens_are_prefixed_unique_and_hash_consistently() {
        let (token_a, hash_a) = generate_api_token();
        let (token_b, hash_b) = generate_api_token();
        assert!(token_a.starts_with(API_TOKEN_PREFIX));
        assert_ne!(
            token_a, token_b,
            "two generated tokens should never collide"
        );
        assert_ne!(hash_a, hash_b);
        assert_eq!(
            hash_api_token(&token_a),
            hash_a,
            "hashing the same plaintext twice must be deterministic"
        );
    }

    #[test]
    fn different_api_tokens_hash_to_different_values() {
        let hash_one = hash_api_token("rpx_one");
        let hash_two = hash_api_token("rpx_two");
        assert_ne!(hash_one, hash_two);
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
