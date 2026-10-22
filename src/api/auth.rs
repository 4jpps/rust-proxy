//! Admin authentication, two independent mechanisms:
//! - Session: argon2 password verification (never a plaintext comparison)
//!   plus a stateless HMAC-signed cookie -- same "no server-side session
//!   table" shape as jpps-store's `token.rs`. The cookie only proves who
//!   signed in; the account's role is looked up on every request (see
//!   `routes::require_admin`), so a role change or a deleted account takes
//!   effect immediately. For the web UI.
//! - API tokens: opaque random bearer credentials, hashed at rest in
//!   sqlite (see `db::api_tokens`) and looked up by hash on every
//!   request. For programmatic/CI use -- see `routes::require_admin`,
//!   which accepts either mechanism on every protected endpoint.

use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const SESSION_COOKIE: &str = "rust_proxy_session";

/// What a signed-in user or API token may do. The owner account from
/// `config.toml` / the setup wizard is always `Admin`; extra accounts and
/// tokens carry one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Everything, including users, API tokens and system settings.
    Admin,
    /// Reads everything and changes the proxy's own configuration (hosts,
    /// port rules, certificates, access lists, hosting allocations), but
    /// not users, tokens or system-wide settings.
    Operator,
    /// Reads everything except users and tokens. Changes nothing.
    Viewer,
}

/// Paths only an admin may touch, for any method (they expose or mint
/// credentials).
const ADMIN_ONLY_PATHS: &[&str] = &["/api/users", "/api/tokens"];

/// Paths anyone may read but only an admin may change (system-wide
/// settings and the secrets and address space behind them).
const ADMIN_WRITE_PATHS: &[&str] = &[
    "/api/dns-credentials",
    "/api/acme-settings",
    "/api/firewall-settings",
    "/api/siem",
    "/api/license",
    "/api/default-site",
    "/api/hosting/pools",
    "/api/trustbridge",
];

fn path_is_under(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }

    /// The one place that decides whether a role may make a request.
    /// `/api/me` and `/api/me/password` are open to every signed-in role
    /// (the password handler itself refuses accounts that have no
    /// password of their own to change).
    pub fn allows(self, method: &axum::http::Method, path: &str) -> bool {
        if path == "/api/me" || path == "/api/me/password" {
            return true;
        }
        if self == Role::Admin {
            return true;
        }
        if ADMIN_ONLY_PATHS.iter().any(|p| path_is_under(path, p)) {
            return false;
        }
        let is_read = method == axum::http::Method::GET || method == axum::http::Method::HEAD;
        match self {
            Role::Admin => true,
            Role::Viewer => is_read,
            Role::Operator => is_read || !ADMIN_WRITE_PATHS.iter().any(|p| path_is_under(path, p)),
        }
    }
}

/// A password hash that no real password matches, verified against when a
/// login names an account that doesn't exist so that "no such user" costs
/// the same as "wrong password".
pub fn verify_against_dummy_hash(password: &str) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let hash = DUMMY.get_or_init(|| {
        hash_password("no account has this password")
            .expect("hashing a constant password cannot fail")
    });
    let _ = verify_password(password, hash);
}
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
    use argon2::PasswordHasher;
    use argon2::password_hash::SaltString;
    use argon2::password_hash::rand_core::OsRng;

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

    use axum::http::Method;

    #[test]
    fn only_admins_manage_trustbridge_certs_but_anyone_may_read() {
        for (m, p) in [
            (Method::PUT, "/api/trustbridge"),
            (Method::POST, "/api/trustbridge/certs"),
            (Method::POST, "/api/trustbridge/certs/123/revoke"),
        ] {
            assert!(Role::Admin.allows(&m, p), "{m} {p}");
            assert!(!Role::Operator.allows(&m, p), "{m} {p}");
            assert!(!Role::Viewer.allows(&m, p), "{m} {p}");
        }
        for p in ["/api/trustbridge", "/api/trustbridge/certs"] {
            assert!(Role::Operator.allows(&Method::GET, p));
            assert!(Role::Viewer.allows(&Method::GET, p));
        }
    }

    #[test]
    fn admin_may_do_anything() {
        assert!(Role::Admin.allows(&Method::DELETE, "/api/users/abc"));
        assert!(Role::Admin.allows(&Method::POST, "/api/tokens"));
        assert!(Role::Admin.allows(&Method::PUT, "/api/firewall-settings"));
    }

    #[test]
    fn operator_changes_proxy_config_but_not_users_tokens_or_system_settings() {
        for (m, p) in [
            (Method::POST, "/api/hosts"),
            (Method::PUT, "/api/hosts/x"),
            (Method::DELETE, "/api/port-rules/x"),
            (Method::POST, "/api/certs"),
            (Method::POST, "/api/acls"),
            (Method::POST, "/api/dns01-certs"),
            (Method::POST, "/api/hosting/allocations"),
            (Method::POST, "/api/hosting/apply"),
            (Method::GET, "/api/dns-credentials"),
            (Method::GET, "/api/siem"),
        ] {
            assert!(Role::Operator.allows(&m, p), "{m} {p}");
        }
        for (m, p) in [
            (Method::GET, "/api/users"),
            (Method::POST, "/api/users"),
            (Method::GET, "/api/tokens"),
            (Method::DELETE, "/api/tokens/x"),
            (Method::POST, "/api/dns-credentials"),
            (Method::PUT, "/api/acme-settings"),
            (Method::PUT, "/api/firewall-settings"),
            (Method::PUT, "/api/siem"),
            (Method::POST, "/api/siem/test"),
            (Method::POST, "/api/hosting/pools"),
            (Method::PUT, "/api/hosting/pools/main"),
        ] {
            assert!(!Role::Operator.allows(&m, p), "{m} {p}");
        }
    }

    #[test]
    fn viewer_only_reads_and_never_sees_users_or_tokens() {
        assert!(Role::Viewer.allows(&Method::GET, "/api/hosts"));
        assert!(Role::Viewer.allows(&Method::GET, "/api/dashboard"));
        assert!(!Role::Viewer.allows(&Method::POST, "/api/hosts"));
        assert!(!Role::Viewer.allows(&Method::DELETE, "/api/hosts/x"));
        assert!(!Role::Viewer.allows(&Method::POST, "/api/hosting/apply"));
        assert!(!Role::Viewer.allows(&Method::GET, "/api/users"));
        assert!(!Role::Viewer.allows(&Method::GET, "/api/tokens"));
    }

    #[test]
    fn every_role_reaches_me_endpoints() {
        for role in [Role::Admin, Role::Operator, Role::Viewer] {
            assert!(role.allows(&Method::GET, "/api/me"));
            assert!(role.allows(&Method::POST, "/api/me/password"));
        }
    }

    #[test]
    fn similarly_named_paths_are_not_treated_as_the_protected_prefix() {
        assert!(Role::Operator.allows(&Method::POST, "/api/userspace"));
        assert!(Role::Viewer.allows(&Method::GET, "/api/tokenizer"));
    }

    #[test]
    fn role_round_trips_through_its_string_form() {
        for role in [Role::Admin, Role::Operator, Role::Viewer] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::parse("root"), None);
        assert_eq!(Role::parse("Admin"), None);
    }

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
