//! Session-cookie login gate for a host's `access_login` -- a real HTML
//! login page plus a signed session cookie, in place of HTTP Basic Auth
//! (removed: its browser-native prompt is poorly supported by most
//! password managers, since there's no real `<form>`/password field for
//! them to recognize and offer to save).
//!
//! The session token shares its framing with `api::auth`'s admin session
//! (HMAC-signed, base64url payload) but is otherwise fully independent:
//! a *derived* key (never `admin.session_secret` itself), a different
//! cookie name, and a payload shape that includes the host's domain. That
//! way a host-login session can never be replayed as an admin session
//! (or vice versa) even though both ultimately trace back to the same
//! configured secret -- important because a host's login credential is
//! typically a much lower-trust "viewer" account than the daemon's own
//! admin account.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::HostAuth;

pub const SESSION_COOKIE: &str = "rust_proxy_host_session";
/// A fixed, unlikely-to-collide path every login-gated host's listener
/// intercepts specially, the same way `acme::http01`'s challenge path is
/// a reserved-by-convention namespace under `/.well-known/`.
pub const LOGIN_SUBMIT_PATH: &str = "/.rust-proxy/login";
pub const SESSION_LIFETIME_SECS: i64 = 12 * 3600;

#[derive(Debug, Serialize, Deserialize)]
struct SessionPayload {
    domain: String,
    username: String,
    exp: i64,
}

#[derive(Debug, Deserialize)]
pub struct LoginSubmission {
    pub username: String,
    pub password: String,
    #[serde(default = "default_return_to")]
    pub return_to: String,
}

fn default_return_to() -> String {
    "/".to_string()
}

/// SHA-256 of a fixed, purpose-specific prefix plus the admin session
/// secret -- deliberately not the raw secret itself, so this key is
/// cryptographically distinct from the one `api::auth::sign_session`/
/// `verify_session` use, without requiring a second secret in the
/// config file.
fn derive_key(admin_session_secret: &str) -> Vec<u8> {
    Sha256::digest(format!("rust-proxy-host-login-session-v1:{admin_session_secret}").as_bytes())
        .to_vec()
}

/// Checks a submitted username/password against `auth`. Plain equality
/// on `username` is fine here (not a secret being compared -- the actual
/// authentication is the argon2-verified password).
pub fn verify_credentials(auth: &HostAuth, username: &str, password: &str) -> bool {
    username == auth.username && crate::api::auth::verify_password(password, &auth.password_hash)
}

/// Union match across every credential pulled in by a host's selected
/// Login ACLs -- succeeds if the submitted username/password matches ANY
/// one of them, per the union-within-kind semantics the ACL system uses.
pub fn verify_credentials_any(credentials: &[HostAuth], username: &str, password: &str) -> bool {
    credentials
        .iter()
        .any(|auth| verify_credentials(auth, username, password))
}

pub fn sign_session(admin_session_secret: &str, domain: &str, username: &str) -> String {
    let key = derive_key(admin_session_secret);
    let payload = SessionPayload {
        domain: domain.to_string(),
        username: username.to_string(),
        exp: chrono::Utc::now().timestamp() + SESSION_LIFETIME_SECS,
    };
    let payload_json = serde_json::to_vec(&payload).expect("SessionPayload always serializes");
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let sig = hmac_sign(&key, payload_b64.as_bytes());
    format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(sig))
}

/// `domain` must match the token's own payload -- a session minted for
/// one host is rejected on another, even if somehow presented there
/// (e.g. manually copied via devtools; browsers never send a host-only
/// cookie cross-origin on their own).
pub fn verify_session(admin_session_secret: &str, domain: &str, token: &str) -> bool {
    let key = derive_key(admin_session_secret);
    let Some((payload_b64, sig_b64)) = token.split_once('.') else {
        return false;
    };
    let Ok(given_sig) = URL_SAFE_NO_PAD.decode(sig_b64) else {
        return false;
    };
    let expected_sig = hmac_sign(&key, payload_b64.as_bytes());
    if given_sig.ct_eq(&expected_sig).unwrap_u8() != 1 {
        return false;
    }
    let Ok(payload_json) = URL_SAFE_NO_PAD.decode(payload_b64) else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<SessionPayload>(&payload_json) else {
        return false;
    };
    payload.domain == domain && payload.exp >= chrono::Utc::now().timestamp()
}

fn hmac_sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub(super) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// JSON-encodes `s` for embedding inside an inline `<script>` block.
/// `serde_json` alone only guarantees the result is a valid JS string
/// *literal* -- it does nothing about the surrounding HTML. If the
/// literal contains the raw bytes `</script`, the HTML parser (which
/// scans for that sequence case-sensitively-enough-in-practice to end a
/// script element regardless of JS string context) closes the element
/// early, turning the rest of the string into live HTML/script. Escaping
/// every `/` is the standard, over-broad-but-safe fix.
fn json_for_script(s: &str) -> String {
    serde_json::to_string(s)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('/', "\\/")
}

/// Only a same-origin relative path is a safe post-login destination for
/// the client-side `window.location.href = returnTo` navigation this
/// page performs. `return_to` reaches here from two places: the
/// server's own derived request path (always origin-form, already
/// safe) *or*, on a failed login attempt, echoed back verbatim from
/// `LoginSubmission::return_to` -- straight from the POST body's JSON,
/// fully attacker-controlled. Without this check, a crafted failed
/// login (`return_to: "https://evil.example"`) embedded in the
/// re-rendered page would redirect a victim to an attacker site
/// immediately after they enter their *real* password and establish a
/// genuine session -- an open redirect used for phishing, not merely a
/// cosmetic bug. `//host/...` and `/\host/...` are also rejected --
/// browsers can treat both as scheme-relative to a different origin.
fn sanitize_return_to(return_to: &str) -> &str {
    let is_safe = return_to.starts_with('/')
        && !return_to.starts_with("//")
        && !return_to.starts_with("/\\")
        && !return_to.contains("://");
    if is_safe { return_to } else { "/" }
}

/// Renders the self-contained login page served in place of the
/// originally-requested resource. A real `<form>` with a real
/// `type="password"` input and `autocomplete` hints -- unlike Basic
/// Auth's browser-native prompt, password managers reliably recognize
/// and offer to save this.
///
/// `return_to` is re-validated by `sanitize_return_to` regardless of
/// where it came from (see that function's doc for why), then both
/// HTML- and JSON-escaped since it's embedded in both a rendered page
/// and inline JS.
pub fn render_login_page(domain: &str, return_to: &str, error: Option<&str>) -> String {
    let return_to = sanitize_return_to(return_to);
    let domain_html = html_escape(domain);
    let return_to_json = json_for_script(return_to);
    let login_path_json = json_for_script(LOGIN_SUBMIT_PATH);
    let error_html = error.map(html_escape).unwrap_or_default();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in -- {domain_html}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; max-width: 320px; margin: 4rem auto; padding: 0 1rem; }}
  h1 {{ font-size: 1.1rem; }}
  form {{ display: flex; flex-direction: column; gap: 0.6rem; margin-top: 1rem; }}
  input {{ padding: 0.5rem; font-size: 1rem; }}
  button {{ padding: 0.5rem; font-size: 1rem; cursor: pointer; }}
  .error {{ color: #c33; font-size: 0.85rem; min-height: 1.1em; }}
</style>
</head>
<body>
  <h1>Sign in to {domain_html}</h1>
  <form id="login-form">
    <input type="text" name="username" placeholder="Username" autocomplete="username" required>
    <input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
    <span class="error" id="error">{error_html}</span>
  </form>
  <script>
    const returnTo = {return_to_json};
    document.getElementById('login-form').addEventListener('submit', async (e) => {{
      e.preventDefault();
      const fd = new FormData(e.target);
      const resp = await fetch({login_path_json}, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ username: fd.get('username'), password: fd.get('password'), return_to: returnTo }}),
      }});
      if (resp.ok) {{
        window.location.href = returnTo;
      }} else {{
        document.getElementById('error').textContent = 'Invalid username or password';
      }}
    }});
  </script>
</body>
</html>"#
    )
}

/// Shown for a host that has an IP-allow ACL and no login ACL to fall
/// back to (see `proxy::mod::handle_https_request`'s "IP over login"
/// combination) when the visitor's source IP doesn't match -- a real
/// page explaining why, not a bare, unstyled 403 with no body.
pub fn render_forbidden_page(domain: &str) -> String {
    let domain_html = html_escape(domain);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access denied -- {domain_html}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; max-width: 320px; margin: 4rem auto; padding: 0 1rem; }}
  h1 {{ font-size: 1.1rem; }}
  p {{ opacity: 0.8; }}
</style>
</head>
<body>
  <h1>Access denied</h1>
  <p>Your network is not allowed to reach {domain_html}.</p>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> HostAuth {
        HostAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        }
    }

    #[test]
    fn correct_credentials_are_accepted() {
        assert!(verify_credentials(&auth(), "viewer", "s3cret"));
    }

    #[test]
    fn wrong_password_is_rejected() {
        assert!(!verify_credentials(&auth(), "viewer", "wrong"));
    }

    #[test]
    fn wrong_username_is_rejected() {
        assert!(!verify_credentials(&auth(), "someone-else", "s3cret"));
    }

    #[test]
    fn a_freshly_signed_session_verifies_for_its_own_domain() {
        let token = sign_session("secret", "example.com", "viewer");
        assert!(verify_session("secret", "example.com", &token));
    }

    #[test]
    fn a_session_signed_for_one_domain_does_not_verify_for_another() {
        let token = sign_session("secret", "example.com", "viewer");
        assert!(!verify_session("secret", "other.example.com", &token));
    }

    #[test]
    fn a_session_signed_with_a_different_secret_does_not_verify() {
        let token = sign_session("secret-a", "example.com", "viewer");
        assert!(!verify_session("secret-b", "example.com", &token));
    }

    #[test]
    fn a_tampered_session_token_is_rejected() {
        let token = sign_session("secret", "example.com", "viewer");
        let (_, sig) = token.split_once('.').unwrap();
        let tampered_payload = URL_SAFE_NO_PAD
            .encode(br#"{"domain":"example.com","username":"admin","exp":9999999999}"#);
        let tampered = format!("{tampered_payload}.{sig}");
        assert!(!verify_session("secret", "example.com", &tampered));
    }

    #[test]
    fn a_malformed_token_is_rejected_not_panicking() {
        assert!(!verify_session(
            "secret",
            "example.com",
            "not-a-valid-token"
        ));
        assert!(!verify_session("secret", "example.com", ""));
        assert!(!verify_session("secret", "example.com", "a.b.c"));
    }

    #[test]
    fn an_expired_session_is_rejected() {
        let key = derive_key("secret");
        let payload = SessionPayload {
            domain: "example.com".into(),
            username: "viewer".into(),
            exp: chrono::Utc::now().timestamp() - 10,
        };
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig = hmac_sign(&key, payload_b64.as_bytes());
        let token = format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(sig));
        assert!(!verify_session("secret", "example.com", &token));
    }

    /// The host-login HMAC key must never equal the admin session's own
    /// raw secret -- otherwise a host-login token could be replayed as
    /// (or forged from knowledge of) an admin session, escalating a
    /// low-trust per-host "viewer" credential into full daemon admin
    /// access. This is the property `api::auth::verify_session` (a
    /// completely separate function/cookie/payload shape) relies on
    /// never being confusable with this module's tokens.
    #[test]
    fn derived_key_is_not_the_raw_admin_session_secret() {
        assert_ne!(derive_key("secret"), "secret".as_bytes());
    }

    #[test]
    fn render_login_page_escapes_html_in_the_domain_and_error() {
        let html = render_login_page("<script>evil</script>", "/", Some("<img onerror=alert(1)>"));
        assert!(!html.contains("<script>evil</script>"));
        assert!(!html.contains("<img onerror"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn render_forbidden_page_mentions_the_domain_and_escapes_html_in_it() {
        let html = render_forbidden_page("<script>evil</script>");
        assert!(!html.contains("<script>evil</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Access denied"));
    }

    #[test]
    fn sanitize_return_to_keeps_an_ordinary_relative_path() {
        assert_eq!(sanitize_return_to("/dashboard?x=1"), "/dashboard?x=1");
    }

    #[test]
    fn sanitize_return_to_rejects_an_absolute_url() {
        // The open-redirect case: a failed login POST can carry any
        // string as return_to (it's attacker-controlled JSON, not a
        // server-derived path), and this must never survive into the
        // page a real login later navigates to.
        assert_eq!(sanitize_return_to("https://evil.example/phish"), "/");
        assert_eq!(sanitize_return_to("http://evil.example"), "/");
    }

    #[test]
    fn sanitize_return_to_rejects_protocol_relative_and_backslash_variants() {
        assert_eq!(sanitize_return_to("//evil.example"), "/");
        assert_eq!(sanitize_return_to("/\\evil.example"), "/");
    }

    #[test]
    fn sanitize_return_to_rejects_a_bare_domain_or_empty_string() {
        assert_eq!(sanitize_return_to("evil.example"), "/");
        assert_eq!(sanitize_return_to(""), "/");
    }

    #[test]
    fn render_login_page_never_embeds_an_unsafe_return_to() {
        let html = render_login_page("example.com", "https://evil.example/phish", None);
        assert!(!html.contains("evil.example"));
    }

    #[test]
    fn render_login_page_json_escapes_return_to_for_safe_inline_embedding() {
        let html = render_login_page(
            "example.com",
            "/a\"</script><script>alert(1)</script>",
            None,
        );
        assert!(!html.contains("</script><script>alert(1)"));
    }
}
