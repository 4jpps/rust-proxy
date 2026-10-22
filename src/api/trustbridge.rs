//! Admin-API bridge to TrustBridge (jpps/pki) org client-certificate
//! management: store the TrustBridge URL and this instance's org token,
//! then list / create / revoke client certificates through TrustBridge's
//! `/api/v1/org/...` API.
//!
//! The org token is write-only: it is accepted by `PUT /api/trustbridge`
//! and used server-side, but no response ever contains it (only
//! `token_set`). The token is never sent anywhere except the configured
//! TrustBridge URL, and redirects are never followed so it can't be
//! bounced to a different host.

use std::sync::OnceLock;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::state::AppState;

pub const DEFAULT_URL: &str = "https://pki.jpps.us";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOKEN_LEN: usize = 256;
const MAX_CN_LEN: usize = 128;
const MAX_DAYS: u32 = 3650;

pub struct TbError(StatusCode, String);

impl TbError {
    fn bad_request(m: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, m.into())
    }
    fn gateway(m: impl Into<String>) -> Self {
        Self(StatusCode::BAD_GATEWAY, m.into())
    }
}

impl From<sqlx::Error> for TbError {
    fn from(e: sqlx::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl IntoResponse for TbError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

/// Normalises and validates a TrustBridge base URL: https only (plain
/// http is allowed solely for a loopback host, for local testing), no
/// credentials, query or fragment. Returns it without a trailing slash.
pub fn validate_base_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let url = reqwest::Url::parse(raw).map_err(|_| "not a valid URL".to_string())?;
    let host = url.host_str().ok_or("URL has no host")?;
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err("URL must be https (http is only allowed for localhost)".into()),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not contain credentials".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("URL must not have a query or fragment".into());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// A serial is interpolated into the upstream URL path, so it must be
/// strictly alphanumeric hex/decimal digits -- nothing else, ever.
pub fn validate_serial(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("serial must be 1-64 hexadecimal/decimal digits".into());
    }
    Ok(())
}

fn validate_token(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() || t.len() > MAX_TOKEN_LEN || !t.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(format!(
            "token must be 1-{MAX_TOKEN_LEN} visible ASCII characters with no spaces"
        ));
    }
    Ok(t.to_string())
}

fn validate_common_name(raw: &str) -> Result<String, String> {
    let cn = raw.trim();
    if cn.is_empty() || cn.chars().count() > MAX_CN_LEN || cn.chars().any(char::is_control) {
        return Err(format!(
            "common_name must be 1-{MAX_CN_LEN} characters with no control characters"
        ));
    }
    Ok(cn.to_string())
}

fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("TrustBridge http client must build")
    })
}

struct Settings {
    url: String,
    token: String,
}

async fn load_settings(state: &AppState) -> Result<Settings, TbError> {
    let (url, token) = crate::db::load_trustbridge_settings(state.db())
        .await?
        .unwrap_or_else(|| (DEFAULT_URL.to_string(), String::new()));
    Ok(Settings { url, token })
}

/// Calls TrustBridge as this org. Upstream errors keep their status and
/// `{error}` message, except 401 (a rejected token): that becomes 502,
/// because a 401 from this admin API means "your admin session expired"
/// and would log the operator out of the UI.
async fn call(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, TbError> {
    let settings = load_settings(state).await?;
    if settings.token.is_empty() {
        return Err(TbError::bad_request(
            "no TrustBridge org token is configured",
        ));
    }
    let mut req = http()
        .request(method, format!("{}{}", settings.url, path))
        .bearer_auth(&settings.token)
        .header(header::ACCEPT, "application/json");
    if let Some(body) = body {
        req = req.json(&body);
    }
    let resp = req.send().await.map_err(|e| {
        TbError::gateway(format!("could not reach TrustBridge: {}", e.without_url()))
    })?;
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| {
        TbError::gateway(format!(
            "could not read TrustBridge's response: {}",
            e.without_url()
        ))
    })?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(TbError::gateway("TrustBridge's response was too large"));
    }
    let parsed: Option<Value> = serde_json::from_slice(&bytes).ok();
    if status.is_success() {
        return parsed.ok_or_else(|| TbError::gateway("TrustBridge returned a non-JSON response"));
    }
    let message = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(Value::as_str)
        .map(|m| m.chars().take(300).collect::<String>())
        .unwrap_or_else(|| format!("TrustBridge returned HTTP {}", status.as_u16()));
    if status == StatusCode::UNAUTHORIZED {
        return Err(TbError::gateway(format!(
            "TrustBridge rejected the org token: {message}"
        )));
    }
    let out = if status.is_client_error() {
        status
    } else {
        StatusCode::BAD_GATEWAY
    };
    Err(TbError(out, message))
}

async fn settings_body(state: &AppState) -> Result<Value, TbError> {
    let settings = load_settings(state).await?;
    let token_set = !settings.token.is_empty();
    let (org, error) = if token_set {
        match call(state, reqwest::Method::GET, "/api/v1/org", None).await {
            Ok(org) => (Some(org), None),
            Err(TbError(_, m)) => (None, Some(m)),
        }
    } else {
        (None, None)
    };
    Ok(json!({
        "url": settings.url,
        "default_url": DEFAULT_URL,
        "token_set": token_set,
        "org": org,
        "error": error,
        "required_org_id": state.required_client_cert_org(),
    }))
}

pub async fn get_settings(State(state): State<AppState>) -> Result<Json<Value>, TbError> {
    Ok(Json(settings_body(&state).await?))
}

#[derive(Deserialize)]
pub struct PutSettings {
    /// Absent keeps the current URL; empty resets to the default.
    url: Option<String>,
    /// Absent keeps the current token; empty clears it.
    token: Option<String>,
    /// Absent keeps the current lock; empty removes it; otherwise only
    /// client certs carrying this org-id are honored.
    required_org_id: Option<String>,
}

fn validate_org_id(s: &str) -> Result<String, String> {
    let ok = (3..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(s.to_string())
    } else {
        Err("org id must be 3-64 letters, digits, '-' or '_'".into())
    }
}

pub async fn put_settings(
    State(state): State<AppState>,
    Json(body): Json<PutSettings>,
) -> Result<Json<Value>, TbError> {
    if body.url.is_none() && body.token.is_none() && body.required_org_id.is_none() {
        return Err(TbError::bad_request(
            "nothing to change: provide url, token and/or required_org_id",
        ));
    }
    let new_lock = match body.required_org_id.as_deref().map(str::trim) {
        None => None,
        Some("") => Some(String::new()),
        Some(o) => Some(validate_org_id(o).map_err(TbError::bad_request)?),
    };
    let current = load_settings(&state).await?;
    let url = match body.url.as_deref().map(str::trim) {
        None => current.url,
        Some("") => DEFAULT_URL.to_string(),
        Some(u) => validate_base_url(u).map_err(TbError::bad_request)?,
    };
    let token = match body.token.as_deref().map(str::trim) {
        None => current.token,
        Some("") => String::new(),
        Some(t) => validate_token(t).map_err(TbError::bad_request)?,
    };
    crate::db::set_trustbridge_settings(state.db(), &url, &token).await?;
    if let Some(lock) = new_lock {
        crate::db::set_required_org_id(state.db(), &lock).await?;
        state.set_required_client_cert_org(Some(lock).filter(|l| !l.is_empty()));
    }
    Ok(Json(settings_body(&state).await?))
}

pub async fn list_certs(State(state): State<AppState>) -> Result<Json<Value>, TbError> {
    Ok(Json(
        call(&state, reqwest::Method::GET, "/api/v1/org/certs", None).await?,
    ))
}

#[derive(Deserialize)]
pub struct CreateCert {
    common_name: String,
    days: Option<u32>,
}

pub async fn create_cert(
    State(state): State<AppState>,
    Json(body): Json<CreateCert>,
) -> Result<Response, TbError> {
    let common_name = validate_common_name(&body.common_name).map_err(TbError::bad_request)?;
    let mut req = json!({ "common_name": common_name });
    if let Some(days) = body.days {
        if days == 0 || days > MAX_DAYS {
            return Err(TbError::bad_request(format!(
                "days must be between 1 and {MAX_DAYS}"
            )));
        }
        req["days"] = json!(days);
    }
    let created = call(
        &state,
        reqwest::Method::POST,
        "/api/v1/org/certs",
        Some(req),
    )
    .await?;
    // The response carries the private key and the .p12 password.
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(created),
    )
        .into_response())
}

pub async fn revoke_cert(
    State(state): State<AppState>,
    Path(serial): Path<String>,
) -> Result<Json<Value>, TbError> {
    validate_serial(&serial).map_err(TbError::bad_request)?;
    let out = call(
        &state,
        reqwest::Method::POST,
        &format!("/api/v1/org/certs/{serial}/revoke"),
        None,
    )
    .await?;
    // Make the next request for any cert re-ask OCSP instead of trusting
    // a cached "good" verdict.
    state.revocation().forget_cached_verdicts();
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_accepts_https_and_normalises() {
        assert_eq!(
            validate_base_url(" https://pki.jpps.us/ ").unwrap(),
            "https://pki.jpps.us"
        );
        assert_eq!(
            validate_base_url("https://pki.example.com:8443/tb").unwrap(),
            "https://pki.example.com:8443/tb"
        );
    }

    #[test]
    fn base_url_allows_plain_http_only_for_loopback() {
        assert!(validate_base_url("http://127.0.0.1:9000").is_ok());
        assert!(validate_base_url("http://localhost:9000").is_ok());
        assert!(validate_base_url("http://pki.jpps.us").is_err());
        assert!(validate_base_url("http://127.0.0.1.evil.com").is_err());
    }

    #[test]
    fn base_url_rejects_junk() {
        for bad in [
            "",
            "pki.jpps.us",
            "ftp://pki.jpps.us",
            "https://user:pw@pki.jpps.us",
            "https://pki.jpps.us/?x=1",
            "https://pki.jpps.us/#frag",
            "file:///etc/passwd",
        ] {
            assert!(validate_base_url(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn serial_must_be_digits_only() {
        assert!(validate_serial("1234567890").is_ok());
        assert!(validate_serial("AbCdEf0123").is_ok());
        for bad in [
            "",
            "../x",
            "12/34",
            "12 34",
            "12;34",
            "1%2f",
            "0x12",
            "12\n",
            &"1".repeat(65),
        ] {
            assert!(validate_serial(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn token_must_be_header_safe() {
        assert_eq!(validate_token("  tbo_abc123 ").unwrap(), "tbo_abc123");
        for bad in ["", "   ", "a b", "tbo\nx", "tbo_\u{e9}", &"x".repeat(257)] {
            assert!(validate_token(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn common_name_is_trimmed_and_bounded() {
        assert_eq!(
            validate_common_name(" Jeff Parrish ").unwrap(),
            "Jeff Parrish"
        );
        assert!(validate_common_name("").is_err());
        assert!(validate_common_name("a\u{0}b").is_err());
        assert!(validate_common_name(&"a".repeat(129)).is_err());
    }
}
