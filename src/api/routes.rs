//! REST API + embedded admin UI. Every mutating handler writes through
//! `db::save_*` and then `state.set_*` in that order -- if the DB write
//! fails, the in-memory state (and therefore the live proxy/firewall)
//! never sees the change, so a persistence failure can't silently diverge
//! from what's actually running.

use std::net::Ipv4Addr;

use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use uuid::Uuid;

use super::auth;
use crate::config::{PortRule, Protocol, ProxyHost};
use crate::state::AppState;

const ADMIN_UI_HTML: &str = include_str!("../../web/index.html");

pub fn build_router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/dashboard", get(dashboard))
        .route("/api/hosts", get(list_hosts).post(create_host))
        .route("/api/hosts/:id", axum::routing::put(update_host).delete(delete_host))
        .route("/api/port-rules", get(list_port_rules).post(create_port_rule))
        .route("/api/port-rules/:id", axum::routing::put(update_port_rule).delete(delete_port_rule))
        .route("/api/certs", get(list_certs))
        .route("/api/tokens", get(list_api_tokens).post(create_api_token))
        .route("/api/tokens/:id", axum::routing::delete(delete_api_token))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_admin));

    Router::new()
        .route("/", get(admin_ui))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .merge(protected)
        .with_state(state)
        .layer(CookieManagerLayer::new())
}

async fn admin_ui() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], ADMIN_UI_HTML).into_response()
}

/// Every protected route accepts either credential, checked in this
/// order: first the session cookie (the common case for the web UI, and
/// cheaper -- no DB round trip), then an `Authorization: Bearer <token>`
/// header (see `api::auth::generate_api_token`/`README.md`'s API Tokens
/// section for how to mint one). A valid token can reach every endpoint
/// this middleware guards, including token management itself -- there's
/// no scope system, a token is exactly as privileged as the admin
/// session it was created from, matching this daemon's single-admin-
/// account model. Treat a token like a password: anyone holding one can
/// reconfigure the proxy and the firewall behind it.
async fn require_admin(State(state): State<AppState>, cookies: Cookies, req: Request, next: Next) -> Response {
    let session_ok = cookies
        .get(auth::SESSION_COOKIE)
        .map(|c| c.value().to_string())
        .and_then(|t| auth::verify_session(&state.admin().session_secret, &t))
        .is_some();
    if session_ok {
        return next.run(req).await;
    }

    if let Some(token) = bearer_token(&req) {
        let hash = auth::hash_api_token(&token);
        if let Ok(Some(id)) = crate::db::find_api_token_id_by_hash(state.db(), &hash).await {
            // Best-effort -- a failure to record last-used time must
            // never block the request it's just bookkeeping for.
            if let Err(err) = crate::db::touch_api_token_last_used(state.db(), id, chrono::Utc::now()).await {
                tracing::warn!(error = %err, "failed to update api token last_used_at");
            }
            return next.run(req).await;
        }
    }

    StatusCode::UNAUTHORIZED.into_response()
}

fn bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

#[derive(Debug)]
enum ApiError {
    BadRequest(String),
    NotFound,
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(State(state): State<AppState>, cookies: Cookies, Json(body): Json<LoginRequest>) -> Response {
    let admin = state.admin();
    if body.username != admin.admin_username || !auth::verify_password(&body.password, &admin.admin_password_hash) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let token = auth::sign_session(&admin.session_secret, &body.username);
    let mut cookie = Cookie::new(auth::SESSION_COOKIE, token);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookies.add(cookie);
    StatusCode::OK.into_response()
}

async fn logout(cookies: Cookies) -> Response {
    let mut cookie = Cookie::new(auth::SESSION_COOKIE, "");
    cookie.set_path("/");
    cookies.remove(cookie);
    StatusCode::OK.into_response()
}

#[derive(Serialize)]
struct DashboardResponse {
    host_count: usize,
    enabled_host_count: usize,
    port_rule_count: usize,
    cert_count: usize,
    /// Empty means unrestricted -- no configured `network.bind_ranges`,
    /// any bind_ip is accepted. The admin UI shows this distinctly from
    /// "restricted to these ranges" rather than an empty list looking
    /// like a loading glitch.
    bind_ranges: Vec<String>,
}

async fn dashboard(State(state): State<AppState>) -> Json<DashboardResponse> {
    let hosts = state.hosts();
    Json(DashboardResponse {
        host_count: hosts.len(),
        enabled_host_count: hosts.iter().filter(|h| h.enabled).count(),
        port_rule_count: state.port_rules().len(),
        cert_count: state.certs().len(),
        bind_ranges: state.network().bind_ranges.iter().map(|n| n.to_string()).collect(),
    })
}

async fn list_hosts(State(state): State<AppState>) -> Json<Vec<ProxyHost>> {
    Json((*state.hosts()).clone())
}

#[derive(Deserialize)]
struct HostRequest {
    domain: String,
    bind_ip: Ipv4Addr,
    bind_port: u16,
    upstream: String,
    #[serde(default)]
    websockets: bool,
    #[serde(default = "default_true")]
    force_https: bool,
    #[serde(default = "default_true")]
    acme_enabled: bool,
    #[serde(default)]
    acme_challenge_type: crate::config::AcmeChallengeType,
    /// CIDR strings (e.g. `"10.0.0.0/24"`) -- empty means unrestricted.
    /// Parsed and validated in `parse_access_allow_ips`.
    #[serde(default)]
    access_allow_ips: Vec<String>,
    /// `None` means no Basic Auth gate. `password` is plaintext, hashed
    /// server-side (`build_basic_auth`) before it ever reaches sqlite --
    /// same as the admin account's own password, never stored raw.
    #[serde(default)]
    access_basic_auth: Option<BasicAuthRequest>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Deserialize)]
struct BasicAuthRequest {
    username: String,
    password: String,
}
fn default_true() -> bool {
    true
}

fn validate_host_request(state: &AppState, req: &HostRequest) -> Result<(), ApiError> {
    crate::config::validate_domain(&req.domain).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if req.bind_port == 0 {
        return Err(ApiError::BadRequest("bind_port must not be 0".into()));
    }
    if !req.upstream.contains(':') {
        return Err(ApiError::BadRequest("upstream must be host:port".into()));
    }
    crate::config::validate_bind_ip(&state.network().bind_ranges, req.bind_ip, "hosts")
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(())
}

fn parse_access_allow_ips(raw: &[String]) -> Result<Vec<ipnet::Ipv4Net>, ApiError> {
    raw.iter()
        .map(|s| s.parse().map_err(|_| ApiError::BadRequest(format!("invalid access_allow_ips entry \"{s}\""))))
        .collect()
}

/// Hashes the plaintext password (argon2, same as the admin account's
/// own) into a storable `BasicAuth` -- `None` in means no auth gate for
/// this host, same as leaving `access_basic_auth` out of the request
/// entirely.
fn build_basic_auth(req: &Option<BasicAuthRequest>) -> Result<Option<crate::config::BasicAuth>, ApiError> {
    let Some(req) = req else { return Ok(None) };
    if req.username.trim().is_empty() || req.password.is_empty() {
        return Err(ApiError::BadRequest("access_basic_auth requires a non-empty username and password".into()));
    }
    let password_hash = auth::hash_password(&req.password).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Some(crate::config::BasicAuth {
        username: req.username.clone(),
        password_hash,
    }))
}

async fn create_host(State(state): State<AppState>, Json(body): Json<HostRequest>) -> Result<Json<ProxyHost>, ApiError> {
    validate_host_request(&state, &body)?;
    let access_allow_ips = parse_access_allow_ips(&body.access_allow_ips)?;
    let access_basic_auth = build_basic_auth(&body.access_basic_auth)?;
    let host = ProxyHost {
        id: Uuid::new_v4(),
        domain: body.domain,
        bind_ip: body.bind_ip,
        bind_port: body.bind_port,
        upstream: body.upstream,
        websockets: body.websockets,
        force_https: body.force_https,
        acme_enabled: body.acme_enabled,
        acme_challenge_type: body.acme_challenge_type,
        access_allow_ips,
        access_basic_auth,
        enabled: body.enabled,
    };
    let to_insert = host.clone();
    mutate_hosts(&state, move |hosts| {
        hosts.push(to_insert);
        true
    })
    .await?;
    Ok(Json(host))
}

async fn update_host(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<HostRequest>,
) -> Result<Json<ProxyHost>, ApiError> {
    validate_host_request(&state, &body)?;
    let access_allow_ips = parse_access_allow_ips(&body.access_allow_ips)?;
    let access_basic_auth = build_basic_auth(&body.access_basic_auth)?;
    let updated = ProxyHost {
        id,
        domain: body.domain,
        bind_ip: body.bind_ip,
        bind_port: body.bind_port,
        upstream: body.upstream,
        websockets: body.websockets,
        force_https: body.force_https,
        acme_enabled: body.acme_enabled,
        acme_challenge_type: body.acme_challenge_type,
        access_allow_ips,
        access_basic_auth,
        enabled: body.enabled,
    };
    let to_store = updated.clone();
    let found = mutate_hosts(&state, move |hosts| match hosts.iter_mut().find(|h| h.id == id) {
        Some(existing) => {
            *existing = to_store;
            true
        }
        None => false,
    })
    .await?;
    if !found {
        return Err(ApiError::NotFound);
    }
    Ok(Json(updated))
}

async fn delete_host(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let found = mutate_hosts(&state, move |hosts| {
        let before = hosts.len();
        hosts.retain(|h| h.id != id);
        hosts.len() != before
    })
    .await?;
    if !found {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Holds `hosts_write_lock` for the entire read-modify-write-persist
/// sequence, so two concurrent mutations can never race and clobber each
/// other -- the lock, not `ArcSwap`, is what makes writes safe under
/// concurrency; `ArcSwap` alone only makes *reads* lock-free.
async fn mutate_hosts(state: &AppState, mutate: impl FnOnce(&mut Vec<ProxyHost>) -> bool) -> Result<bool, ApiError> {
    let _guard = state.lock_hosts_for_write().await;
    let mut hosts = (*state.hosts()).clone();
    let changed = mutate(&mut hosts);
    crate::db::save_hosts(state.db(), &hosts).await?;
    state.set_hosts(hosts);
    Ok(changed)
}

async fn list_port_rules(State(state): State<AppState>) -> Json<Vec<PortRule>> {
    Json((*state.port_rules()).clone())
}

#[derive(Deserialize)]
struct PortRuleRequest {
    bind_ip: Ipv4Addr,
    port_start: u16,
    port_end: u16,
    protocol: Protocol,
    #[serde(default)]
    description: String,
    #[serde(default)]
    passthrough_target: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn validate_port_rule_request(state: &AppState, req: &PortRuleRequest) -> Result<(), ApiError> {
    if req.port_start == 0 || req.port_end == 0 {
        return Err(ApiError::BadRequest("ports must not be 0".into()));
    }
    if req.port_start > req.port_end {
        return Err(ApiError::BadRequest("port_start must be <= port_end".into()));
    }
    crate::config::validate_bind_ip(&state.network().bind_ranges, req.bind_ip, "port_rules")
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(())
}

async fn create_port_rule(State(state): State<AppState>, Json(body): Json<PortRuleRequest>) -> Result<Json<PortRule>, ApiError> {
    validate_port_rule_request(&state, &body)?;
    let rule = PortRule {
        id: Uuid::new_v4(),
        bind_ip: body.bind_ip,
        port_start: body.port_start,
        port_end: body.port_end,
        protocol: body.protocol,
        description: body.description,
        passthrough_target: body.passthrough_target,
        enabled: body.enabled,
    };
    let to_insert = rule.clone();
    mutate_port_rules(&state, move |rules| {
        rules.push(to_insert);
        true
    })
    .await?;
    Ok(Json(rule))
}

async fn update_port_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<PortRuleRequest>,
) -> Result<Json<PortRule>, ApiError> {
    validate_port_rule_request(&state, &body)?;
    let updated = PortRule {
        id,
        bind_ip: body.bind_ip,
        port_start: body.port_start,
        port_end: body.port_end,
        protocol: body.protocol,
        description: body.description,
        passthrough_target: body.passthrough_target,
        enabled: body.enabled,
    };
    let to_store = updated.clone();
    let found = mutate_port_rules(&state, move |rules| match rules.iter_mut().find(|r| r.id == id) {
        Some(existing) => {
            *existing = to_store;
            true
        }
        None => false,
    })
    .await?;
    if !found {
        return Err(ApiError::NotFound);
    }
    Ok(Json(updated))
}

async fn delete_port_rule(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let found = mutate_port_rules(&state, move |rules| {
        let before = rules.len();
        rules.retain(|r| r.id != id);
        rules.len() != before
    })
    .await?;
    if !found {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn mutate_port_rules(state: &AppState, mutate: impl FnOnce(&mut Vec<PortRule>) -> bool) -> Result<bool, ApiError> {
    let _guard = state.lock_port_rules_for_write().await;
    let mut rules = (*state.port_rules()).clone();
    let changed = mutate(&mut rules);
    crate::db::save_port_rules(state.db(), &rules).await?;
    state.set_port_rules(rules);
    Ok(changed)
}

#[derive(Serialize)]
struct CertSummary {
    domain: String,
    not_after: chrono::DateTime<chrono::Utc>,
    days_remaining: i64,
}

async fn list_certs(State(state): State<AppState>) -> Json<Vec<CertSummary>> {
    let now = chrono::Utc::now();
    let mut certs: Vec<CertSummary> = state
        .certs()
        .iter()
        .map(|(domain, entry)| CertSummary {
            domain: domain.clone(),
            not_after: entry.not_after,
            days_remaining: (entry.not_after - now).num_days(),
        })
        .collect();
    certs.sort_by(|a, b| a.domain.cmp(&b.domain));
    Json(certs)
}

#[derive(Serialize)]
struct ApiTokenSummary {
    id: Uuid,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    /// `None` until the token is used for the first time -- lets an
    /// admin spot stale/unused tokens worth revoking.
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
struct CreateApiTokenRequest {
    name: String,
}

#[derive(Serialize)]
struct ApiTokenCreated {
    id: Uuid,
    name: String,
    /// The only time the plaintext is ever transmitted -- callers must
    /// save it now, it can't be retrieved again (only the hash is
    /// persisted; see `db::create_api_token`).
    token: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_api_tokens(State(state): State<AppState>) -> Result<Json<Vec<ApiTokenSummary>>, ApiError> {
    let tokens = crate::db::list_api_tokens(state.db()).await?;
    Ok(Json(
        tokens
            .into_iter()
            .map(|t| ApiTokenSummary {
                id: t.id,
                name: t.name,
                created_at: t.created_at,
                last_used_at: t.last_used_at,
            })
            .collect(),
    ))
}

async fn create_api_token(
    State(state): State<AppState>,
    Json(body): Json<CreateApiTokenRequest>,
) -> Result<Json<ApiTokenCreated>, ApiError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }
    let (token, hash) = auth::generate_api_token();
    let id = Uuid::new_v4();
    let created_at = chrono::Utc::now();
    crate::db::create_api_token(state.db(), id, name, &hash, created_at).await?;
    Ok(Json(ApiTokenCreated {
        id,
        name: name.to_string(),
        token,
        created_at,
    }))
}

async fn delete_api_token(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let found = crate::db::delete_api_token(state.db(), id).await?;
    if !found {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeConfig, AdminConfig, Config, NetworkConfig};
    use http_body_util::BodyExt;
    use std::path::PathBuf;
    use tower::ServiceExt;

    async fn test_state() -> AppState {
        let cfg = Config {
            network: NetworkConfig {
                bind_ranges: vec!["10.0.0.0/29".parse().unwrap()],
            },
            admin: AdminConfig {
                bind_ip: "10.0.0.1".parse().unwrap(),
                bind_port: 8080,
                allowed_ips: vec![],
                session_secret: "test-secret-key".into(),
                admin_username: "admin".into(),
                admin_password_hash: auth::hash_password("correct-password").unwrap(),
                db_path: PathBuf::from(":memory:"),
            },
            acme: AcmeConfig {
                directory_url: "https://example.invalid/directory".into(),
                contact_email: "admin@example.com".into(),
                dns_provider: crate::config::DnsProviderKind::Cloudflare,
                dns_api_token: "token".into(),
                cert_dir: PathBuf::from("/tmp/certs"),
                account_key_path: PathBuf::from("/tmp/account.key"),
                renew_before_days: 30,
            },
            hosts: vec![],
            port_rules: vec![],
        };
        let pool = crate::db::connect(&PathBuf::from(":memory:")).await.unwrap();
        AppState::new(cfg, pool, vec![], vec![])
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn session_cookie_header(resp: &Response) -> String {
        resp.headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn unauthenticated_request_to_protected_route_is_rejected() {
        let router = build_router(test_state().await);
        let resp = router
            .oneshot(Request::builder().uri("/api/dashboard").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_with_wrong_password_is_rejected() {
        let router = build_router(test_state().await);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"admin","password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_then_dashboard_round_trip_with_session_cookie() {
        let router = build_router(test_state().await);

        let login_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"admin","password":"correct-password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let cookie = session_cookie_header(&login_resp);

        let dash_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dash_resp.status(), StatusCode::OK);
        let json = body_json(dash_resp).await;
        assert_eq!(json["host_count"], 0);
    }

    async fn logged_in_cookie(router: &Router) -> String {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"admin","password":"correct-password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        session_cookie_header(&resp)
    }

    #[tokio::test]
    async fn create_host_persists_and_appears_in_list() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let create_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(
                        r#"{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);

        let list_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/hosts")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(list_resp).await;
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["domain"], "example.com");
    }

    #[tokio::test]
    async fn create_host_with_bind_ip_outside_bind_ranges_is_rejected() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(
                        r#"{"domain":"example.com","bind_ip":"192.168.1.5","bind_port":443,"upstream":"127.0.0.1:8000"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_host_with_access_control_persists_ip_allow_list_and_never_returns_the_password_hash() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let create_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(
                        r#"{"domain":"internal.example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000",
                        "access_allow_ips":["10.0.0.0/24"],"access_basic_auth":{"username":"viewer","password":"s3cret"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
        let created = body_json(create_resp).await;
        assert_eq!(created["access_allow_ips"], serde_json::json!(["10.0.0.0/24"]));
        assert_eq!(created["access_basic_auth"]["username"], "viewer");
        assert!(
            created["access_basic_auth"].get("password_hash").is_none(),
            "the argon2 hash must never be returned, even to an authenticated admin"
        );

        let list_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/hosts")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(list_resp).await;
        assert_eq!(json[0]["access_allow_ips"], serde_json::json!(["10.0.0.0/24"]));
        assert_eq!(json[0]["access_basic_auth"]["username"], "viewer");
    }

    #[tokio::test]
    async fn create_host_with_an_invalid_access_allow_ips_entry_is_rejected() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(
                        r#"{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000",
                        "access_allow_ips":["not-a-cidr"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_host_with_an_empty_basic_auth_password_is_rejected() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(
                        r#"{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000",
                        "access_basic_auth":{"username":"viewer","password":""}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_nonexistent_host_returns_404() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/hosts/{}", Uuid::new_v4()))
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn concurrent_host_creates_all_persist_without_data_loss() {
        let state = test_state().await;
        let router = build_router(state.clone());
        let cookie = logged_in_cookie(&router).await;

        let mut handles = Vec::new();
        for i in 0..20 {
            let router = router.clone();
            let cookie = cookie.clone();
            handles.push(tokio::spawn(async move {
                let body = format!(r#"{{"domain":"host{i}.example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000"}}"#);
                router
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/hosts")
                            .header(header::CONTENT_TYPE, "application/json")
                            .header(header::COOKIE, cookie)
                            .body(axum::body::Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }));
        }
        for h in handles {
            let resp = h.await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // hosts_write_lock serializes the whole read-modify-write-persist
        // sequence, so 20 concurrent creates must never clobber each
        // other -- both the in-memory state and sqlite should end up with
        // all 20, not fewer.
        assert_eq!(state.hosts().len(), 20);
        let loaded = crate::db::load_hosts(state.db()).await.unwrap();
        assert_eq!(loaded.len(), 20);
    }

    #[tokio::test]
    async fn creating_an_api_token_returns_the_plaintext_exactly_once() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tokens")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(r#"{"name":"ci pipeline"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["name"], "ci pipeline");
        assert!(json["token"].as_str().unwrap().starts_with(auth::API_TOKEN_PREFIX));
    }

    #[tokio::test]
    async fn a_bearer_token_authenticates_protected_routes_without_a_session_cookie() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let create_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tokens")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(r#"{"name":"ci pipeline"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let token = body_json(create_resp).await["token"].as_str().unwrap().to_string();

        let dash_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dash_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_invalid_bearer_token_is_rejected() {
        let router = build_router(test_state().await);
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .header(header::AUTHORIZATION, "Bearer rpx_not-a-real-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_revoked_api_token_can_no_longer_authenticate() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let create_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tokens")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(r#"{"name":"short-lived"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let created = body_json(create_resp).await;
        let token = created["token"].as_str().unwrap().to_string();
        let id = created["id"].as_str().unwrap().to_string();

        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/tokens/{id}"))
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/dashboard")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn listed_tokens_never_include_the_plaintext_or_hash() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tokens")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(r#"{"name":"ci pipeline"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let list_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/tokens")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(list_resp).await;
        let entry = &json.as_array().unwrap()[0];
        assert_eq!(entry["name"], "ci pipeline");
        assert!(entry.get("token").is_none());
        assert!(entry.get("token_hash").is_none());
    }
}
