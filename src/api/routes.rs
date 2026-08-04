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
        .route("/api/certs", get(list_certs).post(upload_cert))
        .route("/api/certs/:domain", axum::routing::delete(delete_cert))
        .route("/api/tokens", get(list_api_tokens).post(create_api_token))
        .route("/api/tokens/:id", axum::routing::delete(delete_api_token))
        .route("/api/dns-credentials", get(list_dns_credentials).post(create_dns_credential))
        .route("/api/dns-credentials/:id", axum::routing::delete(delete_dns_credential))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_admin));

    Router::new()
        .route("/", get(admin_ui))
        .route("/api/setup-status", get(setup_status))
        .route("/api/setup", post(setup))
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
    let Some(identity) = state.admin_identity() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let session_ok = cookies
        .get(auth::SESSION_COOKIE)
        .map(|c| c.value().to_string())
        .and_then(|t| auth::verify_session(&identity.session_secret, &t))
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
    Conflict(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
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
    let Some(identity) = state.admin_identity() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if body.username != identity.username || !auth::verify_password(&body.password, &identity.password_hash) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let token = auth::sign_session(&identity.session_secret, &body.username);
    let mut cookie = Cookie::new(auth::SESSION_COOKIE, token);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookies.add(cookie);
    StatusCode::OK.into_response()
}

#[derive(Serialize)]
struct SetupStatusResponse {
    configured: bool,
}

async fn setup_status(State(state): State<AppState>) -> Json<SetupStatusResponse> {
    Json(SetupStatusResponse {
        configured: state.admin_identity().is_some(),
    })
}

#[derive(Deserialize)]
struct SetupRequest {
    username: String,
    password: String,
    #[serde(default)]
    dns_credential: Option<CreateDnsCredentialRequest>,
}

/// Creates the admin identity on a genuinely unconfigured instance.
/// Checks the CURRENT resolved state (config.toml or DB, via
/// `admin_identity()`) at request time and refuses with 409 if an
/// identity already exists by either path -- this must never be
/// replayable against an already-configured instance to hijack it.
/// That in-memory check alone isn't race-free against two concurrent
/// `POST /api/setup` calls both racing past it (the argon2 hash below
/// alone takes 100ms+), so the actual arbiter is
/// `db::create_admin_identity_if_absent`'s atomic `INSERT ... ON
/// CONFLICT DO NOTHING` against the DB's own single-row constraint --
/// only the request that actually inserts the row gets to publish it.
async fn setup(State(state): State<AppState>, Json(body): Json<SetupRequest>) -> Result<StatusCode, ApiError> {
    if state.admin_identity().is_some() {
        return Err(ApiError::Conflict("this instance is already configured".into()));
    }
    if body.username.trim().is_empty() || body.password.is_empty() {
        return Err(ApiError::BadRequest("username and password must not be empty".into()));
    }
    let password_hash = auth::hash_password(&body.password).map_err(|e| ApiError::Internal(e.to_string()))?;
    let session_secret = generate_session_secret();
    let created = crate::db::create_admin_identity_if_absent(state.db(), &body.username, &password_hash, &session_secret).await?;
    if !created {
        return Err(ApiError::Conflict("this instance is already configured".into()));
    }
    state.set_admin_identity(crate::state::AdminIdentity {
        username: body.username.clone(),
        password_hash,
        session_secret,
    });

    if let Some(cred) = body.dns_credential {
        let name = cred.name.trim();
        if !name.is_empty() && !cred.token.trim().is_empty() && !crate::db::dns_credential_name_exists(state.db(), name).await? {
            crate::db::create_dns_credential(state.db(), Uuid::new_v4(), name, cred.provider, &cred.token, chrono::Utc::now()).await?;
        }
    }
    Ok(StatusCode::CREATED)
}

/// 32 bytes of real randomness, hex-encoded -- same strength as the
/// `openssl rand -hex 32` convention the README documents for the
/// config.toml path, generated with the `rand` crate (already a
/// dependency), never hand-rolled.
fn generate_session_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    /// Required unless `redirect` is set, in which case it's ignored and
    /// may be omitted entirely.
    #[serde(default)]
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
    /// `None` means no login gate (see `proxy::login`). `password` is
    /// plaintext, hashed server-side (`build_host_login`) before it ever
    /// reaches sqlite -- same as the admin account's own password, never
    /// stored raw.
    #[serde(default)]
    access_login: Option<HostLoginRequest>,
    #[serde(default)]
    dns_credential_id: Option<Uuid>,
    /// When set, this host redirects instead of proxying -- see
    /// `config::RedirectTarget`. No password/hashing involved, so this
    /// is deserialized straight from the request with no separate DTO.
    #[serde(default)]
    redirect: Option<crate::config::RedirectTarget>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Deserialize)]
struct HostLoginRequest {
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
    match &req.redirect {
        Some(redirect) => crate::config::validate_redirect_target(&redirect.target).map_err(|e| ApiError::BadRequest(e.to_string()))?,
        None => {
            if !req.upstream.contains(':') {
                return Err(ApiError::BadRequest("upstream must be host:port".into()));
            }
        }
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
/// own) into a storable `HostAuth` -- `None` in means no login gate for
/// this host, same as leaving `access_login` out of the request
/// entirely.
fn build_host_login(req: &Option<HostLoginRequest>) -> Result<Option<crate::config::HostAuth>, ApiError> {
    let Some(req) = req else { return Ok(None) };
    if req.username.trim().is_empty() || req.password.is_empty() {
        return Err(ApiError::BadRequest("access_login requires a non-empty username and password".into()));
    }
    let password_hash = auth::hash_password(&req.password).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Some(crate::config::HostAuth {
        username: req.username.clone(),
        password_hash,
    }))
}

async fn create_host(State(state): State<AppState>, Json(body): Json<HostRequest>) -> Result<Json<ProxyHost>, ApiError> {
    validate_host_request(&state, &body)?;
    let access_allow_ips = parse_access_allow_ips(&body.access_allow_ips)?;
    let access_login = build_host_login(&body.access_login)?;
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
        access_login,
        dns_credential_id: body.dns_credential_id,
        redirect: body.redirect,
        enabled: body.enabled,
    };
    validate_dns_credential_choice(&state, &host).await?;
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
    let access_login = build_host_login(&body.access_login)?;
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
        access_login,
        dns_credential_id: body.dns_credential_id,
        redirect: body.redirect,
        enabled: body.enabled,
    };
    validate_dns_credential_choice(&state, &updated).await?;
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

#[derive(Deserialize)]
struct UploadCertRequest {
    domain: String,
    /// Full chain PEM (leaf + any intermediates), same shape ACME
    /// downloads -- see `acme::cert::build_cert_entry`.
    fullchain_pem: String,
    private_key_pem: String,
}

/// Publishes a manually-provided cert/key pair for `domain`, bypassing
/// ACME entirely -- e.g. an internal CA's cert, or a wildcard bought
/// elsewhere. Guarded against the obvious footgun: if a configured host
/// for this domain still has `acme_enabled = true`, the next renewal
/// check would otherwise silently overwrite this cert with an
/// ACME-issued one.
async fn upload_cert(State(state): State<AppState>, Json(body): Json<UploadCertRequest>) -> Result<Json<CertSummary>, ApiError> {
    let domain = body.domain.trim().to_string();
    crate::config::validate_domain(&domain).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if state.hosts().iter().any(|h| h.domain.eq_ignore_ascii_case(&domain) && h.acme_enabled) {
        return Err(ApiError::BadRequest(format!(
            "a host for {domain} still has acme_enabled=true -- disable ACME for it first, otherwise the next renewal check will overwrite this custom certificate"
        )));
    }
    let entry = crate::acme::cert::build_cert_entry(&body.fullchain_pem, &body.private_key_pem).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    crate::acme::persist_cert_files(&state.acme().cert_dir, &domain, &body.fullchain_pem, &body.private_key_pem)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let not_after = entry.not_after;
    state.upsert_cert(domain.clone(), entry);
    Ok(Json(CertSummary {
        domain,
        not_after,
        days_remaining: (not_after - chrono::Utc::now()).num_days(),
    }))
}

async fn delete_cert(State(state): State<AppState>, Path(domain): Path<String>) -> Result<StatusCode, ApiError> {
    if !state.remove_cert(&domain) {
        return Err(ApiError::NotFound);
    }
    // Best-effort -- the in-memory map (already cleared above) is what
    // actually controls whether this domain is servable; a stale/
    // unremovable directory on disk is untidy but not unsafe.
    let _ = std::fs::remove_dir_all(state.acme().cert_dir.join(&domain));
    Ok(StatusCode::NO_CONTENT)
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

#[derive(Serialize)]
struct DnsCredentialSummary {
    id: Uuid,
    name: String,
    provider: crate::config::DnsProviderKind,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct CreateDnsCredentialRequest {
    name: String,
    provider: crate::config::DnsProviderKind,
    token: String,
}

async fn list_dns_credentials(State(state): State<AppState>) -> Result<Json<Vec<DnsCredentialSummary>>, ApiError> {
    let creds = crate::db::list_dns_credentials(state.db()).await?;
    Ok(Json(
        creds
            .into_iter()
            .map(|c| DnsCredentialSummary {
                id: c.id,
                name: c.name,
                provider: c.provider,
                created_at: c.created_at,
            })
            .collect(),
    ))
}

async fn create_dns_credential(State(state): State<AppState>, Json(body): Json<CreateDnsCredentialRequest>) -> Result<Json<DnsCredentialSummary>, ApiError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }
    if body.token.trim().is_empty() {
        return Err(ApiError::BadRequest("token must not be empty".into()));
    }
    if crate::db::dns_credential_name_exists(state.db(), name).await? {
        return Err(ApiError::BadRequest(format!("a DNS credential named \"{name}\" already exists")));
    }
    let id = Uuid::new_v4();
    let created_at = chrono::Utc::now();
    crate::db::create_dns_credential(state.db(), id, name, body.provider, &body.token, created_at).await?;
    Ok(Json(DnsCredentialSummary {
        id,
        name: name.to_string(),
        provider: body.provider,
        created_at,
    }))
}

/// Refuses to delete a credential that any live host still references
/// by ID -- otherwise the reference silently dangles (deletion has no
/// FK/cascade) and that host's next renewal fails with no fallback:
/// `validate_dns_credential_choice`'s "exactly one credential means use
/// it implicitly" rule only ever applies when a host has NO explicit
/// `dns_credential_id`, so an orphaned explicit reference doesn't
/// recover even if only one credential is left afterward.
async fn delete_dns_credential(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let still_in_use = state.hosts().iter().any(|h| h.dns_credential_id == Some(id));
    if still_in_use {
        return Err(ApiError::Conflict("one or more hosts still reference this DNS credential -- repoint or delete them first".into()));
    }
    let found = crate::db::delete_dns_credential(state.db(), id).await?;
    if !found {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Rejects creating/updating a dns-01 host with no way to pick a DNS
/// credential unambiguously -- see `acme::resolve_dns_credential`'s doc
/// comment for the same "None falls back only when there's exactly one"
/// rule this mirrors, surfaced here as an immediate 400 instead of a
/// renewal-time failure discovered hours later.
async fn validate_dns_credential_choice(state: &AppState, host: &ProxyHost) -> Result<(), ApiError> {
    if crate::acme::resolve_challenge_type(host) != crate::acme::ChallengeMethod::Dns01 {
        return Ok(());
    }
    if let Some(id) = host.dns_credential_id {
        // An explicit ID must actually resolve -- a typo'd/deleted
        // credential must never be accepted here only to fail silently
        // at renewal time hours later (the whole point of this
        // function). Deliberately does NOT fall back to the
        // exactly-one-credential-exists rule below even if that would
        // resolve unambiguously: an explicit choice that no longer
        // exists is a configuration error to surface, not paper over.
        if crate::db::get_dns_credential(state.db(), id).await?.is_none() {
            return Err(ApiError::BadRequest(format!("{} references a DNS credential that no longer exists", host.domain)));
        }
        return Ok(());
    }
    let count = crate::db::list_dns_credentials(state.db()).await?.len();
    match count {
        0 => Err(ApiError::BadRequest(format!(
            "{} needs a dns-01 DNS credential but none are configured -- add one first",
            host.domain
        ))),
        1 => Ok(()),
        _ => Err(ApiError::BadRequest(format!(
            "{} needs a dns-01 DNS credential and multiple are configured -- set dns_credential_id explicitly",
            host.domain
        ))),
    }
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
                session_secret: Some("test-secret-key".into()),
                admin_username: Some("admin".into()),
                admin_password_hash: Some(auth::hash_password("correct-password").unwrap()),
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
        AppState::new(cfg, pool, vec![], vec![], None)
    }

    async fn unconfigured_test_state() -> AppState {
        let cfg = Config {
            network: NetworkConfig {
                bind_ranges: vec!["10.0.0.0/29".parse().unwrap()],
            },
            admin: AdminConfig {
                bind_ip: "10.0.0.1".parse().unwrap(),
                bind_port: 8080,
                allowed_ips: vec![],
                session_secret: None,
                admin_username: None,
                admin_password_hash: None,
                db_path: PathBuf::from(":memory:"),
            },
            acme: AcmeConfig {
                directory_url: "https://example.invalid/directory".into(),
                contact_email: "admin@example.com".into(),
                dns_provider: crate::config::DnsProviderKind::Cloudflare,
                dns_api_token: "".into(),
                cert_dir: PathBuf::from("/tmp/certs"),
                account_key_path: PathBuf::from("/tmp/account.key"),
                renew_before_days: 30,
            },
            hosts: vec![],
            port_rules: vec![],
        };
        cfg.validate().expect("valid: all three identity fields omitted together");
        let pool = crate::db::connect(&PathBuf::from(":memory:")).await.unwrap();
        AppState::new(cfg, pool, vec![], vec![], None)
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

    async fn logged_in_cookie_with(router: &Router, username: &str, password: &str) -> String {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(format!(r#"{{"username":"{username}","password":"{password}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        session_cookie_header(&resp)
    }

    #[tokio::test]
    async fn setup_status_reports_unconfigured_before_any_setup() {
        let router = build_router(unconfigured_test_state().await);
        let resp = router
            .oneshot(Request::builder().uri("/api/setup-status").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["configured"], false);
    }

    #[tokio::test]
    async fn setup_status_reports_configured_once_config_supplies_an_identity() {
        let router = build_router(test_state().await);
        let resp = router
            .oneshot(Request::builder().uri("/api/setup-status").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["configured"], true);
    }

    #[tokio::test]
    async fn setup_creates_an_admin_identity_that_can_then_log_in() {
        let router = build_router(unconfigured_test_state().await);

        let setup_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/setup")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"admin","password":"a-real-password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(setup_resp.status(), StatusCode::CREATED);

        let login_resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"admin","password":"a-real-password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn setup_cannot_be_replayed_once_the_instance_is_configured() {
        let router = build_router(unconfigured_test_state().await);

        for _ in 0..2 {
            let _ = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/setup")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(r#"{"username":"admin","password":"a-real-password"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        let second_resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/setup")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"attacker","password":"hijack"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn setup_is_refused_when_config_toml_already_supplies_an_identity() {
        let router = build_router(test_state().await);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/setup")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"attacker","password":"hijack"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn setup_rejects_an_empty_password() {
        let router = build_router(unconfigured_test_state().await);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/setup")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"admin","password":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn setup_can_optionally_create_an_initial_dns_credential() {
        let router = build_router(unconfigured_test_state().await);

        let setup_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/setup")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        r#"{"username":"admin","password":"a-real-password","dns_credential":{"name":"default","provider":"hetzner","token":"tok"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(setup_resp.status(), StatusCode::CREATED);

        let cookie = logged_in_cookie_with(&router, "admin", "a-real-password").await;
        let list_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/dns-credentials")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(list_resp).await;
        assert_eq!(json[0]["name"], "default");
    }

    #[tokio::test]
    async fn login_is_rejected_before_setup_on_an_unconfigured_instance() {
        let router = build_router(unconfigured_test_state().await);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"username":"admin","password":"anything"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
                        "access_allow_ips":["10.0.0.0/24"],"access_login":{"username":"viewer","password":"s3cret"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
        let created = body_json(create_resp).await;
        assert_eq!(created["access_allow_ips"], serde_json::json!(["10.0.0.0/24"]));
        assert_eq!(created["access_login"]["username"], "viewer");
        assert!(
            created["access_login"].get("password_hash").is_none(),
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
        assert_eq!(json[0]["access_login"]["username"], "viewer");
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
    async fn create_host_with_an_empty_login_password_is_rejected() {
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
                        "access_login":{"username":"viewer","password":""}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_dns_credential_persists_and_appears_in_the_list_without_the_token() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let create_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns-credentials")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(r#"{"name":"prod-hetzner","provider":"hetzner","token":"secret-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
        let created = body_json(create_resp).await;
        assert_eq!(created["name"], "prod-hetzner");
        assert!(created.get("token").is_none(), "the credential's secret token must never be returned, even on creation");

        let list_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/dns-credentials")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(list_resp).await;
        assert_eq!(json[0]["name"], "prod-hetzner");
        assert_eq!(json[0]["provider"], "hetzner");
        assert!(json[0].get("token").is_none());
    }

    #[tokio::test]
    async fn create_dns_credential_with_a_duplicate_name_is_rejected() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        for _ in 0..2 {
            let _ = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/dns-credentials")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, cookie.clone())
                        .body(axum::body::Body::from(r#"{"name":"dup","provider":"hetzner","token":"tok"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        let list_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/dns-credentials")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(list_resp).await;
        assert_eq!(json.as_array().unwrap().len(), 1, "the second create with a duplicate name must have been rejected, not silently duplicated");
    }

    #[tokio::test]
    async fn delete_dns_credential_removes_it_and_repeated_delete_returns_404() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let create_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns-credentials")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(r#"{"name":"prod-hetzner","provider":"hetzner","token":"secret-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let id = body_json(create_resp).await["id"].as_str().unwrap().to_string();

        let delete_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/dns-credentials/{id}"))
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

        let repeat_resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/dns-credentials/{id}"))
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(repeat_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn deleting_a_dns_credential_still_referenced_by_a_host_is_refused() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let create_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns-credentials")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(r#"{"name":"prod-hetzner","provider":"hetzner","token":"secret-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cred_id = body_json(create_resp).await["id"].as_str().unwrap().to_string();

        let host_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(format!(
                        r#"{{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000","acme_challenge_type":"dns01","dns_credential_id":"{cred_id}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(host_resp.status(), StatusCode::OK);

        let delete_resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/dns-credentials/{cred_id}"))
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_resp.status(), StatusCode::CONFLICT, "a host still points at this credential by ID");
    }

    #[tokio::test]
    async fn creating_a_dns01_host_with_a_dns_credential_id_that_does_not_exist_is_rejected() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;
        let bogus_id = uuid::Uuid::new_v4();

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(format!(
                        r#"{{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000","acme_challenge_type":"dns01","dns_credential_id":"{bogus_id}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn dns_credential_endpoints_require_authentication() {
        let router = build_router(test_state().await);
        let resp = router
            .oneshot(Request::builder().uri("/api/dns-credentials").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn creating_a_dns01_host_with_no_credential_and_none_configured_is_rejected() {
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
                        r#"{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000","acme_challenge_type":"dns01"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn creating_a_dns01_host_with_no_credential_and_exactly_one_configured_succeeds() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns-credentials")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(r#"{"name":"only-one","provider":"hetzner","token":"tok"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(
                        r#"{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000","acme_challenge_type":"dns01"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn creating_a_dns01_host_with_no_credential_and_multiple_configured_is_rejected() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        for name in ["one", "two"] {
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/dns-credentials")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, cookie.clone())
                        .body(axum::body::Body::from(format!(r#"{{"name":"{name}","provider":"hetzner","token":"tok"}}"#)))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(
                        r#"{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000","acme_challenge_type":"dns01"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn creating_an_http01_host_needs_no_dns_credential_at_all() {
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
                        r#"{"domain":"example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000","acme_challenge_type":"http01"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_redirect_host_requires_no_upstream_and_persists_the_target() {
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
                        r#"{"domain":"old.example.com","bind_ip":"10.0.0.2","bind_port":443,
                        "redirect":{"target":"https://new.example.com","preserve_path":true,"status":"permanent"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
        let created = body_json(create_resp).await;
        assert_eq!(created["redirect"]["target"], "https://new.example.com");

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
        assert_eq!(json[0]["redirect"]["target"], "https://new.example.com");
    }

    #[tokio::test]
    async fn create_redirect_host_with_a_non_absolute_target_is_rejected() {
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
                        r#"{"domain":"old.example.com","bind_ip":"10.0.0.2","bind_port":443,
                        "redirect":{"target":"new.example.com","preserve_path":true,"status":"permanent"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    fn self_signed_cert_json(domain: &str) -> serde_json::Value {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        serde_json::json!({
            "domain": domain,
            "fullchain_pem": cert.pem(),
            "private_key_pem": key_pair.serialize_pem(),
        })
    }

    #[tokio::test]
    async fn upload_cert_persists_and_appears_in_the_cert_list() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let upload_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/certs")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(serde_json::to_vec(&self_signed_cert_json("custom.example.com")).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(upload_resp.status(), StatusCode::OK);
        let created = body_json(upload_resp).await;
        assert_eq!(created["domain"], "custom.example.com");

        let list_resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/certs")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(list_resp).await;
        assert_eq!(json[0]["domain"], "custom.example.com");
    }

    #[tokio::test]
    async fn upload_cert_with_malformed_pem_is_rejected() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/certs")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(
                        r#"{"domain":"custom.example.com","fullchain_pem":"not a pem","private_key_pem":"also not a pem"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_cert_is_rejected_when_a_host_still_has_acme_enabled() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/hosts")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(
                        r#"{"domain":"custom.example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000","acme_enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/certs")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(serde_json::to_vec(&self_signed_cert_json("custom.example.com")).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_cert_removes_it_and_repeated_delete_returns_404() {
        let router = build_router(test_state().await);
        let cookie = logged_in_cookie(&router).await;

        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/certs")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::from(serde_json::to_vec(&self_signed_cert_json("custom.example.com")).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let delete_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/certs/custom.example.com")
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

        let repeat_resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/certs/custom.example.com")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(repeat_resp.status(), StatusCode::NOT_FOUND);
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
