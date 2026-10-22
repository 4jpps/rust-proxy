//! `/api/hosting/*`: routed address pools and the allocations that forward
//! a public address to a customer VM. All rules live in
//! `crate::hosting::model`; these handlers only translate requests, take the
//! hosting write lock, persist (DB first, then in-memory state, same order
//! as every other mutating handler) and wake the sync loop.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use ipnet::Ipv4Net;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use super::routes::ApiError;
use crate::config::Protocol;
use crate::hosting::model::{
    self, Allocation, AllocationContext, ForwardMode, HostingError, HostingPool, PortSpec,
};
use crate::hosting::HostingStatus;
use crate::state::AppState;

impl From<HostingError> for ApiError {
    fn from(e: HostingError) -> Self {
        match e {
            HostingError::Invalid(m) => ApiError::BadRequest(m),
            HostingError::Conflict(m) => ApiError::Conflict(m),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_forward() -> ForwardMode {
    ForwardMode::All
}

/// Distinguishes a JSON field that is absent (`None`) from one explicitly
/// set to `null` (`Some(None)`), which PATCH needs to clear `vm_ip`.
fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::deserialize(d)?))
}

fn bound_ips(state: &AppState) -> HashSet<Ipv4Addr> {
    let hosts = state.hosts();
    let rules = state.port_rules();
    hosts
        .iter()
        .filter_map(|h| h.bind_ip_v4)
        .chain(rules.iter().filter_map(|r| r.bind_ip_v4))
        .collect()
}

async fn commit(
    state: &AppState,
    pools: Vec<HostingPool>,
    allocations: Vec<Allocation>,
) -> Result<(), ApiError> {
    crate::db::save_hosting(state.db(), &pools, &allocations).await?;
    state.set_hosting(pools, allocations);
    Ok(())
}

// ---------------------------------------------------------------- pools

#[derive(Serialize)]
pub struct PoolView {
    #[serde(flatten)]
    pool: HostingPool,
    usable: usize,
    allocated: usize,
    free: usize,
}

fn pool_view(pool: &HostingPool, allocations: &[Allocation]) -> PoolView {
    let usable = model::usable_addresses(pool).len();
    let allocated = allocations.iter().filter(|a| a.pool == pool.name).count();
    PoolView {
        pool: pool.clone(),
        usable,
        allocated,
        free: usable.saturating_sub(allocated),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolRequest {
    /// Required on create; on update it must match the path if given.
    #[serde(default)]
    name: Option<String>,
    cidr: Ipv4Net,
    #[serde(default)]
    description: String,
    #[serde(default)]
    reserved: Vec<Ipv4Addr>,
    #[serde(default)]
    vm_cidr: Option<Ipv4Net>,
    #[serde(default)]
    gateway: Option<Ipv4Addr>,
}

pub async fn list_pools(State(state): State<AppState>) -> Json<Vec<PoolView>> {
    let allocations = state.hosting_allocations();
    Json(
        state
            .hosting_pools()
            .iter()
            .map(|p| pool_view(p, &allocations))
            .collect(),
    )
}

pub async fn create_pool(
    State(state): State<AppState>,
    Json(req): Json<PoolRequest>,
) -> Result<(StatusCode, Json<PoolView>), ApiError> {
    let name = req
        .name
        .clone()
        .ok_or_else(|| ApiError::BadRequest("name is required".into()))?;
    let _guard = state.lock_hosting_for_write().await;
    let mut pools = (*state.hosting_pools()).clone();
    let allocations = (*state.hosting_allocations()).clone();
    if pools.iter().any(|p| p.name == name) {
        return Err(ApiError::Conflict(format!("pool '{name}' already exists")));
    }
    let pool = HostingPool {
        name,
        cidr: req.cidr,
        description: req.description,
        reserved: req.reserved,
        vm_cidr: req.vm_cidr,
        gateway: req.gateway,
    };
    model::validate_pool(&pool, &pools, &state.network().dedicated_ips)?;
    pools.push(pool.clone());
    commit(&state, pools, allocations.clone()).await?;
    Ok((StatusCode::CREATED, Json(pool_view(&pool, &allocations))))
}

pub async fn update_pool(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<PoolRequest>,
) -> Result<Json<PoolView>, ApiError> {
    if req.name.as_deref().is_some_and(|n| n != name) {
        return Err(ApiError::BadRequest(
            "a pool cannot be renamed -- create a new one and move allocations".into(),
        ));
    }
    let _guard = state.lock_hosting_for_write().await;
    let mut pools = (*state.hosting_pools()).clone();
    let allocations = (*state.hosting_allocations()).clone();
    let idx = pools
        .iter()
        .position(|p| p.name == name)
        .ok_or(ApiError::NotFound)?;
    let updated = HostingPool {
        name,
        cidr: req.cidr,
        description: req.description,
        reserved: req.reserved,
        vm_cidr: req.vm_cidr,
        gateway: req.gateway,
    };
    let others: Vec<HostingPool> = pools
        .iter()
        .filter(|p| p.name != updated.name)
        .cloned()
        .collect();
    model::validate_pool(&updated, &others, &state.network().dedicated_ips)?;

    // Every existing allocation must still be valid against the edited pool
    // (a shrunk CIDR, a newly reserved address, a different vm_cidr).
    let mut all_pools = others;
    all_pools.push(updated.clone());
    let bound = bound_ips(&state);
    for a in allocations.iter().filter(|a| a.pool == updated.name) {
        let others_alloc: Vec<Allocation> =
            allocations.iter().filter(|o| o.id != a.id).cloned().collect();
        model::validate_allocation(
            a,
            &AllocationContext {
                pool: &updated,
                all_pools: &all_pools,
                others: &others_alloc,
                dedicated: &state.network().dedicated_ips,
                bound_ips: &bound,
            },
        )
        .map_err(|e| {
            let msg = match e {
                HostingError::Invalid(m) | HostingError::Conflict(m) => m,
            };
            ApiError::Conflict(format!(
                "allocation '{}' ({}) would become invalid: {msg}",
                a.name, a.public_ip
            ))
        })?;
    }

    pools[idx] = updated.clone();
    commit(&state, pools, allocations.clone()).await?;
    Ok(Json(pool_view(&updated, &allocations)))
}

pub async fn delete_pool(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let _guard = state.lock_hosting_for_write().await;
    let mut pools = (*state.hosting_pools()).clone();
    let allocations = (*state.hosting_allocations()).clone();
    if !pools.iter().any(|p| p.name == name) {
        return Err(ApiError::NotFound);
    }
    if allocations.iter().any(|a| a.pool == name) {
        return Err(ApiError::Conflict(format!(
            "pool '{name}' still has allocations -- delete them first"
        )));
    }
    pools.retain(|p| p.name != name);
    commit(&state, pools, allocations).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------- allocations

#[derive(Serialize)]
pub struct AllocationView {
    #[serde(flatten)]
    allocation: Allocation,
    /// `reserved` (no VM yet), `active` or `disabled`.
    state: &'static str,
    /// What the VM must use as its default gateway (the pool's `gateway`).
    gateway: Option<Ipv4Addr>,
    vm_cidr: Option<Ipv4Net>,
    /// Ready-to-use network settings for building the VM; present once the
    /// allocation has a `vm_ip` inside a pool that has a `vm_cidr`.
    provision: Option<Provision>,
}

/// Everything a provisioning tool needs to configure the VM's NIC.
#[derive(Serialize)]
pub struct Provision {
    public_ip: Ipv4Addr,
    private_ip: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    netmask: Ipv4Addr,
    /// `private_ip/prefix`, e.g. `172.16.63.10/24`.
    cidr: String,
    /// Suggested hostname (the allocation name, lowercased and sanitised).
    hostname: String,
    /// Proxmox `ipconfig0` value for cloud-init.
    ipconfig0: String,
}

fn hostname_hint(name: &str) -> String {
    let h: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let h = h.trim_matches('-');
    if h.is_empty() { "vm".into() } else { h.chars().take(63).collect() }
}

fn provision_for(a: &Allocation, pool: Option<&HostingPool>) -> Option<Provision> {
    let pool = pool?;
    let (vm_ip, net) = (a.vm_ip?, pool.vm_cidr?);
    let cidr = format!("{vm_ip}/{}", net.prefix_len());
    let ipconfig0 = match pool.gateway {
        Some(gw) => format!("ip={cidr},gw={gw}"),
        None => format!("ip={cidr}"),
    };
    Some(Provision {
        public_ip: a.public_ip,
        private_ip: vm_ip,
        gateway: pool.gateway,
        netmask: net.netmask(),
        cidr,
        hostname: hostname_hint(&a.name),
        ipconfig0,
    })
}

fn allocation_view(a: &Allocation, pools: &[HostingPool]) -> AllocationView {
    let pool = pools.iter().find(|p| p.name == a.pool);
    AllocationView {
        allocation: a.clone(),
        state: a.state(),
        gateway: pool.and_then(|p| p.gateway),
        vm_cidr: pool.and_then(|p| p.vm_cidr),
        provision: provision_for(a, pool),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRequest {
    protocol: Protocol,
    port_start: u16,
    /// Defaults to `port_start` (a single port).
    #[serde(default)]
    port_end: Option<u16>,
    /// Port on the VM to translate to; defaults to keeping the public port.
    #[serde(default)]
    vm_port: Option<u16>,
    /// `IpAllow` ACLs limiting which sources may reach this port, and/or `IpBlock` ACLs refusing some.
    #[serde(default)]
    acl_ids: Vec<Uuid>,
}

fn to_specs(ports: Vec<PortRequest>) -> Vec<PortSpec> {
    ports
        .into_iter()
        .map(|p| PortSpec {
            protocol: p.protocol,
            port_start: p.port_start,
            port_end: p.port_end.unwrap_or(p.port_start),
            vm_port: p.vm_port,
            acl_ids: p.acl_ids,
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationRequest {
    /// The class: a pool name such as `standard` or `ham`. `class` is
    /// accepted as an alias.
    #[serde(alias = "class")]
    pool: String,
    /// A specific address from the pool; omitted means the lowest free one.
    #[serde(default)]
    public_ip: Option<Ipv4Addr>,
    name: String,
    #[serde(default)]
    customer: String,
    #[serde(default)]
    notes: String,
    /// Omitted: the next free address in the pool's `vm_cidr` is assigned
    /// (unless `assign_vm_ip` is false or the pool has no `vm_cidr`).
    #[serde(default)]
    vm_ip: Option<Ipv4Addr>,
    /// Set false to only reserve the public address with no VM yet.
    #[serde(default = "default_true")]
    assign_vm_ip: bool,
    #[serde(default)]
    vm_id: Option<u32>,
    #[serde(default = "default_forward")]
    forward: ForwardMode,
    #[serde(default)]
    ports: Vec<PortRequest>,
    #[serde(default = "default_true")]
    enabled: bool,
}

/// Partial update. `pool` and `public_ip` are fixed for an allocation's
/// life (an unknown field is rejected), so changing them means releasing
/// the allocation and creating a new one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationPatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    customer: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    vm_ip: Option<Option<Ipv4Addr>>,
    #[serde(default, deserialize_with = "double_option")]
    vm_id: Option<Option<u32>>,
    #[serde(default)]
    forward: Option<ForwardMode>,
    #[serde(default)]
    ports: Option<Vec<PortRequest>>,
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pool: Option<String>,
}

pub async fn list_allocations(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Json<Vec<AllocationView>> {
    let pools = state.hosting_pools();
    Json(
        state
            .hosting_allocations()
            .iter()
            .filter(|a| q.pool.as_ref().is_none_or(|p| &a.pool == p))
            .map(|a| allocation_view(a, &pools))
            .collect(),
    )
}

pub async fn get_allocation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AllocationView>, ApiError> {
    let pools = state.hosting_pools();
    let allocations = state.hosting_allocations();
    let a = allocations
        .iter()
        .find(|a| a.id == id)
        .ok_or(ApiError::NotFound)?;
    Ok(Json(allocation_view(a, &pools)))
}

pub async fn create_allocation(
    State(state): State<AppState>,
    Json(req): Json<AllocationRequest>,
) -> Result<(StatusCode, Json<AllocationView>), ApiError> {
    let _guard = state.lock_hosting_for_write().await;
    let pools = (*state.hosting_pools()).clone();
    let mut allocations = (*state.hosting_allocations()).clone();
    let pool = pools
        .iter()
        .find(|p| p.name == req.pool)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown pool '{}'", req.pool)))?;
    let public_ip = match req.public_ip {
        Some(ip) => ip,
        None => model::next_free_ip(pool, &allocations).ok_or_else(|| {
            ApiError::Conflict(format!("pool '{}' has no free addresses", pool.name))
        })?,
    };
    let vm_ip = match req.vm_ip {
        Some(ip) => Some(ip),
        None if req.assign_vm_ip && pool.vm_cidr.is_some() => {
            Some(model::next_free_vm_ip(pool, &pools, &allocations, Some(public_ip)).ok_or_else(|| {
                ApiError::Conflict(format!("pool '{}' has no free VM addresses", pool.name))
            })?)
        }
        None => None,
    };
    let allocation = Allocation {
        id: Uuid::new_v4(),
        pool: pool.name.clone(),
        public_ip,
        name: req.name,
        customer: req.customer,
        notes: req.notes,
        vm_ip,
        vm_id: req.vm_id,
        forward: req.forward,
        ports: to_specs(req.ports),
        enabled: req.enabled,
        created_at: Utc::now(),
    };
    model::validate_allocation(
        &allocation,
        &AllocationContext {
            pool,
            all_pools: &pools,
            others: &allocations,
            dedicated: &state.network().dedicated_ips,
            bound_ips: &bound_ips(&state),
        },
    )?;
    validate_port_acls(&state, &allocation).await?;
    allocations.push(allocation.clone());
    let view = allocation_view(&allocation, &pools);
    commit(&state, pools, allocations).await?;
    Ok((StatusCode::CREATED, Json(view)))
}

async fn validate_port_acls(state: &AppState, a: &Allocation) -> Result<(), ApiError> {
    for p in &a.ports {
        super::routes::validate_acl_ids(state, &p.acl_ids).await?;
    }
    Ok(())
}

pub async fn patch_allocation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(patch): Json<AllocationPatch>,
) -> Result<Json<AllocationView>, ApiError> {
    let _guard = state.lock_hosting_for_write().await;
    let pools = (*state.hosting_pools()).clone();
    let mut allocations = (*state.hosting_allocations()).clone();
    let idx = allocations
        .iter()
        .position(|a| a.id == id)
        .ok_or(ApiError::NotFound)?;
    let mut updated = allocations[idx].clone();
    if let Some(v) = patch.name {
        updated.name = v;
    }
    if let Some(v) = patch.customer {
        updated.customer = v;
    }
    if let Some(v) = patch.notes {
        updated.notes = v;
    }
    if let Some(v) = patch.vm_ip {
        updated.vm_ip = v;
    }
    if let Some(v) = patch.vm_id {
        updated.vm_id = v;
    }
    if let Some(v) = patch.forward {
        updated.forward = v;
        // Switching to "all" without saying what to do with the old port
        // list would otherwise be rejected; the list is meaningless then.
        if v == ForwardMode::All && patch.ports.is_none() {
            updated.ports.clear();
        }
    }
    if let Some(v) = patch.ports {
        updated.ports = to_specs(v);
    }
    if let Some(v) = patch.enabled {
        updated.enabled = v;
    }
    let pool = pools
        .iter()
        .find(|p| p.name == updated.pool)
        .ok_or_else(|| ApiError::Internal("allocation refers to a missing pool".into()))?;
    let others: Vec<Allocation> = allocations.iter().filter(|a| a.id != id).cloned().collect();
    // `public_ip` can't change in a patch, so the address-identity checks
    // (dedicated / already bound) were settled at creation. Re-running them
    // would lock out any allocation whose address was later added to
    // `dedicated_ips` or bound to a proxy host -- exactly what an operator
    // does to serve a site on a hosted address.
    model::validate_allocation(
        &updated,
        &AllocationContext {
            pool,
            all_pools: &pools,
            others: &others,
            dedicated: &[],
            bound_ips: &HashSet::new(),
        },
    )?;
    validate_port_acls(&state, &updated).await?;
    allocations[idx] = updated.clone();
    let view = allocation_view(&updated, &pools);
    commit(&state, pools, allocations).await?;
    Ok(Json(view))
}

pub async fn delete_allocation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let _guard = state.lock_hosting_for_write().await;
    let pools = (*state.hosting_pools()).clone();
    let mut allocations = (*state.hosting_allocations()).clone();
    let before = allocations.len();
    allocations.retain(|a| a.id != id);
    if allocations.len() == before {
        return Err(ApiError::NotFound);
    }
    commit(&state, pools, allocations).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- status

#[derive(Serialize)]
pub struct StatusView {
    #[serde(flatten)]
    status: HostingStatus,
    pool_count: usize,
    allocation_count: usize,
    pools: Vec<PoolStatus>,
}

#[derive(Serialize)]
pub struct PoolStatus {
    name: String,
    cidr: Ipv4Net,
    usable: usize,
    allocated: usize,
    free: usize,
    active: usize,
}

pub async fn status(State(state): State<AppState>) -> Json<StatusView> {
    let pools = state.hosting_pools();
    let allocations = state.hosting_allocations();
    Json(StatusView {
        status: (*state.hosting_status()).clone(),
        pool_count: pools.len(),
        allocation_count: allocations.len(),
        pools: pools
            .iter()
            .map(|p| {
                let v = pool_view(p, &allocations);
                PoolStatus {
                    name: p.name.clone(),
                    cidr: p.cidr,
                    usable: v.usable,
                    allocated: v.allocated,
                    free: v.free,
                    active: allocations
                        .iter()
                        .filter(|a| a.pool == p.name && a.is_active())
                        .count(),
                }
            })
            .collect(),
    })
}

/// Read-only live inspection of one allocation: address on `lo`, DNAT and
/// SNAT rules loaded, VM answering ping.
pub async fn check(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::hosting::CheckReport>, ApiError> {
    let allocation = state
        .hosting_allocations()
        .iter()
        .find(|a| a.id == id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    Ok(Json(crate::hosting::check_allocation(&allocation).await))
}

/// Forces a re-sync now instead of waiting for the next change or the
/// 5-minute fallback. The result shows up in `GET /api/hosting/status`.
pub async fn apply(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    state.request_hosting_sync();
    (StatusCode::ACCEPTED, Json(serde_json::json!({"queued": true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth;
    use crate::api::routes::build_router;
    use crate::config::{AcmeConfig, AdminConfig, Config, NetworkConfig};
    use axum::http::{header, Request};
    use axum::Router;
    use std::path::PathBuf;
    use tower::ServiceExt;

    async fn test_state(dedicated: Vec<std::net::IpAddr>) -> AppState {
        let cfg = Config {
            network: NetworkConfig {
                bind_ranges: vec!["204.52.221.224/27".parse().unwrap()],
                dedicated_ips: dedicated,
                dhcp_interfaces: vec![],
            },
            admin: AdminConfig {
                bind_ip_v4: Some("10.0.0.1".parse().unwrap()),
                bind_ip_v6: None,
                bind_port: 8080,
                allowed_ips: vec![],
                expose_admin_port: None,
                session_secret: Some("test-secret-key".into()),
                admin_username: Some("admin".into()),
                admin_password_hash: Some(auth::hash_password("correct-password").unwrap()),
                db_path: PathBuf::from(":memory:"),
                log_dir: None,
                client_cert_subjects: vec![],
            },
            acme: AcmeConfig {
                directory_url: "https://example.invalid/directory".into(),
                contact_email: "admin@example.com".into(),
                dns_provider: crate::config::DnsProviderKind::Cloudflare,
                dns_api_token: "token".into(),
                cert_dir: PathBuf::from("/tmp/certs"),
                account_key_path: PathBuf::from("/tmp/account.key"),
                renew_before_days: 30,
                organization: None,
                organizational_unit: None,
            },
            hosts: vec![],
            port_rules: vec![],
            client_cert_forward_token: None,
            siem: None,
            hosting: None,
        };
        let pool = crate::db::connect(&PathBuf::from(":memory:")).await.unwrap();
        AppState::new(cfg, pool, vec![], vec![], None, None, None)
    }

    async fn login(router: &Router) -> String {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        r#"{"username":"admin","password":"correct-password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
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

    async fn call(
        router: &Router,
        cookie: &str,
        method: &str,
        uri: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    const STANDARD: &str = r#"{"name":"standard","cidr":"204.52.221.224/28","vm_cidr":"172.16.63.0/24","gateway":"172.16.63.1","reserved":["204.52.221.225"]}"#;

    async fn setup(dedicated: Vec<std::net::IpAddr>) -> (AppState, Router, String) {
        let state = test_state(dedicated).await;
        let router = build_router(state.clone());
        let cookie = login(&router).await;
        (state, router, cookie)
    }

    #[tokio::test]
    async fn hosting_endpoints_require_authentication() {
        let state = test_state(vec![]).await;
        let router = build_router(state);
        for (m, uri) in [
            ("GET", "/api/hosting/pools"),
            ("POST", "/api/hosting/pools"),
            ("GET", "/api/hosting/allocations"),
            ("POST", "/api/hosting/allocations"),
            ("GET", "/api/hosting/status"),
            ("POST", "/api/hosting/apply"),
            ("POST", "/api/hosting/allocations/00000000-0000-0000-0000-000000000000/check"),
        ] {
            let resp = router
                .clone()
                .oneshot(Request::builder().method(m).uri(uri).body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{m} {uri}");
        }
    }

    #[tokio::test]
    async fn pool_lifecycle_and_validation() {
        let (state, router, cookie) = setup(vec![]).await;
        let (s, body) = call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        assert_eq!(body["usable"], 13);
        assert_eq!(body["free"], 13);

        let (s, _) = call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        assert_eq!(s, StatusCode::CONFLICT, "duplicate name");
        let (s, _) = call(&router, &cookie, "POST", "/api/hosting/pools", r#"{"name":"x","cidr":"204.52.221.232/29"}"#).await;
        assert_eq!(s, StatusCode::CONFLICT, "overlapping cidr");
        let (s, _) = call(&router, &cookie, "POST", "/api/hosting/pools", r#"{"name":"x","cidr":"10.1.0.0/28"}"#).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "private space");
        let (s, _) = call(&router, &cookie, "POST", "/api/hosting/pools", r#"{"cidr":"44.30.51.224/28"}"#).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "name required");
        let (s, _) = call(&router, &cookie, "POST", "/api/hosting/pools", r#"{"name":"x","cidr":"44.30.51.224/28","bogus":1}"#).await;
        assert!(s.is_client_error(), "unknown fields are rejected");

        let (s, list) = call(&router, &cookie, "GET", "/api/hosting/pools", "").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(state.hosting_pools().len(), 1);

        let (s, _) = call(&router, &cookie, "DELETE", "/api/hosting/pools/nope", "").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _) = call(&router, &cookie, "DELETE", "/api/hosting/pools/standard", "").await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        assert!(state.hosting_pools().is_empty());
    }

    #[tokio::test]
    async fn pool_may_not_cover_a_dedicated_ip_via_the_api() {
        let (_, router, cookie) = setup(vec!["204.52.221.230".parse().unwrap()]).await;
        let (s, body) = call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    }

    #[tokio::test]
    async fn allocate_picks_lowest_free_ip_and_reports_gateway() {
        let (state, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        let req = r#"{"pool":"standard","name":"web01","customer":"Acme","vm_ip":"172.16.63.10","vm_id":4001}"#;
        let (s, a) = call(&router, &cookie, "POST", "/api/hosting/allocations", req).await;
        assert_eq!(s, StatusCode::CREATED, "{a}");
        assert_eq!(a["public_ip"], "204.52.221.226", "225 is reserved, 224 is the network");
        assert_eq!(a["state"], "active");
        assert_eq!(a["gateway"], "172.16.63.1");
        assert_eq!(a["forward"], "all");

        let (s, b) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"web02","assign_vm_ip":false}"#).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(b["public_ip"], "204.52.221.227");
        assert_eq!(b["state"], "reserved");
        assert!(b["provision"].is_null(), "no VM address, nothing to provision");
        assert_eq!(state.hosting_allocations().len(), 2);
        assert_eq!(state.hosting_pools()[0].name, "standard");
    }

    #[tokio::test]
    async fn allocation_rejects_bad_requests() {
        let (_, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        let post = |body: &'static str| {
            let router = router.clone();
            let cookie = cookie.clone();
            async move { call(&router, &cookie, "POST", "/api/hosting/allocations", body).await }
        };
        assert_eq!(post(r#"{"pool":"nope","name":"a"}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post(r#"{"pool":"standard","name":"a","public_ip":"204.52.221.250"}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post(r#"{"pool":"standard","name":"a","public_ip":"204.52.221.239"}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post(r#"{"pool":"standard","name":"a","vm_ip":"8.8.8.8"}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post(r#"{"pool":"standard","name":"a","vm_ip":"172.16.64.5"}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post(r#"{"pool":"standard","name":"a","forward":"ports"}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post(r#"{"pool":"standard","name":"a","ports":[{"protocol":"tcp","port_start":22}]}"#).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post(r#"{"pool":"standard","name":""}"#).await.0, StatusCode::BAD_REQUEST);
        assert!(post(r#"{"pool":"standard","name":"a","unknown":true}"#).await.0.is_client_error());

        assert_eq!(post(r#"{"pool":"standard","name":"a","public_ip":"204.52.221.230","vm_ip":"172.16.63.10"}"#).await.0, StatusCode::CREATED);
        assert_eq!(post(r#"{"pool":"standard","name":"b","public_ip":"204.52.221.230"}"#).await.0, StatusCode::CONFLICT);
        assert_eq!(post(r#"{"pool":"standard","name":"c","vm_ip":"172.16.63.10"}"#).await.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn pool_exhaustion_is_a_conflict() {
        let (_, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", r#"{"name":"tiny","cidr":"204.52.221.236/30"}"#).await;
        for i in 0..2 {
            let (s, b) = call(&router, &cookie, "POST", "/api/hosting/allocations", &format!(r#"{{"pool":"tiny","name":"v{i}"}}"#)).await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
        }
        let (s, _) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"tiny","name":"v2"}"#).await;
        assert_eq!(s, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn allocation_may_not_take_an_address_a_host_binds() {
        let (state, router, cookie) = setup(vec![]).await;
        let mut rules = (*state.port_rules()).clone();
        rules.push(crate::config::PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some("204.52.221.226".parse().unwrap()),
            bind_ip_v6: None,
            port_start: 22,
            port_end: 22,
            protocol: Protocol::Tcp,
            description: String::new(),
            passthrough_target: None,
            acl_ids: vec![],
            enabled: true,
        });
        state.set_port_rules(rules);
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        let (s, _) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"a","public_ip":"204.52.221.226"}"#).await;
        assert_eq!(s, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn patch_sets_the_vm_activates_and_clears_it() {
        let (state, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        let (_, a) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"web01"}"#).await;
        let id = a["id"].as_str().unwrap().to_string();
        let uri = format!("/api/hosting/allocations/{id}");

        let (s, p) = call(&router, &cookie, "PATCH", &uri, r#"{"vm_ip":"172.16.63.20","vm_id":4002}"#).await;
        assert_eq!(s, StatusCode::OK, "{p}");
        assert_eq!(p["state"], "active");
        assert_eq!(p["name"], "web01", "untouched fields are kept");
        assert!(state.hosting_allocations()[0].is_active());

        let (s, p) = call(&router, &cookie, "PATCH", &uri, r#"{"forward":"ports","ports":[{"protocol":"tcp","port_start":22},{"protocol":"udp","port_start":20100,"port_end":20200}]}"#).await;
        assert_eq!(s, StatusCode::OK, "{p}");
        assert_eq!(p["ports"][0]["port_end"], 22);

        let (s, p) = call(&router, &cookie, "PATCH", &uri, r#"{"forward":"all"}"#).await;
        assert_eq!(s, StatusCode::OK, "{p}");
        assert_eq!(p["ports"].as_array().unwrap().len(), 0, "switching to all drops the port list");

        let (s, p) = call(&router, &cookie, "PATCH", &uri, r#"{"enabled":false}"#).await;
        assert_eq!((s, p["state"].as_str()), (StatusCode::OK, Some("disabled")));
        let (s, p) = call(&router, &cookie, "PATCH", &uri, r#"{"enabled":true,"vm_ip":null}"#).await;
        assert_eq!((s, p["state"].as_str()), (StatusCode::OK, Some("reserved")));
        assert!(state.hosting_allocations()[0].vm_ip.is_none());

        let (s, _) = call(&router, &cookie, "PATCH", &uri, r#"{"public_ip":"204.52.221.230"}"#).await;
        assert!(s.is_client_error(), "public_ip is immutable");
        let (s, _) = call(&router, &cookie, "PATCH", &uri, r#"{"vm_ip":"8.8.8.8"}"#).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = call(&router, &cookie, "PATCH", "/api/hosting/allocations/00000000-0000-0000-0000-000000000000", r#"{"enabled":true}"#).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_releases_the_address_and_unblocks_the_pool() {
        let (state, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        let (_, a) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"web01"}"#).await;
        let id = a["id"].as_str().unwrap().to_string();
        let (s, _) = call(&router, &cookie, "DELETE", "/api/hosting/pools/standard", "").await;
        assert_eq!(s, StatusCode::CONFLICT, "pool with allocations");
        let (s, _) = call(&router, &cookie, "DELETE", &format!("/api/hosting/allocations/{id}"), "").await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (s, _) = call(&router, &cookie, "DELETE", &format!("/api/hosting/allocations/{id}"), "").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(state.hosting_allocations().is_empty());
        let (_, b) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"web02"}"#).await;
        assert_eq!(b["public_ip"], "204.52.221.226", "released address is reused");
        let (s, list) = call(&router, &cookie, "GET", "/api/hosting/allocations?pool=standard", "").await;
        assert_eq!((s, list.as_array().unwrap().len()), (StatusCode::OK, 1));
        let (_, none) = call(&router, &cookie, "GET", "/api/hosting/allocations?pool=ham", "").await;
        assert_eq!(none.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn pool_edit_cannot_invalidate_existing_allocations() {
        let (_, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"a","public_ip":"204.52.221.236","vm_ip":"172.16.63.10"}"#).await;
        // Shrinking so .236 falls outside the pool.
        let (s, b) = call(&router, &cookie, "PUT", "/api/hosting/pools/standard", r#"{"cidr":"204.52.221.224/29","vm_cidr":"172.16.63.0/24","gateway":"172.16.63.1"}"#).await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}");
        // Reserving an address that is in use.
        let (s, _) = call(&router, &cookie, "PUT", "/api/hosting/pools/standard", r#"{"cidr":"204.52.221.224/28","reserved":["204.52.221.236"],"vm_cidr":"172.16.63.0/24","gateway":"172.16.63.1"}"#).await;
        assert_eq!(s, StatusCode::CONFLICT);
        // Moving the VM network away from the VM.
        let (s, _) = call(&router, &cookie, "PUT", "/api/hosting/pools/standard", r#"{"cidr":"204.52.221.224/28","vm_cidr":"172.16.64.0/24","gateway":"172.16.64.1"}"#).await;
        assert_eq!(s, StatusCode::CONFLICT);
        // A harmless edit works; renames do not.
        let (s, b) = call(&router, &cookie, "PUT", "/api/hosting/pools/standard", r#"{"cidr":"204.52.221.224/28","description":"std","vm_cidr":"172.16.63.0/24","gateway":"172.16.63.1"}"#).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["description"], "std");
        let (s, _) = call(&router, &cookie, "PUT", "/api/hosting/pools/standard", r#"{"name":"other","cidr":"204.52.221.224/28"}"#).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = call(&router, &cookie, "PUT", "/api/hosting/pools/missing", r#"{"cidr":"204.52.221.224/28"}"#).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn status_and_apply_endpoints_work_and_persistence_survives_reload() {
        let (state, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"a","vm_ip":"172.16.63.10"}"#).await;
        let (s, st) = call(&router, &cookie, "GET", "/api/hosting/status", "").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!((st["pool_count"].as_u64(), st["allocation_count"].as_u64()), (Some(1), Some(1)));
        let (s, b) = call(&router, &cookie, "POST", "/api/hosting/apply", "").await;
        assert_eq!((s, b["queued"].as_bool()), (StatusCode::ACCEPTED, Some(true)));

        // What the API wrote is what a restart would load.
        let pools = crate::db::load_hosting_pools(state.db()).await.unwrap();
        let allocs = crate::db::load_hosting_allocations(state.db()).await.unwrap();
        assert_eq!(pools.len(), 1);
        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].vm_ip, Some("172.16.63.10".parse().unwrap()));
    }

    #[tokio::test]
    async fn create_auto_assigns_vm_ip_and_returns_provision() {
        let (_, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        let (s, a) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"class":"standard","name":"My Web_01"}"#).await;
        assert_eq!(s, StatusCode::CREATED, "{a}");
        assert_eq!(a["pool"], "standard", "`class` is an alias for `pool`");
        assert_eq!(a["state"], "active");
        assert_eq!(a["vm_ip"], "172.16.63.226", "private last octet matches the public address");
        let p = &a["provision"];
        assert_eq!(p["public_ip"], "204.52.221.226");
        assert_eq!(p["private_ip"], "172.16.63.226");
        assert_eq!(p["gateway"], "172.16.63.1");
        assert_eq!(p["netmask"], "255.255.255.0");
        assert_eq!(p["cidr"], "172.16.63.226/24");
        assert_eq!(p["hostname"], "my-web-01");
        assert_eq!(p["ipconfig0"], "ip=172.16.63.226/24,gw=172.16.63.1");

        let (_, b) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"b"}"#).await;
        assert_eq!(b["vm_ip"], "172.16.63.227", "each VM gets its own private address");

        let (s, _) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","class":"standard","name":"c"}"#).await;
        assert!(s.is_client_error(), "pool and class together is ambiguous");

        let (_, g) = call(&router, &cookie, "GET", &format!("/api/hosting/allocations/{}", a["id"].as_str().unwrap()), "").await;
        assert_eq!(g["provision"]["private_ip"], "172.16.63.226", "GET carries provision too");
    }

    #[tokio::test]
    async fn pool_without_vm_cidr_reserves_only() {
        let (_, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", r#"{"name":"ham","cidr":"44.30.51.224/28"}"#).await;
        let (s, a) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"ham","name":"w1aw"}"#).await;
        assert_eq!(s, StatusCode::CREATED, "{a}");
        assert_eq!(a["state"], "reserved");
        assert!(a["vm_ip"].is_null());
    }

    #[tokio::test]
    async fn status_lists_per_pool_usage() {
        let (_, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", r#"{"name":"ham","cidr":"44.30.51.224/28"}"#).await;
        call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"a"}"#).await;
        call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"b","assign_vm_ip":false}"#).await;
        let (_, st) = call(&router, &cookie, "GET", "/api/hosting/status", "").await;
        let pools = st["pools"].as_array().unwrap();
        assert_eq!(pools.len(), 2);
        let std = pools.iter().find(|p| p["name"] == "standard").unwrap();
        assert_eq!(std["cidr"], "204.52.221.224/28");
        assert_eq!((std["usable"].as_u64(), std["allocated"].as_u64(), std["free"].as_u64(), std["active"].as_u64()), (Some(13), Some(2), Some(11), Some(1)));
        let ham = pools.iter().find(|p| p["name"] == "ham").unwrap();
        assert_eq!((ham["allocated"].as_u64(), ham["free"].as_u64()), (Some(0), Some(14)));
        assert_eq!(st["allocation_count"], 2);
        assert!(st["ok"].is_boolean() && st["inert"].is_boolean());
    }

    #[tokio::test]
    async fn check_endpoint_reports_per_item_results() {
        let (_, router, cookie) = setup(vec![]).await;
        call(&router, &cookie, "POST", "/api/hosting/pools", STANDARD).await;
        let (_, a) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"a"}"#).await;
        let (_, r) = call(&router, &cookie, "POST", "/api/hosting/allocations", r#"{"pool":"standard","name":"r","assign_vm_ip":false}"#).await;

        // Nothing has been applied in the test environment, so a live check
        // of an active allocation must come back not-ok, item by item.
        let uri = format!("/api/hosting/allocations/{}/check", a["id"].as_str().unwrap());
        let (s, c) = call(&router, &cookie, "POST", &uri, "").await;
        assert_eq!(s, StatusCode::OK, "{c}");
        assert_eq!(c["ok"], false);
        assert_eq!(c["state"], "active");
        let names: Vec<&str> = c["checks"].as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["active", "address_on_lo", "dnat_rule", "snat_rule", "vm_reachable"]);

        let uri = format!("/api/hosting/allocations/{}/check", r["id"].as_str().unwrap());
        let (s, c) = call(&router, &cookie, "POST", &uri, "").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(c["ok"], false);
        assert_eq!(c["checks"].as_array().unwrap().len(), 1);

        let (s, _) = call(&router, &cookie, "POST", &format!("/api/hosting/allocations/{}/check", uuid::Uuid::new_v4()), "").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
}
