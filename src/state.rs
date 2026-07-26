//! Shared application state. `network`/`admin`/`acme` settings are fixed at
//! startup (changing them means a restart); `hosts`/`port_rules`/`certs`
//! are hot-reloadable -- readers (the proxy data plane, the nftables sync
//! loop) take a lock-free `Guard` via `ArcSwap::load`, writers (the admin
//! API) publish a whole new `Vec`/`HashMap` via `ArcSwap::store`. No reader
//! ever blocks a writer or another reader.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use sqlx::SqlitePool;
use tokio::sync::{Mutex, Notify};

use crate::config::{AcmeConfig, AdminConfig, Config, NetworkConfig, PortRule, ProxyHost};

/// One domain's live TLS material, ready for SNI dispatch.
#[derive(Clone, Debug)]
pub struct CertEntry {
    pub cert_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    pub private_key: Arc<rustls_pki_types::PrivateKeyDer<'static>>,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

struct Inner {
    network: NetworkConfig,
    admin: AdminConfig,
    acme: AcmeConfig,
    hosts: ArcSwap<Vec<ProxyHost>>,
    port_rules: ArcSwap<Vec<PortRule>>,
    certs: ArcSwap<HashMap<String, CertEntry>>,
    /// Pending http-01 challenges, keyed by token: `acme::issue_via_http01`
    /// publishes the key authorization here before telling the CA the
    /// challenge is ready, and `proxy::http`'s port-80 request handler
    /// reads it back to answer `/.well-known/acme-challenge/<token>`.
    /// Tokens are opaque and global (not scoped per-host), so a plain
    /// lookup by token is all serving one needs -- no host matching.
    http01_challenges: ArcSwap<HashMap<String, String>>,
    /// Fires whenever `hosts`/`port_rules` change, so `nftables::run_sync_loop`
    /// and `proxy::run`'s listener supervisor can both re-sync immediately
    /// instead of polling on a timer. `notify_waiters` (not `notify_one`)
    /// since there are two independent long-lived waiters.
    config_dirty: Notify,
    db: SqlitePool,
    /// `ArcSwap` alone makes reads lock-free but a naive read-modify-write
    /// (clone the Vec, mutate, store) from two concurrent admin API
    /// requests can still race and silently drop one write. These serialize
    /// the *write* path only -- readers (the proxy/nftables loops) are
    /// never blocked by them, since they only ever call `.load_full()`.
    hosts_write_lock: Mutex<()>,
    port_rules_write_lock: Mutex<()>,
}

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl AppState {
    /// `db` is expected to already hold whichever `hosts`/`port_rules`
    /// should be live at startup -- see `main.rs`'s "load from sqlite,
    /// seeding from config.toml only if the DB was empty" bootstrap.
    pub fn new(cfg: Config, db: SqlitePool, hosts: Vec<ProxyHost>, port_rules: Vec<PortRule>) -> Self {
        Self(Arc::new(Inner {
            network: cfg.network,
            admin: cfg.admin,
            acme: cfg.acme,
            hosts: ArcSwap::from_pointee(hosts),
            port_rules: ArcSwap::from_pointee(port_rules),
            certs: ArcSwap::from_pointee(HashMap::new()),
            http01_challenges: ArcSwap::from_pointee(HashMap::new()),
            config_dirty: Notify::new(),
            db,
            hosts_write_lock: Mutex::new(()),
            port_rules_write_lock: Mutex::new(()),
        }))
    }

    pub fn db(&self) -> &SqlitePool {
        &self.0.db
    }

    pub async fn lock_hosts_for_write(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.0.hosts_write_lock.lock().await
    }

    pub async fn lock_port_rules_for_write(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.0.port_rules_write_lock.lock().await
    }

    pub fn network(&self) -> &NetworkConfig {
        &self.0.network
    }

    pub fn admin(&self) -> &AdminConfig {
        &self.0.admin
    }

    pub fn acme(&self) -> &AcmeConfig {
        &self.0.acme
    }

    pub fn hosts(&self) -> Arc<Vec<ProxyHost>> {
        self.0.hosts.load_full()
    }

    pub fn set_hosts(&self, hosts: Vec<ProxyHost>) {
        self.0.hosts.store(Arc::new(hosts));
        self.0.config_dirty.notify_waiters();
    }

    pub fn port_rules(&self) -> Arc<Vec<PortRule>> {
        self.0.port_rules.load_full()
    }

    pub fn set_port_rules(&self, rules: Vec<PortRule>) {
        self.0.port_rules.store(Arc::new(rules));
        self.0.config_dirty.notify_waiters();
    }

    /// Resolves the next time `hosts`/`port_rules` change. Used by both
    /// `nftables::run_sync_loop` and the proxy listener supervisor to
    /// re-sync in real time instead of polling.
    pub async fn wait_for_change(&self) {
        self.0.config_dirty.notified().await;
    }

    pub fn certs(&self) -> Arc<HashMap<String, CertEntry>> {
        self.0.certs.load_full()
    }

    /// Publishes a single domain's cert, leaving every other domain's
    /// entry untouched -- copy-on-write over the whole map, same
    /// lock-free-read tradeoff as `hosts`/`port_rules`.
    pub fn upsert_cert(&self, domain: String, entry: CertEntry) {
        let mut next = (*self.0.certs.load_full()).clone();
        next.insert(domain, entry);
        self.0.certs.store(Arc::new(next));
    }

    /// Publishes an http-01 key authorization for `token`, copy-on-write
    /// like `certs`/`hosts` -- reads (every plain-HTTP request on port
    /// 80) are far more frequent than writes (once per issuance attempt).
    pub fn set_http01_challenge(&self, token: String, key_authorization: String) {
        let mut next = (*self.0.http01_challenges.load_full()).clone();
        next.insert(token, key_authorization);
        self.0.http01_challenges.store(Arc::new(next));
    }

    pub fn get_http01_challenge(&self, token: &str) -> Option<String> {
        self.0.http01_challenges.load().get(token).cloned()
    }

    pub fn remove_http01_challenge(&self, token: &str) {
        let mut next = (*self.0.http01_challenges.load_full()).clone();
        next.remove(token);
        self.0.http01_challenges.store(Arc::new(next));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeConfig, AdminConfig, NetworkConfig, Protocol};
    use std::path::PathBuf;

    fn test_config() -> Config {
        Config {
            network: NetworkConfig {
                bind_ranges: vec!["10.0.0.0/29".parse().unwrap()],
            },
            admin: AdminConfig {
                bind_ip: "10.0.0.1".parse().unwrap(),
                bind_port: 8080,
                allowed_ips: vec![],
                session_secret: "test-secret".into(),
                admin_username: "admin".into(),
                admin_password_hash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into(),
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
        }
    }

    async fn test_state() -> AppState {
        let pool = crate::db::connect(&PathBuf::from(":memory:")).await.unwrap();
        AppState::new(test_config(), pool, vec![], vec![])
    }

    #[tokio::test]
    async fn hot_reload_swaps_hosts_without_replacing_state_handle() {
        let state = test_state().await;
        assert_eq!(state.hosts().len(), 0);

        state.set_hosts(vec![ProxyHost {
            id: uuid::Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip: "10.0.0.2".parse().unwrap(),
            bind_port: 443,
            upstream: "127.0.0.1:8000".into(),
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            enabled: true,
        }]);

        assert_eq!(state.hosts().len(), 1);
        assert_eq!(state.hosts()[0].domain, "example.com");
    }

    #[tokio::test]
    async fn port_rules_are_isolated_from_hosts() {
        let state = test_state().await;
        state.set_port_rules(vec![PortRule {
            id: uuid::Uuid::new_v4(),
            bind_ip: "10.0.0.4".parse().unwrap(),
            port_start: 21115,
            port_end: 21119,
            protocol: Protocol::Tcp,
            description: "rustdesk".into(),
            passthrough_target: None,
            enabled: true,
        }]);
        assert_eq!(state.port_rules().len(), 1);
        assert_eq!(state.hosts().len(), 0);
    }

    #[tokio::test]
    async fn http01_challenge_round_trips_by_token() {
        let state = test_state().await;
        assert_eq!(state.get_http01_challenge("token-1"), None);

        state.set_http01_challenge("token-1".into(), "token-1.thumbprint".into());
        assert_eq!(state.get_http01_challenge("token-1"), Some("token-1.thumbprint".into()));

        state.remove_http01_challenge("token-1");
        assert_eq!(state.get_http01_challenge("token-1"), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_reads_and_writes_never_panic_or_deadlock() {
        let state = test_state().await;
        let mut handles = Vec::new();

        for i in 0..50 {
            let s = state.clone();
            handles.push(tokio::spawn(async move {
                s.set_hosts(vec![ProxyHost {
                    id: uuid::Uuid::new_v4(),
                    domain: format!("host-{i}.example.com"),
                    bind_ip: "10.0.0.2".parse().unwrap(),
                    bind_port: 443,
                    upstream: "127.0.0.1:8000".into(),
                    websockets: false,
                    force_https: true,
                    acme_enabled: true,
                    acme_challenge_type: crate::config::AcmeChallengeType::Auto,
                    enabled: true,
                }]);
            }));
        }
        for i in 0..50 {
            let s = state.clone();
            handles.push(tokio::spawn(async move {
                let _ = s.hosts();
                let _ = i;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Whatever the last write happened to be, exactly one host should
        // be present -- no torn/partial state visible.
        assert_eq!(state.hosts().len(), 1);
    }
}
