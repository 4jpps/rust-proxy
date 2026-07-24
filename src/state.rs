//! Shared application state. `network`/`admin`/`acme` settings are fixed at
//! startup (changing them means a restart); `hosts`/`port_rules`/`certs`
//! are hot-reloadable -- readers (the proxy data plane, the nftables sync
//! loop) take a lock-free `Guard` via `ArcSwap::load`, writers (the admin
//! API) publish a whole new `Vec`/`HashMap` via `ArcSwap::store`. No reader
//! ever blocks a writer or another reader.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::Notify;

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
    /// Fires whenever `hosts`/`port_rules` change, so `nftables::run_sync_loop`
    /// can re-sync immediately instead of polling on a timer.
    firewall_dirty: Notify,
}

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl AppState {
    pub fn new(cfg: Config) -> Self {
        Self(Arc::new(Inner {
            network: cfg.network,
            admin: cfg.admin,
            acme: cfg.acme,
            hosts: ArcSwap::from_pointee(cfg.hosts),
            port_rules: ArcSwap::from_pointee(cfg.port_rules),
            certs: ArcSwap::from_pointee(HashMap::new()),
            firewall_dirty: Notify::new(),
        }))
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
        self.0.firewall_dirty.notify_one();
    }

    pub fn port_rules(&self) -> Arc<Vec<PortRule>> {
        self.0.port_rules.load_full()
    }

    pub fn set_port_rules(&self, rules: Vec<PortRule>) {
        self.0.port_rules.store(Arc::new(rules));
        self.0.firewall_dirty.notify_one();
    }

    /// Resolves the next time `hosts`/`port_rules` change (or immediately,
    /// if a change happened since the last call and hasn't been consumed
    /// yet). Used by `nftables::run_sync_loop` to re-sync in real time
    /// instead of polling.
    pub async fn wait_for_firewall_change(&self) {
        self.0.firewall_dirty.notified().await;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeConfig, AdminConfig, NetworkConfig, Protocol};
    use std::path::PathBuf;

    fn test_config() -> Config {
        Config {
            network: NetworkConfig {
                subnet: "10.0.0.0/29".parse().unwrap(),
            },
            admin: AdminConfig {
                bind_ip: "10.0.0.1".parse().unwrap(),
                bind_port: 8080,
                allowed_ips: vec![],
                session_secret: "test-secret".into(),
            },
            acme: AcmeConfig {
                directory_url: "https://example.invalid/directory".into(),
                contact_email: "admin@example.com".into(),
                cloudflare_api_token: "token".into(),
                cert_dir: PathBuf::from("/tmp/certs"),
                account_key_path: PathBuf::from("/tmp/account.key"),
                renew_before_days: 30,
            },
            hosts: vec![],
            port_rules: vec![],
        }
    }

    #[test]
    fn hot_reload_swaps_hosts_without_replacing_state_handle() {
        let state = AppState::new(test_config());
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
            enabled: true,
        }]);

        assert_eq!(state.hosts().len(), 1);
        assert_eq!(state.hosts()[0].domain, "example.com");
    }

    #[test]
    fn port_rules_are_isolated_from_hosts() {
        let state = AppState::new(test_config());
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_reads_and_writes_never_panic_or_deadlock() {
        let state = AppState::new(test_config());
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
