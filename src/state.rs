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

/// The daemon's resolved admin login identity -- either straight from
/// `config.toml` (when all three of its fields are set) or from the
/// `admin_identity` DB table (set by the first-launch setup wizard).
/// See `AppState::admin_identity`'s doc comment for the precedence rule.
#[derive(Clone)]
pub struct AdminIdentity {
    pub username: String,
    pub password_hash: String,
    pub session_secret: String,
}

/// Hand-written, not derived -- `password_hash`/`session_secret` are
/// live secrets (an argon2 hash is enough to offline-crack a weak
/// password; the session secret signs every admin session) and must
/// never appear in a log line or panic message via an incidental
/// `{:?}`, matching `db::DnsCredential`'s same redaction choice.
impl std::fmt::Debug for AdminIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminIdentity")
            .field("username", &self.username)
            .field("password_hash", &"<redacted>")
            .field("session_secret", &"<redacted>")
            .finish()
    }
}

struct Inner {
    network: NetworkConfig,
    admin: AdminConfig,
    acme: AcmeConfig,
    /// See `config::Config::client_cert_forward_token`'s doc comment --
    /// config.toml-only (not exposed to the admin API/UI), since this
    /// is the actual secret an upstream verifies against, not something
    /// that should be settable through the same surface a compromised
    /// admin session could reach.
    client_cert_forward_token: Option<String>,
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
    /// The DB-sourced identity, if any -- only ever consulted by
    /// `admin_identity()` when config.toml's own three identity fields
    /// are absent. `ArcSwap` (not a plain field) because the setup
    /// wizard's `POST /api/setup` writes this at runtime, well after
    /// `AppState` is constructed, and every in-flight/future request
    /// must see the update immediately with no restart -- same
    /// lock-free-read/copy-on-write pattern as `hosts`/`port_rules`/
    /// `certs` above.
    admin_identity_db: ArcSwap<Option<AdminIdentity>>,
    /// Same "config.toml wins if set, else this DB-backed fallback"
    /// precedence and `ArcSwap` reasoning as `admin_identity_db` --
    /// `acme.contact_email` used to be config.toml-only; the admin UI's
    /// settings section can now set/change it at runtime via
    /// `set_acme_contact_email`, same as the setup wizard does for the
    /// admin identity.
    acme_contact_email_db: ArcSwap<Option<String>>,
    /// Same "config.toml wins if set, else this DB-backed fallback"
    /// precedence as `acme_contact_email_db` -- `admin.expose_admin_port`
    /// used to be config.toml-only; the admin UI's settings section can
    /// now set/change it at runtime. Defaults to `true` (mirrors the
    /// original, only-ever behavior) when neither config.toml nor the DB
    /// has ever set it.
    expose_admin_port_db: ArcSwap<bool>,
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
    pub fn new(
        cfg: Config,
        db: SqlitePool,
        hosts: Vec<ProxyHost>,
        port_rules: Vec<PortRule>,
        initial_admin_identity: Option<AdminIdentity>,
        initial_acme_contact_email: Option<String>,
        initial_expose_admin_port: Option<bool>,
    ) -> Self {
        Self(Arc::new(Inner {
            network: cfg.network,
            admin: cfg.admin,
            acme: cfg.acme,
            client_cert_forward_token: cfg.client_cert_forward_token,
            hosts: ArcSwap::from_pointee(hosts),
            port_rules: ArcSwap::from_pointee(port_rules),
            certs: ArcSwap::from_pointee(HashMap::new()),
            http01_challenges: ArcSwap::from_pointee(HashMap::new()),
            admin_identity_db: ArcSwap::from_pointee(initial_admin_identity),
            acme_contact_email_db: ArcSwap::from_pointee(initial_acme_contact_email),
            expose_admin_port_db: ArcSwap::from_pointee(initial_expose_admin_port.unwrap_or(true)),
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

    pub fn client_cert_forward_token(&self) -> Option<&str> {
        self.0.client_cert_forward_token.as_deref()
    }

    /// Resolves the admin login identity: config.toml wins outright
    /// whenever all three of its fields (`session_secret`,
    /// `admin_username`, `admin_password_hash`) are set -- checked fresh
    /// on every call, not just once at startup, per the deliberate
    /// "config.toml always wins if present" precedence. Only when
    /// config.toml omits all three does this fall back to whatever's
    /// currently in the DB-backed `ArcSwap` (`None` on an unconfigured
    /// first launch, until `set_admin_identity` is called).
    pub fn admin_identity(&self) -> Option<AdminIdentity> {
        let admin = &self.0.admin;
        if let (Some(username), Some(password_hash), Some(session_secret)) = (
            &admin.admin_username,
            &admin.admin_password_hash,
            &admin.session_secret,
        ) {
            return Some(AdminIdentity {
                username: username.clone(),
                password_hash: password_hash.clone(),
                session_secret: session_secret.clone(),
            });
        }
        (*self.0.admin_identity_db.load_full()).clone()
    }

    /// Publishes a newly-created (or updated) DB-backed admin identity,
    /// visible to every subsequent `admin_identity()` call immediately --
    /// used by the first-launch setup wizard (`POST /api/setup`). Has no
    /// effect on what `admin_identity()` returns whenever config.toml
    /// supplies its own identity (that branch is checked first, always).
    pub fn set_admin_identity(&self, identity: AdminIdentity) {
        self.0.admin_identity_db.store(Arc::new(Some(identity)));
    }

    pub fn acme(&self) -> &AcmeConfig {
        &self.0.acme
    }

    /// Resolves the contact email `acme::init_acme_client` registers the
    /// ACME account under: config.toml's `acme.contact_email` wins
    /// outright whenever it's non-empty (checked fresh on every call,
    /// same precedence rule `admin_identity` uses), otherwise whatever's
    /// currently in the DB-backed `ArcSwap` (`None` until an operator
    /// sets one via the admin UI's settings section or the setup
    /// wizard). A changed value only takes effect the next time an
    /// `AcmeClient` is built (daemon startup, or the next time
    /// `run_renewal_loop`'s init retry loop runs after an earlier
    /// failure) -- this daemon has no RFC 8555 account-contact-update
    /// call, so an already-registered, already-running client keeps
    /// using whatever email it registered with until then.
    pub fn acme_contact_email(&self) -> Option<String> {
        let configured = self.0.acme.contact_email.trim();
        if !configured.is_empty() {
            return Some(configured.to_string());
        }
        (*self.0.acme_contact_email_db.load_full()).clone()
    }

    /// Publishes a newly-set (or changed) DB-backed ACME contact email,
    /// visible to every subsequent `acme_contact_email()` call
    /// immediately -- used by the admin UI's settings section and the
    /// setup wizard's optional step. Has no effect on what
    /// `acme_contact_email()` returns whenever config.toml supplies its
    /// own non-empty `contact_email` (that branch is checked first,
    /// always).
    pub fn set_acme_contact_email(&self, email: String) {
        self.0.acme_contact_email_db.store(Arc::new(Some(email)));
    }

    /// Effective "expose the admin port via the firewall" setting --
    /// config.toml's `admin.expose_admin_port` if set, else the
    /// DB-backed value (defaulting to `true` until an operator changes
    /// it from the admin UI's settings section). Consulted by
    /// `nftables::run_sync_loop` on every sync, so a change here takes
    /// effect on the next resync, no restart needed -- unlike
    /// `acme_contact_email`, this has no "already in flight" state to
    /// worry about.
    pub fn expose_admin_port(&self) -> bool {
        self.0
            .admin
            .expose_admin_port
            .unwrap_or_else(|| *self.0.expose_admin_port_db.load_full())
    }

    /// Publishes a newly-set DB-backed value, visible to the next
    /// `expose_admin_port()` call immediately. Has no effect when
    /// config.toml already supplies `admin.expose_admin_port` (checked
    /// first, always, same precedence as `acme_contact_email`).
    pub fn set_expose_admin_port(&self, value: bool) {
        self.0.expose_admin_port_db.store(Arc::new(value));
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

    /// Wakes the same waiters `set_hosts`/`set_port_rules` do, without
    /// actually replacing either list -- for a change that isn't a
    /// host/port-rule edit itself but still needs `nftables::sync_once`
    /// to re-run, e.g. editing the IP entries of an `AclList` a port
    /// rule has selected. `sync_once` re-resolves `acl_ids` from the DB
    /// on every run, so the only piece missing without this is the
    /// prompt wakeup -- without it, the edit still applies, but only
    /// after the 5-minute `FALLBACK_RESYNC_INTERVAL` catches up.
    pub fn notify_config_change(&self) {
        self.0.config_dirty.notify_waiters();
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

    /// Removes a cert from the live map (e.g. deleting a custom-uploaded
    /// one via the admin API) -- returns whether it was present. TLS
    /// dispatch (`proxy::tls::CertResolver`) reads this same map, so the
    /// domain stops being servable the moment this returns.
    pub fn remove_cert(&self, domain: &str) -> bool {
        let mut next = (*self.0.certs.load_full()).clone();
        let existed = next.remove(domain).is_some();
        self.0.certs.store(Arc::new(next));
        existed
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
                dedicated_ips: vec![],
            },
            admin: AdminConfig {
                bind_ip_v4: Some("10.0.0.1".parse().unwrap()),
                bind_ip_v6: None,
                bind_port: 8080,
                allowed_ips: vec![],
                expose_admin_port: None,
                session_secret: Some("test-secret".into()),
                admin_username: Some("admin".into()),
                admin_password_hash: Some(
                    "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into(),
                ),
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
        }
    }

    async fn test_state() -> AppState {
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        AppState::new(test_config(), pool, vec![], vec![], None, None, None)
    }

    #[tokio::test]
    async fn hot_reload_swaps_hosts_without_replacing_state_handle() {
        let state = test_state().await;
        assert_eq!(state.hosts().len(), 0);

        state.set_hosts(vec![ProxyHost {
            id: uuid::Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: "127.0.0.1:8000".into(),
            upstream_https: false,
            upstream_tls_verify: true,
            upstream_preserve_host: true,
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: None,
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            pass_client_cert_header: false,
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
            bind_ip_v4: Some("10.0.0.4".parse().unwrap()),
            bind_ip_v6: None,
            port_start: 21115,
            port_end: 21119,
            protocol: Protocol::Tcp,
            description: "rustdesk".into(),
            passthrough_target: None,
            acl_ids: vec![],
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
        assert_eq!(
            state.get_http01_challenge("token-1"),
            Some("token-1.thumbprint".into())
        );

        state.remove_http01_challenge("token-1");
        assert_eq!(state.get_http01_challenge("token-1"), None);
    }

    #[tokio::test]
    async fn remove_cert_deletes_it_and_reports_whether_it_existed() {
        let state = test_state().await;
        assert!(!state.remove_cert("example.com"), "nothing to remove yet");

        state.upsert_cert(
            "example.com".to_string(),
            crate::proxy::tls::self_signed_entry("example.com"),
        );
        assert!(state.certs().contains_key("example.com"));

        assert!(state.remove_cert("example.com"));
        assert!(!state.certs().contains_key("example.com"));
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
                    bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
                    bind_ip_v6: None,
                    bind_port: 443,
                    upstream: "127.0.0.1:8000".into(),
                    upstream_https: false,
                    upstream_tls_verify: true,
                    upstream_preserve_host: true,
                    websockets: false,
                    force_https: true,
                    acme_enabled: true,
                    acme_challenge_type: crate::config::AcmeChallengeType::Auto,
                    acl_ids: vec![],
                    dns_credential_id: None,
                    redirect: None,
                    path_rewrite: None,
                    static_root: None,
                    rewrite_samesite_none_cookies: false,
            pass_client_cert_header: false,
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

    #[tokio::test]
    async fn admin_identity_comes_from_config_when_config_supplies_all_three_fields() {
        let state = test_state().await;
        let identity = state
            .admin_identity()
            .expect("test_config sets all three identity fields");
        assert_eq!(identity.username, "admin");
    }

    #[tokio::test]
    async fn admin_identity_is_none_when_config_omits_it_and_the_db_has_nothing_yet() {
        let mut cfg = test_config();
        cfg.admin.session_secret = None;
        cfg.admin.admin_username = None;
        cfg.admin.admin_password_hash = None;
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        let state = AppState::new(cfg, pool, vec![], vec![], None, None, None);

        assert!(state.admin_identity().is_none());
    }

    #[tokio::test]
    async fn set_admin_identity_is_visible_immediately_when_config_omits_its_own_identity() {
        let mut cfg = test_config();
        cfg.admin.session_secret = None;
        cfg.admin.admin_username = None;
        cfg.admin.admin_password_hash = None;
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        let state = AppState::new(cfg, pool, vec![], vec![], None, None, None);

        state.set_admin_identity(AdminIdentity {
            username: "wizard-admin".into(),
            password_hash: "hash".into(),
            session_secret: "secret".into(),
        });

        let identity = state.admin_identity().expect("just set it");
        assert_eq!(identity.username, "wizard-admin");
    }

    #[tokio::test]
    async fn config_supplied_identity_always_wins_even_after_set_admin_identity_is_called() {
        // The deliberate, non-default precedence choice: config.toml
        // wins on every read, not just at first boot -- calling
        // set_admin_identity (e.g. a stray leftover DB row from before
        // config.toml was populated) must never override it.
        let state = test_state().await;
        state.set_admin_identity(AdminIdentity {
            username: "db-admin".into(),
            password_hash: "hash".into(),
            session_secret: "secret".into(),
        });

        let identity = state.admin_identity().unwrap();
        assert_eq!(
            identity.username, "admin",
            "config.toml's identity must still win"
        );
    }

    async fn test_state_with_blank_contact_email() -> AppState {
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        let mut cfg = test_config();
        cfg.acme.contact_email = String::new();
        AppState::new(cfg, pool, vec![], vec![], None, None, None)
    }

    #[tokio::test]
    async fn acme_contact_email_comes_from_config_when_set() {
        let state = test_state().await; // test_config() sets a non-empty contact_email
        assert_eq!(
            state.acme_contact_email().as_deref(),
            Some("admin@example.com")
        );
    }

    #[tokio::test]
    async fn acme_contact_email_is_none_when_config_is_blank_and_the_db_has_nothing_yet() {
        let state = test_state_with_blank_contact_email().await;
        assert!(state.acme_contact_email().is_none());
    }

    #[tokio::test]
    async fn set_acme_contact_email_is_visible_immediately_when_config_is_blank() {
        let state = test_state_with_blank_contact_email().await;
        state.set_acme_contact_email("ops@example.com".into());
        assert_eq!(
            state.acme_contact_email().as_deref(),
            Some("ops@example.com")
        );
    }

    #[tokio::test]
    async fn config_supplied_contact_email_always_wins_even_after_set_acme_contact_email_is_called()
    {
        let state = test_state().await; // config's contact_email is non-empty
        state.set_acme_contact_email("db-email@example.com".into());
        assert_eq!(
            state.acme_contact_email().as_deref(),
            Some("admin@example.com"),
            "config.toml's contact_email must still win"
        );
    }

    /// Regression test for a real bug: editing an `AclList`'s IP entries
    /// (via the admin API's add/update/delete-entry endpoints) didn't
    /// wake `nftables::run_sync_loop`, which only re-runs on
    /// `set_hosts`/`set_port_rules` or the 5-minute fallback timer --
    /// even though a port rule's firewall enforcement of that ACL's IPs
    /// is resolved fresh from the DB on every sync. An operator adding
    /// an IP to an ACL a port rule (e.g. SSH) already selects would be
    /// locked out until the fallback timer happened to catch up.
    /// `notify_config_change` is the fix -- the routes that mutate an
    /// ACL's IP entries call it after a successful write.
    #[tokio::test]
    async fn notify_config_change_wakes_a_pending_wait_for_change() {
        let state = test_state().await;
        let waiter = tokio::spawn({
            let state = state.clone();
            async move { state.wait_for_change().await }
        });
        // Give the spawned task a chance to actually reach `.notified().await`
        // before we fire -- Notify only wakes waiters registered before the
        // call, same as any other tokio::sync::Notify usage.
        tokio::task::yield_now().await;
        state.notify_config_change();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("notify_config_change must wake a pending wait_for_change")
            .unwrap();
    }
}
