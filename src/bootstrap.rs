//! Startup sequencing pulled out of `main.rs`'s `main()` -- turns "read
//! `main()` top to bottom to understand what happens at boot" into a
//! set of small, independently named, independently testable
//! functions. Each one does exactly one bootstrapping concern (seed
//! hosts/port_rules, seed the default DNS credential, resolve the
//! admin identity), so reviewing "did startup seed/load things
//! correctly" means reading one focused function with its own unit
//! tests, not tracing mutable state through one long `main()` body.
//!
//! `build_app_state` is the only thing `main.rs` actually calls --
//! everything else here exists to be individually reviewed and tested,
//! not as a wider public API.

use sqlx::SqlitePool;

use crate::config::{Config, PortRule, ProxyHost};
use crate::state::{AdminIdentity, AppState};

/// Loads hosts/port_rules from sqlite -- the source of truth after
/// first boot -- seeding them from config.toml's inline `[[hosts]]`/
/// `[[port_rules]]` entries only if the DB is still empty, so a
/// config.toml carried forward from a previous deployment never
/// silently overwrites admin-UI-managed state, but a genuinely fresh
/// DB still gets whatever config.toml shipped instead of an empty
/// dashboard.
pub async fn load_or_seed_hosts_and_port_rules(
    db_pool: &SqlitePool,
    cfg: &Config,
) -> Result<(Vec<ProxyHost>, Vec<PortRule>), sqlx::Error> {
    let mut hosts = crate::db::load_hosts(db_pool).await?;
    let mut port_rules = crate::db::load_port_rules(db_pool).await?;
    if hosts.is_empty() && !cfg.hosts.is_empty() {
        crate::db::save_hosts(db_pool, &cfg.hosts).await?;
        hosts = cfg.hosts.clone();
    }
    if port_rules.is_empty() && !cfg.port_rules.is_empty() {
        crate::db::save_port_rules(db_pool, &cfg.port_rules).await?;
        port_rules = cfg.port_rules.clone();
    }
    Ok((hosts, port_rules))
}

/// config.toml's `acme.dns_provider`/`acme.dns_api_token` (if set) seed
/// a "default" `dns_credentials` row, idempotently -- zero config.toml
/// changes needed for an existing single-provider deployment carried
/// forward from before the multi-credential DB table existed. Omitted/
/// blank `dns_api_token` means no implicit row; credentials must then
/// come from the DB (admin UI or setup wizard) instead.
pub async fn seed_default_dns_credential_if_configured(
    db_pool: &SqlitePool,
    cfg: &Config,
) -> Result<(), sqlx::Error> {
    if !cfg.acme.dns_api_token.trim().is_empty() {
        crate::db::seed_default_dns_credential(
            db_pool,
            cfg.acme.dns_provider,
            &cfg.acme.dns_api_token,
        )
        .await?;
    }
    Ok(())
}

/// Whatever admin identity the DB already has, if any -- `None` on a
/// genuinely fresh install (first-launch setup wizard territory) or
/// when config.toml supplies its own identity and the DB has never
/// been asked to store one. Note config.toml's own identity fields (if
/// set) always win over this at *read* time, on every call to
/// `AppState::admin_identity`, not just here at startup -- this
/// function only resolves what's persisted, not the final precedence.
pub async fn load_persisted_admin_identity(
    db_pool: &SqlitePool,
) -> Result<Option<AdminIdentity>, sqlx::Error> {
    let row = crate::db::load_admin_identity(db_pool).await?;
    Ok(row.map(|row| AdminIdentity {
        username: row.username,
        password_hash: row.password_hash,
        session_secret: row.session_secret,
    }))
}

/// Starts SIEM forwarding if configured (config.toml's `[siem]` wins,
/// else the DB copy). A bad or unreachable collector config must never
/// stop the proxy from starting, so failures are logged and swallowed.
async fn start_siem(state: &AppState) {
    let cfg = match state.siem_config() {
        Some(cfg) => Some(cfg.clone()),
        None => match crate::db::load_siem_settings(state.db()).await {
            Ok(cfg) => cfg,
            Err(err) => {
                tracing::error!(error = %err, "failed to load SIEM settings");
                None
            }
        },
    };
    let Some(cfg) = cfg else { return };
    match crate::siem::apply(&cfg) {
        Ok(()) if cfg.enabled => {
            tracing::info!(host = %cfg.host, port = cfg.port, protocol = ?cfg.protocol, "SIEM forwarding enabled");
            crate::siem::emit(
                crate::siem::Category::System,
                crate::siem::Severity::Notice,
                "daemon_start",
                "rust-proxy started",
                &[("version", env!("CARGO_PKG_VERSION"))],
            );
        }
        Ok(()) => {}
        Err(err) => tracing::error!(error = %err, "SIEM forwarding not started"),
    }
}

/// Full startup sequence: connect the DB, load/seed hosts, port_rules,
/// and the default DNS credential, resolve the persisted admin identity
/// and ACME contact email, build `AppState`, and load certs from disk.
/// Everything `main()` needs before it can spawn the long-running
/// service tasks.
pub async fn build_app_state(cfg: Config) -> anyhow::Result<AppState> {
    build_app_state_with(cfg, true).await
}

/// `build_app_state`, optionally without starting the SIEM forwarder --
/// `rust-proxy check` builds a throwaway state and must not open
/// outbound connections.
pub async fn build_app_state_with(cfg: Config, start_services: bool) -> anyhow::Result<AppState> {
    let db_pool = crate::db::connect(&cfg.admin.db_path).await?;

    let (hosts, port_rules) = load_or_seed_hosts_and_port_rules(&db_pool, &cfg).await?;
    seed_default_dns_credential_if_configured(&db_pool, &cfg).await?;
    let admin_identity = load_persisted_admin_identity(&db_pool).await?;
    let acme_contact_email = crate::db::load_acme_contact_email(&db_pool).await?;
    let expose_admin_port = crate::db::load_expose_admin_port(&db_pool).await?;

    let seeded = seed_hosting_pools(&cfg);
    let state = AppState::new(
        cfg,
        db_pool,
        hosts,
        port_rules,
        admin_identity,
        acme_contact_email,
        expose_admin_port,
    );
    crate::blocklist::rebuild(&state).await;
    state.set_required_client_cert_org(crate::db::load_required_org_id(state.db()).await?);
    state.set_admin_allowed_ips(crate::db::load_admin_allowed_ips(state.db()).await?);
    state.set_mobile_pass_enabled(crate::db::load_mobile_pass_enabled(state.db()).await?);
    if let Some(site) = crate::db::load_default_site(state.db()).await? {
        state.set_default_site(site);
    }
    crate::acme::load_certs_from_disk(&state)?;
    state.revocation().load_revoked().await;
    let mut hosting_pools = crate::db::load_hosting_pools(state.db()).await?;
    let hosting_allocations = crate::db::load_hosting_allocations(state.db()).await?;
    if hosting_pools.is_empty() && hosting_allocations.is_empty() && !seeded.is_empty() {
        crate::db::save_hosting(state.db(), &seeded, &[]).await?;
        tracing::info!(pools = seeded.len(), "hosting pools seeded from config");
        hosting_pools = seeded;
    }
    state.set_hosting(hosting_pools, hosting_allocations);
    if start_services {
        start_siem(&state).await;
    }
    Ok(state)
}

/// Pools from the optional `[hosting]` config section, minus any that fail
/// validation (logged and skipped, so one typo cannot block startup).
pub(crate) fn seed_hosting_pools(
    cfg: &crate::config::Config,
) -> Vec<crate::hosting::model::HostingPool> {
    let Some(seed) = &cfg.hosting else {
        return vec![];
    };
    let mut accepted: Vec<crate::hosting::model::HostingPool> = Vec::new();
    for pool in &seed.pools {
        if accepted.iter().any(|p| p.name == pool.name) {
            tracing::warn!(pool = %pool.name, "ignoring duplicate [hosting] pool name");
            continue;
        }
        match crate::hosting::model::validate_pool(pool, &accepted, &cfg.network.dedicated_ips) {
            Ok(()) => accepted.push(pool.clone()),
            Err(err) => {
                tracing::warn!(pool = %pool.name, error = ?err, "ignoring invalid [hosting] pool")
            }
        }
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    #[test]
    fn hosting_seed_keeps_valid_pools_and_skips_invalid_ones() {
        let mut cfg = test_config();
        let pool = |name: &str, cidr: &str| crate::hosting::model::HostingPool {
            name: name.into(),
            cidr: cidr.parse().unwrap(),
            description: String::new(),
            reserved: vec![],
            vm_cidr: None,
            gateway: None,
        };
        assert!(seed_hosting_pools(&cfg).is_empty(), "no [hosting] section");
        cfg.hosting = Some(crate::config::HostingSeedConfig {
            pools: vec![
                pool("standard", "204.52.221.224/28"),
                pool("ham", "44.30.51.224/28"),
                pool("overlap", "204.52.221.232/29"),
                pool("private", "10.9.0.0/28"),
                pool("standard", "198.51.100.0/28"),
            ],
        });
        let names: Vec<String> = seed_hosting_pools(&cfg)
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, ["standard", "ham"]);
    }

    fn test_config() -> Config {
        Config {
            network: crate::config::NetworkConfig {
                bind_ranges: vec![],
                dedicated_ips: vec![],
                dhcp_interfaces: vec![],
                max_connections_per_ip: crate::config::DEFAULT_MAX_CONNECTIONS_PER_IP,
            },
            admin: crate::config::AdminConfig {
                bind_ip_v4: Some(Ipv4Addr::UNSPECIFIED),
                bind_ip_v6: None,
                bind_port: 8084,
                allowed_ips: vec![],
                expose_admin_port: None,
                session_secret: None,
                admin_username: None,
                admin_password_hash: None,
                db_path: PathBuf::from(":memory:"),
                log_dir: None,
                client_cert_subjects: vec![],
            },
            acme: crate::config::AcmeConfig {
                directory_url: "https://example.invalid/directory".into(),
                contact_email: "admin@example.com".into(),
                dns_provider: crate::config::DnsProviderKind::Cloudflare,
                dns_api_token: String::new(),
                cert_dir: PathBuf::from("/tmp/rust-proxy-bootstrap-test-certs"),
                account_key_path: PathBuf::from("/tmp/rust-proxy-bootstrap-test-account.key"),
                renew_before_days: 30,
                organization: None,
                organizational_unit: None,
            },
            hosts: vec![],
            port_rules: vec![],
            client_cert_forward_token: None,
            siem: None,
            hosting: None,
        }
    }

    async fn memory_pool() -> SqlitePool {
        crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn seeds_hosts_and_port_rules_from_config_only_when_the_db_is_empty() {
        let pool = memory_pool().await;
        let mut cfg = test_config();
        cfg.hosts.push(ProxyHost {
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
            acme_enabled: false,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: None,
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            deny_fallback: None,
            locations: Vec::new(),
            block_exploits: false,
            fixed_response: None,
            hsts: false,
            hsts_subdomains: false,
            pass_client_cert_header: false,
            enabled: true,
        });

        let (hosts, _) = load_or_seed_hosts_and_port_rules(&pool, &cfg)
            .await
            .unwrap();
        assert_eq!(hosts.len(), 1, "empty DB should be seeded from config.toml");

        // Second call, DB no longer empty -- config.toml's copy must not
        // be re-applied/duplicated even though cfg.hosts is unchanged.
        let (hosts_again, _) = load_or_seed_hosts_and_port_rules(&pool, &cfg)
            .await
            .unwrap();
        assert_eq!(
            hosts_again.len(),
            1,
            "must not duplicate on a second call once the DB has real data"
        );
    }

    #[tokio::test]
    async fn seeds_the_default_dns_credential_only_when_a_token_is_configured() {
        let pool = memory_pool().await;
        let mut cfg = test_config();
        cfg.acme.dns_api_token = "  ".into(); // blank after trim
        seed_default_dns_credential_if_configured(&pool, &cfg)
            .await
            .unwrap();
        assert!(
            crate::db::list_dns_credentials(&pool)
                .await
                .unwrap()
                .is_empty(),
            "a blank token must not seed anything"
        );

        cfg.acme.dns_api_token = "real-token".into();
        seed_default_dns_credential_if_configured(&pool, &cfg)
            .await
            .unwrap();
        let creds = crate::db::list_dns_credentials(&pool).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].name, "default");
    }

    #[tokio::test]
    async fn persisted_admin_identity_is_none_before_setup_and_populated_after() {
        let pool = memory_pool().await;
        assert!(
            load_persisted_admin_identity(&pool)
                .await
                .unwrap()
                .is_none()
        );

        crate::db::create_admin_identity_if_absent(&pool, "admin", "hash", "secret")
            .await
            .unwrap();
        let identity = load_persisted_admin_identity(&pool)
            .await
            .unwrap()
            .expect("should now be present");
        assert_eq!(identity.username, "admin");
        assert_eq!(identity.password_hash, "hash");
        assert_eq!(identity.session_secret, "secret");
    }

    #[tokio::test]
    async fn build_app_state_wires_everything_together() {
        let cfg = test_config();
        let state = build_app_state(cfg)
            .await
            .expect("should build cleanly with no hosts/certs configured");
        assert_eq!(state.hosts().len(), 0);
        assert_eq!(state.port_rules().len(), 0);
        assert!(state.admin_identity().is_none());
    }
}
