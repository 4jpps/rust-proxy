//! TOML configuration: static daemon settings (network, admin, ACME) loaded
//! once at startup. Proxy hosts and port rules also parse here for the
//! initial load, but after startup they're mutated through the admin API
//! and persisted to sqlite -- see `state.rs`.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("{0}")]
    Validation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub admin: AdminConfig,
    pub acme: AcmeConfig,
    #[serde(default)]
    pub hosts: Vec<ProxyHost>,
    #[serde(default)]
    pub port_rules: Vec<PortRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// IP ranges every `bind_ip` (admin UI, a host, or a port rule) must
    /// fall inside. Empty (the default) means unrestricted -- bind to
    /// whatever address the environment actually has: a single
    /// dedicated IP, a full LXC /29 block, several disjoint ranges,
    /// whatever's available. Populating this is opt-in hardening for
    /// anyone who *does* know their exact range ahead of time (e.g. a
    /// dedicated LXC subnet) and wants a bind_ip typo caught at
    /// config-validation time instead of silently failing to bind at
    /// runtime -- not something every deployment needs to think about.
    #[serde(default)]
    pub bind_ranges: Vec<Ipv4Net>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub bind_ip: Ipv4Addr,
    pub bind_port: u16,
    /// IPs/CIDRs allowed to reach the admin UI/API. Enforced both at the
    /// application layer and mirrored into the nftables default-DROP
    /// posture (see `nftables`).
    #[serde(default)]
    pub allowed_ips: Vec<Ipv4Net>,
    /// HMAC key signing admin session tokens. Required, no default --
    /// same "refuse to start rather than guess a secret" stance as
    /// jpps-store's ACCOUNT_SECRET.
    pub session_secret: String,
    pub admin_username: String,
    /// Argon2 PHC hash string (`argon2::password_hash`), never a plaintext
    /// password -- generate with `rust-proxy hash-password` (see main.rs).
    pub admin_password_hash: String,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/etc/rust-proxy/rust-proxy.db")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProviderKind {
    Cloudflare,
    DigitalOcean,
    Hetzner,
}

impl Default for DnsProviderKind {
    /// Matches the original Cloudflare-only behavior for anyone upgrading
    /// an existing config.toml that predates `dns_provider` -- an absent
    /// field must not silently switch providers out from under a live
    /// deployment.
    fn default() -> Self {
        Self::Cloudflare
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    pub contact_email: String,
    #[serde(default)]
    pub dns_provider: DnsProviderKind,
    /// API token for whichever `dns_provider` is selected -- a Cloudflare
    /// API token with Zone:DNS:Edit, a DigitalOcean personal access
    /// token, or a Hetzner DNS API token. All three providers use a
    /// single bearer/header token, so one field covers all of them
    /// instead of a per-provider config block.
    pub dns_api_token: String,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    #[serde(default = "default_account_key_path")]
    pub account_key_path: PathBuf,
    /// Renew when fewer than this many days remain before expiry.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: i64,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
fn default_cert_dir() -> PathBuf {
    PathBuf::from("/etc/rust-proxy/certs")
}
fn default_account_key_path() -> PathBuf {
    PathBuf::from("/etc/rust-proxy/acme-account.key")
}
fn default_renew_before_days() -> i64 {
    30
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHost {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub domain: String,
    pub bind_ip: Ipv4Addr,
    #[serde(default = "default_https_port")]
    pub bind_port: u16,
    /// `host:port` of the upstream this domain proxies to.
    pub upstream: String,
    #[serde(default)]
    pub websockets: bool,
    #[serde(default = "default_true")]
    pub force_https: bool,
    #[serde(default = "default_true")]
    pub acme_enabled: bool,
    /// Which ACME challenge type to use -- see `acme::resolve_challenge_type`
    /// for how `Auto` actually resolves (wildcard domains always get
    /// dns-01 regardless of this setting; CAs never offer http-01 for
    /// them).
    #[serde(default)]
    pub acme_challenge_type: AcmeChallengeType,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_https_port() -> u16 {
    443
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeChallengeType {
    /// http-01 for a plain domain with `force_https` (no DNS provider
    /// credentials needed -- the common case), dns-01 for a wildcard
    /// domain or a plain domain without `force_https` (http-01 needs
    /// port 80 reachable, which nothing opens without it).
    Auto,
    Http01,
    Dns01,
}

impl Default for AcmeChallengeType {
    fn default() -> Self {
        Self::Auto
    }
}

/// `*.` leading label, same shape `validate_domain` already accepts --
/// shared here since both config validation and ACME challenge-type
/// resolution (`acme::resolve_challenge_type`) need to recognize a
/// wildcard domain.
pub fn is_wildcard_domain(domain: &str) -> bool {
    domain.starts_with("*.")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRule {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub bind_ip: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
    pub protocol: Protocol,
    #[serde(default)]
    pub description: String,
    /// `Some("host:port")` forwards traffic there (TCP/UDP passthrough).
    /// `None` just opens the firewall for a service already listening
    /// locally on that port (e.g. sshd).
    #[serde(default)]
    pub passthrough_target: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl PortRule {
    pub fn is_range(&self) -> bool {
        self.port_end != self.port_start
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
        let cfg: Config = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_bind_ip(&self.network.bind_ranges, self.admin.bind_ip, "admin")?;
        if self.admin.session_secret.trim().is_empty() {
            return Err(ConfigError::Validation("admin.session_secret must not be empty".into()));
        }
        if self.admin.admin_username.trim().is_empty() {
            return Err(ConfigError::Validation("admin.admin_username must not be empty".into()));
        }
        if self.admin.admin_password_hash.trim().is_empty() {
            return Err(ConfigError::Validation("admin.admin_password_hash must not be empty".into()));
        }

        // `seen_socket_binds` tracks exclusive claims on a raw (ip, port,
        // protocol) socket -- a host implicitly claims one for TCP, and a
        // port_rule claims one explicitly. Multiple *hosts* are allowed to
        // share the same socket key (SNI-based virtual hosting on one
        // listener), so that check is separate: `seen_host_domains` only
        // rejects the same domain appearing twice on the same bind.
        let mut seen_socket_binds: Vec<(Ipv4Addr, u16, Protocol)> = Vec::new();
        let mut seen_host_domains: Vec<(Ipv4Addr, u16, String)> = Vec::new();

        for host in &self.hosts {
            validate_bind_ip(&self.network.bind_ranges, host.bind_ip, "hosts")?;
            validate_port(host.bind_port, "hosts.bind_port")?;
            validate_domain(&host.domain)?;
            if host.upstream.trim().is_empty() || !host.upstream.contains(':') {
                return Err(ConfigError::Validation(format!(
                    "hosts entry for {} has an invalid upstream (expected host:port)",
                    host.domain
                )));
            }

            let domain_key = (host.bind_ip, host.bind_port, host.domain.to_ascii_lowercase());
            if seen_host_domains.contains(&domain_key) {
                return Err(ConfigError::Validation(format!(
                    "duplicate host {} on {}:{}",
                    host.domain, host.bind_ip, host.bind_port
                )));
            }
            seen_host_domains.push(domain_key);

            let socket_key = (host.bind_ip, host.bind_port, Protocol::Tcp);
            if !seen_socket_binds.contains(&socket_key) {
                seen_socket_binds.push(socket_key);
            }
        }

        for rule in &self.port_rules {
            validate_bind_ip(&self.network.bind_ranges, rule.bind_ip, "port_rules")?;
            validate_port(rule.port_start, "port_rules.port_start")?;
            validate_port(rule.port_end, "port_rules.port_end")?;
            if rule.port_start > rule.port_end {
                return Err(ConfigError::Validation(format!(
                    "port_rules entry has port_start {} > port_end {}",
                    rule.port_start, rule.port_end
                )));
            }
            for port in rule.port_start..=rule.port_end {
                let key = (rule.bind_ip, port, rule.protocol);
                if seen_socket_binds.contains(&key) {
                    return Err(ConfigError::Validation(format!(
                        "port_rules entry conflicts with an existing bind at {}:{}/{:?}",
                        rule.bind_ip, port, rule.protocol
                    )));
                }
                seen_socket_binds.push(key);
            }
        }

        Ok(())
    }
}

/// Empty domains are rejected outright; `*.` is only accepted as a single
/// leading label (matching real X.509 wildcard cert semantics -- one
/// level of subdomain, never `foo.*.bar` or `*foo.com`).
pub(crate) fn validate_domain(domain: &str) -> Result<(), ConfigError> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Validation("hosts entry has an empty domain".into()));
    }
    match trimmed.strip_prefix("*.") {
        Some(rest) if rest.is_empty() || rest.contains('*') => Err(ConfigError::Validation(format!(
            "invalid wildcard domain \"{domain}\" -- must be \"*.\" followed by a real domain"
        ))),
        Some(_) => Ok(()),
        None if trimmed.contains('*') => Err(ConfigError::Validation(format!(
            "invalid domain \"{domain}\" -- \"*\" is only allowed as a single leading \"*.\" label"
        ))),
        None => Ok(()),
    }
}

pub(crate) fn validate_bind_ip(allowed: &[Ipv4Net], ip: Ipv4Addr, ctx: &str) -> Result<(), ConfigError> {
    if allowed.is_empty() {
        // Unrestricted -- no configured ranges to check against.
        return Ok(());
    }
    if !allowed.iter().any(|net| net.contains(&ip)) {
        let ranges = allowed.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
        return Err(ConfigError::Validation(format!(
            "{ctx} bind_ip {ip} is not inside any of network.bind_ranges ({ranges})"
        )));
    }
    Ok(())
}

fn validate_port(port: u16, ctx: &str) -> Result<(), ConfigError> {
    if port == 0 {
        return Err(ConfigError::Validation(format!("{ctx} must not be 0")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_toml() -> String {
        r#"
[network]
bind_ranges = ["10.0.0.0/29"]

[admin]
bind_ip = "10.0.0.1"
bind_port = 8080
session_secret = "test-secret-do-not-use-in-prod"
admin_username = "admin"
admin_password_hash = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g"

[acme]
contact_email = "admin@example.com"
dns_api_token = "token-placeholder"
"#
        .to_string()
    }

    #[test]
    fn parses_minimal_valid_config() {
        let cfg: Config = toml::from_str(&base_toml()).expect("should parse");
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.acme.directory_url, "https://acme-v02.api.letsencrypt.org/directory");
        assert_eq!(cfg.acme.renew_before_days, 30);
    }

    #[test]
    fn rejects_admin_bind_ip_outside_subnet() {
        let mut toml_str = base_toml();
        toml_str = toml_str.replace("10.0.0.1", "10.0.0.9");
        let cfg: Config = toml::from_str(&toml_str).expect("should parse");
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn rejects_empty_session_secret() {
        let toml_str = base_toml().replace("test-secret-do-not-use-in-prod", "");
        let cfg: Config = toml::from_str(&toml_str).expect("should parse");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_cidr_at_parse_time() {
        let toml_str = base_toml().replace("10.0.0.0/29", "not-a-cidr");
        let result: Result<Config, _> = toml::from_str(&toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn empty_bind_ranges_means_unrestricted() {
        // The flexible default: no configured ranges at all means any
        // bind_ip is accepted, for environments that don't have (or
        // don't want to think about) a dedicated block up front.
        let toml_str = base_toml().replace(r#"bind_ranges = ["10.0.0.0/29"]"#, "").replace("10.0.0.1", "203.0.113.7");
        let mut cfg: Config = toml::from_str(&toml_str).expect("should parse");
        assert!(cfg.network.bind_ranges.is_empty());
        assert!(cfg.validate().is_ok());

        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip: "198.51.100.9".parse().unwrap(),
            bind_port: 443,
            upstream: "127.0.0.1:9000".into(),
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            enabled: true,
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn bind_ranges_may_be_multiple_disjoint_ranges() {
        let toml_str = base_toml().replace(r#"bind_ranges = ["10.0.0.0/29"]"#, r#"bind_ranges = ["10.0.0.0/29", "192.168.1.0/24"]"#);
        let mut cfg: Config = toml::from_str(&toml_str).expect("should parse");
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip: "192.168.1.50".parse().unwrap(),
            bind_port: 443,
            upstream: "127.0.0.1:9000".into(),
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            enabled: true,
        });
        assert!(cfg.validate().is_ok(), "bind_ip in the second range should be accepted");
    }

    #[test]
    fn rejects_host_bind_ip_outside_subnet() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip: "192.168.1.5".parse().unwrap(),
            bind_port: 443,
            upstream: "127.0.0.1:8000".into(),
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            enabled: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_host_with_malformed_upstream() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip: "10.0.0.2".parse().unwrap(),
            bind_port: 443,
            upstream: "no-port-here".into(),
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            enabled: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_port_rule_with_start_after_end() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip: "10.0.0.4".parse().unwrap(),
            port_start: 21119,
            port_end: 21115,
            protocol: Protocol::Tcp,
            description: "rustdesk".into(),
            passthrough_target: None,
            enabled: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_port_rule_with_zero_port() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip: "10.0.0.4".parse().unwrap(),
            port_start: 0,
            port_end: 0,
            protocol: Protocol::Udp,
            description: "bogus".into(),
            passthrough_target: None,
            enabled: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_valid_port_range_for_rustdesk() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip: "10.0.0.4".parse().unwrap(),
            port_start: 21115,
            port_end: 21119,
            protocol: Protocol::Tcp,
            description: "rustdesk tcp".into(),
            passthrough_target: None,
            enabled: true,
        });
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip: "10.0.0.4".parse().unwrap(),
            port_start: 21116,
            port_end: 21116,
            protocol: Protocol::Udp,
            description: "rustdesk udp".into(),
            passthrough_target: None,
            enabled: true,
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_duplicate_bind_across_hosts() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        for _ in 0..2 {
            cfg.hosts.push(ProxyHost {
                id: Uuid::new_v4(),
                domain: "dup.example.com".into(),
                bind_ip: "10.0.0.2".parse().unwrap(),
                bind_port: 443,
                upstream: "127.0.0.1:9000".into(),
                websockets: false,
                force_https: true,
                acme_enabled: true,
                acme_challenge_type: crate::config::AcmeChallengeType::Auto,
                enabled: true,
            });
        }
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn different_domains_may_share_one_bind_via_sni() {
        // This is the whole point of SNI-based virtual hosting -- two
        // *different* hostnames on the same ip:port must be allowed, only
        // the exact same hostname twice should be rejected.
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        for domain in ["a.example.com", "b.example.com"] {
            cfg.hosts.push(ProxyHost {
                id: Uuid::new_v4(),
                domain: domain.into(),
                bind_ip: "10.0.0.2".parse().unwrap(),
                bind_port: 443,
                upstream: "127.0.0.1:9000".into(),
                websockets: false,
                force_https: true,
                acme_enabled: true,
                acme_challenge_type: crate::config::AcmeChallengeType::Auto,
                enabled: true,
            });
        }
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn port_rule_conflicting_with_an_existing_host_bind_is_rejected() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip: "10.0.0.2".parse().unwrap(),
            bind_port: 443,
            upstream: "127.0.0.1:9000".into(),
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            enabled: true,
        });
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip: "10.0.0.2".parse().unwrap(),
            port_start: 443,
            port_end: 443,
            protocol: Protocol::Tcp,
            description: "conflicting raw passthrough".into(),
            passthrough_target: Some("127.0.0.1:1".into()),
            enabled: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_a_wildcard_domain() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "*.pages.example.com".into(),
            bind_ip: "10.0.0.2".parse().unwrap(),
            bind_port: 443,
            upstream: "127.0.0.1:9000".into(),
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            enabled: true,
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_a_bare_wildcard_with_nothing_after_it() {
        assert!(validate_domain("*.").is_err());
        assert!(validate_domain("*").is_err());
    }

    #[test]
    fn rejects_a_wildcard_that_is_not_a_single_leading_label() {
        assert!(validate_domain("foo.*.example.com").is_err());
        assert!(validate_domain("*foo.example.com").is_err());
        assert!(validate_domain("foo.*").is_err());
    }

    #[test]
    fn accepts_an_ordinary_non_wildcard_domain() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("*.example.com").is_ok());
    }
}
