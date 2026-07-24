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
    /// The LXC's assigned /29 (or other) subnet. Every `bind_ip` used by a
    /// host or port rule must fall inside this network.
    pub subnet: Ipv4Net,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    pub contact_email: String,
    pub cloudflare_api_token: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_https_port() -> u16 {
    443
}
fn default_true() -> bool {
    true
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
        if !self.network.subnet.contains(&self.admin.bind_ip) {
            return Err(ConfigError::Validation(format!(
                "admin.bind_ip {} is not inside network.subnet {}",
                self.admin.bind_ip, self.network.subnet
            )));
        }
        if self.admin.session_secret.trim().is_empty() {
            return Err(ConfigError::Validation("admin.session_secret must not be empty".into()));
        }

        let mut seen_binds: Vec<(Ipv4Addr, u16, Protocol)> = Vec::new();

        for host in &self.hosts {
            validate_bind_ip(&self.network.subnet, host.bind_ip, "hosts")?;
            validate_port(host.bind_port, "hosts.bind_port")?;
            if host.domain.trim().is_empty() {
                return Err(ConfigError::Validation("hosts entry has an empty domain".into()));
            }
            if host.upstream.trim().is_empty() || !host.upstream.contains(':') {
                return Err(ConfigError::Validation(format!(
                    "hosts entry for {} has an invalid upstream (expected host:port)",
                    host.domain
                )));
            }
            let key = (host.bind_ip, host.bind_port, Protocol::Tcp);
            if seen_binds.contains(&key) {
                return Err(ConfigError::Validation(format!(
                    "duplicate bind {}:{}/tcp across hosts/port_rules",
                    host.bind_ip, host.bind_port
                )));
            }
            seen_binds.push(key);
        }

        for rule in &self.port_rules {
            validate_bind_ip(&self.network.subnet, rule.bind_ip, "port_rules")?;
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
                if seen_binds.contains(&key) {
                    return Err(ConfigError::Validation(format!(
                        "duplicate bind {}:{}/{:?} across hosts/port_rules",
                        rule.bind_ip, port, rule.protocol
                    )));
                }
                seen_binds.push(key);
            }
        }

        Ok(())
    }
}

fn validate_bind_ip(subnet: &Ipv4Net, ip: Ipv4Addr, ctx: &str) -> Result<(), ConfigError> {
    if !subnet.contains(&ip) {
        return Err(ConfigError::Validation(format!(
            "{ctx} bind_ip {ip} is not inside network.subnet {subnet}"
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
subnet = "10.0.0.0/29"

[admin]
bind_ip = "10.0.0.1"
bind_port = 8080
session_secret = "test-secret-do-not-use-in-prod"

[acme]
contact_email = "admin@example.com"
cloudflare_api_token = "token-placeholder"
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
                enabled: true,
            });
        }
        assert!(cfg.validate().is_err());
    }
}
