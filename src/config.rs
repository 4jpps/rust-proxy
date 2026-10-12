//! TOML configuration: static daemon settings (network, admin, ACME) loaded
//! once at startup. Proxy hosts and port rules also parse here for the
//! initial load, but after startup they're mutated through the admin API
//! and persisted to sqlite -- see `state.rs`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
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
    /// A shared secret sent as `X-RustProxy-Client-Cert-Token` alongside
    /// `X-Client-Cert-Subject` on every host with
    /// `pass_client_cert_header` set -- the upstream is expected to
    /// verify this token matches before trusting the subject header at
    /// all. Exists because the subject header alone is only ever
    /// *stripped* from what an external client sends (see proxy/mod.rs)
    /// -- that's not proof the request actually came through this
    /// proxy, since anything co-located on the same host as an
    /// upstream (another container, a compromised neighbor process)
    /// could still reach it directly on its loopback/internal address
    /// and forge the header itself. `None` (the default) means the
    /// header is never sent at all, regardless of any host's
    /// `pass_client_cert_header` setting -- this feature is opt-in at
    /// the daemon level, not just per-host, specifically so it can't be
    /// half-configured into looking safe when it isn't.
    #[serde(default)]
    pub client_cert_forward_token: Option<String>,
    /// Optional security-event forwarding to any syslog collector or SIEM
    /// (Wazuh, Splunk, Graylog, rsyslog, ...). Absent or `enabled = false`
    /// means the feature is entirely inert. When present here it always
    /// wins over the admin-API/UI-managed copy stored in the database,
    /// same precedence as every other runtime-settable option.
    #[serde(default)]
    pub siem: Option<SiemConfig>,
}

fn default_siem_port() -> u16 {
    514
}
fn default_siem_facility() -> String {
    "local0".into()
}
fn default_siem_app_name() -> String {
    "rust-proxy".into()
}
fn default_siem_queue_size() -> usize {
    4096
}
fn default_siem_categories() -> Vec<String> {
    ["denied", "admin", "cert", "system"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiemProtocol {
    #[default]
    Udp,
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    #[default]
    Rfc5424,
    Rfc3164,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiemMessageFormat {
    /// `key=value` pairs.
    Kv,
    /// One flat JSON object.
    #[default]
    Json,
    /// ArcSight Common Event Format.
    Cef,
}

/// Valid values for `SiemConfig::categories`.
pub const SIEM_CATEGORIES: [&str; 5] = ["access", "denied", "admin", "cert", "system"];

/// Settings for forwarding security-relevant events to a remote syslog
/// collector. Contains no secrets by design: the collector is addressed
/// by host/port, and TLS (if used) verifies the server against the
/// bundled Mozilla roots plus an optional CA file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiemConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_siem_port")]
    pub port: u16,
    #[serde(default)]
    pub protocol: SiemProtocol,
    #[serde(default)]
    pub syslog_format: SyslogFormat,
    #[serde(default)]
    pub message_format: SiemMessageFormat,
    /// A syslog facility name (`local0`..`local7`, `daemon`, `auth`,
    /// `authpriv`, `user`, ...) or a number 0-23.
    #[serde(default = "default_siem_facility")]
    pub facility: String,
    #[serde(default = "default_siem_app_name")]
    pub app_name: String,
    /// Reported hostname; defaults to the machine's own hostname.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Which event categories to forward: any of `SIEM_CATEGORIES`.
    /// `access` (one event per proxied request) is high volume and so is
    /// not in the default set.
    #[serde(default = "default_siem_categories")]
    pub categories: Vec<String>,
    /// Extra PEM CA bundle trusted for `protocol = "tls"` (for a collector
    /// with a private-CA certificate).
    #[serde(default)]
    pub tls_ca_file: Option<PathBuf>,
    /// Events buffered while the collector is slow or unreachable; beyond
    /// this, new events are dropped rather than ever slowing a request.
    #[serde(default = "default_siem_queue_size")]
    pub queue_size: usize,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: default_siem_port(),
            protocol: SiemProtocol::default(),
            syslog_format: SyslogFormat::default(),
            message_format: SiemMessageFormat::default(),
            facility: default_siem_facility(),
            app_name: default_siem_app_name(),
            hostname: None,
            categories: default_siem_categories(),
            tls_ca_file: None,
            queue_size: default_siem_queue_size(),
        }
    }
}

impl SiemConfig {
    /// Syslog facility number for `facility`, or an error message.
    pub fn facility_number(&self) -> Result<u8, String> {
        let f = self.facility.trim().to_ascii_lowercase();
        if let Ok(n) = f.parse::<u8>() {
            return if n <= 23 {
                Ok(n)
            } else {
                Err(format!("siem.facility {n} is out of range (0-23)"))
            };
        }
        let n = match f.as_str() {
            "kern" => 0,
            "user" => 1,
            "mail" => 2,
            "daemon" => 3,
            "auth" => 4,
            "syslog" => 5,
            "lpr" => 6,
            "news" => 7,
            "uucp" => 8,
            "cron" => 9,
            "authpriv" => 10,
            "ftp" => 11,
            "local0" => 16,
            "local1" => 17,
            "local2" => 18,
            "local3" => 19,
            "local4" => 20,
            "local5" => 21,
            "local6" => 22,
            "local7" => 23,
            other => {
                return Err(format!(
                    "siem.facility \"{other}\" is not a known syslog facility"
                ))
            }
        };
        Ok(n)
    }

    /// Checked whenever the section is loaded or saved. A disabled config
    /// is only checked for self-consistency, not for being usable, so a
    /// half-filled form can be saved with `enabled = false`.
    pub fn validate(&self) -> Result<(), String> {
        self.facility_number()?;
        if self.queue_size == 0 || self.queue_size > 1_000_000 {
            return Err("siem.queue_size must be between 1 and 1000000".into());
        }
        let app = self.app_name.trim();
        if app.is_empty() || app.len() > 48 || !app.chars().all(|c| c.is_ascii_graphic()) {
            return Err(
                "siem.app_name must be 1-48 printable ASCII characters with no spaces".into(),
            );
        }
        if let Some(h) = &self.hostname {
            if h.is_empty() || h.len() > 255 || !h.chars().all(|c| c.is_ascii_graphic()) {
                return Err(
                    "siem.hostname must be 1-255 printable ASCII characters with no spaces".into(),
                );
            }
        }
        for c in &self.categories {
            if !SIEM_CATEGORIES.contains(&c.as_str()) {
                return Err(format!(
                    "siem.categories contains unknown category \"{c}\" (valid: {})",
                    SIEM_CATEGORIES.join(", ")
                ));
            }
        }
        if self.enabled {
            let host = self.host.trim();
            if host.is_empty() {
                return Err("siem.host is required when siem.enabled is true".into());
            }
            if host.len() > 253 || host.chars().any(|c| c.is_whitespace() || c == '/') {
                return Err("siem.host must be a hostname or IP address".into());
            }
            if self.port == 0 {
                return Err("siem.port must not be 0".into());
            }
            if self.categories.is_empty() {
                return Err("siem.categories must list at least one category when enabled".into());
            }
        }
        Ok(())
    }
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
    /// Holds both IPv4 and IPv6 ranges (`ipnet::IpNet` covers either) --
    /// a bind_ip_v4/bind_ip_v6 is checked against whichever ranges here
    /// are the same family, ranges of the other family are simply never
    /// matched against it.
    #[serde(default)]
    pub bind_ranges: Vec<IpNet>,
    /// Addresses that serve ONLY hosts and port rules explicitly bound to
    /// them. A wildcard (0.0.0.0 / ::) host, port rule, SSH carve-out or
    /// the always-open 80/443 would otherwise answer on every address the
    /// box holds, including a public IP added just to give one site its
    /// own address. Listed here, the firewall drops everything to that
    /// address except what is explicitly bound to it, and wildcard HTTP(S)
    /// listeners refuse connections that arrived on it.
    #[serde(default)]
    pub dedicated_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Defaults to 0.0.0.0 (every interface), not loopback -- the
    /// first-launch setup wizard needs to be reachable from the network
    /// on a genuinely fresh install with no config.toml edits at all.
    /// `nftables::generator`'s admin rule is the actual gatekeeper for
    /// who can reach it (see `allowed_ips` below); this only controls
    /// which local interface(s) the listener itself is bound to.
    /// `None` means "don't bind this family at all" -- at least one of
    /// `bind_ip_v4`/`bind_ip_v6` must be set (see `Config::validate`).
    #[serde(default = "default_admin_bind_ip_v4")]
    pub bind_ip_v4: Option<Ipv4Addr>,
    /// Same as `bind_ip_v4`, for IPv6 -- defaults to `::` (every
    /// interface, IPv6's equivalent of 0.0.0.0), so a fresh install is
    /// dual-stack-reachable out of the box, matching `bind_ip_v4`'s own
    /// reasoning.
    #[serde(default = "default_admin_bind_ip_v6")]
    pub bind_ip_v6: Option<Ipv6Addr>,
    /// Defaults to 8084 -- deliberately not 8080, the extremely common
    /// default for a dozen other self-hosted tools, to cut down on
    /// same-host port collisions.
    #[serde(default = "default_admin_bind_port")]
    pub bind_port: u16,
    /// IPs/CIDRs allowed to reach the admin UI/API -- IPv4 and IPv6
    /// alike. Enforced both at the application layer and mirrored into
    /// the nftables default-DROP posture (see `nftables`). Empty (the
    /// default) means unrestricted -- deliberately, not loopback-only:
    /// paired with `bind_ip_v4`/`bind_ip_v6` defaulting to unspecified
    /// above, this is what actually makes the first-launch setup wizard
    /// reachable from the network out of the box. Set this once you know
    /// your real management network/IP to narrow it down -- see
    /// `nftables::generator::write_admin_rule`.
    #[serde(default)]
    pub allowed_ips: Vec<IpNet>,
    /// `None` (the default -- not set in config.toml) defers to the
    /// DB-backed value the admin UI's settings section can set/change at
    /// runtime (`state::AppState::expose_admin_port`/
    /// `set_expose_admin_port`, same "config.toml wins if set, else a
    /// DB-backed fallback" precedence `acme.contact_email` already
    /// uses) -- itself defaulting to `true` if nothing has set it yet.
    /// `Some(true)`/`Some(false)` here always wins over the DB, same as
    /// every other config.toml-vs-DB precedence in this project.
    ///
    /// `true` mirrors the original, only-ever behavior: `nftables::generator`
    /// emits an accept rule for the admin port (open to any source, or
    /// scoped to `allowed_ips` if set). `false` emits no accept rule for
    /// it at all -- default-DROP then keeps the admin port unreachable
    /// from the network entirely, leaving only loopback (`iif "lo"
    /// accept`, already unconditional) able to reach it, e.g. for an
    /// operator who only ever administers this box over an SSH tunnel
    /// and wants the admin port to never appear reachable on the wire.
    /// This only controls the firewall rule -- the listener itself still
    /// binds per `bind_ip_v4`/`bind_ip_v6` either way; a `false` here
    /// with a non-loopback bind_ip relies entirely on the firewall (not
    /// the listener) to keep it unreachable.
    #[serde(default)]
    pub expose_admin_port: Option<bool>,
    /// HMAC key signing admin session tokens. `None` means "not set in
    /// config.toml" -- the resolved admin identity then falls back to
    /// whatever's in the `admin_identity` sqlite table (populated by the
    /// first-launch setup wizard). When all three of these fields ARE
    /// set in config.toml, config.toml always wins over the DB, on
    /// every read, not just at first boot -- see
    /// `state::AppState::admin_identity`.
    #[serde(default)]
    pub session_secret: Option<String>,
    #[serde(default)]
    pub admin_username: Option<String>,
    /// Argon2 PHC hash string (`argon2::password_hash`), never a plaintext
    /// password -- generate with `rust-proxy hash-password` (see main.rs).
    #[serde(default)]
    pub admin_password_hash: Option<String>,
    /// TrustBridge client-cert Subject CN(s) that log in as this
    /// daemon's own admin identity -- no accounts table for the admin
    /// UI (single-admin model), so this is just a trusted-subjects
    /// list rather than a per-account mapping like jpps/store's. Empty
    /// (the default) disables the bypass entirely; config.toml-only,
    /// same as `client_cert_forward_token` below -- not settable from
    /// the admin UI, since this is itself an authentication bypass for
    /// that UI. Only takes effect on a host that also has
    /// `pass_client_cert_header` enabled and is proxied back to this
    /// daemon's own admin API (see `proxy.jpps.us`'s config).
    #[serde(default)]
    pub client_cert_subjects: Vec<String>,
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    /// Where `proxy.log`/`access.log`/`server.log` are written (see
    /// `logging.rs`). `None` (the default) keeps the original
    /// behavior: same directory as `db_path`, so an existing install
    /// with no config.toml edit at all sees no change. Set this to
    /// split logs out from the state directory -- e.g. onto a
    /// dedicated `/var/log/rust-proxy`, matching where most other
    /// daemons on a box keep their logs, separate from `StateDirectory`.
    #[serde(default)]
    pub log_dir: Option<PathBuf>,
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/etc/rust-proxy/rust-proxy.db")
}

fn default_admin_bind_ip_v4() -> Option<Ipv4Addr> {
    Some(Ipv4Addr::UNSPECIFIED)
}

fn default_admin_bind_ip_v6() -> Option<Ipv6Addr> {
    Some(Ipv6Addr::UNSPECIFIED)
}

fn default_bind_ip_v4() -> Option<Ipv4Addr> {
    Some(Ipv4Addr::UNSPECIFIED)
}

fn default_bind_ip_v6() -> Option<Ipv6Addr> {
    Some(Ipv6Addr::UNSPECIFIED)
}

fn default_admin_bind_port() -> u16 {
    8084
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProviderKind {
    Cloudflare,
    DigitalOcean,
    Hetzner,
    DuckDns,
    GoDaddy,
    Namecheap,
    Route53,
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
    /// Defaults to empty (not required) -- same "config.toml is only
    /// for seeding, the DB-backed value (settable from the admin UI's
    /// ACME settings section or the setup wizard) takes over from
    /// there" precedence `admin_username`/`admin_password_hash`/
    /// `session_secret` already use. See
    /// `state::AppState::acme_contact_email`'s doc comment for the
    /// exact precedence rule. Left blank, ACME issuance won't work
    /// until an operator sets one via the admin UI.
    #[serde(default)]
    pub contact_email: String,
    #[serde(default)]
    pub dns_provider: DnsProviderKind,
    /// API token for whichever `dns_provider` is selected -- a Cloudflare
    /// API token with Zone:DNS:Edit, a DigitalOcean personal access
    /// token, or a Hetzner DNS API token. All three providers use a
    /// single bearer/header token, so one field covers all of them
    /// instead of a per-provider config block. Defaults to empty
    /// (not required) -- omitting it entirely is the deliberate,
    /// documented way to skip seeding a "default" DNS credential from
    /// config.toml and manage credentials from the admin UI/setup
    /// wizard instead (see `main.rs`'s blank-token check and
    /// `deploy/config.toml.example`).
    #[serde(default)]
    pub dns_api_token: String,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    #[serde(default = "default_account_key_path")]
    pub account_key_path: PathBuf,
    /// Renew when fewer than this many days remain before expiry.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: i64,
    /// Requested (not guaranteed) in every issued certificate's Subject
    /// -- see `acme::cert::generate_csr`'s doc comment for why most
    /// public CAs (Let's Encrypt included) silently discard this for
    /// Domain Validated certs, and when it actually lands in the issued
    /// cert (a private/enterprise ACME CA that does organization
    /// vetting).
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub organizational_unit: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    /// `None` means "don't listen on this family for this host" -- at
    /// least one of `bind_ip_v4`/`bind_ip_v6` must be set (see
    /// `Config::validate`). Both default to unspecified (0.0.0.0/`::`),
    /// so a host is dual-stack-reachable on every interface unless
    /// narrowed down explicitly, same reasoning as `AdminConfig`'s own
    /// bind fields.
    #[serde(default = "default_bind_ip_v4")]
    pub bind_ip_v4: Option<Ipv4Addr>,
    #[serde(default = "default_bind_ip_v6")]
    pub bind_ip_v6: Option<Ipv6Addr>,
    #[serde(default = "default_https_port")]
    pub bind_port: u16,
    /// `host:port` of the upstream this domain proxies to. Ignored
    /// (and may be left empty) when `redirect` is set.
    #[serde(default)]
    pub upstream: String,
    /// Whether `upstream` speaks TLS -- an internal service can be
    /// behind its own HTTPS (its own cert, self-signed or otherwise),
    /// not just plain HTTP. `false` (the default) is the original,
    /// unchanged plain-HTTP-upstream behavior.
    #[serde(default)]
    pub upstream_https: bool,
    /// Only consulted when `upstream_https` is set. `true` (the
    /// default) verifies the upstream's certificate chain against the
    /// bundled Mozilla root store, same trust model any normal HTTPS
    /// client uses. `false` accepts any certificate the upstream
    /// presents, self-signed included -- the connection is still
    /// encrypted, it just isn't authenticated, so this only makes sense
    /// for an upstream already reached over a network this proxy
    /// otherwise trusts (loopback, an internal subnet). See
    /// `proxy::upstream_tls`.
    #[serde(default = "default_true")]
    pub upstream_tls_verify: bool,
    /// `true` (the default) forwards the client's original `Host`
    /// header to `upstream` unmodified -- the existing, unchanged
    /// behavior. `false` rewrites it to `upstream`'s own `host:port`
    /// instead, for a backend that expects to see its own hostname
    /// (virtual-hosting on its own name, not the public-facing one this
    /// proxy answers requests for).
    #[serde(default = "default_true")]
    pub upstream_preserve_host: bool,
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
    /// Named, reusable ACLs this host has selected -- see `AclList`.
    /// Empty (the default) means no access restriction at all: every
    /// source IP passes and there's no login gate. Selecting one or
    /// more `IpAllow`-kind ACLs restricts source IPs to the union of
    /// their entries (an IP passes if it's in ANY selected list);
    /// selecting one or more `Login`-kind ACLs adds a login-page gate
    /// (see `proxy::login`) accepting ANY credential from ANY selected
    /// list's entries. The two kinds are independent gates, checked in
    /// that order (IP allow list, then login), same as the single
    /// inline `access_allow_ips`/`access_login` fields this replaced --
    /// only the source of the data changed, not the enforcement model.
    /// Resolved against the `acl_lists`/`acl_ip_entries`/
    /// `acl_credentials` DB tables at request time by
    /// `proxy::mod::resolve_host_acls`, not stored inline here.
    #[serde(default)]
    pub acl_ids: Vec<Uuid>,
    /// `false` (the default) strips any inbound `X-Client-Cert-Subject`
    /// header before forwarding (so a client can't spoof one), and adds
    /// nothing of its own. `true` forwards the verified TrustBridge
    /// client cert's Subject CN as `X-Client-Cert-Subject` whenever the
    /// connection presented one (see `proxy::client_cert`) -- for an
    /// upstream app (store, wiki, ...) with its own admin login to
    /// trust as a bypass, the same way this proxy's own `ClientCert`
    /// ACL kind bypasses its login gate. The upstream is responsible
    /// for deciding what to do with the header; this only guarantees
    /// it's genuine, not spoofable by the client, and only present when
    /// this flag is on.
    #[serde(default)]
    pub pass_client_cert_header: bool,
    /// Which named `dns_credentials` DB row (see `db::create_dns_credential`)
    /// to use for this host's dns-01 issuance. `None` means either this
    /// host never needs dns-01 (http-01, or ACME disabled), or -- when it
    /// does need dns-01 -- fall back to the single configured credential
    /// if there's exactly one; with zero or more than one, that's a
    /// validation/runtime error (see `acme::resolve_dns_credential`).
    #[serde(default)]
    pub dns_credential_id: Option<Uuid>,
    /// When set, this host answers every matched request with a redirect
    /// to `RedirectTarget::target` instead of proxying to `upstream`.
    /// Domain matching, TLS/ACME issuance, the firewall rule, and access
    /// control (`acl_ids`) are all identical either way -- a redirect
    /// host still gets its own real cert, same
    /// as Nginx Proxy Manager's own Redirection Hosts. `None` (the
    /// default) is a normal reverse-proxy host.
    #[serde(default)]
    pub redirect: Option<RedirectTarget>,
    /// Rewrites the request path before it's forwarded to `upstream` --
    /// `pattern` is matched against the incoming path (not the query
    /// string) with `regex` crate syntax, and `replacement` is the
    /// upstream path to use instead, with `$1`/`$2`/... substituted from
    /// `pattern`'s capture groups (same as `regex::Regex::replace`'s own
    /// replacement syntax; an unmatched optional group substitutes as
    /// empty string). `None` (the default) forwards the original path
    /// unchanged. Ignored on a `redirect` host (see `redirect` above --
    /// there's no upstream request to rewrite the path of). A path that
    /// doesn't match `pattern` at all is forwarded unchanged, not
    /// rejected -- e.g. useful for mounting a whole external site's wiki
    /// under a clean URL: pattern `^/((?:jpps|kb9gxk)/[^/]+)/?$`,
    /// replacement `/$1/-/wikis/Home` (this project's own wiki.jpps.us
    /// host uses exactly this). Sharp edges worth understanding before
    /// writing a pattern, all hit for real in production while building
    /// this:
    ///
    /// - `regex` (RE2-based) has no lookahead support, so a pattern
    ///   can't express "matches, but not if the path already starts with
    ///   the target's own `-/` namespace" -- a looser pattern like
    ///   `^/([^/]+/[^/]+)(?:/(.*))?$` (matches any two-segment-plus-rest
    ///   path, trying to also preserve deeper links) ends up matching
    ///   *and mangling* the target's own already-rewritten URLs the
    ///   moment a visitor clicks a link on the resulting page.
    /// - matching "any two-segment path" is dangerously broad on a
    ///   real site: it also matches unrelated top-level paths like
    ///   `/assets/app.css` or `/api/v4/version`, silently breaking the
    ///   target's own static assets and API calls.
    /// - the fix for both: anchor to an explicit allowlist of the real
    ///   values the first segment can actually be (an alternation, e.g.
    ///   `(?:jpps|kb9gxk)`), not "two segments" in the abstract -- this
    ///   also stays correct automatically as the target adds new
    ///   reserved top-level paths in the future, with nothing to update
    ///   here unless a new real value is added to the alternation.
    #[serde(default)]
    pub path_rewrite: Option<PathRewrite>,
    /// When set, this host serves files directly from this local
    /// directory instead of proxying to `upstream` -- same "alternative
    /// to upstream" shape as `redirect` above (checked first, in that
    /// order: `redirect`, then `static_root`, then normal upstream
    /// proxying), and like `redirect`, domain matching/TLS/ACME/access
    /// control are all identical either way. `path_rewrite` is ignored
    /// on a static host -- there's no upstream request to rewrite the
    /// path of, only a local file to resolve. See
    /// `proxy::http::serve_static_response` for exactly how a request
    /// path resolves to a file (path-traversal guard, `index.html`
    /// fallback, content-type by extension).
    #[serde(default)]
    pub static_root: Option<PathBuf>,
    /// `true` downgrades any `SameSite=None` attribute on a `Set-Cookie`
    /// header coming back from `upstream` to `SameSite=Lax` before
    /// returning the response to the client (`Secure`/`HttpOnly`/other
    /// attributes untouched). Some applications hardcode `SameSite=None`
    /// on their session cookie for historical reasons (a since-obsoleted
    /// browser-compat workaround, or a genuine but no-longer-applicable
    /// cross-site requirement) even when there's no real cross-site use
    /// -- `SameSite=None` cookies are exactly the kind modern browsers'
    /// privacy/tracking-protection features are increasingly willing to
    /// silently drop, even in ordinary first-party same-site use, which
    /// can break login entirely with no visible error beyond a generic
    /// CSRF/session failure on the application side (confirmed live: a
    /// real GitLab instance behind this proxy hit exactly this -- see
    /// `proxy::http::rewrite_samesite_none_cookies`'s doc comment for the
    /// full diagnosis). `false` (the default) leaves every `Set-Cookie`
    /// header exactly as the upstream sent it -- this is opt-in, not a
    /// blanket rewrite, since a host that genuinely needs `SameSite=None`
    /// (a legitimately embeddable widget, a real cross-site OAuth flow)
    /// would break if this were forced on unconditionally.
    #[serde(default)]
    pub rewrite_samesite_none_cookies: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// See `ProxyHost::path_rewrite`'s doc comment for the exact semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathRewrite {
    pub pattern: String,
    pub replacement: String,
}

/// Where a `redirect` host sends visitors, and how.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectTarget {
    /// Absolute `http://` or `https://` URL -- validated in
    /// `validate_redirect_target`. Unlike `proxy::login`'s `return_to`
    /// (which must never leave the site -- see the open-redirect fix in
    /// `proxy::login::sanitize_return_to`), this one is *meant* to be an
    /// arbitrary destination: it's an admin-configured value, not
    /// something reflected from request input.
    pub target: String,
    /// When true (the default), the incoming request's own path and
    /// query string are appended to `target` -- e.g. redirecting
    /// `old.example.com/blog/post` straight to
    /// `new.example.com/blog/post`. When false, every request goes to
    /// `target` verbatim regardless of the path visited.
    #[serde(default = "default_true")]
    pub preserve_path: bool,
    #[serde(default)]
    pub status: RedirectStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedirectStatus {
    /// 301 -- browsers and search engines cache this redirect
    /// indefinitely, same as `proxy::http::https_redirect_response`'s
    /// own `force_https` redirect.
    #[default]
    Permanent,
    /// 302 -- for a redirect that might change later (a temporary
    /// migration, an A/B test) and shouldn't be cached hard.
    Temporary,
}

/// A single login credential gating one host behind `proxy::login`'s
/// login page. `password_hash` is an argon2 PHC string, never a
/// plaintext password -- same hashing as the admin account's own
/// password (see `api::auth::hash_password`), computed server-side from
/// a plaintext password submitted through the admin API/UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostAuth {
    pub username: String,
    /// Never serialized back out over the admin API -- `ProxyHost` is
    /// returned directly from `GET`/`POST`/`PUT /api/hosts`, and an
    /// already-authenticated caller still has no legitimate need to see
    /// even a hashed credential (same reasoning as why API tokens are
    /// never listed with their hash either).
    #[serde(skip_serializing)]
    pub password_hash: String,
}

/// A named, reusable access-control list -- see `ProxyHost.acl_ids`'s
/// doc comment for how hosts select and combine these. Metadata only
/// (no entries): `AclKind::IpAllow`'s CIDRs live in `db::AclIpEntry`
/// rows, `AclKind::Login`'s credentials in `db::AclCredential` rows --
/// kept out of this struct so listing ACLs (e.g. for a host's picker)
/// never has to pull every list's full entry set along with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclList {
    pub id: Uuid,
    pub name: String,
    pub kind: AclKind,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclKind {
    /// A list of CIDRs; a source IP passes if it's inside any entry
    /// across every `IpAllow` list a host has selected.
    IpAllow,
    /// A list of username/password_hash pairs; a login succeeds if it
    /// matches any entry across every `Login` list a host has selected.
    Login,
    /// No entries of its own (unlike the other two kinds) -- selecting
    /// a `ClientCert`-kind list means "a TrustBridge-issued client
    /// certificate satisfies this host's login gate," checked against
    /// the connection-level client cert `proxy::client_cert` already
    /// verified (or didn't -- absence just means this ACL doesn't
    /// match, same as a non-matching IP). See `proxy::mod::
    /// handle_https_request`'s ACL-gate logic for exactly how this
    /// combines with `IpAllow`/`Login` lists on the same host.
    ClientCert,
}

fn default_https_port() -> u16 {
    443
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeChallengeType {
    /// http-01 for a plain domain with `force_https` (no DNS provider
    /// credentials needed -- the common case), dns-01 for a wildcard
    /// domain or a plain domain without `force_https` (http-01 needs
    /// port 80 reachable, which nothing opens without it).
    #[default]
    Auto,
    Http01,
    Dns01,
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
    #[serde(default = "default_bind_ip_v4")]
    pub bind_ip_v4: Option<Ipv4Addr>,
    #[serde(default = "default_bind_ip_v6")]
    pub bind_ip_v6: Option<Ipv6Addr>,
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
    /// `IpAllow`-kind ACLs this rule's firewall entry is restricted to --
    /// same union-of-selected-lists semantics as `ProxyHost.acl_ids`, but
    /// enforced entirely at the firewall layer (`nftables::generator`),
    /// not the application: a raw TCP/UDP passthrough rule has no HTTP
    /// layer to show a login page on, so only `AclKind::IpAllow` lists
    /// are meaningful here -- a `Login`-kind list selected on a port
    /// rule is simply ignored (see `nftables::sync_once`). Empty (the
    /// default) means unrestricted, same as `ProxyHost.acl_ids`.
    #[serde(default)]
    pub acl_ids: Vec<Uuid>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl PortRule {
    pub fn is_range(&self) -> bool {
        self.port_end != self.port_start
    }
}

/// The same file `postinst` installs verbatim on a fresh `.deb`
/// install (see `deploy/debian/postinst`) and `deploy/config.toml.example`
/// documents for manual installs -- embedded here too so a non-packaged
/// run (`cargo run`, a manually-copied binary, a container with no
/// postinst-equivalent step) gets the identical safe-by-default
/// behavior instead of a hard failure. One source of truth: editing
/// `deploy/config.toml.example` updates both paths at once.
const DEFAULT_CONFIG_TOML: &str = include_str!("../deploy/config.toml.example");

impl Config {
    /// Loads `path`, creating it first (with `DEFAULT_CONFIG_TOML`'s
    /// safe, working defaults -- 0.0.0.0:8084 admin, no admin identity
    /// or DNS credential set, so a first-launch setup wizard serves
    /// instead) if nothing exists there yet. Matches this project's
    /// "no config file dependency" goal: a genuinely fresh environment
    /// with no config.toml at all should still start cleanly and be
    /// immediately configurable from the admin UI, not fail before it
    /// ever gets that far.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
            }
            std::fs::write(path, DEFAULT_CONFIG_TOML)
                .map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
            tracing::info!(path = %path.display(), "no config file found -- wrote a default one with safe, working settings");
        }
        let raw =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
        let cfg: Config = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(siem) = &self.siem {
            siem.validate().map_err(ConfigError::Validation)?;
        }
        validate_dual_bind(
            &self.network.bind_ranges,
            self.admin.bind_ip_v4,
            self.admin.bind_ip_v6,
            "admin",
        )?;
        let identity_fields_set = [
            self.admin.session_secret.is_some(),
            self.admin.admin_username.is_some(),
            self.admin.admin_password_hash.is_some(),
        ]
        .iter()
        .filter(|set| **set)
        .count();
        if identity_fields_set != 0 && identity_fields_set != 3 {
            return Err(ConfigError::Validation(
                "admin.session_secret, admin.admin_username, and admin.admin_password_hash must either all be set or all omitted -- a partial admin identity in config.toml is not allowed".into(),
            ));
        }
        if let Some(secret) = &self.admin.session_secret {
            if secret.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "admin.session_secret must not be empty if set".into(),
                ));
            }
        }
        if let Some(username) = &self.admin.admin_username {
            if username.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "admin.admin_username must not be empty if set".into(),
                ));
            }
        }
        if let Some(hash) = &self.admin.admin_password_hash {
            if hash.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "admin.admin_password_hash must not be empty if set".into(),
                ));
            }
        }

        // `seen_socket_binds` tracks exclusive claims on a raw (ip, port,
        // protocol) socket -- a host implicitly claims one for TCP, and a
        // port_rule claims one explicitly. Multiple *hosts* are allowed to
        // share the same socket key (SNI-based virtual hosting on one
        // listener), so that check is separate: `seen_host_domains` only
        // rejects the same domain appearing twice on the same bind.
        let mut seen_socket_binds: Vec<(IpAddr, u16, Protocol)> = Vec::new();
        let mut seen_host_domains: Vec<(IpAddr, u16, String)> = Vec::new();

        for host in &self.hosts {
            validate_dual_bind(
                &self.network.bind_ranges,
                host.bind_ip_v4,
                host.bind_ip_v6,
                "hosts",
            )?;
            validate_port(host.bind_port, "hosts.bind_port")?;
            validate_domain(&host.domain)?;
            match &host.redirect {
                Some(redirect) => validate_redirect_target(&redirect.target)?,
                None => {
                    if host.upstream.trim().is_empty() || !host.upstream.contains(':') {
                        return Err(ConfigError::Validation(format!(
                            "hosts entry for {} has an invalid upstream (expected host:port)",
                            host.domain
                        )));
                    }
                }
            }

            for bind_ip in host_bind_ips(host) {
                let domain_key = (bind_ip, host.bind_port, host.domain.to_ascii_lowercase());
                if seen_host_domains.contains(&domain_key) {
                    return Err(ConfigError::Validation(format!(
                        "duplicate host {} on {}:{}",
                        host.domain, bind_ip, host.bind_port
                    )));
                }
                seen_host_domains.push(domain_key);

                let socket_key = (bind_ip, host.bind_port, Protocol::Tcp);
                if !seen_socket_binds.contains(&socket_key) {
                    seen_socket_binds.push(socket_key);
                }
            }
        }

        for rule in &self.port_rules {
            validate_dual_bind(
                &self.network.bind_ranges,
                rule.bind_ip_v4,
                rule.bind_ip_v6,
                "port_rules",
            )?;
            validate_port(rule.port_start, "port_rules.port_start")?;
            validate_port(rule.port_end, "port_rules.port_end")?;
            if rule.port_start > rule.port_end {
                return Err(ConfigError::Validation(format!(
                    "port_rules entry has port_start {} > port_end {}",
                    rule.port_start, rule.port_end
                )));
            }
            for bind_ip in port_rule_bind_ips(rule) {
                for port in rule.port_start..=rule.port_end {
                    let key = (bind_ip, port, rule.protocol);
                    if seen_socket_binds.contains(&key) {
                        return Err(ConfigError::Validation(format!("port_rules entry conflicts with an existing bind at {bind_ip}:{port}/{:?}", rule.protocol)));
                    }
                    seen_socket_binds.push(key);
                }
            }
        }

        Ok(())
    }
}

/// Every family this host is actually configured to bind -- `IpAddr::V4`
/// for `bind_ip_v4` when set, `IpAddr::V6` for `bind_ip_v6` when set, both
/// if both are set. Used anywhere dedup/validation needs to walk each
/// socket a host actually claims.
pub fn host_bind_ips(host: &ProxyHost) -> Vec<IpAddr> {
    dual_bind_ips(host.bind_ip_v4, host.bind_ip_v6)
}

pub fn port_rule_bind_ips(rule: &PortRule) -> Vec<IpAddr> {
    dual_bind_ips(rule.bind_ip_v4, rule.bind_ip_v6)
}

fn dual_bind_ips(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> Vec<IpAddr> {
    let mut ips = Vec::with_capacity(2);
    if let Some(v4) = v4 {
        ips.push(IpAddr::V4(v4));
    }
    if let Some(v6) = v6 {
        ips.push(IpAddr::V6(v6));
    }
    ips
}

/// Empty domains are rejected outright; `*.` is only accepted as a single
/// leading label (matching real X.509 wildcard cert semantics -- one
/// level of subdomain, never `foo.*.bar` or `*foo.com`).
pub(crate) fn validate_domain(domain: &str) -> Result<(), ConfigError> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Validation(
            "hosts entry has an empty domain".into(),
        ));
    }
    match trimmed.strip_prefix("*.") {
        Some(rest) if rest.is_empty() || rest.contains('*') => {
            Err(ConfigError::Validation(format!(
                "invalid wildcard domain \"{domain}\" -- must be \"*.\" followed by a real domain"
            )))
        }
        Some(_) => Ok(()),
        None if trimmed.contains('*') => Err(ConfigError::Validation(format!(
            "invalid domain \"{domain}\" -- \"*\" is only allowed as a single leading \"*.\" label"
        ))),
        None => Ok(()),
    }
}

/// Only requires an absolute `http://`/`https://` URL -- anything more
/// (a real `Uri` parse, rejecting a bare domain, etc.) is left to
/// whatever HTTP client eventually follows the redirect; this is just
/// enough to catch an obviously-wrong value (a bare domain, a typo)
/// before it's saved.
pub(crate) fn validate_redirect_target(target: &str) -> Result<(), ConfigError> {
    if !(target.starts_with("http://") || target.starts_with("https://")) {
        return Err(ConfigError::Validation(format!(
            "redirect target \"{target}\" must be an absolute http:// or https:// URL"
        )));
    }
    Ok(())
}

pub(crate) fn validate_bind_ip(
    allowed: &[IpNet],
    ip: IpAddr,
    ctx: &str,
) -> Result<(), ConfigError> {
    if ip.is_unspecified() {
        // 0.0.0.0/:: means "every interface", not one specific address --
        // it's never meaningfully "outside" a configured bind_ranges
        // allowlist the way a single real IP could be, so there's
        // nothing to range-check. Matters most for admin.bind_ip_v4/_v6,
        // whose own defaults are now unspecified (see AdminConfig) --
        // without this, any operator who set network.bind_ranges without
        // also explicitly overriding the admin bind fields would fail
        // validation on a field they never touched.
        return Ok(());
    }
    // Only ranges of the same family as `ip` are meaningful to check --
    // an IPv4 bind_ip is never "inside" an IPv6 range or vice versa, and
    // an operator who only configured v4 ranges shouldn't have that
    // silently reject every v6 bind as if it were an empty allowlist (or
    // the reverse).
    let same_family: Vec<&IpNet> = allowed
        .iter()
        .filter(|net| net.addr().is_ipv4() == ip.is_ipv4())
        .collect();
    if same_family.is_empty() {
        // Unrestricted -- no configured ranges of this family to check against.
        return Ok(());
    }
    if !same_family.iter().any(|net| net.contains(&ip)) {
        let ranges = same_family
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ConfigError::Validation(format!(
            "{ctx} bind_ip {ip} is not inside any of network.bind_ranges ({ranges})"
        )));
    }
    Ok(())
}

/// At least one of `v4`/`v6` must be set -- a host/port_rule/admin with
/// both `None` binds nothing at all, which is never a useful
/// configuration (silently listening on neither family is almost
/// certainly a mistake, not an intentionally-disabled bind -- there's no
/// "enabled: false" story for a bind pair the way there is for
/// `ProxyHost.enabled`).
pub(crate) fn validate_dual_bind(
    allowed: &[IpNet],
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    ctx: &str,
) -> Result<(), ConfigError> {
    if v4.is_none() && v6.is_none() {
        return Err(ConfigError::Validation(format!(
            "{ctx} must set at least one of bind_ip_v4/bind_ip_v6"
        )));
    }
    if let Some(v4) = v4 {
        validate_bind_ip(allowed, IpAddr::V4(v4), ctx)?;
    }
    if let Some(v6) = v6 {
        validate_bind_ip(allowed, IpAddr::V6(v6), ctx)?;
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
bind_ip_v4 = "10.0.0.1"
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
    fn load_creates_a_default_config_file_when_none_exists_yet() {
        let dir = std::env::temp_dir().join(format!("rust-proxy-config-test-{}", Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        // Nested, not-yet-created parent dir too -- proves the parent
        // gets created along with the file itself, matching a genuinely
        // fresh environment where /etc/rust-proxy doesn't exist at all.
        let path = dir.join("nested").join("config.toml");
        assert!(!path.exists());

        let cfg = Config::load(&path).expect("should create a valid default and load it");
        assert!(
            path.is_file(),
            "should have written the default config file"
        );
        assert_eq!(cfg.admin.bind_ip_v4, Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(cfg.admin.bind_ip_v6, Some(Ipv6Addr::UNSPECIFIED));
        assert_eq!(cfg.admin.bind_port, 8084);
        assert!(
            cfg.admin.session_secret.is_none(),
            "the default must not bake in a fixed admin identity"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_does_not_overwrite_an_existing_config_file() {
        let dir = std::env::temp_dir().join(format!("rust-proxy-config-test-{}", Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        std::fs::write(&path, base_toml()).unwrap();

        let cfg = Config::load(&path).expect("should load the existing file as-is");
        assert_eq!(
            cfg.admin.bind_ip_v4,
            Some("10.0.0.1".parse::<Ipv4Addr>().unwrap()),
            "must not have replaced the operator's own config"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_minimal_valid_config() {
        let cfg: Config = toml::from_str(&base_toml()).expect("should parse");
        assert!(cfg.validate().is_ok());
        assert_eq!(
            cfg.acme.directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
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
    fn acme_contact_email_defaults_to_blank_when_omitted() {
        // config.toml is only ever a seed for contact_email -- like the
        // admin identity fields, the DB-backed value (set via the admin
        // UI's ACME settings section or the setup wizard) takes over
        // from there. A config.toml that never mentions contact_email
        // at all must still parse and validate cleanly.
        let toml_str = base_toml().replace(r#"contact_email = "admin@example.com""#, "");
        let cfg: Config = toml::from_str(&toml_str)
            .expect("contact_email must be optional, not a required field");
        assert_eq!(cfg.acme.contact_email, "");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn admin_bind_ip_and_port_default_to_0000_and_8084_when_omitted() {
        let toml_str = base_toml()
            .replace(r#"bind_ip_v4 = "10.0.0.1""#, "")
            .replace("bind_port = 8080", "");
        let cfg: Config = toml::from_str(&toml_str).expect("should parse");
        assert_eq!(cfg.admin.bind_ip_v4, Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(cfg.admin.bind_port, 8084);
        assert!(
            cfg.validate().is_ok(),
            "0.0.0.0 must not fail bind_ranges membership validation"
        );
    }

    #[test]
    fn admin_log_dir_defaults_to_none_when_omitted() {
        let cfg: Config = toml::from_str(&base_toml()).expect("should parse");
        assert_eq!(cfg.admin.log_dir, None);
    }

    #[test]
    fn admin_log_dir_parses_when_set() {
        // log_dir belongs under [admin] -- insert it into base_toml()'s
        // own [admin] table rather than appending after the whole
        // document, which would land the key outside any table.
        let toml_str = base_toml().replacen(
            "[admin]",
            "[admin]\nlog_dir = \"/var/log/rust-proxy\"",
            1,
        );
        let cfg: Config = toml::from_str(&toml_str).expect("should parse");
        assert_eq!(cfg.admin.log_dir, Some(std::path::PathBuf::from("/var/log/rust-proxy")));
    }

    #[test]
    fn admin_bind_ip_of_0000_is_valid_even_with_bind_ranges_configured() {
        // network.bind_ranges is set to 10.0.0.0/29 in base_toml() --
        // 0.0.0.0 is never literally inside that range, but it means
        // "every interface", so it must not be rejected as if it were
        // one specific out-of-range address.
        let toml_str =
            base_toml().replace(r#"bind_ip_v4 = "10.0.0.1""#, r#"bind_ip_v4 = "0.0.0.0""#);
        let cfg: Config = toml::from_str(&toml_str).expect("should parse");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn omitting_all_three_admin_identity_fields_is_valid() {
        let toml_str = base_toml()
            .replace(r#"session_secret = "test-secret-do-not-use-in-prod""#, "")
            .replace(r#"admin_username = "admin""#, "")
            .replace(
                r#"admin_password_hash = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g""#,
                "",
            );
        let cfg: Config = toml::from_str(&toml_str).expect("should parse");
        assert!(cfg.admin.session_secret.is_none());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn setting_only_some_of_the_three_admin_identity_fields_is_rejected() {
        let toml_str = base_toml().replace(r#"admin_username = "admin""#, "");
        let cfg: Config = toml::from_str(&toml_str).expect("should parse");
        assert!(cfg.admin.admin_username.is_none());
        assert!(cfg.admin.session_secret.is_some());
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
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
        let toml_str = base_toml()
            .replace(r#"bind_ranges = ["10.0.0.0/29"]"#, "")
            .replace("10.0.0.1", "203.0.113.7");
        let mut cfg: Config = toml::from_str(&toml_str).expect("should parse");
        assert!(cfg.network.bind_ranges.is_empty());
        assert!(cfg.validate().is_ok());

        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip_v4: Some("198.51.100.9".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: "127.0.0.1:9000".into(),
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
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn bind_ranges_may_be_multiple_disjoint_ranges() {
        let toml_str = base_toml().replace(
            r#"bind_ranges = ["10.0.0.0/29"]"#,
            r#"bind_ranges = ["10.0.0.0/29", "192.168.1.0/24"]"#,
        );
        let mut cfg: Config = toml::from_str(&toml_str).expect("should parse");
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip_v4: Some("192.168.1.50".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: "127.0.0.1:9000".into(),
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
        });
        assert!(
            cfg.validate().is_ok(),
            "bind_ip in the second range should be accepted"
        );
    }

    #[test]
    fn rejects_host_bind_ip_outside_subnet() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip_v4: Some("192.168.1.5".parse().unwrap()),
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
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_host_with_malformed_upstream() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: "no-port-here".into(),
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
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_a_redirect_host_with_no_upstream() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "old.example.com".into(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: String::new(),
            upstream_https: false,
            upstream_tls_verify: true,
            upstream_preserve_host: true,
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: Some(RedirectTarget {
                target: "https://new.example.com".into(),
                preserve_path: true,
                status: RedirectStatus::Permanent,
            }),
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            pass_client_cert_header: false,
            enabled: true,
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_a_redirect_host_with_a_non_absolute_target() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.hosts.push(ProxyHost {
            id: Uuid::new_v4(),
            domain: "old.example.com".into(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: String::new(),
            upstream_https: false,
            upstream_tls_verify: true,
            upstream_preserve_host: true,
            websockets: false,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: Some(RedirectTarget {
                target: "new.example.com".into(),
                preserve_path: true,
                status: RedirectStatus::Permanent,
            }),
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            pass_client_cert_header: false,
            enabled: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_port_rule_with_start_after_end() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some("10.0.0.4".parse().unwrap()),
            bind_ip_v6: None,
            port_start: 21119,
            port_end: 21115,
            protocol: Protocol::Tcp,
            description: "rustdesk".into(),
            passthrough_target: None,
            acl_ids: vec![],
            enabled: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_port_rule_with_zero_port() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some("10.0.0.4".parse().unwrap()),
            bind_ip_v6: None,
            port_start: 0,
            port_end: 0,
            protocol: Protocol::Udp,
            description: "bogus".into(),
            passthrough_target: None,
            acl_ids: vec![],
            enabled: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_valid_port_range_for_rustdesk() {
        let mut cfg: Config = toml::from_str(&base_toml()).unwrap();
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some("10.0.0.4".parse().unwrap()),
            bind_ip_v6: None,
            port_start: 21115,
            port_end: 21119,
            protocol: Protocol::Tcp,
            description: "rustdesk tcp".into(),
            passthrough_target: None,
            acl_ids: vec![],
            enabled: true,
        });
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some("10.0.0.4".parse().unwrap()),
            bind_ip_v6: None,
            port_start: 21116,
            port_end: 21116,
            protocol: Protocol::Udp,
            description: "rustdesk udp".into(),
            passthrough_target: None,
            acl_ids: vec![],
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
                bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
                bind_ip_v6: None,
                bind_port: 443,
                upstream: "127.0.0.1:9000".into(),
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
                bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
                bind_ip_v6: None,
                bind_port: 443,
                upstream: "127.0.0.1:9000".into(),
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
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: "127.0.0.1:9000".into(),
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
        });
        cfg.port_rules.push(PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            port_start: 443,
            port_end: 443,
            protocol: Protocol::Tcp,
            description: "conflicting raw passthrough".into(),
            passthrough_target: Some("127.0.0.1:1".into()),
            acl_ids: vec![],
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
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: "127.0.0.1:9000".into(),
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
