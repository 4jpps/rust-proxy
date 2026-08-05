//! sqlite persistence for `hosts`/`port_rules` -- the admin API's source
//! of truth across restarts. `config.toml`'s inline `hosts`/`port_rules`
//! (if any) only ever seed an empty database on first boot; every edit
//! after that goes through here, not the TOML file.
//!
//! Table count is small (dozens of rows at the scale this is built for,
//! same assumption jpps-store's CLAUDE.md makes about its own admin
//! data) so mutations are simple delete-all-then-reinsert-all rather than
//! per-row diffing.

use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

use crate::config::{AcmeChallengeType, AclKind, AclList, DnsProviderKind, HostAuth, PortRule, Protocol, ProxyHost, RedirectStatus, RedirectTarget};

pub async fn connect(db_path: &Path) -> Result<SqlitePool, sqlx::Error> {
    let url = if db_path.as_os_str() == ":memory:" {
        "sqlite::memory:".to_string()
    } else {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        format!("sqlite://{}", db_path.display())
    };
    let options = SqliteConnectOptions::from_str(&url)?.create_if_missing(true);
    let pool = SqlitePoolOptions::new().max_connections(5).connect_with(options).await?;
    run_migrations(&pool).await?;
    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            bind_ip TEXT NOT NULL,
            bind_port INTEGER NOT NULL,
            upstream TEXT NOT NULL,
            upstream_https INTEGER NOT NULL DEFAULT 0,
            upstream_tls_verify INTEGER NOT NULL DEFAULT 1,
            upstream_preserve_host INTEGER NOT NULL DEFAULT 1,
            websockets INTEGER NOT NULL,
            force_https INTEGER NOT NULL,
            acme_enabled INTEGER NOT NULL,
            acme_challenge_type TEXT NOT NULL DEFAULT 'auto',
            access_allow_ips TEXT NOT NULL DEFAULT '',
            access_login_username TEXT,
            access_login_password_hash TEXT,
            redirect_target TEXT,
            redirect_preserve_path INTEGER NOT NULL DEFAULT 1,
            redirect_status TEXT NOT NULL DEFAULT 'permanent',
            dns_credential_id TEXT,
            enabled INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    // A pre-existing `hosts` table (from before these columns existed)
    // won't have them -- `CREATE TABLE IF NOT EXISTS` only runs for a
    // brand-new database, so an upgrade needs its own `ALTER TABLE`s.
    // Ignore the error when a column's already there (sqlite has no
    // `ADD COLUMN IF NOT EXISTS`); the defaults above only apply to
    // genuinely new tables, so this also backfills existing rows.
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN acme_challenge_type TEXT NOT NULL DEFAULT 'auto'").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN access_allow_ips TEXT NOT NULL DEFAULT ''").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN access_login_username TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN access_login_password_hash TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN redirect_target TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN redirect_preserve_path INTEGER NOT NULL DEFAULT 1").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN redirect_status TEXT NOT NULL DEFAULT 'permanent'").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN dns_credential_id TEXT").execute(pool).await;
    // Comma-joined ACL UUIDs -- same convention as the (now-legacy,
    // still-present-but-unread-by-new-code) access_allow_ips column
    // above. The access_allow_ips/access_login_* columns are left in
    // place, not dropped: migrate_legacy_host_access below reads them
    // once to preserve any pre-existing per-host access control as a
    // real ACL, and DROP COLUMN support varies enough across sqlite
    // versions in the wild that leaving a few unused columns behind is
    // a safer bet than risking that migration failing outright.
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN acl_ids TEXT NOT NULL DEFAULT ''").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN upstream_https INTEGER NOT NULL DEFAULT 0").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN upstream_tls_verify INTEGER NOT NULL DEFAULT 1").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN upstream_preserve_host INTEGER NOT NULL DEFAULT 1").execute(pool).await;

    // Metadata only -- kind is 'ip_allow' or 'login'; entries live in
    // the two tables below, keyed by acl_list_id. name is UNIQUE so an
    // operator gets an immediate, clear conflict error rather than two
    // indistinguishable lists in the picker.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acl_lists (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acl_ip_entries (
            id TEXT PRIMARY KEY,
            acl_list_id TEXT NOT NULL,
            cidr TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acl_credentials (
            id TEXT PRIMARY KEY,
            acl_list_id TEXT NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    migrate_legacy_host_access(pool).await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS port_rules (
            id TEXT PRIMARY KEY,
            bind_ip TEXT NOT NULL,
            port_start INTEGER NOT NULL,
            port_end INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            description TEXT NOT NULL,
            passthrough_target TEXT,
            enabled INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Only `token_hash` is ever persisted -- the plaintext token is shown
    // to the caller exactly once, at creation, and never stored anywhere.
    // `UNIQUE` on the hash isn't a meaningful collision defense (256-bit
    // digests don't collide in practice); it's there so a lookup during
    // auth can never ambiguously match more than one token.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS api_tokens (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_used_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // `token` holds whatever that row's `provider` needs -- a single
    // bearer token for most providers, or a colon-packed multi-field
    // credential (Namecheap, Route53) -- see each provider module's own
    // doc comment in `acme::dns01`. `name` is UNIQUE so `seed_default_
    // dns_credential`'s `INSERT OR IGNORE` (keyed on the literal name
    // "default") is idempotent across restarts without a separate
    // existence check.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dns_credentials (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            provider TEXT NOT NULL,
            token TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // A DNS-01 certificate issued for a domain with no `hosts` row at
    // all -- the whole point being a wildcard (`*.example.com`) can be
    // issued once here and then every subdomain host just works via
    // `proxy::tls::select_cert_for_sni`'s existing wildcard fallback,
    // no per-host "attach" step needed. `domain` is UNIQUE so
    // `create_standalone_cert` naturally rejects a duplicate instead of
    // silently tracking the same domain twice under two ids.
    // `dns_credential_id` is remembered (not just used once) so
    // `acme::run_renewal_loop` can pick the same credential again on
    // its next renewal check.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS standalone_certs (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL UNIQUE,
            dns_credential_id TEXT,
            created_at TEXT NOT NULL,
            organization TEXT,
            organizational_unit TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Single-row table (id is always 1) holding the DB-backed ACME
    // contact email -- only ever consulted by
    // `state::AppState::acme_contact_email` when config.toml's own
    // `acme.contact_email` is blank, same precedence as admin_identity
    // below. Settable at runtime from the admin UI's settings section
    // or the setup wizard, unlike config.toml's own field which needs a
    // restart to change.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acme_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            contact_email TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Single-row table (id is always 1, enforced by the CHECK constraint
    // -- `create_admin_identity_if_absent` relies on it as the atomic
    // arbiter for "has this instance been set up yet"). Holds the admin
    // identity set by the first-launch setup wizard; only consulted
    // when config.toml omits
    // session_secret/admin_username/admin_password_hash entirely -- see
    // `state::AppState::admin_identity`.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS admin_identity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            session_secret TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Metadata about an API token, as returned by the admin API -- never
/// includes the hash (nothing outside `find_api_token_id_by_hash` needs
/// it) or the plaintext (never persisted at all, see `create_api_token`).
pub struct ApiTokenMeta {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

pub async fn create_api_token(pool: &SqlitePool, id: Uuid, name: &str, token_hash: &str, created_at: DateTime<Utc>) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO api_tokens (id, name, token_hash, created_at, last_used_at) VALUES (?, ?, ?, ?, NULL)")
        .bind(id.to_string())
        .bind(name)
        .bind(token_hash)
        .bind(created_at.to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_api_tokens(pool: &SqlitePool) -> Result<Vec<ApiTokenMeta>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, name, created_at, last_used_at FROM api_tokens ORDER BY created_at ASC")
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ApiTokenMeta {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or_else(|_| Uuid::new_v4()),
                name: row.get("name"),
                created_at: parse_rfc3339(&row.get::<String, _>("created_at")),
                last_used_at: row.get::<Option<String>, _>("last_used_at").map(|s| parse_rfc3339(&s)),
            })
        })
        .collect()
}

/// Looks up a token by the hash of its plaintext (never by plaintext
/// itself -- callers hash first, see `api::auth::hash_api_token`).
pub async fn find_api_token_id_by_hash(pool: &SqlitePool, token_hash: &str) -> Result<Option<Uuid>, sqlx::Error> {
    let row = sqlx::query("SELECT id FROM api_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| Uuid::parse_str(r.get::<String, _>("id").as_str()).unwrap_or_else(|_| Uuid::new_v4())))
}

/// Best-effort last-used tracking, called on every successful token auth
/// -- a failure here should never fail the request it's just bookkeeping
/// for, so callers log-and-ignore rather than propagate the error.
pub async fn touch_api_token_last_used(pool: &SqlitePool, id: Uuid, when: DateTime<Utc>) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
        .bind(when.to_rfc3339())
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_api_token(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM api_tokens WHERE id = ?").bind(id.to_string()).execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

fn parse_rfc3339(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now())
}

#[derive(Debug)]
pub struct DnsCredentialMeta {
    pub id: Uuid,
    pub name: String,
    pub provider: DnsProviderKind,
    pub created_at: DateTime<Utc>,
}

/// Deliberately no `Debug` derive that would print `token` -- this type
/// holds a live secret (see `get_dns_credential`), and an accidental
/// `{:?}`/`.unwrap()` on it anywhere (logs, a panic message) must never
/// leak it. `#[derive(Debug)]` was added back for `DnsCredentialError`
/// (below)'s `#[error(transparent)] Db(#[from] sqlx::Error)` bound and
/// `resolve_dns_credential`'s own tests, which only ever call
/// `.unwrap_err()` on the `Result<DnsCredential, _>` -- that bound
/// requires `T: Debug` even though the Ok value is never actually
/// printed on that path, so a hand-written impl that never prints
/// `token` is used instead of the derive.
pub struct DnsCredential {
    pub id: Uuid,
    pub name: String,
    pub provider: DnsProviderKind,
    pub token: String,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for DnsCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsCredential")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("token", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

fn dns_provider_to_str(provider: DnsProviderKind) -> &'static str {
    match provider {
        DnsProviderKind::Cloudflare => "cloudflare",
        DnsProviderKind::DigitalOcean => "digitalocean",
        DnsProviderKind::Hetzner => "hetzner",
        DnsProviderKind::DuckDns => "duckdns",
        DnsProviderKind::GoDaddy => "godaddy",
        DnsProviderKind::Namecheap => "namecheap",
        DnsProviderKind::Route53 => "route53",
    }
}

fn dns_provider_from_str(s: &str) -> DnsProviderKind {
    match s {
        "digitalocean" => DnsProviderKind::DigitalOcean,
        "hetzner" => DnsProviderKind::Hetzner,
        "duckdns" => DnsProviderKind::DuckDns,
        "godaddy" => DnsProviderKind::GoDaddy,
        "namecheap" => DnsProviderKind::Namecheap,
        "route53" => DnsProviderKind::Route53,
        _ => DnsProviderKind::Cloudflare,
    }
}

pub async fn create_dns_credential(
    pool: &SqlitePool,
    id: Uuid,
    name: &str,
    provider: DnsProviderKind,
    token: &str,
    created_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO dns_credentials (id, name, provider, token, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(id.to_string())
        .bind(name)
        .bind(dns_provider_to_str(provider))
        .bind(token)
        .bind(created_at.to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

/// Seeds a `"default"` credential from `config.toml`'s legacy
/// `acme.dns_provider`/`acme.dns_api_token` fields, called once at
/// startup (see `main.rs`) whenever `dns_api_token` is non-blank.
/// `INSERT OR IGNORE` on the UNIQUE `name` column makes this idempotent
/// across restarts, and -- deliberately -- never overwrites a row that
/// already exists (an admin may have renamed or edited it since; the DB
/// is the source of truth once a row exists at all).
pub async fn seed_default_dns_credential(pool: &SqlitePool, provider: DnsProviderKind, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO dns_credentials (id, name, provider, token, created_at) VALUES (?, 'default', ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(dns_provider_to_str(provider))
        .bind(token)
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_dns_credentials(pool: &SqlitePool) -> Result<Vec<DnsCredentialMeta>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, name, provider, created_at FROM dns_credentials ORDER BY created_at ASC")
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(DnsCredentialMeta {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or_else(|_| Uuid::new_v4()),
                name: row.get("name"),
                provider: dns_provider_from_str(&row.get::<String, _>("provider")),
                created_at: parse_rfc3339(&row.get::<String, _>("created_at")),
            })
        })
        .collect()
}

pub async fn get_dns_credential(pool: &SqlitePool, id: Uuid) -> Result<Option<DnsCredential>, sqlx::Error> {
    let row = sqlx::query("SELECT id, name, provider, token, created_at FROM dns_credentials WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| DnsCredential {
        id,
        name: row.get("name"),
        provider: dns_provider_from_str(&row.get::<String, _>("provider")),
        token: row.get("token"),
        created_at: parse_rfc3339(&row.get::<String, _>("created_at")),
    }))
}

pub async fn dns_credential_name_exists(pool: &SqlitePool, name: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT 1 FROM dns_credentials WHERE name = ?").bind(name).fetch_optional(pool).await?;
    Ok(row.is_some())
}

pub async fn delete_dns_credential(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM dns_credentials WHERE id = ?").bind(id.to_string()).execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

#[derive(Debug, Clone)]
pub struct StandaloneCert {
    pub id: Uuid,
    pub domain: String,
    pub dns_credential_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    /// Whatever was actually requested in the CSR at issuance time --
    /// stored (not re-resolved against `acme.organization`/
    /// `organizational_unit` on every renewal) so a renewal keeps
    /// requesting the exact same Subject the cert was originally issued
    /// with, even if the global config default changes later.
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn create_standalone_cert(
    pool: &SqlitePool,
    id: Uuid,
    domain: &str,
    dns_credential_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    organization: Option<&str>,
    organizational_unit: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO standalone_certs (id, domain, dns_credential_id, created_at, organization, organizational_unit) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(id.to_string())
        .bind(domain)
        .bind(dns_credential_id.map(|id| id.to_string()))
        .bind(created_at.to_rfc3339())
        .bind(organization)
        .bind(organizational_unit)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_standalone_certs(pool: &SqlitePool) -> Result<Vec<StandaloneCert>, sqlx::Error> {
    let rows =
        sqlx::query("SELECT id, domain, dns_credential_id, created_at, organization, organizational_unit FROM standalone_certs ORDER BY created_at ASC").fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            Ok(StandaloneCert {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap_or_else(|_| Uuid::new_v4()),
                domain: row.get("domain"),
                dns_credential_id: row.get::<Option<String>, _>("dns_credential_id").and_then(|s| Uuid::parse_str(&s).ok()),
                created_at: parse_rfc3339(&row.get::<String, _>("created_at")),
                organization: row.get("organization"),
                organizational_unit: row.get("organizational_unit"),
            })
        })
        .collect()
}

pub async fn standalone_cert_domain_exists(pool: &SqlitePool, domain: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT 1 FROM standalone_certs WHERE domain = ?").bind(domain).fetch_optional(pool).await?;
    Ok(row.is_some())
}

pub async fn delete_standalone_cert(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM standalone_certs WHERE id = ?").bind(id.to_string()).execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

fn acl_kind_to_str(kind: AclKind) -> &'static str {
    match kind {
        AclKind::IpAllow => "ip_allow",
        AclKind::Login => "login",
    }
}

fn acl_kind_from_str(s: &str) -> AclKind {
    match s {
        "login" => AclKind::Login,
        _ => AclKind::IpAllow,
    }
}

pub async fn create_acl_list(pool: &SqlitePool, id: Uuid, name: &str, kind: AclKind, created_at: DateTime<Utc>) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO acl_lists (id, name, kind, created_at) VALUES (?, ?, ?, ?)")
        .bind(id.to_string())
        .bind(name)
        .bind(acl_kind_to_str(kind))
        .bind(created_at.to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn add_acl_ip_entries(pool: &SqlitePool, acl_list_id: Uuid, cidrs: &[String]) -> Result<(), sqlx::Error> {
    for cidr in cidrs {
        sqlx::query("INSERT INTO acl_ip_entries (id, acl_list_id, cidr) VALUES (?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(acl_list_id.to_string())
            .bind(cidr)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// `credentials` is `(username, password_hash)` pairs -- hashing
/// happens at the API layer, same as every other credential this
/// project stores (admin identity, host logins before this replaced
/// them).
pub async fn add_acl_credentials(pool: &SqlitePool, acl_list_id: Uuid, credentials: &[(String, String)]) -> Result<(), sqlx::Error> {
    for (username, password_hash) in credentials {
        sqlx::query("INSERT INTO acl_credentials (id, acl_list_id, username, password_hash) VALUES (?, ?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(acl_list_id.to_string())
            .bind(username)
            .bind(password_hash)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn list_acl_lists(pool: &SqlitePool) -> Result<Vec<AclList>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, name, kind, created_at FROM acl_lists ORDER BY created_at ASC").fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            Ok(AclList {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap_or_else(|_| Uuid::new_v4()),
                name: row.get("name"),
                kind: acl_kind_from_str(&row.get::<String, _>("kind")),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at")).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
            })
        })
        .collect()
}

pub async fn acl_list_name_exists(pool: &SqlitePool, name: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT 1 FROM acl_lists WHERE name = ?").bind(name).fetch_optional(pool).await?;
    Ok(row.is_some())
}

/// Deletes the list and its entries. Doesn't check whether any host
/// still references it by id -- see `api::routes::delete_acl_list`,
/// which refuses the request at the API layer while any live host's
/// `acl_ids` still contains it, the same guard already used for DNS
/// credentials.
pub async fn delete_acl_list(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM acl_lists WHERE id = ?").bind(id.to_string()).execute(pool).await?;
    let deleted = result.rows_affected() > 0;
    if deleted {
        sqlx::query("DELETE FROM acl_ip_entries WHERE acl_list_id = ?").bind(id.to_string()).execute(pool).await?;
        sqlx::query("DELETE FROM acl_credentials WHERE acl_list_id = ?").bind(id.to_string()).execute(pool).await?;
    }
    Ok(deleted)
}

/// What a host with `acl_ids` selected actually resolves to at request
/// time -- the union of every selected `IpAllow` list's CIDRs, and the
/// union of every selected `Login` list's credentials. Both empty means
/// no restriction of that kind at all (matches the pre-ACL-system
/// default of "empty access_allow_ips/no access_login").
#[derive(Debug, Default, Clone)]
pub struct ResolvedAcls {
    pub allow_ips: Vec<ipnet::Ipv4Net>,
    pub credentials: Vec<HostAuth>,
}

pub async fn resolve_acl_ids(pool: &SqlitePool, acl_ids: &[Uuid]) -> Result<ResolvedAcls, sqlx::Error> {
    let mut resolved = ResolvedAcls::default();
    for &acl_id in acl_ids {
        let Some(list_row) = sqlx::query("SELECT kind FROM acl_lists WHERE id = ?").bind(acl_id.to_string()).fetch_optional(pool).await? else {
            // Referenced by a host but the list itself was deleted out
            // from under it (shouldn't normally happen -- delete_acl_list
            // is guarded at the API layer -- but a dangling id must never
            // silently grant access, only ever silently contribute
            // nothing).
            continue;
        };
        match acl_kind_from_str(&list_row.get::<String, _>("kind")) {
            AclKind::IpAllow => {
                let rows = sqlx::query("SELECT cidr FROM acl_ip_entries WHERE acl_list_id = ?").bind(acl_id.to_string()).fetch_all(pool).await?;
                resolved.allow_ips.extend(rows.into_iter().filter_map(|r| r.get::<String, _>("cidr").parse::<ipnet::Ipv4Net>().ok()));
            }
            AclKind::Login => {
                let rows = sqlx::query("SELECT username, password_hash FROM acl_credentials WHERE acl_list_id = ?")
                    .bind(acl_id.to_string())
                    .fetch_all(pool)
                    .await?;
                resolved.credentials.extend(rows.into_iter().map(|r| HostAuth {
                    username: r.get("username"),
                    password_hash: r.get("password_hash"),
                }));
            }
        }
    }
    Ok(resolved)
}

pub struct AdminIdentityRow {
    pub username: String,
    pub password_hash: String,
    pub session_secret: String,
}

pub async fn load_admin_identity(pool: &SqlitePool) -> Result<Option<AdminIdentityRow>, sqlx::Error> {
    let row = sqlx::query("SELECT username, password_hash, session_secret FROM admin_identity WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| AdminIdentityRow {
        username: r.get("username"),
        password_hash: r.get("password_hash"),
        session_secret: r.get("session_secret"),
    }))
}

/// `ON CONFLICT(id) DO NOTHING` -- used by the first-launch setup
/// wizard (`POST /api/setup`), where two concurrent requests both
/// observing `state.admin_identity() == None` must not both succeed
/// (the second one silently overwriting the first's account, or the
/// first's already-issued session becoming invalid underneath it).
/// Returns whether this call actually created the row: the DB's own
/// uniqueness (the `CHECK (id = 1)` single-row constraint) is the race-free
/// arbiter, not the caller's earlier `admin_identity()` read.
pub async fn create_admin_identity_if_absent(pool: &SqlitePool, username: &str, password_hash: &str, session_secret: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO admin_identity (id, username, password_hash, session_secret) VALUES (1, ?, ?, ?) \
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(username)
    .bind(password_hash)
    .bind(session_secret)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn load_acme_contact_email(pool: &SqlitePool) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT contact_email FROM acme_settings WHERE id = 1").fetch_optional(pool).await?;
    Ok(row.map(|r| r.get("contact_email")))
}

/// Upserts the single settings row -- unlike `create_admin_identity_if_absent`
/// this is meant to be changeable after first set (an operator revising
/// a typo'd or outdated contact email), so a plain `INSERT ... ON
/// CONFLICT(id) DO UPDATE` replaces it every call rather than only ever
/// writing once.
pub async fn set_acme_contact_email(pool: &SqlitePool, email: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO acme_settings (id, contact_email) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET contact_email = excluded.contact_email")
        .bind(email)
        .execute(pool)
        .await?;
    Ok(())
}

/// One-time upgrade path: any host with pre-ACL-system inline
/// `access_allow_ips`/`access_login_*` data (from before the reusable
/// ACL system existed) gets that data preserved as a dedicated,
/// auto-created per-host ACL (named `"<domain> (migrated)"`) instead of
/// silently losing its access control on upgrade. Only touches hosts
/// whose `acl_ids` is still empty (the column's own default), so this
/// is safe to run on every startup -- a host only ever gets migrated
/// once, even though the legacy columns are deliberately left populated
/// afterward (see `run_migrations`'s comment on why they're not dropped).
async fn migrate_legacy_host_access(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, domain, access_allow_ips, access_login_username, access_login_password_hash \
         FROM hosts WHERE acl_ids = '' AND (access_allow_ips != '' OR access_login_username IS NOT NULL)",
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let host_id: String = row.get("id");
        let domain: String = row.get("domain");
        let allow_ips: String = row.get("access_allow_ips");
        let login_username: Option<String> = row.get("access_login_username");
        let login_password_hash: Option<String> = row.get("access_login_password_hash");

        let mut new_acl_ids = Vec::new();

        if !allow_ips.is_empty() {
            let acl_id = Uuid::new_v4();
            create_acl_list(pool, acl_id, &format!("{domain} (migrated)"), AclKind::IpAllow, Utc::now()).await?;
            let cidrs: Vec<String> = allow_ips.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
            add_acl_ip_entries(pool, acl_id, &cidrs).await?;
            new_acl_ids.push(acl_id);
        }

        if let (Some(username), Some(password_hash)) = (login_username, login_password_hash) {
            let acl_id = Uuid::new_v4();
            create_acl_list(pool, acl_id, &format!("{domain} (migrated login)"), AclKind::Login, Utc::now()).await?;
            add_acl_credentials(pool, acl_id, &[(username, password_hash)]).await?;
            new_acl_ids.push(acl_id);
        }

        let acl_ids_csv = new_acl_ids.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
        sqlx::query("UPDATE hosts SET acl_ids = ? WHERE id = ?")
            .bind(acl_ids_csv)
            .bind(host_id)
            .execute(pool)
            .await?;
        tracing::info!(domain, "migrated legacy per-host access control into a new ACL");
    }
    Ok(())
}

pub async fn load_hosts(pool: &SqlitePool) -> Result<Vec<ProxyHost>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, domain, bind_ip, bind_port, upstream, upstream_https, upstream_tls_verify, upstream_preserve_host, websockets, force_https, acme_enabled, acme_challenge_type, \
         acl_ids, redirect_target, redirect_preserve_path, redirect_status, dns_credential_id, enabled FROM hosts",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let challenge_type = match row.get::<String, _>("acme_challenge_type").as_str() {
                "http01" => AcmeChallengeType::Http01,
                "dns01" => AcmeChallengeType::Dns01,
                _ => AcmeChallengeType::Auto,
            };
            let acl_ids = row
                .get::<String, _>("acl_ids")
                .split(',')
                .filter(|s| !s.is_empty())
                .filter_map(|s| Uuid::parse_str(s).ok())
                .collect();
            let redirect = row.get::<Option<String>, _>("redirect_target").map(|target| RedirectTarget {
                target,
                preserve_path: row.get::<i64, _>("redirect_preserve_path") != 0,
                status: match row.get::<String, _>("redirect_status").as_str() {
                    "temporary" => RedirectStatus::Temporary,
                    _ => RedirectStatus::Permanent,
                },
            });
            let dns_credential_id = row.get::<Option<String>, _>("dns_credential_id").and_then(|s| Uuid::parse_str(&s).ok());
            Ok(ProxyHost {
                id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or_else(|_| uuid::Uuid::new_v4()),
                domain: row.get("domain"),
                bind_ip: row.get::<String, _>("bind_ip").parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
                bind_port: row.get::<i64, _>("bind_port") as u16,
                upstream: row.get("upstream"),
                upstream_https: row.get::<i64, _>("upstream_https") != 0,
                upstream_tls_verify: row.get::<i64, _>("upstream_tls_verify") != 0,
                upstream_preserve_host: row.get::<i64, _>("upstream_preserve_host") != 0,
                websockets: row.get::<i64, _>("websockets") != 0,
                force_https: row.get::<i64, _>("force_https") != 0,
                acme_enabled: row.get::<i64, _>("acme_enabled") != 0,
                acme_challenge_type: challenge_type,
                acl_ids,
                dns_credential_id,
                redirect,
                enabled: row.get::<i64, _>("enabled") != 0,
            })
        })
        .collect()
}

pub async fn save_hosts(pool: &SqlitePool, hosts: &[ProxyHost]) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM hosts").execute(&mut *tx).await?;
    for h in hosts {
        let challenge_type = match h.acme_challenge_type {
            AcmeChallengeType::Auto => "auto",
            AcmeChallengeType::Http01 => "http01",
            AcmeChallengeType::Dns01 => "dns01",
        };
        let acl_ids = h.acl_ids.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
        let (redirect_target, redirect_preserve_path, redirect_status) = match &h.redirect {
            Some(redirect) => (
                Some(redirect.target.as_str()),
                redirect.preserve_path as i64,
                match redirect.status {
                    RedirectStatus::Permanent => "permanent",
                    RedirectStatus::Temporary => "temporary",
                },
            ),
            None => (None, true as i64, "permanent"),
        };
        sqlx::query(
            "INSERT INTO hosts (id, domain, bind_ip, bind_port, upstream, upstream_https, upstream_tls_verify, upstream_preserve_host, websockets, force_https, acme_enabled, \
             acme_challenge_type, acl_ids, redirect_target, redirect_preserve_path, redirect_status, dns_credential_id, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(h.id.to_string())
        .bind(&h.domain)
        .bind(h.bind_ip.to_string())
        .bind(h.bind_port as i64)
        .bind(&h.upstream)
        .bind(h.upstream_https as i64)
        .bind(h.upstream_tls_verify as i64)
        .bind(h.upstream_preserve_host as i64)
        .bind(h.websockets as i64)
        .bind(h.force_https as i64)
        .bind(h.acme_enabled as i64)
        .bind(challenge_type)
        .bind(acl_ids)
        .bind(redirect_target)
        .bind(redirect_preserve_path)
        .bind(redirect_status)
        .bind(h.dns_credential_id.map(|id| id.to_string()))
        .bind(h.enabled as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

pub async fn load_port_rules(pool: &SqlitePool) -> Result<Vec<PortRule>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, bind_ip, port_start, port_end, protocol, description, passthrough_target, enabled FROM port_rules")
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            let protocol = match row.get::<String, _>("protocol").as_str() {
                "udp" => Protocol::Udp,
                _ => Protocol::Tcp,
            };
            Ok(PortRule {
                id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or_else(|_| uuid::Uuid::new_v4()),
                bind_ip: row.get::<String, _>("bind_ip").parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
                port_start: row.get::<i64, _>("port_start") as u16,
                port_end: row.get::<i64, _>("port_end") as u16,
                protocol,
                description: row.get("description"),
                passthrough_target: row.get("passthrough_target"),
                enabled: row.get::<i64, _>("enabled") != 0,
            })
        })
        .collect()
}

pub async fn save_port_rules(pool: &SqlitePool, rules: &[PortRule]) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM port_rules").execute(&mut *tx).await?;
    for r in rules {
        let protocol = match r.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        sqlx::query(
            "INSERT INTO port_rules (id, bind_ip, port_start, port_end, protocol, description, passthrough_target, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(r.id.to_string())
        .bind(r.bind_ip.to_string())
        .bind(r.port_start as i64)
        .bind(r.port_end as i64)
        .bind(protocol)
        .bind(&r.description)
        .bind(&r.passthrough_target)
        .bind(r.enabled as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    async fn memory_pool() -> SqlitePool {
        connect(&PathBuf::from(":memory:")).await.unwrap()
    }

    fn sample_host() -> ProxyHost {
        ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip: "10.0.0.2".parse().unwrap(),
            bind_port: 443,
            upstream: "127.0.0.1:8000".into(),
            upstream_https: false,
            upstream_tls_verify: true,
            upstream_preserve_host: true,
            websockets: true,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: None,
            enabled: true,
        }
    }

    fn sample_rule() -> PortRule {
        PortRule {
            id: Uuid::new_v4(),
            bind_ip: "10.0.0.4".parse().unwrap(),
            port_start: 21115,
            port_end: 21119,
            protocol: Protocol::Tcp,
            description: "rustdesk".into(),
            passthrough_target: Some("127.0.0.1:21115".into()),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn hosts_round_trip_through_sqlite() {
        let pool = memory_pool().await;
        let host = sample_host();
        save_hosts(&pool, std::slice::from_ref(&host)).await.unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].domain, "example.com");
        assert_eq!(loaded[0].id, host.id);
        assert!(loaded[0].websockets);
    }

    #[tokio::test]
    async fn acl_ids_round_trip_through_sqlite() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "test acl", AclKind::IpAllow, Utc::now()).await.unwrap();
        let mut host = sample_host();
        host.acl_ids = vec![acl_id];
        save_hosts(&pool, std::slice::from_ref(&host)).await.unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].acl_ids, host.acl_ids);
    }

    #[tokio::test]
    async fn acl_ids_default_to_unrestricted_when_absent() {
        let pool = memory_pool().await;
        save_hosts(&pool, std::slice::from_ref(&sample_host())).await.unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert!(loaded[0].acl_ids.is_empty());
        assert!(loaded[0].redirect.is_none());
    }

    #[tokio::test]
    async fn redirect_target_round_trips_through_sqlite() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.redirect = Some(RedirectTarget {
            target: "https://new.example.com".into(),
            preserve_path: false,
            status: RedirectStatus::Temporary,
        });
        save_hosts(&pool, std::slice::from_ref(&host)).await.unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].redirect, host.redirect);
    }

    #[tokio::test]
    async fn dns_credential_id_round_trips_through_sqlite() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.dns_credential_id = Some(Uuid::new_v4());
        save_hosts(&pool, std::slice::from_ref(&host)).await.unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].dns_credential_id, host.dns_credential_id);
    }

    #[tokio::test]
    async fn dns_credential_id_defaults_to_none_when_absent() {
        let pool = memory_pool().await;
        save_hosts(&pool, std::slice::from_ref(&sample_host())).await.unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert!(loaded[0].dns_credential_id.is_none());
    }

    #[tokio::test]
    async fn saving_hosts_replaces_the_previous_set() {
        let pool = memory_pool().await;
        save_hosts(&pool, &[sample_host()]).await.unwrap();
        save_hosts(&pool, &[]).await.unwrap();
        assert!(load_hosts(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn port_rules_round_trip_including_protocol_and_passthrough_target() {
        let pool = memory_pool().await;
        let rule = sample_rule();
        save_port_rules(&pool, std::slice::from_ref(&rule)).await.unwrap();

        let loaded = load_port_rules(&pool).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].protocol, Protocol::Tcp);
        assert_eq!(loaded[0].passthrough_target.as_deref(), Some("127.0.0.1:21115"));
        assert_eq!(loaded[0].port_start, 21115);
        assert_eq!(loaded[0].port_end, 21119);
    }

    #[tokio::test]
    async fn port_rule_with_no_passthrough_target_round_trips_as_none() {
        let pool = memory_pool().await;
        let mut rule = sample_rule();
        rule.passthrough_target = None;
        save_port_rules(&pool, &[rule]).await.unwrap();

        let loaded = load_port_rules(&pool).await.unwrap();
        assert_eq!(loaded[0].passthrough_target, None);
    }

    #[tokio::test]
    async fn created_api_token_appears_in_the_list_with_no_last_used_at() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_api_token(&pool, id, "ci pipeline", "hash-of-token", Utc::now()).await.unwrap();

        let tokens = list_api_tokens(&pool).await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].id, id);
        assert_eq!(tokens[0].name, "ci pipeline");
        assert_eq!(tokens[0].last_used_at, None);
    }

    #[tokio::test]
    async fn api_token_is_found_by_its_hash_and_not_by_a_wrong_one() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_api_token(&pool, id, "ci pipeline", "hash-of-token", Utc::now()).await.unwrap();

        assert_eq!(find_api_token_id_by_hash(&pool, "hash-of-token").await.unwrap(), Some(id));
        assert_eq!(find_api_token_id_by_hash(&pool, "wrong-hash").await.unwrap(), None);
    }

    #[tokio::test]
    async fn touching_an_api_token_updates_its_last_used_at() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_api_token(&pool, id, "ci pipeline", "hash-of-token", Utc::now()).await.unwrap();

        let now = Utc::now();
        touch_api_token_last_used(&pool, id, now).await.unwrap();

        let tokens = list_api_tokens(&pool).await.unwrap();
        let last_used = tokens[0].last_used_at.expect("should be set after touch");
        assert_eq!(last_used.timestamp(), now.timestamp());
    }

    #[tokio::test]
    async fn deleting_an_api_token_removes_it_and_reports_whether_it_existed() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_api_token(&pool, id, "ci pipeline", "hash-of-token", Utc::now()).await.unwrap();

        assert!(delete_api_token(&pool, id).await.unwrap());
        assert!(list_api_tokens(&pool).await.unwrap().is_empty());
        assert!(!delete_api_token(&pool, id).await.unwrap(), "deleting again should report nothing was found");
    }

    #[tokio::test]
    async fn dns_credentials_round_trip_through_sqlite() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_dns_credential(&pool, id, "prod-cloudflare", crate::config::DnsProviderKind::Cloudflare, "cf-token-value", Utc::now())
            .await
            .unwrap();

        let metas = list_dns_credentials(&pool).await.unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].id, id);
        assert_eq!(metas[0].name, "prod-cloudflare");
        assert_eq!(metas[0].provider, crate::config::DnsProviderKind::Cloudflare);

        let full = get_dns_credential(&pool, id).await.unwrap().unwrap();
        assert_eq!(full.token, "cf-token-value");
    }

    #[tokio::test]
    async fn dns_credential_not_found_returns_none() {
        let pool = memory_pool().await;
        assert!(get_dns_credential(&pool, Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deleting_a_dns_credential_removes_it_and_reports_whether_it_existed() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_dns_credential(&pool, id, "prod-cloudflare", crate::config::DnsProviderKind::Cloudflare, "cf-token", Utc::now())
            .await
            .unwrap();

        assert!(delete_dns_credential(&pool, id).await.unwrap());
        assert!(list_dns_credentials(&pool).await.unwrap().is_empty());
        assert!(!delete_dns_credential(&pool, id).await.unwrap());
    }

    #[tokio::test]
    async fn dns_credential_name_exists_reflects_current_rows() {
        let pool = memory_pool().await;
        assert!(!dns_credential_name_exists(&pool, "prod-cloudflare").await.unwrap());
        create_dns_credential(&pool, Uuid::new_v4(), "prod-cloudflare", crate::config::DnsProviderKind::Cloudflare, "tok", Utc::now())
            .await
            .unwrap();
        assert!(dns_credential_name_exists(&pool, "prod-cloudflare").await.unwrap());
    }

    #[tokio::test]
    async fn seed_default_dns_credential_is_idempotent_across_restarts() {
        let pool = memory_pool().await;
        seed_default_dns_credential(&pool, crate::config::DnsProviderKind::Hetzner, "hetzner-token").await.unwrap();
        seed_default_dns_credential(&pool, crate::config::DnsProviderKind::Hetzner, "hetzner-token").await.unwrap();

        let metas = list_dns_credentials(&pool).await.unwrap();
        assert_eq!(metas.len(), 1, "seeding twice (e.g. two restarts) must not create a duplicate 'default' row");
        assert_eq!(metas[0].name, "default");
    }

    #[tokio::test]
    async fn seed_default_dns_credential_does_not_overwrite_a_user_renamed_or_edited_default() {
        let pool = memory_pool().await;
        seed_default_dns_credential(&pool, crate::config::DnsProviderKind::Hetzner, "original-token").await.unwrap();
        seed_default_dns_credential(&pool, crate::config::DnsProviderKind::Hetzner, "a-different-token-from-a-later-config-edit")
            .await
            .unwrap();

        let metas = list_dns_credentials(&pool).await.unwrap();
        let full = get_dns_credential(&pool, metas[0].id).await.unwrap().unwrap();
        assert_eq!(full.token, "original-token", "seeding is INSERT OR IGNORE -- the DB row, once created, is the source of truth");
    }

    #[tokio::test]
    async fn admin_identity_round_trips_and_is_none_before_first_save() {
        let pool = memory_pool().await;
        assert!(load_admin_identity(&pool).await.unwrap().is_none());

        create_admin_identity_if_absent(&pool, "admin", "hashed-password", "session-secret").await.unwrap();
        let row = load_admin_identity(&pool).await.unwrap().unwrap();
        assert_eq!(row.username, "admin");
        assert_eq!(row.password_hash, "hashed-password");
        assert_eq!(row.session_secret, "session-secret");
    }

    #[tokio::test]
    async fn create_admin_identity_if_absent_only_ever_creates_the_first_one() {
        let pool = memory_pool().await;
        assert!(create_admin_identity_if_absent(&pool, "admin", "hash-1", "secret-1").await.unwrap());
        assert!(!create_admin_identity_if_absent(&pool, "attacker", "hash-2", "secret-2").await.unwrap());

        let row = load_admin_identity(&pool).await.unwrap().unwrap();
        assert_eq!(row.username, "admin", "the second call must not have overwritten the first");
        assert_eq!(row.password_hash, "hash-1");
    }

    #[tokio::test]
    async fn standalone_cert_organization_and_organizational_unit_round_trip() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_standalone_cert(&pool, id, "*.example.com", None, Utc::now(), Some("Acme Corp"), Some("Platform Engineering")).await.unwrap();

        let certs = list_standalone_certs(&pool).await.unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].organization.as_deref(), Some("Acme Corp"));
        assert_eq!(certs[0].organizational_unit.as_deref(), Some("Platform Engineering"));
    }

    #[tokio::test]
    async fn standalone_cert_organization_and_organizational_unit_default_to_none() {
        let pool = memory_pool().await;
        create_standalone_cert(&pool, Uuid::new_v4(), "*.example.com", None, Utc::now(), None, None).await.unwrap();

        let certs = list_standalone_certs(&pool).await.unwrap();
        assert!(certs[0].organization.is_none());
        assert!(certs[0].organizational_unit.is_none());
    }
}
