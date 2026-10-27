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
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

use crate::api::auth::Role;
use crate::config::{
    AclKind, AclList, AcmeChallengeType, DnsProviderKind, HostAuth, PortRule, Protocol, ProxyHost,
    RedirectStatus, RedirectTarget,
};
use crate::hosting::model::{Allocation, ForwardMode, HostingPool};

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
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    run_migrations(&pool).await?;
    Ok(pool)
}

/// Safely snapshots the whole live DB to `destination` via sqlite's own
/// `VACUUM INTO` -- a full, consistent copy even while the daemon is
/// running and actively writing, unlike a raw file copy (which could
/// catch the DB mid-write, especially under WAL mode, and produce a
/// corrupt copy). `destination` must not already exist; `VACUUM INTO`
/// refuses to overwrite. Used by `rust-proxy backup` (see main.rs),
/// itself driven nightly by `rust-proxy-backup.timer` (see deploy/).
pub async fn backup_to(pool: &SqlitePool, destination: &Path) -> Result<(), sqlx::Error> {
    // `?`-bound VACUUM INTO silently no-ops on this sqlx/libsqlite3-sys
    // combination (confirmed: returns Ok(()) but never writes the file)
    // -- the destination path is escaped by hand instead (doubling any
    // embedded single quotes, the same escaping SQL string literals
    // always use) and interpolated directly.
    let escaped = destination.to_string_lossy().replace('\'', "''");
    sqlx::query(&format!("VACUUM INTO '{escaped}'"))
        .execute(pool)
        .await?;
    Ok(())
}

/// `backup_to` for a database this binary hasn't migrated: opens `source`
/// read-only with no migrations, so a newer binary can test its upgrade
/// on the copy (`rust-proxy check`) without touching the live file.
pub async fn snapshot_unmigrated(source: &Path, destination: &Path) -> Result<(), sqlx::Error> {
    let options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", source.display()))?.read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    backup_to(&pool, destination).await?;
    pool.close().await;
    Ok(())
}

/// Compacts the live DB in place -- unlike `backup_to`'s `VACUUM INTO`
/// (which produces an already-compact *copy*, leaving the live file
/// untouched), a plain `VACUUM` rewrites the live database file itself,
/// reclaiming space freed by deleted rows and dropped columns (e.g. the
/// legacy columns `run_migrations` drops during an upgrade -- `ALTER
/// TABLE ... DROP COLUMN` alone doesn't shrink the file). Always run
/// `backup_to` first when compacting as part of a maintenance job --
/// `VACUUM` rewrites the whole file in place, so a real backup should
/// exist before that begins, not after.
pub async fn vacuum(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("VACUUM").execute(pool).await?;
    Ok(())
}

async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            bind_port INTEGER NOT NULL,
            upstream TEXT NOT NULL,
            upstream_https INTEGER NOT NULL DEFAULT 0,
            upstream_tls_verify INTEGER NOT NULL DEFAULT 1,
            upstream_preserve_host INTEGER NOT NULL DEFAULT 1,
            websockets INTEGER NOT NULL,
            force_https INTEGER NOT NULL,
            acme_enabled INTEGER NOT NULL,
            acme_challenge_type TEXT NOT NULL DEFAULT 'auto',
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
    let _ = sqlx::query(
        "ALTER TABLE hosts ADD COLUMN acme_challenge_type TEXT NOT NULL DEFAULT 'auto'",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN redirect_target TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE hosts ADD COLUMN redirect_preserve_path INTEGER NOT NULL DEFAULT 1",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "ALTER TABLE hosts ADD COLUMN redirect_status TEXT NOT NULL DEFAULT 'permanent'",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN dns_credential_id TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN acl_ids TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN upstream_https INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ =
        sqlx::query("ALTER TABLE hosts ADD COLUMN upstream_tls_verify INTEGER NOT NULL DEFAULT 1")
            .execute(pool)
            .await;
    let _ = sqlx::query(
        "ALTER TABLE hosts ADD COLUMN upstream_preserve_host INTEGER NOT NULL DEFAULT 1",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN bind_ip_v4 TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN bind_ip_v6 TEXT")
        .execute(pool)
        .await;
    // Copy any pre-existing single-family `bind_ip` value (a real
    // column only on a table created before this cleanup -- a fresh
    // install's CREATE TABLE above no longer has it) into `bind_ip_v4`
    // before it's dropped a few lines down, so a pre-existing row's
    // original bind is preserved as its v4 half instead of lost. Errors
    // harmlessly on a fresh table (no such column), same as everything
    // else here.
    let _ = sqlx::query(
        "UPDATE hosts SET bind_ip_v4 = bind_ip WHERE bind_ip_v4 IS NULL AND bind_ip IS NOT NULL",
    )
    .execute(pool)
    .await;
    // Both NULL means no rewrite (ProxyHost.path_rewrite is None); both
    // set together (the API layer never persists just one) means it is.
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN path_rewrite_pattern TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN path_rewrite_replacement TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN static_root TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE hosts ADD COLUMN rewrite_samesite_none_cookies INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "ALTER TABLE hosts ADD COLUMN pass_client_cert_header INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;
    // JSON-encoded `config::DenyFallback`; NULL means none.
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN deny_fallback TEXT")
        .execute(pool)
        .await;
    // JSON-encoded `Vec<config::HostLocation>`; NULL or empty means none.
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN locations TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN block_exploits INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    // JSON-encoded `config::FixedResponse`; NULL means none.
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN fixed_response TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN hsts INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN hsts_subdomains INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE hosts ADD COLUMN rate_limit_per_minute INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN rate_limit_burst INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    // Dead-column cleanup: `bind_ip` (superseded by bind_ip_v4/bind_ip_v6,
    // copied above) and `access_allow_ips`/`access_login_username`/
    // `access_login_password_hash` (superseded by the acl_lists/
    // acl_ip_entries/acl_credentials tables, migrated forward once by
    // the now-removed `migrate_legacy_host_access` -- confirmed zero
    // rows needed it in production before this was written) are real
    // DROP COLUMNs, not just left inert -- sqlite 3.35+ (this project's
    // bundled libsqlite3-sys is well above that) supports it, and a
    // fresh install's CREATE TABLE above never had these columns in the
    // first place, so DROP COLUMN harmlessly errors (ignored, same
    // pattern as every ADD COLUMN above) rather than needing its own
    // "does this column exist" branch.
    let _ = sqlx::query("ALTER TABLE hosts DROP COLUMN bind_ip")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts DROP COLUMN access_allow_ips")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts DROP COLUMN access_login_username")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hosts DROP COLUMN access_login_password_hash")
        .execute(pool)
        .await;

    // Serials of client certificates an OCSP responder has reported
    // revoked. Never pruned: once seen revoked, a cert stays revoked even
    // if the responder later fails or answers differently.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS revoked_client_certs (
            serial TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

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
            cidr TEXT NOT NULL,
            description TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    // Pre-existing table from before `description` existed -- see the
    // `hosts` table's identical comment above for why CREATE TABLE IF NOT
    // EXISTS alone can't backfill an upgrade.
    let _ = sqlx::query("ALTER TABLE acl_ip_entries ADD COLUMN description TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE acl_lists ADD COLUMN global_block INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    // IP-allow list -> the Login list whose credentials may hold a mobile
    // pass for it (see `proxy::mobile_pass`). Additive, like global_block.
    let _ = sqlx::query("ALTER TABLE acl_lists ADD COLUMN mobile_login_acl_id TEXT")
        .execute(pool)
        .await;
    // IP-allow list: whether its mobile passes also open the port rules and
    // hosted ports that select it, at the firewall (off until set).
    let _ = sqlx::query(
        "ALTER TABLE acl_lists ADD COLUMN mobile_pass_firewall INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;
    // Single row: whether mobile passes are turned on (off until set).
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mobile_pass_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asn_prefixes (
            asn INTEGER NOT NULL,
            cidr TEXT NOT NULL,
            PRIMARY KEY (asn, cidr)
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asn_status (
            asn INTEGER PRIMARY KEY,
            attempted_at TEXT NOT NULL,
            fetched_at TEXT,
            prefix_count INTEGER NOT NULL DEFAULT 0,
            error TEXT
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
            password_hash TEXT NOT NULL,
            description TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    let _ = sqlx::query("ALTER TABLE acl_credentials ADD COLUMN description TEXT")
        .execute(pool)
        .await;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acl_client_cert_entries (
            id TEXT PRIMARY KEY,
            acl_list_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS port_rules (
            id TEXT PRIMARY KEY,
            port_start INTEGER NOT NULL,
            port_end INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            description TEXT NOT NULL,
            passthrough_target TEXT,
            enabled INTEGER NOT NULL,
            bind_ip_v4 TEXT,
            bind_ip_v6 TEXT,
            acl_ids TEXT NOT NULL DEFAULT ''
        )
        "#,
    )
    .execute(pool)
    .await?;
    let _ = sqlx::query("ALTER TABLE port_rules ADD COLUMN bind_ip_v4 TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE port_rules ADD COLUMN bind_ip_v6 TEXT")
        .execute(pool)
        .await;
    // See the identical `hosts.bind_ip` comment above -- same
    // copy-then-drop, errors harmlessly on a fresh table.
    let _ = sqlx::query("UPDATE port_rules SET bind_ip_v4 = bind_ip WHERE bind_ip_v4 IS NULL AND bind_ip IS NOT NULL").execute(pool).await;
    // Comma-joined ACL UUIDs -- same convention as hosts.acl_ids above.
    // Only AclKind::IpAllow lists are meaningful here (see PortRule::acl_ids'
    // own doc comment); a Login-kind list stored in here is simply
    // ignored at read time (nftables::sync_once), not rejected -- there's
    // no application layer on a raw port rule to reject it against.
    let _ = sqlx::query("ALTER TABLE port_rules ADD COLUMN acl_ids TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE port_rules DROP COLUMN bind_ip")
        .execute(pool)
        .await;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS hosting_pools (
            name TEXT PRIMARY KEY,
            cidr TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            reserved TEXT NOT NULL DEFAULT '',
            vm_cidr TEXT,
            gateway TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS hosting_allocations (
            id TEXT PRIMARY KEY,
            pool TEXT NOT NULL,
            public_ip TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            customer TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            vm_ip TEXT,
            vm_id INTEGER,
            forward TEXT NOT NULL DEFAULT 'all',
            ports TEXT NOT NULL DEFAULT '[]',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
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

    // Tokens created before roles existed keep full access.
    let _ = sqlx::query("ALTER TABLE api_tokens ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
        .execute(pool)
        .await;

    // Extra admin-UI accounts beside the owner identity (config.toml or the
    // setup wizard), which is never stored here. `role` is one of
    // admin/operator/viewer; `disabled` blocks sign-in without losing the
    // account.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login_at TEXT
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
    let _ = sqlx::query("ALTER TABLE standalone_certs ADD COLUMN organization TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE standalone_certs ADD COLUMN organizational_unit TEXT")
        .execute(pool)
        .await;

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

    // Same single-row/settable-at-runtime pattern as acme_settings above,
    // for `AdminConfig.expose_admin_port` -- only ever consulted by
    // `state::AppState::expose_admin_port` when config.toml's own field
    // is unset (`None`). No row yet means "nothing has overridden the
    // built-in default of true" -- see `load_expose_admin_port`.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS firewall_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            expose_admin_port INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    // Admin UI "lock to" list (JSON array of CIDRs), the DB-backed
    // fallback for `AdminConfig.allowed_ips`. Additive, like host columns.
    let _ = sqlx::query("ALTER TABLE firewall_settings ADD COLUMN admin_allowed_ips TEXT")
        .execute(pool)
        .await;

    // Single-row table holding the Default Site setting as JSON (see
    // `config::DefaultSite`). No row means the built-in default (404).
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS default_site (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            config_json TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Single-row record of a Commercial License key that was validated once
    // against the license store. Purely informational (it drives the About
    // page badge); nothing in the daemon is gated on it.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS commercial_license (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            license_key TEXT NOT NULL,
            licensee TEXT NOT NULL,
            expires_at TEXT,
            lifetime INTEGER NOT NULL,
            validated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Single-row table: where this instance's TrustBridge org lives and
    // the org token that authenticates it (write-only through the API).
    // No row means defaults (public TrustBridge, no token).
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS trustbridge_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            url TEXT NOT NULL,
            org_token TEXT NOT NULL DEFAULT ''
        )
        "#,
    )
    .execute(pool)
    .await?;

    // When non-empty, a client cert must carry exactly this TrustBridge
    // org-id to count as a certificate at all.
    let _ = sqlx::query(
        "ALTER TABLE trustbridge_settings ADD COLUMN required_org_id TEXT NOT NULL DEFAULT ''",
    )
    .execute(pool)
    .await;

    // Single-row table holding the admin-UI/API-managed SIEM forwarding
    // settings as a JSON document (see `config::SiemConfig`) -- only
    // consulted when config.toml has no `[siem]` section. No row means
    // forwarding has never been configured (off).
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS siem_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            config_json TEXT NOT NULL
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
/// includes the hash (nothing outside `find_api_token_by_hash` needs
/// it) or the plaintext (never persisted at all, see `create_api_token`).
pub struct ApiTokenMeta {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// An API token resolved from its hash during authentication.
pub struct ApiTokenAuth {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
}

/// A stored role string, with anything unrecognised treated as the least
/// powerful role rather than the most.
fn role_from_db(s: &str) -> Role {
    Role::parse(s).unwrap_or(Role::Viewer)
}

pub async fn create_api_token(
    pool: &SqlitePool,
    id: Uuid,
    name: &str,
    role: Role,
    token_hash: &str,
    created_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO api_tokens (id, name, role, token_hash, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, NULL)")
        .bind(id.to_string())
        .bind(name)
        .bind(role.as_str())
        .bind(token_hash)
        .bind(created_at.to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_api_tokens(pool: &SqlitePool) -> Result<Vec<ApiTokenMeta>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, name, role, created_at, last_used_at FROM api_tokens ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ApiTokenMeta {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str())
                    .unwrap_or_else(|_| Uuid::new_v4()),
                name: row.get("name"),
                role: role_from_db(&row.get::<String, _>("role")),
                created_at: parse_rfc3339(&row.get::<String, _>("created_at")),
                last_used_at: row
                    .get::<Option<String>, _>("last_used_at")
                    .map(|s| parse_rfc3339(&s)),
            })
        })
        .collect()
}

/// Looks up a token by the hash of its plaintext (never by plaintext
/// itself -- callers hash first, see `api::auth::hash_api_token`).
pub async fn find_api_token_by_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<ApiTokenAuth>, sqlx::Error> {
    let row = sqlx::query("SELECT id, name, role FROM api_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| ApiTokenAuth {
        id: Uuid::parse_str(r.get::<String, _>("id").as_str()).unwrap_or_else(|_| Uuid::new_v4()),
        name: r.get("name"),
        role: role_from_db(&r.get::<String, _>("role")),
    }))
}

/// Best-effort last-used tracking, called on every successful token auth
/// -- a failure here should never fail the request it's just bookkeeping
/// for, so callers log-and-ignore rather than propagate the error.
pub async fn touch_api_token_last_used(
    pool: &SqlitePool,
    id: Uuid,
    when: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
        .bind(when.to_rfc3339())
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_api_token(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM api_tokens WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// An extra admin-UI account. `password_hash` is only ever read back for
/// sign-in and password changes, never returned by the API.
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub disabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for UserRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRow")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"<redacted>")
            .field("role", &self.role)
            .field("disabled", &self.disabled)
            .finish()
    }
}

fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> UserRow {
    UserRow {
        id: Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or_else(|_| Uuid::new_v4()),
        username: row.get("username"),
        password_hash: row.get("password_hash"),
        role: role_from_db(&row.get::<String, _>("role")),
        disabled: row.get::<i64, _>("disabled") != 0,
        created_at: parse_rfc3339(&row.get::<String, _>("created_at")),
        last_login_at: row
            .get::<Option<String>, _>("last_login_at")
            .map(|s| parse_rfc3339(&s)),
    }
}

const USER_COLUMNS: &str = "id, username, password_hash, role, disabled, created_at, last_login_at";

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<UserRow>, sqlx::Error> {
    let rows = sqlx::query(&format!(
        "SELECT {USER_COLUMNS} FROM users ORDER BY username COLLATE NOCASE ASC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(user_from_row).collect())
}

pub async fn find_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    let row = sqlx::query(&format!(
        "SELECT {USER_COLUMNS} FROM users WHERE username = ? COLLATE NOCASE"
    ))
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(user_from_row))
}

pub async fn find_user_by_id(pool: &SqlitePool, id: Uuid) -> Result<Option<UserRow>, sqlx::Error> {
    let row = sqlx::query(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?"))
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(user_from_row))
}

/// Returns `Ok(false)` when the username is already taken (case-insensitively).
pub async fn create_user(
    pool: &SqlitePool,
    id: Uuid,
    username: &str,
    password_hash: &str,
    role: Role,
    created_at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT OR IGNORE INTO users (id, username, password_hash, role, disabled, created_at, last_login_at) \
         SELECT ?, ?, ?, ?, 0, ?, NULL \
         WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = ? COLLATE NOCASE)",
    )
    .bind(id.to_string())
    .bind(username)
    .bind(password_hash)
    .bind(role.as_str())
    .bind(created_at.to_rfc3339())
    .bind(username)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_user(
    pool: &SqlitePool,
    id: Uuid,
    role: Role,
    disabled: bool,
    password_hash: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let result = match password_hash {
        Some(hash) => {
            sqlx::query("UPDATE users SET role = ?, disabled = ?, password_hash = ? WHERE id = ?")
                .bind(role.as_str())
                .bind(disabled as i64)
                .bind(hash)
                .bind(id.to_string())
                .execute(pool)
                .await?
        }
        None => {
            sqlx::query("UPDATE users SET role = ?, disabled = ? WHERE id = ?")
                .bind(role.as_str())
                .bind(disabled as i64)
                .bind(id.to_string())
                .execute(pool)
                .await?
        }
    };
    Ok(result.rows_affected() > 0)
}

pub async fn set_user_password(
    pool: &SqlitePool,
    id: Uuid,
    password_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(password_hash)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn touch_user_last_login(
    pool: &SqlitePool,
    id: Uuid,
    when: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
        .bind(when.to_rfc3339())
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_user(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

fn parse_rfc3339(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
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
pub async fn seed_default_dns_credential(
    pool: &SqlitePool,
    provider: DnsProviderKind,
    token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO dns_credentials (id, name, provider, token, created_at) VALUES (?, 'default', ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(dns_provider_to_str(provider))
        .bind(token)
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_dns_credentials(
    pool: &SqlitePool,
) -> Result<Vec<DnsCredentialMeta>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, name, provider, created_at FROM dns_credentials ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(DnsCredentialMeta {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str())
                    .unwrap_or_else(|_| Uuid::new_v4()),
                name: row.get("name"),
                provider: dns_provider_from_str(&row.get::<String, _>("provider")),
                created_at: parse_rfc3339(&row.get::<String, _>("created_at")),
            })
        })
        .collect()
}

pub async fn get_dns_credential(
    pool: &SqlitePool,
    id: Uuid,
) -> Result<Option<DnsCredential>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, name, provider, token, created_at FROM dns_credentials WHERE id = ?",
    )
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

pub async fn dns_credential_name_exists(
    pool: &SqlitePool,
    name: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT 1 FROM dns_credentials WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

pub async fn delete_dns_credential(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM dns_credentials WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
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
                dns_credential_id: row
                    .get::<Option<String>, _>("dns_credential_id")
                    .and_then(|s| Uuid::parse_str(&s).ok()),
                created_at: parse_rfc3339(&row.get::<String, _>("created_at")),
                organization: row.get("organization"),
                organizational_unit: row.get("organizational_unit"),
            })
        })
        .collect()
}

pub async fn standalone_cert_domain_exists(
    pool: &SqlitePool,
    domain: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT 1 FROM standalone_certs WHERE domain = ?")
        .bind(domain)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

pub async fn delete_standalone_cert(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM standalone_certs WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

fn acl_kind_to_str(kind: AclKind) -> &'static str {
    match kind {
        AclKind::IpAllow => "ip_allow",
        AclKind::Login => "login",
        AclKind::ClientCert => "client_cert",
        AclKind::IpBlock => "ip_block",
    }
}

fn acl_kind_from_str(s: &str) -> AclKind {
    match s {
        "login" => AclKind::Login,
        "client_cert" => AclKind::ClientCert,
        "ip_block" => AclKind::IpBlock,
        _ => AclKind::IpAllow,
    }
}

pub async fn create_acl_list(
    pool: &SqlitePool,
    id: Uuid,
    name: &str,
    kind: AclKind,
    created_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO acl_lists (id, name, kind, created_at) VALUES (?, ?, ?, ?)")
        .bind(id.to_string())
        .bind(name)
        .bind(acl_kind_to_str(kind))
        .bind(created_at.to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn add_acl_ip_entries(
    pool: &SqlitePool,
    acl_list_id: Uuid,
    cidrs: &[String],
) -> Result<(), sqlx::Error> {
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
pub async fn add_acl_credentials(
    pool: &SqlitePool,
    acl_list_id: Uuid,
    credentials: &[(String, String)],
) -> Result<(), sqlx::Error> {
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

/// `subjects` is `(subject, description)` pairs -- bulk-insert path used
/// only by `create_acl_list`, same relationship `add_acl_ip_entries`/
/// `add_acl_credentials` have to their own single-entry counterparts.
pub async fn add_acl_client_cert_entries(
    pool: &SqlitePool,
    acl_list_id: Uuid,
    subjects: &[(String, Option<String>)],
) -> Result<(), sqlx::Error> {
    for (subject, description) in subjects {
        sqlx::query("INSERT INTO acl_client_cert_entries (id, acl_list_id, subject, description) VALUES (?, ?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(acl_list_id.to_string())
            .bind(subject)
            .bind(description.as_deref())
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// A single `AclKind::IpAllow` entry, as returned to the admin UI for
/// per-item display/edit/delete -- unlike the bulk-creation path above,
/// this is used once a list already exists.
#[derive(Debug, Clone, Serialize)]
pub struct AclIpEntry {
    pub id: Uuid,
    pub cidr: String,
    pub description: Option<String>,
}

/// A single `AclKind::Login` credential, deliberately without
/// `password_hash` -- same reasoning as `HostAuth::password_hash` never
/// being serialized back out over the admin API.
#[derive(Debug, Clone, Serialize)]
pub struct AclCredentialSummary {
    pub id: Uuid,
    pub username: String,
    pub description: Option<String>,
}

/// A single `AclKind::ClientCert` allowed-subject entry -- the exact
/// TLS client-cert Subject CN (as `client_cert::client_cert_subject`
/// extracts it) that must match for a presented cert to satisfy this
/// ACL. See `AclKind::ClientCert`'s doc comment: a list with zero of
/// these trusts no certificate.
#[derive(Debug, Clone, Serialize)]
pub struct AclClientCertEntry {
    pub id: Uuid,
    pub subject: String,
    pub description: Option<String>,
}

pub async fn get_acl_list(pool: &SqlitePool, id: Uuid) -> Result<Option<AclList>, sqlx::Error> {
    let row =
        sqlx::query("SELECT id, name, kind, created_at, global_block, mobile_login_acl_id, mobile_pass_firewall FROM acl_lists WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|row| AclList {
        id,
        name: row.get("name"),
        kind: acl_kind_from_str(&row.get::<String, _>("kind")),
        created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        global: row.get::<i64, _>("global_block") != 0,
        mobile_login_acl_id: mobile_login_of(&row),
        mobile_pass_firewall: row.get::<i64, _>("mobile_pass_firewall") != 0,
    }))
}

pub async fn list_acl_ip_entries(
    pool: &SqlitePool,
    acl_list_id: Uuid,
) -> Result<Vec<AclIpEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, cidr, description FROM acl_ip_entries WHERE acl_list_id = ? ORDER BY rowid ASC",
    )
    .bind(acl_list_id.to_string())
    .fetch_all(pool)
    .await?;
    let mut entries = rows
        .into_iter()
        .map(|row| {
            Ok(AclIpEntry {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap_or_else(|_| Uuid::new_v4()),
                cidr: row.get("cidr"),
                description: row.get("description"),
            })
        })
        .collect::<Result<Vec<AclIpEntry>, sqlx::Error>>()?;
    // Sorted by parsed address rather than the raw CIDR string -- plain
    // text sort puts "10.0.0.0/24" before "2.2.2.2/32" (lexicographic:
    // '1' < '2'), which reads as broken to an operator scanning the
    // list. A CIDR that fails to parse (shouldn't happen -- every entry
    // is validated by `normalize_cidr` before insert) sorts last rather
    // than panicking or dropping the row -- `Option::Some(_) < None`
    // reads backwards, so the comparator flips it explicitly instead of
    // relying on `Option`'s own default (`None` first) ordering.
    entries.sort_by(|a, b| {
        let a = a.cidr.parse::<ipnet::IpNet>().ok();
        let b = b.cidr.parse::<ipnet::IpNet>().ok();
        match (a, b) {
            (Some(a), Some(b)) => a.cmp(&b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    Ok(entries)
}

/// Returns the new entry's id -- the API layer echoes it straight back so
/// the just-added row can be targeted by a follow-up edit/delete without a
/// round trip through `list_acl_ip_entries`.
pub async fn add_acl_ip_entry(
    pool: &SqlitePool,
    acl_list_id: Uuid,
    cidr: &str,
    description: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO acl_ip_entries (id, acl_list_id, cidr, description) VALUES (?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(acl_list_id.to_string())
    .bind(cidr)
    .bind(description)
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn update_acl_ip_entry(
    pool: &SqlitePool,
    entry_id: Uuid,
    cidr: &str,
    description: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE acl_ip_entries SET cidr = ?, description = ? WHERE id = ?")
        .bind(cidr)
        .bind(description)
        .bind(entry_id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_acl_ip_entry(pool: &SqlitePool, entry_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM acl_ip_entries WHERE id = ?")
        .bind(entry_id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_acl_credentials(
    pool: &SqlitePool,
    acl_list_id: Uuid,
) -> Result<Vec<AclCredentialSummary>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, username, description FROM acl_credentials WHERE acl_list_id = ? ORDER BY rowid ASC")
        .bind(acl_list_id.to_string())
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(AclCredentialSummary {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap_or_else(|_| Uuid::new_v4()),
                username: row.get("username"),
                description: row.get("description"),
            })
        })
        .collect()
}

pub async fn add_acl_credential(
    pool: &SqlitePool,
    acl_list_id: Uuid,
    username: &str,
    password_hash: &str,
    description: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO acl_credentials (id, acl_list_id, username, password_hash, description) VALUES (?, ?, ?, ?, ?)")
        .bind(id.to_string())
        .bind(acl_list_id.to_string())
        .bind(username)
        .bind(password_hash)
        .bind(description)
        .execute(pool)
        .await?;
    Ok(id)
}

/// `password_hash` of `None` leaves the stored hash untouched -- lets an
/// operator rename a credential's username or change its description
/// without being forced to retype (and re-hash) a password that isn't
/// changing.
pub async fn update_acl_credential(
    pool: &SqlitePool,
    credential_id: Uuid,
    username: &str,
    password_hash: Option<&str>,
    description: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let result = match password_hash {
        Some(hash) => {
            sqlx::query("UPDATE acl_credentials SET username = ?, password_hash = ?, description = ? WHERE id = ?")
                .bind(username)
                .bind(hash)
                .bind(description)
                .bind(credential_id.to_string())
                .execute(pool)
                .await?
        }
        None => {
            sqlx::query("UPDATE acl_credentials SET username = ?, description = ? WHERE id = ?")
                .bind(username)
                .bind(description)
                .bind(credential_id.to_string())
                .execute(pool)
                .await?
        }
    };
    Ok(result.rows_affected() > 0)
}

pub async fn delete_acl_credential(
    pool: &SqlitePool,
    credential_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM acl_credentials WHERE id = ?")
        .bind(credential_id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_acl_client_cert_entries(
    pool: &SqlitePool,
    acl_list_id: Uuid,
) -> Result<Vec<AclClientCertEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, subject, description FROM acl_client_cert_entries WHERE acl_list_id = ? ORDER BY rowid ASC",
    )
    .bind(acl_list_id.to_string())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(AclClientCertEntry {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap_or_else(|_| Uuid::new_v4()),
                subject: row.get("subject"),
                description: row.get("description"),
            })
        })
        .collect()
}

pub async fn add_acl_client_cert_entry(
    pool: &SqlitePool,
    acl_list_id: Uuid,
    subject: &str,
    description: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO acl_client_cert_entries (id, acl_list_id, subject, description) VALUES (?, ?, ?, ?)")
        .bind(id.to_string())
        .bind(acl_list_id.to_string())
        .bind(subject)
        .bind(description)
        .execute(pool)
        .await?;
    Ok(id)
}

pub async fn update_acl_client_cert_entry(
    pool: &SqlitePool,
    entry_id: Uuid,
    subject: &str,
    description: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE acl_client_cert_entries SET subject = ?, description = ? WHERE id = ?")
            .bind(subject)
            .bind(description)
            .bind(entry_id.to_string())
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_acl_client_cert_entry(
    pool: &SqlitePool,
    entry_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM acl_client_cert_entries WHERE id = ?")
        .bind(entry_id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_acl_lists(pool: &SqlitePool) -> Result<Vec<AclList>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, name, kind, created_at, global_block, mobile_login_acl_id, mobile_pass_firewall FROM acl_lists ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(AclList {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap_or_else(|_| Uuid::new_v4()),
                name: row.get("name"),
                kind: acl_kind_from_str(&row.get::<String, _>("kind")),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                global: row.get::<i64, _>("global_block") != 0,
                mobile_login_acl_id: mobile_login_of(&row),
                mobile_pass_firewall: row.get::<i64, _>("mobile_pass_firewall") != 0,
            })
        })
        .collect()
}

fn mobile_login_of(row: &sqlx::sqlite::SqliteRow) -> Option<Uuid> {
    row.get::<Option<String>, _>("mobile_login_acl_id")
        .and_then(|s| Uuid::parse_str(&s).ok())
}

/// Links an IP-allow list to the Login list whose credentials may hold a
/// mobile pass for it (`None` unlinks). False when the list doesn't exist.
pub async fn set_acl_mobile_login(
    pool: &SqlitePool,
    id: Uuid,
    login_acl_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE acl_lists SET mobile_login_acl_id = ? WHERE id = ?")
        .bind(login_acl_id.map(|u| u.to_string()))
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Sets whether an IP-allow list's mobile passes also open the port rules and
/// hosted ports that select it. False when the list doesn't exist.
pub async fn set_acl_mobile_pass_firewall(
    pool: &SqlitePool,
    id: Uuid,
    on: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE acl_lists SET mobile_pass_firewall = ? WHERE id = ?")
        .bind(i64::from(on))
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Every Login list some IP-allow list accepts mobile passes from, with its
/// credentials: what a phone's sign-in is checked against.
pub async fn mobile_pass_logins(
    pool: &SqlitePool,
) -> Result<Vec<(Uuid, Vec<HostAuth>)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT DISTINCT l.id AS id FROM acl_lists a JOIN acl_lists l ON l.id = a.mobile_login_acl_id \
         WHERE a.kind = 'ip_allow' AND l.kind = 'login'",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for row in rows {
        let id: String = row.get("id");
        let Ok(uuid) = Uuid::parse_str(&id) else {
            continue;
        };
        let creds = sqlx::query(
            "SELECT username, password_hash FROM acl_credentials WHERE acl_list_id = ?",
        )
        .bind(&id)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| HostAuth {
            username: r.get("username"),
            password_hash: r.get("password_hash"),
        })
        .collect();
        out.push((uuid, creds));
    }
    Ok(out)
}

/// Whether mobile passes are turned on (off when never set).
pub async fn load_mobile_pass_enabled(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT enabled FROM mobile_pass_settings WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some_and(|r| r.get::<i64, _>("enabled") != 0))
}

pub async fn set_mobile_pass_enabled(pool: &SqlitePool, value: bool) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO mobile_pass_settings (id, enabled) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled")
        .bind(value as i64)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_acl_global(
    pool: &SqlitePool,
    id: Uuid,
    global: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE acl_lists SET global_block = ? WHERE id = ?")
        .bind(global as i64)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Every `IpBlock` list as `(id, global, entries)`, entries being the raw
/// CIDR / `AS<n>` strings.
pub async fn load_block_lists(
    pool: &SqlitePool,
) -> Result<Vec<(Uuid, bool, Vec<String>)>, sqlx::Error> {
    let lists = sqlx::query("SELECT id, global_block FROM acl_lists WHERE kind = 'ip_block'")
        .fetch_all(pool)
        .await?;
    let mut out = Vec::with_capacity(lists.len());
    for row in lists {
        let Ok(id) = Uuid::parse_str(&row.get::<String, _>("id")) else {
            continue;
        };
        let entries = sqlx::query("SELECT cidr FROM acl_ip_entries WHERE acl_list_id = ?")
            .bind(id.to_string())
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|r| r.get::<String, _>("cidr"))
            .collect();
        out.push((id, row.get::<i64, _>("global_block") != 0, entries));
    }
    Ok(out)
}

pub async fn load_asn_prefixes(
    pool: &SqlitePool,
) -> Result<std::collections::HashMap<u32, Vec<String>>, sqlx::Error> {
    let rows = sqlx::query("SELECT asn, cidr FROM asn_prefixes")
        .fetch_all(pool)
        .await?;
    let mut map: std::collections::HashMap<u32, Vec<String>> = std::collections::HashMap::new();
    for r in rows {
        map.entry(r.get::<i64, _>("asn") as u32)
            .or_default()
            .push(r.get("cidr"));
    }
    Ok(map)
}

#[derive(Debug, Clone, Serialize)]
pub struct AsnStatus {
    pub asn: u32,
    pub prefix_count: i64,
    pub fetched_at: Option<String>,
    pub attempted_at: String,
    pub error: Option<String>,
}

pub async fn load_asn_status(pool: &SqlitePool) -> Result<Vec<AsnStatus>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT asn, attempted_at, fetched_at, prefix_count, error FROM asn_status ORDER BY asn",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| AsnStatus {
            asn: r.get::<i64, _>("asn") as u32,
            prefix_count: r.get("prefix_count"),
            fetched_at: r.get("fetched_at"),
            attempted_at: r.get("attempted_at"),
            error: r.get("error"),
        })
        .collect())
}

/// Replaces an AS's stored prefixes with a fresh, non-empty fetch.
pub async fn store_asn_prefixes(
    pool: &SqlitePool,
    asn: u32,
    prefixes: &[String],
) -> Result<(), sqlx::Error> {
    let now = Utc::now().to_rfc3339();
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM asn_prefixes WHERE asn = ?")
        .bind(asn as i64)
        .execute(&mut *tx)
        .await?;
    for p in prefixes {
        sqlx::query("INSERT OR IGNORE INTO asn_prefixes (asn, cidr) VALUES (?, ?)")
            .bind(asn as i64)
            .bind(p)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO asn_status (asn, attempted_at, fetched_at, prefix_count, error) VALUES (?, ?, ?, ?, NULL)
         ON CONFLICT(asn) DO UPDATE SET attempted_at = excluded.attempted_at, fetched_at = excluded.fetched_at,
         prefix_count = excluded.prefix_count, error = NULL",
    )
    .bind(asn as i64)
    .bind(&now)
    .bind(&now)
    .bind(prefixes.len() as i64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// A failed fetch keeps whatever prefixes were stored before.
pub async fn record_asn_failure(
    pool: &SqlitePool,
    asn: u32,
    error: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO asn_status (asn, attempted_at, fetched_at, prefix_count, error) VALUES (?, ?, NULL, 0, ?)
         ON CONFLICT(asn) DO UPDATE SET attempted_at = excluded.attempted_at, error = excluded.error",
    )
    .bind(asn as i64)
    .bind(Utc::now().to_rfc3339())
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn acl_list_name_exists(pool: &SqlitePool, name: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT 1 FROM acl_lists WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

/// Deletes the list and its entries. Doesn't check whether any host
/// still references it by id -- see `api::routes::delete_acl_list`,
/// which refuses the request at the API layer while any live host's
/// `acl_ids` still contains it, the same guard already used for DNS
/// credentials.
pub async fn delete_acl_list(pool: &SqlitePool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM acl_lists WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    let deleted = result.rows_affected() > 0;
    if deleted {
        sqlx::query("DELETE FROM acl_ip_entries WHERE acl_list_id = ?")
            .bind(id.to_string())
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM acl_credentials WHERE acl_list_id = ?")
            .bind(id.to_string())
            .execute(pool)
            .await?;
    }
    Ok(deleted)
}

/// What a host with `acl_ids` selected actually resolves to at request
/// time -- the union of every selected `IpAllow` list's CIDRs, and the
/// union of every selected `Login` list's credentials. Both empty means
/// no restriction of that kind at all (matches the pre-ACL-system
/// default of "empty access_allow_ips/no access_login"). `has_ip_allow_acl`/
/// `has_login_acl` track whether a list of that *kind* was selected at
/// all, independent of whether it currently has any entries -- needed
/// because `proxy::mod::handle_https_request`'s IP-over-login combination
/// (an IP-allow ACL that matches admits the request outright, one that
/// doesn't match falls through to the login gate instead of a bare 403,
/// same as it always has when only one kind of ACL is configured) has to
/// tell "no IP-allow ACL was ever selected" apart from "one was selected
/// but happens to have zero entries right now" -- `allow_ips.is_empty()`
/// alone can't distinguish those two cases.
#[derive(Debug, Default, Clone)]
pub struct ResolvedAcls {
    pub allow_ips: Vec<ipnet::IpNet>,
    pub credentials: Vec<HostAuth>,
    pub has_ip_allow_acl: bool,
    pub has_login_acl: bool,
    /// Set once any selected `ClientCert`-kind list exists, regardless
    /// of whether it has entries -- see `config::AclKind::ClientCert`'s
    /// doc comment.
    pub has_client_cert_acl: bool,
    /// Every subject entry across every selected `ClientCert`-kind
    /// list. The presented subject must be one of these to satisfy the
    /// gate, so empty means no certificate is trusted.
    pub allowed_client_cert_subjects: Vec<String>,
    /// Login lists whose mobile passes count as inside the selected
    /// IP-allow lists (see `proxy::mobile_pass`).
    pub mobile_login_lists: Vec<Uuid>,
    /// The subset of `mobile_login_lists` whose IP-allow list also opens
    /// the firewall for passes (`AclList::mobile_pass_firewall`).
    pub firewall_mobile_login_lists: Vec<Uuid>,
}

pub async fn resolve_acl_ids(
    pool: &SqlitePool,
    acl_ids: &[Uuid],
) -> Result<ResolvedAcls, sqlx::Error> {
    let mut resolved = ResolvedAcls::default();
    for &acl_id in acl_ids {
        let Some(list_row) = sqlx::query("SELECT kind FROM acl_lists WHERE id = ?")
            .bind(acl_id.to_string())
            .fetch_optional(pool)
            .await?
        else {
            // Referenced by a host but the list itself was deleted out
            // from under it (shouldn't normally happen -- delete_acl_list
            // is guarded at the API layer -- but a dangling id must never
            // silently grant access, only ever silently contribute
            // nothing).
            continue;
        };
        match acl_kind_from_str(&list_row.get::<String, _>("kind")) {
            AclKind::IpAllow => {
                resolved.has_ip_allow_acl = true;
                if let Ok(Some(row)) = sqlx::query(
                    "SELECT mobile_login_acl_id, mobile_pass_firewall FROM acl_lists WHERE id = ?",
                )
                .bind(acl_id.to_string())
                .fetch_optional(pool)
                .await
                    && let Some(login) = mobile_login_of(&row)
                {
                    resolved.mobile_login_lists.push(login);
                    if row.get::<i64, _>("mobile_pass_firewall") != 0 {
                        resolved.firewall_mobile_login_lists.push(login);
                    }
                }
                let rows = sqlx::query("SELECT cidr FROM acl_ip_entries WHERE acl_list_id = ?")
                    .bind(acl_id.to_string())
                    .fetch_all(pool)
                    .await?;
                resolved.allow_ips.extend(
                    rows.into_iter()
                        .filter_map(|r| r.get::<String, _>("cidr").parse::<ipnet::IpNet>().ok()),
                );
            }
            AclKind::Login => {
                resolved.has_login_acl = true;
                let rows = sqlx::query(
                    "SELECT username, password_hash FROM acl_credentials WHERE acl_list_id = ?",
                )
                .bind(acl_id.to_string())
                .fetch_all(pool)
                .await?;
                resolved
                    .credentials
                    .extend(rows.into_iter().map(|r| HostAuth {
                        username: r.get("username"),
                        password_hash: r.get("password_hash"),
                    }));
            }
            // Deny lists are evaluated from the in-memory block index.
            AclKind::IpBlock => {}
            AclKind::ClientCert => {
                resolved.has_client_cert_acl = true;
                let rows = sqlx::query(
                    "SELECT subject FROM acl_client_cert_entries WHERE acl_list_id = ?",
                )
                .bind(acl_id.to_string())
                .fetch_all(pool)
                .await?;
                resolved
                    .allowed_client_cert_subjects
                    .extend(rows.into_iter().map(|r| r.get::<String, _>("subject")));
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

pub async fn load_admin_identity(
    pool: &SqlitePool,
) -> Result<Option<AdminIdentityRow>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT username, password_hash, session_secret FROM admin_identity WHERE id = 1",
    )
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
pub async fn create_admin_identity_if_absent(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
    session_secret: &str,
) -> Result<bool, sqlx::Error> {
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
    let row = sqlx::query("SELECT contact_email FROM acme_settings WHERE id = 1")
        .fetch_optional(pool)
        .await?;
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

/// `None` means nothing has ever overridden the built-in default (see
/// `state::AppState::expose_admin_port`, which treats `None` here as `true`).
pub async fn load_expose_admin_port(pool: &SqlitePool) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query("SELECT expose_admin_port FROM firewall_settings WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<i64, _>("expose_admin_port") != 0))
}

/// Same upsert-a-single-row pattern as `set_acme_contact_email`.
pub async fn set_expose_admin_port(pool: &SqlitePool, value: bool) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO firewall_settings (id, expose_admin_port) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET expose_admin_port = excluded.expose_admin_port")
        .bind(value as i64)
        .execute(pool)
        .await?;
    Ok(())
}

/// The DB-backed admin "lock to" list (empty when never set).
pub async fn load_admin_allowed_ips(pool: &SqlitePool) -> Result<Vec<ipnet::IpNet>, sqlx::Error> {
    let row = sqlx::query("SELECT admin_allowed_ips FROM firewall_settings WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    let json: Option<String> = row.and_then(|r| r.get("admin_allowed_ips"));
    Ok(json
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default())
}

pub async fn set_admin_allowed_ips(
    pool: &SqlitePool,
    ips: &[ipnet::IpNet],
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_string(ips).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    sqlx::query("INSERT INTO firewall_settings (id, expose_admin_port, admin_allowed_ips) VALUES (1, 1, ?) ON CONFLICT(id) DO UPDATE SET admin_allowed_ips = excluded.admin_allowed_ips")
        .bind(json)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load_default_site(
    pool: &SqlitePool,
) -> Result<Option<crate::config::DefaultSite>, sqlx::Error> {
    let row = sqlx::query("SELECT config_json FROM default_site WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let json: String = row.get("config_json");
    match serde_json::from_str(&json) {
        Ok(cfg) => Ok(Some(cfg)),
        Err(err) => {
            tracing::error!(error = %err, "stored default_site row is unreadable -- using the built-in 404");
            Ok(None)
        }
    }
}

pub async fn set_default_site(
    pool: &SqlitePool,
    cfg: &crate::config::DefaultSite,
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_string(cfg).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    sqlx::query("INSERT INTO default_site (id, config_json) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json")
        .bind(json)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommercialLicense {
    pub license_key: String,
    pub licensee: String,
    pub expires_at: Option<String>,
    pub lifetime: bool,
    pub validated_at: String,
}

pub async fn load_commercial_license(
    pool: &SqlitePool,
) -> Result<Option<CommercialLicense>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT license_key, licensee, expires_at, lifetime, validated_at FROM commercial_license WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| CommercialLicense {
        license_key: row.get("license_key"),
        licensee: row.get("licensee"),
        expires_at: row.get("expires_at"),
        lifetime: row.get::<i64, _>("lifetime") != 0,
        validated_at: row.get("validated_at"),
    }))
}

pub async fn set_commercial_license(
    pool: &SqlitePool,
    lic: &CommercialLicense,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO commercial_license (id, license_key, licensee, expires_at, lifetime, validated_at) VALUES (1, ?, ?, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET license_key = excluded.license_key, licensee = excluded.licensee, expires_at = excluded.expires_at, lifetime = excluded.lifetime, validated_at = excluded.validated_at",
    )
    .bind(&lic.license_key)
    .bind(&lic.licensee)
    .bind(&lic.expires_at)
    .bind(lic.lifetime as i64)
    .bind(&lic.validated_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn clear_commercial_license(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM commercial_license WHERE id = 1")
        .execute(pool)
        .await?;
    Ok(())
}

/// `(url, org_token)`; `None` when never configured.
pub async fn load_trustbridge_settings(
    pool: &SqlitePool,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query("SELECT url, org_token FROM trustbridge_settings WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| (r.get("url"), r.get("org_token"))))
}

pub async fn set_trustbridge_settings(
    pool: &SqlitePool,
    url: &str,
    org_token: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO trustbridge_settings (id, url, org_token) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET url = excluded.url, org_token = excluded.org_token")
        .bind(url)
        .bind(org_token)
        .execute(pool)
        .await?;
    Ok(())
}

/// The org-id every client cert must carry; `None` when not locked.
pub async fn load_required_org_id(pool: &SqlitePool) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT required_org_id FROM trustbridge_settings WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row
        .map(|r| r.get::<String, _>("required_org_id"))
        .filter(|s| !s.is_empty()))
}

/// Needs the settings row to exist (`set_trustbridge_settings` creates it).
pub async fn set_required_org_id(pool: &SqlitePool, org_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE trustbridge_settings SET required_org_id = ? WHERE id = 1")
        .bind(org_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load_siem_settings(
    pool: &SqlitePool,
) -> Result<Option<crate::config::SiemConfig>, sqlx::Error> {
    let row = sqlx::query("SELECT config_json FROM siem_settings WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let json: String = row.get("config_json");
    match serde_json::from_str(&json) {
        Ok(cfg) => Ok(Some(cfg)),
        Err(err) => {
            tracing::error!(error = %err, "stored siem_settings row is unreadable -- treating SIEM forwarding as unconfigured");
            Ok(None)
        }
    }
}

pub async fn set_siem_settings(
    pool: &SqlitePool,
    cfg: &crate::config::SiemConfig,
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_string(cfg).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    sqlx::query("INSERT INTO siem_settings (id, config_json) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json")
        .bind(json)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load_hosts(pool: &SqlitePool) -> Result<Vec<ProxyHost>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, domain, bind_ip_v4, bind_ip_v6, bind_port, upstream, upstream_https, upstream_tls_verify, upstream_preserve_host, websockets, force_https, acme_enabled, acme_challenge_type, \
         acl_ids, redirect_target, redirect_preserve_path, redirect_status, dns_credential_id, path_rewrite_pattern, path_rewrite_replacement, static_root, rewrite_samesite_none_cookies, pass_client_cert_header, deny_fallback, locations, block_exploits, fixed_response, hsts, hsts_subdomains, rate_limit_per_minute, rate_limit_burst, enabled FROM hosts",
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
            let redirect = row
                .get::<Option<String>, _>("redirect_target")
                .map(|target| RedirectTarget {
                    target,
                    preserve_path: row.get::<i64, _>("redirect_preserve_path") != 0,
                    status: match row.get::<String, _>("redirect_status").as_str() {
                        "temporary" => RedirectStatus::Temporary,
                        _ => RedirectStatus::Permanent,
                    },
                });
            let dns_credential_id = row
                .get::<Option<String>, _>("dns_credential_id")
                .and_then(|s| Uuid::parse_str(&s).ok());
            let path_rewrite = match (
                row.get::<Option<String>, _>("path_rewrite_pattern"),
                row.get::<Option<String>, _>("path_rewrite_replacement"),
            ) {
                (Some(pattern), Some(replacement)) => Some(crate::config::PathRewrite {
                    pattern,
                    replacement,
                }),
                _ => None,
            };
            Ok(ProxyHost {
                id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str())
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                domain: row.get("domain"),
                bind_ip_v4: row
                    .get::<Option<String>, _>("bind_ip_v4")
                    .and_then(|s| s.parse().ok()),
                bind_ip_v6: row
                    .get::<Option<String>, _>("bind_ip_v6")
                    .and_then(|s| s.parse().ok()),
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
                path_rewrite,
                static_root: row
                    .get::<Option<String>, _>("static_root")
                    .map(std::path::PathBuf::from),
                rewrite_samesite_none_cookies: row.get::<i64, _>("rewrite_samesite_none_cookies")
                    != 0,
                pass_client_cert_header: row.get::<i64, _>("pass_client_cert_header") != 0,
                deny_fallback: row
                    .get::<Option<String>, _>("deny_fallback")
                    .and_then(|s| serde_json::from_str(&s).ok()),
                locations: row
                    .get::<Option<String>, _>("locations")
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                block_exploits: row.get::<i64, _>("block_exploits") != 0,
                fixed_response: row
                    .get::<Option<String>, _>("fixed_response")
                    .and_then(|s| serde_json::from_str(&s).ok()),
                hsts: row.get::<i64, _>("hsts") != 0,
                hsts_subdomains: row.get::<i64, _>("hsts_subdomains") != 0,
                rate_limit_per_minute: row
                    .get::<i64, _>("rate_limit_per_minute")
                    .clamp(0, u32::MAX as i64) as u32,
                rate_limit_burst: row
                    .get::<i64, _>("rate_limit_burst")
                    .clamp(0, u32::MAX as i64) as u32,
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
        let acl_ids = h
            .acl_ids
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",");
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
        let (path_rewrite_pattern, path_rewrite_replacement) = match &h.path_rewrite {
            Some(pr) => (Some(pr.pattern.as_str()), Some(pr.replacement.as_str())),
            None => (None, None),
        };
        sqlx::query(
            "INSERT INTO hosts (id, domain, bind_ip_v4, bind_ip_v6, bind_port, upstream, upstream_https, upstream_tls_verify, upstream_preserve_host, websockets, force_https, acme_enabled, \
             acme_challenge_type, acl_ids, redirect_target, redirect_preserve_path, redirect_status, dns_credential_id, path_rewrite_pattern, path_rewrite_replacement, static_root, rewrite_samesite_none_cookies, pass_client_cert_header, deny_fallback, locations, block_exploits, fixed_response, hsts, hsts_subdomains, rate_limit_per_minute, rate_limit_burst, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(h.id.to_string())
        .bind(&h.domain)
        .bind(h.bind_ip_v4.map(|ip| ip.to_string()))
        .bind(h.bind_ip_v6.map(|ip| ip.to_string()))
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
        .bind(path_rewrite_pattern)
        .bind(path_rewrite_replacement)
        .bind(h.static_root.as_ref().map(|p| p.to_string_lossy().to_string()))
        .bind(h.rewrite_samesite_none_cookies as i64)
        .bind(h.pass_client_cert_header as i64)
        .bind(h.deny_fallback.as_ref().and_then(|d| serde_json::to_string(d).ok()))
        .bind(if h.locations.is_empty() { None } else { serde_json::to_string(&h.locations).ok() })
        .bind(h.block_exploits as i64)
        .bind(h.fixed_response.as_ref().and_then(|d| serde_json::to_string(d).ok()))
        .bind(h.hsts as i64)
        .bind(h.hsts_subdomains as i64)
        .bind(h.rate_limit_per_minute as i64)
        .bind(h.rate_limit_burst as i64)
        .bind(h.enabled as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

pub async fn load_port_rules(pool: &SqlitePool) -> Result<Vec<PortRule>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, bind_ip_v4, bind_ip_v6, port_start, port_end, protocol, description, passthrough_target, acl_ids, enabled FROM port_rules")
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|row| {
            let protocol = match row.get::<String, _>("protocol").as_str() {
                "udp" => Protocol::Udp,
                _ => Protocol::Tcp,
            };
            let acl_ids = row
                .get::<String, _>("acl_ids")
                .split(',')
                .filter(|s| !s.is_empty())
                .filter_map(|s| uuid::Uuid::parse_str(s).ok())
                .collect();
            Ok(PortRule {
                id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str())
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                bind_ip_v4: row
                    .get::<Option<String>, _>("bind_ip_v4")
                    .and_then(|s| s.parse().ok()),
                bind_ip_v6: row
                    .get::<Option<String>, _>("bind_ip_v6")
                    .and_then(|s| s.parse().ok()),
                port_start: row.get::<i64, _>("port_start") as u16,
                port_end: row.get::<i64, _>("port_end") as u16,
                protocol,
                description: row.get("description"),
                passthrough_target: row.get("passthrough_target"),
                acl_ids,
                enabled: row.get::<i64, _>("enabled") != 0,
            })
        })
        .collect()
}

pub async fn save_port_rules(pool: &SqlitePool, rules: &[PortRule]) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM port_rules")
        .execute(&mut *tx)
        .await?;
    for r in rules {
        let protocol = match r.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        let acl_ids = r
            .acl_ids
            .iter()
            .map(uuid::Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(
            "INSERT INTO port_rules (id, bind_ip_v4, bind_ip_v6, port_start, port_end, protocol, description, passthrough_target, acl_ids, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(r.id.to_string())
        .bind(r.bind_ip_v4.map(|ip| ip.to_string()))
        .bind(r.bind_ip_v6.map(|ip| ip.to_string()))
        .bind(r.port_start as i64)
        .bind(r.port_end as i64)
        .bind(protocol)
        .bind(&r.description)
        .bind(&r.passthrough_target)
        .bind(acl_ids)
        .bind(r.enabled as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

pub async fn load_hosting_pools(pool: &SqlitePool) -> Result<Vec<HostingPool>, sqlx::Error> {
    let rows = sqlx::query("SELECT name, cidr, description, reserved, vm_cidr, gateway FROM hosting_pools ORDER BY name")
        .fetch_all(pool)
        .await?;
    // A row that no longer parses is skipped rather than aborting startup;
    // the API only ever writes validated values, so this is for manual edits.
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            Some(HostingPool {
                name: row.get("name"),
                cidr: row.get::<String, _>("cidr").parse().ok()?,
                description: row.get("description"),
                reserved: row
                    .get::<String, _>("reserved")
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse().ok())
                    .collect(),
                vm_cidr: row
                    .get::<Option<String>, _>("vm_cidr")
                    .and_then(|s| s.parse().ok()),
                gateway: row
                    .get::<Option<String>, _>("gateway")
                    .and_then(|s| s.parse().ok()),
            })
        })
        .collect())
}

pub async fn load_hosting_allocations(pool: &SqlitePool) -> Result<Vec<Allocation>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, pool, public_ip, name, customer, notes, vm_ip, vm_id, forward, ports, enabled, created_at FROM hosting_allocations ORDER BY public_ip")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            Some(Allocation {
                id: Uuid::parse_str(&row.get::<String, _>("id")).ok()?,
                pool: row.get("pool"),
                public_ip: row.get::<String, _>("public_ip").parse().ok()?,
                name: row.get("name"),
                customer: row.get("customer"),
                notes: row.get("notes"),
                vm_ip: row
                    .get::<Option<String>, _>("vm_ip")
                    .and_then(|s| s.parse().ok()),
                vm_id: row
                    .get::<Option<i64>, _>("vm_id")
                    .and_then(|v| u32::try_from(v).ok()),
                forward: match row.get::<String, _>("forward").as_str() {
                    "ports" => ForwardMode::Ports,
                    _ => ForwardMode::All,
                },
                ports: serde_json::from_str(&row.get::<String, _>("ports")).unwrap_or_default(),
                enabled: row.get::<i64, _>("enabled") != 0,
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .ok()?
                    .with_timezone(&Utc),
            })
        })
        .collect())
}

/// Replaces both hosting tables in one transaction, so a pool and the
/// allocations validated against it can never be persisted half-way.
pub async fn save_hosting(
    pool: &SqlitePool,
    pools: &[HostingPool],
    allocations: &[Allocation],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM hosting_allocations")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM hosting_pools")
        .execute(&mut *tx)
        .await?;
    for p in pools {
        let reserved = p
            .reserved
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query("INSERT INTO hosting_pools (name, cidr, description, reserved, vm_cidr, gateway) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&p.name)
            .bind(p.cidr.to_string())
            .bind(&p.description)
            .bind(reserved)
            .bind(p.vm_cidr.map(|n| n.to_string()))
            .bind(p.gateway.map(|ip| ip.to_string()))
            .execute(&mut *tx)
            .await?;
    }
    for a in allocations {
        let forward = match a.forward {
            ForwardMode::All => "all",
            ForwardMode::Ports => "ports",
        };
        sqlx::query("INSERT INTO hosting_allocations (id, pool, public_ip, name, customer, notes, vm_ip, vm_id, forward, ports, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(a.id.to_string())
            .bind(&a.pool)
            .bind(a.public_ip.to_string())
            .bind(&a.name)
            .bind(&a.customer)
            .bind(&a.notes)
            .bind(a.vm_ip.map(|ip| ip.to_string()))
            .bind(a.vm_id.map(i64::from))
            .bind(forward)
            .bind(serde_json::to_string(&a.ports).unwrap_or_else(|_| "[]".into()))
            .bind(a.enabled as i64)
            .bind(a.created_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosting::model::PortSpec;
    use std::path::PathBuf;
    use uuid::Uuid;

    async fn memory_pool() -> SqlitePool {
        connect(&PathBuf::from(":memory:")).await.unwrap()
    }

    fn sample_host() -> ProxyHost {
        ProxyHost {
            id: Uuid::new_v4(),
            domain: "example.com".into(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
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
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            deny_fallback: None,
            locations: Vec::new(),
            block_exploits: false,
            fixed_response: None,
            hsts: false,
            hsts_subdomains: false,
            rate_limit_per_minute: 0,
            rate_limit_burst: 0,
            pass_client_cert_header: false,
            enabled: true,
        }
    }

    fn sample_rule() -> PortRule {
        PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some("10.0.0.4".parse().unwrap()),
            bind_ip_v6: None,
            port_start: 21115,
            port_end: 21119,
            protocol: Protocol::Tcp,
            description: "rustdesk".into(),
            passthrough_target: Some("127.0.0.1:21115".into()),
            acl_ids: vec![],
            enabled: true,
        }
    }

    #[tokio::test]
    async fn hosts_round_trip_through_sqlite() {
        let pool = memory_pool().await;
        let host = sample_host();
        save_hosts(&pool, std::slice::from_ref(&host))
            .await
            .unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].domain, "example.com");
        assert_eq!(loaded[0].id, host.id);
        assert!(loaded[0].websockets);
        assert!(
            !loaded[0].rewrite_samesite_none_cookies,
            "sample_host()'s default (false) must round-trip too, not just true"
        );
    }

    #[tokio::test]
    async fn deny_fallback_round_trips() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.deny_fallback = Some(crate::config::DenyFallback {
            scope: crate::config::DenyScope::Everyone,
            redirect_path: "/guest/".into(),
            lock: true,
            allow_paths: vec!["/css/".into()],
        });
        save_hosts(&pool, std::slice::from_ref(&host))
            .await
            .unwrap();
        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].deny_fallback, host.deny_fallback);
    }

    #[tokio::test]
    async fn parity_fields_round_trip() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.locations = vec![crate::config::HostLocation {
            path: "/api".into(),
            upstream: "10.0.0.5:9000".into(),
            upstream_https: true,
            upstream_tls_verify: false,
        }];
        host.block_exploits = true;
        host.fixed_response = Some(crate::config::FixedResponse {
            status: 404,
            body: "nothing here".into(),
            html: false,
        });
        save_hosts(&pool, std::slice::from_ref(&host))
            .await
            .unwrap();
        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].locations, host.locations);
        assert!(loaded[0].block_exploits);
        assert_eq!(loaded[0].fixed_response, host.fixed_response);
    }

    #[tokio::test]
    async fn rewrite_samesite_none_cookies_round_trips_when_enabled() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.rewrite_samesite_none_cookies = true;
        save_hosts(&pool, std::slice::from_ref(&host))
            .await
            .unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert!(loaded[0].rewrite_samesite_none_cookies);
    }

    #[tokio::test]
    async fn acl_ids_round_trip_through_sqlite() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "test acl", AclKind::IpAllow, Utc::now())
            .await
            .unwrap();
        let mut host = sample_host();
        host.acl_ids = vec![acl_id];
        save_hosts(&pool, std::slice::from_ref(&host))
            .await
            .unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].acl_ids, host.acl_ids);
    }

    #[tokio::test]
    async fn acl_ids_default_to_unrestricted_when_absent() {
        let pool = memory_pool().await;
        save_hosts(&pool, std::slice::from_ref(&sample_host()))
            .await
            .unwrap();

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
        save_hosts(&pool, std::slice::from_ref(&host))
            .await
            .unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].redirect, host.redirect);
    }

    #[tokio::test]
    async fn dns_credential_id_round_trips_through_sqlite() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.dns_credential_id = Some(Uuid::new_v4());
        save_hosts(&pool, std::slice::from_ref(&host))
            .await
            .unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].dns_credential_id, host.dns_credential_id);
    }

    #[tokio::test]
    async fn dns_credential_id_defaults_to_none_when_absent() {
        let pool = memory_pool().await;
        save_hosts(&pool, std::slice::from_ref(&sample_host()))
            .await
            .unwrap();

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

    fn sample_hosting() -> (HostingPool, Allocation) {
        let pool = HostingPool {
            name: "standard".into(),
            cidr: "204.52.221.224/28".parse().unwrap(),
            description: "standard hosting".into(),
            reserved: vec!["204.52.221.225".parse().unwrap()],
            vm_cidr: Some("172.16.63.0/24".parse().unwrap()),
            gateway: Some("172.16.63.1".parse().unwrap()),
        };
        let alloc = Allocation {
            id: Uuid::new_v4(),
            pool: "standard".into(),
            public_ip: "204.52.221.226".parse().unwrap(),
            name: "web01".into(),
            customer: "Acme".into(),
            notes: "line1\nline2".into(),
            vm_ip: Some("172.16.63.10".parse().unwrap()),
            vm_id: Some(4001),
            forward: ForwardMode::Ports,
            ports: vec![
                PortSpec {
                    protocol: Protocol::Tcp,
                    port_start: 22,
                    port_end: 22,
                    vm_port: Some(2222),
                    acl_ids: vec![],
                },
                PortSpec {
                    protocol: Protocol::Udp,
                    port_start: 20100,
                    port_end: 20200,
                    vm_port: None,
                    acl_ids: vec![],
                },
            ],
            enabled: true,
            created_at: Utc::now(),
        };
        (pool, alloc)
    }

    #[tokio::test]
    async fn hosting_round_trips_including_ports_and_optional_fields() {
        let pool = memory_pool().await;
        let (p, a) = sample_hosting();
        save_hosting(&pool, std::slice::from_ref(&p), std::slice::from_ref(&a))
            .await
            .unwrap();
        let pools = load_hosting_pools(&pool).await.unwrap();
        let allocs = load_hosting_allocations(&pool).await.unwrap();
        assert_eq!(pools, vec![p]);
        assert_eq!(allocs.len(), 1);
        let got = &allocs[0];
        assert_eq!(got.id, a.id);
        assert_eq!(got.ports, a.ports);
        assert_eq!(got.forward, ForwardMode::Ports);
        assert_eq!(got.vm_ip, a.vm_ip);
        assert_eq!(got.vm_id, Some(4001));
        assert_eq!(got.notes, "line1\nline2");
        assert_eq!(got.created_at.timestamp(), a.created_at.timestamp());
    }

    #[tokio::test]
    async fn hosting_reserved_allocation_without_a_vm_round_trips_and_save_replaces() {
        let pool = memory_pool().await;
        let (mut p, mut a) = sample_hosting();
        p.vm_cidr = None;
        p.gateway = None;
        p.reserved.clear();
        a.vm_ip = None;
        a.vm_id = None;
        a.forward = ForwardMode::All;
        a.ports.clear();
        a.enabled = false;
        save_hosting(&pool, &[p], &[a]).await.unwrap();
        let allocs = load_hosting_allocations(&pool).await.unwrap();
        assert!(allocs[0].vm_ip.is_none() && !allocs[0].enabled);
        let pools = load_hosting_pools(&pool).await.unwrap();
        assert!(pools[0].vm_cidr.is_none() && pools[0].reserved.is_empty());
        save_hosting(&pool, &[], &[]).await.unwrap();
        assert!(load_hosting_pools(&pool).await.unwrap().is_empty());
        assert!(load_hosting_allocations(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn hosting_public_ip_is_unique_in_the_schema() {
        let pool = memory_pool().await;
        let (p, a) = sample_hosting();
        let mut dup = a.clone();
        dup.id = Uuid::new_v4();
        assert!(save_hosting(&pool, &[p], &[a, dup]).await.is_err());
        assert!(
            load_hosting_allocations(&pool).await.unwrap().is_empty(),
            "failed save must roll back"
        );
    }

    #[tokio::test]
    async fn run_migrations_adds_hosting_tables_to_a_pre_existing_database_and_is_idempotent() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE port_rules (id TEXT PRIMARY KEY, bind_ip TEXT, port_start INTEGER NOT NULL, port_end INTEGER NOT NULL, protocol TEXT NOT NULL, description TEXT NOT NULL, passthrough_target TEXT, enabled INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();
        assert!(load_hosting_pools(&pool).await.unwrap().is_empty());
        assert!(load_hosting_allocations(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn port_rules_round_trip_including_protocol_and_passthrough_target() {
        let pool = memory_pool().await;
        let rule = sample_rule();
        save_port_rules(&pool, std::slice::from_ref(&rule))
            .await
            .unwrap();

        let loaded = load_port_rules(&pool).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].protocol, Protocol::Tcp);
        assert_eq!(
            loaded[0].passthrough_target.as_deref(),
            Some("127.0.0.1:21115")
        );
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
        create_api_token(
            &pool,
            id,
            "ci pipeline",
            Role::Admin,
            "hash-of-token",
            Utc::now(),
        )
        .await
        .unwrap();

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
        create_api_token(
            &pool,
            id,
            "ci pipeline",
            Role::Admin,
            "hash-of-token",
            Utc::now(),
        )
        .await
        .unwrap();

        let found = find_api_token_by_hash(&pool, "hash-of-token")
            .await
            .unwrap()
            .expect("token should be found by its hash");
        assert_eq!(found.id, id);
        assert_eq!(found.name, "ci pipeline");
        assert_eq!(found.role, Role::Admin);
        assert!(
            find_api_token_by_hash(&pool, "wrong-hash")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn api_token_keeps_the_role_it_was_created_with() {
        let pool = memory_pool().await;
        create_api_token(
            &pool,
            Uuid::new_v4(),
            "grafana",
            Role::Viewer,
            "h-viewer",
            Utc::now(),
        )
        .await
        .unwrap();
        let found = find_api_token_by_hash(&pool, "h-viewer")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.role, Role::Viewer);
        assert_eq!(list_api_tokens(&pool).await.unwrap()[0].role, Role::Viewer);
    }

    #[tokio::test]
    async fn tokens_from_before_roles_existed_stay_admin() {
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE api_tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, last_used_at TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_tokens (id, name, token_hash, created_at) VALUES ('2d6c5d0e-0000-4000-8000-000000000001', 'old', 'old-hash', '2026-01-01T00:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();
        run_migrations(&pool).await.unwrap();
        let found = find_api_token_by_hash(&pool, "old-hash")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.role, Role::Admin);
    }

    #[tokio::test]
    async fn users_are_created_found_case_insensitively_and_listed() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        assert!(
            create_user(&pool, id, "Alice", "hash", Role::Operator, Utc::now())
                .await
                .unwrap()
        );
        let found = find_user_by_username(&pool, "alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, id);
        assert_eq!(found.username, "Alice");
        assert_eq!(found.role, Role::Operator);
        assert!(!found.disabled);
        assert_eq!(list_users(&pool).await.unwrap().len(), 1);
        assert_eq!(
            find_user_by_id(&pool, id).await.unwrap().unwrap().username,
            "Alice"
        );
    }

    #[tokio::test]
    async fn a_username_cannot_be_reused_even_in_a_different_case() {
        let pool = memory_pool().await;
        assert!(
            create_user(&pool, Uuid::new_v4(), "bob", "h", Role::Viewer, Utc::now())
                .await
                .unwrap()
        );
        assert!(
            !create_user(&pool, Uuid::new_v4(), "BOB", "h", Role::Admin, Utc::now())
                .await
                .unwrap()
        );
        assert_eq!(list_users(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn updating_a_user_changes_role_disabled_and_optionally_the_password() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_user(&pool, id, "carol", "old-hash", Role::Viewer, Utc::now())
            .await
            .unwrap();
        assert!(
            update_user(&pool, id, Role::Operator, true, None)
                .await
                .unwrap()
        );
        let u = find_user_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(
            (u.role, u.disabled, u.password_hash.as_str()),
            (Role::Operator, true, "old-hash")
        );
        assert!(
            update_user(&pool, id, Role::Admin, false, Some("new-hash"))
                .await
                .unwrap()
        );
        let u = find_user_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(
            (u.role, u.disabled, u.password_hash.as_str()),
            (Role::Admin, false, "new-hash")
        );
        assert!(
            !update_user(&pool, Uuid::new_v4(), Role::Admin, false, None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn deleting_a_user_removes_it_and_reports_whether_it_existed() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_user(&pool, id, "dave", "h", Role::Viewer, Utc::now())
            .await
            .unwrap();
        assert!(delete_user(&pool, id).await.unwrap());
        assert!(!delete_user(&pool, id).await.unwrap());
        assert!(
            find_user_by_username(&pool, "dave")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn last_login_is_recorded() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_user(&pool, id, "erin", "h", Role::Viewer, Utc::now())
            .await
            .unwrap();
        assert!(
            find_user_by_id(&pool, id)
                .await
                .unwrap()
                .unwrap()
                .last_login_at
                .is_none()
        );
        let now = Utc::now();
        touch_user_last_login(&pool, id, now).await.unwrap();
        let got = find_user_by_id(&pool, id)
            .await
            .unwrap()
            .unwrap()
            .last_login_at
            .unwrap();
        assert_eq!(got.timestamp(), now.timestamp());
    }

    #[tokio::test]
    async fn touching_an_api_token_updates_its_last_used_at() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_api_token(
            &pool,
            id,
            "ci pipeline",
            Role::Admin,
            "hash-of-token",
            Utc::now(),
        )
        .await
        .unwrap();

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
        create_api_token(
            &pool,
            id,
            "ci pipeline",
            Role::Admin,
            "hash-of-token",
            Utc::now(),
        )
        .await
        .unwrap();

        assert!(delete_api_token(&pool, id).await.unwrap());
        assert!(list_api_tokens(&pool).await.unwrap().is_empty());
        assert!(
            !delete_api_token(&pool, id).await.unwrap(),
            "deleting again should report nothing was found"
        );
    }

    #[tokio::test]
    async fn dns_credentials_round_trip_through_sqlite() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_dns_credential(
            &pool,
            id,
            "prod-cloudflare",
            crate::config::DnsProviderKind::Cloudflare,
            "cf-token-value",
            Utc::now(),
        )
        .await
        .unwrap();

        let metas = list_dns_credentials(&pool).await.unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].id, id);
        assert_eq!(metas[0].name, "prod-cloudflare");
        assert_eq!(
            metas[0].provider,
            crate::config::DnsProviderKind::Cloudflare
        );

        let full = get_dns_credential(&pool, id).await.unwrap().unwrap();
        assert_eq!(full.token, "cf-token-value");
    }

    #[tokio::test]
    async fn dns_credential_not_found_returns_none() {
        let pool = memory_pool().await;
        assert!(
            get_dns_credential(&pool, Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_a_dns_credential_removes_it_and_reports_whether_it_existed() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_dns_credential(
            &pool,
            id,
            "prod-cloudflare",
            crate::config::DnsProviderKind::Cloudflare,
            "cf-token",
            Utc::now(),
        )
        .await
        .unwrap();

        assert!(delete_dns_credential(&pool, id).await.unwrap());
        assert!(list_dns_credentials(&pool).await.unwrap().is_empty());
        assert!(!delete_dns_credential(&pool, id).await.unwrap());
    }

    #[tokio::test]
    async fn dns_credential_name_exists_reflects_current_rows() {
        let pool = memory_pool().await;
        assert!(
            !dns_credential_name_exists(&pool, "prod-cloudflare")
                .await
                .unwrap()
        );
        create_dns_credential(
            &pool,
            Uuid::new_v4(),
            "prod-cloudflare",
            crate::config::DnsProviderKind::Cloudflare,
            "tok",
            Utc::now(),
        )
        .await
        .unwrap();
        assert!(
            dns_credential_name_exists(&pool, "prod-cloudflare")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn seed_default_dns_credential_is_idempotent_across_restarts() {
        let pool = memory_pool().await;
        seed_default_dns_credential(
            &pool,
            crate::config::DnsProviderKind::Hetzner,
            "hetzner-token",
        )
        .await
        .unwrap();
        seed_default_dns_credential(
            &pool,
            crate::config::DnsProviderKind::Hetzner,
            "hetzner-token",
        )
        .await
        .unwrap();

        let metas = list_dns_credentials(&pool).await.unwrap();
        assert_eq!(
            metas.len(),
            1,
            "seeding twice (e.g. two restarts) must not create a duplicate 'default' row"
        );
        assert_eq!(metas[0].name, "default");
    }

    #[tokio::test]
    async fn seed_default_dns_credential_does_not_overwrite_a_user_renamed_or_edited_default() {
        let pool = memory_pool().await;
        seed_default_dns_credential(
            &pool,
            crate::config::DnsProviderKind::Hetzner,
            "original-token",
        )
        .await
        .unwrap();
        seed_default_dns_credential(
            &pool,
            crate::config::DnsProviderKind::Hetzner,
            "a-different-token-from-a-later-config-edit",
        )
        .await
        .unwrap();

        let metas = list_dns_credentials(&pool).await.unwrap();
        let full = get_dns_credential(&pool, metas[0].id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            full.token, "original-token",
            "seeding is INSERT OR IGNORE -- the DB row, once created, is the source of truth"
        );
    }

    #[tokio::test]
    async fn admin_identity_round_trips_and_is_none_before_first_save() {
        let pool = memory_pool().await;
        assert!(load_admin_identity(&pool).await.unwrap().is_none());

        create_admin_identity_if_absent(&pool, "admin", "hashed-password", "session-secret")
            .await
            .unwrap();
        let row = load_admin_identity(&pool).await.unwrap().unwrap();
        assert_eq!(row.username, "admin");
        assert_eq!(row.password_hash, "hashed-password");
        assert_eq!(row.session_secret, "session-secret");
    }

    #[tokio::test]
    async fn create_admin_identity_if_absent_only_ever_creates_the_first_one() {
        let pool = memory_pool().await;
        assert!(
            create_admin_identity_if_absent(&pool, "admin", "hash-1", "secret-1")
                .await
                .unwrap()
        );
        assert!(
            !create_admin_identity_if_absent(&pool, "attacker", "hash-2", "secret-2")
                .await
                .unwrap()
        );

        let row = load_admin_identity(&pool).await.unwrap().unwrap();
        assert_eq!(
            row.username, "admin",
            "the second call must not have overwritten the first"
        );
        assert_eq!(row.password_hash, "hash-1");
    }

    /// Regression test for a real deployment bug: `CREATE TABLE IF NOT
    /// EXISTS` with the new `organization`/`organizational_unit`
    /// columns already in its definition is a no-op against a
    /// pre-existing `standalone_certs` table from before those columns
    /// existed -- only the paired `ALTER TABLE ... ADD COLUMN` actually
    /// upgrades it. `memory_pool()`/`connect()` always create a brand
    /// new table (so `CREATE TABLE IF NOT EXISTS` alone happens to
    /// "work" there, masking a missing `ALTER TABLE` in every other
    /// test), so this manually recreates the *pre-upgrade* schema first
    /// to actually exercise the upgrade path a real production DB goes
    /// through.
    #[tokio::test]
    async fn run_migrations_adds_organization_columns_to_a_pre_existing_standalone_certs_table() {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE standalone_certs (id TEXT PRIMARY KEY, domain TEXT NOT NULL UNIQUE, dns_credential_id TEXT, created_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();

        run_migrations(&pool).await.unwrap();

        // Would fail with "no such column" before the fix -- confirmed
        // against the exact same error a real upgraded production
        // instance hit.
        create_standalone_cert(
            &pool,
            Uuid::new_v4(),
            "*.example.com",
            None,
            Utc::now(),
            Some("Acme Corp"),
            None,
        )
        .await
        .unwrap();
        let certs = list_standalone_certs(&pool).await.unwrap();
        assert_eq!(certs[0].organization.as_deref(), Some("Acme Corp"));
    }

    #[tokio::test]
    async fn standalone_cert_organization_and_organizational_unit_round_trip() {
        let pool = memory_pool().await;
        let id = Uuid::new_v4();
        create_standalone_cert(
            &pool,
            id,
            "*.example.com",
            None,
            Utc::now(),
            Some("Acme Corp"),
            Some("Platform Engineering"),
        )
        .await
        .unwrap();

        let certs = list_standalone_certs(&pool).await.unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].organization.as_deref(), Some("Acme Corp"));
        assert_eq!(
            certs[0].organizational_unit.as_deref(),
            Some("Platform Engineering")
        );
    }

    #[tokio::test]
    async fn standalone_cert_organization_and_organizational_unit_default_to_none() {
        let pool = memory_pool().await;
        create_standalone_cert(
            &pool,
            Uuid::new_v4(),
            "*.example.com",
            None,
            Utc::now(),
            None,
            None,
        )
        .await
        .unwrap();

        let certs = list_standalone_certs(&pool).await.unwrap();
        assert!(certs[0].organization.is_none());
        assert!(certs[0].organizational_unit.is_none());
    }

    /// Regression test for the same class of bug as
    /// `run_migrations_adds_organization_columns_to_a_pre_existing_standalone_certs_table`
    /// above, this time for `acl_ip_entries`/`acl_credentials`'s new
    /// `description` column: manually recreates the pre-upgrade schema
    /// (no `description` column) before running migrations, so the
    /// `ALTER TABLE` path is actually exercised rather than masked by
    /// `CREATE TABLE IF NOT EXISTS` starting fresh.
    #[tokio::test]
    async fn run_migrations_adds_description_columns_to_pre_existing_acl_tables() {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE acl_lists (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, created_at TEXT NOT NULL)").execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE acl_ip_entries (id TEXT PRIMARY KEY, acl_list_id TEXT NOT NULL, cidr TEXT NOT NULL)").execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE acl_credentials (id TEXT PRIMARY KEY, acl_list_id TEXT NOT NULL, username TEXT NOT NULL, password_hash TEXT NOT NULL)").execute(&pool).await.unwrap();

        run_migrations(&pool).await.unwrap();

        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "office", AclKind::IpAllow, Utc::now())
            .await
            .unwrap();
        add_acl_ip_entry(&pool, acl_id, "10.0.0.0/24", Some("HQ subnet"))
            .await
            .unwrap();
        let entries = list_acl_ip_entries(&pool, acl_id).await.unwrap();
        assert_eq!(entries[0].description.as_deref(), Some("HQ subnet"));
    }

    /// Regression test for the dead-column cleanup: manually recreates
    /// the pre-cleanup `hosts` schema (the single-family `bind_ip`
    /// column, plus the pre-ACL-system `access_allow_ips`/
    /// `access_login_username`/`access_login_password_hash` columns),
    /// seeds a row with real legacy data the way a genuine production
    /// upgrade would carry it forward, then proves: the DROP COLUMNs
    /// actually ran (querying a dropped column errors), and the
    /// existing row's `bind_ip` was correctly copied into `bind_ip_v4`
    /// before that column was dropped out from under it -- exactly the
    /// two ways this migration could have silently lost data.
    #[tokio::test]
    async fn run_migrations_drops_legacy_columns_from_a_pre_existing_hosts_table_without_losing_data()
     {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE hosts (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                bind_ip TEXT NOT NULL,
                bind_port INTEGER NOT NULL,
                upstream TEXT NOT NULL,
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
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let host_id = Uuid::new_v4();
        sqlx::query("INSERT INTO hosts (id, domain, bind_ip, bind_port, upstream, websockets, force_https, acme_enabled, enabled) VALUES (?, ?, ?, ?, ?, 0, 1, 0, 1)")
            .bind(host_id.to_string())
            .bind("legacy.example.com")
            .bind("10.0.0.9")
            .bind(443i64)
            .bind("127.0.0.1:8000")
            .execute(&pool)
            .await
            .unwrap();

        run_migrations(&pool).await.unwrap();

        // The dropped columns must genuinely be gone, not just unused.
        for column in [
            "bind_ip",
            "access_allow_ips",
            "access_login_username",
            "access_login_password_hash",
        ] {
            let result = sqlx::query(&format!("SELECT {column} FROM hosts"))
                .fetch_optional(&pool)
                .await;
            assert!(
                result.is_err(),
                "column {column} should have been dropped but a query against it still succeeded"
            );
        }

        let hosts = load_hosts(&pool).await.unwrap();
        let host = hosts
            .iter()
            .find(|h| h.id == host_id)
            .expect("the pre-existing row must survive the migration");
        assert_eq!(
            host.bind_ip_v4,
            Some("10.0.0.9".parse().unwrap()),
            "the old bind_ip value must have been copied into bind_ip_v4 before bind_ip was dropped"
        );
        assert_eq!(host.domain, "legacy.example.com");
    }

    /// Same regression coverage as the `hosts` test above, for
    /// `port_rules.bind_ip`.
    #[tokio::test]
    async fn run_migrations_drops_legacy_bind_ip_from_a_pre_existing_port_rules_table_without_losing_data()
     {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE port_rules (
                id TEXT PRIMARY KEY,
                bind_ip TEXT NOT NULL,
                port_start INTEGER NOT NULL,
                port_end INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                description TEXT NOT NULL,
                passthrough_target TEXT,
                enabled INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let rule_id = Uuid::new_v4();
        sqlx::query("INSERT INTO port_rules (id, bind_ip, port_start, port_end, protocol, description, enabled) VALUES (?, ?, ?, ?, ?, ?, 1)")
            .bind(rule_id.to_string())
            .bind("10.0.0.9")
            .bind(21115i64)
            .bind(21115i64)
            .bind("tcp")
            .bind("rustdesk")
            .execute(&pool)
            .await
            .unwrap();

        run_migrations(&pool).await.unwrap();

        let result = sqlx::query("SELECT bind_ip FROM port_rules")
            .fetch_optional(&pool)
            .await;
        assert!(
            result.is_err(),
            "bind_ip should have been dropped but a query against it still succeeded"
        );

        let rules = load_port_rules(&pool).await.unwrap();
        let rule = rules
            .iter()
            .find(|r| r.id == rule_id)
            .expect("the pre-existing row must survive the migration");
        assert_eq!(
            rule.bind_ip_v4,
            Some("10.0.0.9".parse().unwrap()),
            "the old bind_ip value must have been copied into bind_ip_v4 before bind_ip was dropped"
        );
    }

    #[tokio::test]
    async fn acl_ip_entries_can_be_added_individually_and_listed() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "office", AclKind::IpAllow, Utc::now())
            .await
            .unwrap();

        let id1 = add_acl_ip_entry(&pool, acl_id, "10.0.0.0/24", Some("HQ"))
            .await
            .unwrap();
        let id2 = add_acl_ip_entry(&pool, acl_id, "192.168.1.0/24", None)
            .await
            .unwrap();

        let entries = list_acl_ip_entries(&pool, acl_id).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, id1);
        assert_eq!(entries[0].cidr, "10.0.0.0/24");
        assert_eq!(entries[0].description.as_deref(), Some("HQ"));
        assert_eq!(entries[1].id, id2);
        assert!(entries[1].description.is_none());
    }

    #[tokio::test]
    async fn acl_ip_entries_support_ipv6_cidrs_end_to_end() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "v6 office", AclKind::IpAllow, Utc::now())
            .await
            .unwrap();
        add_acl_ip_entry(&pool, acl_id, "2001:db8::/32", Some("v6 HQ"))
            .await
            .unwrap();
        add_acl_ip_entry(&pool, acl_id, "10.0.0.0/24", None)
            .await
            .unwrap();

        let entries = list_acl_ip_entries(&pool, acl_id).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.cidr == "2001:db8::/32"));

        let resolved = resolve_acl_ids(&pool, &[acl_id]).await.unwrap();
        assert_eq!(resolved.allow_ips.len(), 2);
        assert!(resolved
            .allow_ips
            .iter()
            .any(|net| matches!(net, ipnet::IpNet::V6(_)) && net.to_string() == "2001:db8::/32"));
        assert!(
            resolved
                .allow_ips
                .iter()
                .any(|net| matches!(net, ipnet::IpNet::V4(_)))
        );
    }

    #[tokio::test]
    async fn acl_ip_entry_update_and_delete_target_a_single_row() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "office", AclKind::IpAllow, Utc::now())
            .await
            .unwrap();
        let id1 = add_acl_ip_entry(&pool, acl_id, "10.0.0.0/24", None)
            .await
            .unwrap();
        let id2 = add_acl_ip_entry(&pool, acl_id, "192.168.1.0/24", None)
            .await
            .unwrap();

        let updated = update_acl_ip_entry(&pool, id1, "10.0.0.0/16", Some("widened"))
            .await
            .unwrap();
        assert!(updated);
        let entries = list_acl_ip_entries(&pool, acl_id).await.unwrap();
        assert_eq!(
            entries.iter().find(|e| e.id == id1).unwrap().cidr,
            "10.0.0.0/16"
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.id == id1)
                .unwrap()
                .description
                .as_deref(),
            Some("widened")
        );

        let deleted = delete_acl_ip_entry(&pool, id2).await.unwrap();
        assert!(deleted);
        let entries = list_acl_ip_entries(&pool, acl_id).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id1);

        assert!(
            !delete_acl_ip_entry(&pool, id2).await.unwrap(),
            "deleting an already-deleted entry must report false, not error"
        );
    }

    #[tokio::test]
    async fn acl_ip_entries_list_sorted_by_address_not_insertion_order_or_cidr_text() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "office", AclKind::IpAllow, Utc::now())
            .await
            .unwrap();
        // Inserted out of order, and deliberately including a pair
        // ("10.0.0.0/24" vs "2.2.2.2/32") where plain text sort and
        // numeric address sort disagree -- '1' < '2' puts "10." first
        // lexicographically, but 2.2.2.2 is numerically the lower address.
        add_acl_ip_entry(&pool, acl_id, "204.52.221.6/32", None)
            .await
            .unwrap();
        add_acl_ip_entry(&pool, acl_id, "10.0.0.0/24", None)
            .await
            .unwrap();
        add_acl_ip_entry(&pool, acl_id, "2.2.2.2/32", None)
            .await
            .unwrap();
        add_acl_ip_entry(&pool, acl_id, "2001:db8::/32", None)
            .await
            .unwrap();

        let entries = list_acl_ip_entries(&pool, acl_id).await.unwrap();
        let cidrs: Vec<&str> = entries.iter().map(|e| e.cidr.as_str()).collect();
        assert_eq!(
            cidrs,
            vec![
                "2.2.2.2/32",
                "10.0.0.0/24",
                "204.52.221.6/32",
                "2001:db8::/32",
            ]
        );
    }

    #[tokio::test]
    async fn acl_credentials_can_be_added_individually_and_listed_without_password_hashes() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "viewers", AclKind::Login, Utc::now())
            .await
            .unwrap();

        let id = add_acl_credential(&pool, acl_id, "alice", "hashed-secret", Some("contractor"))
            .await
            .unwrap();

        let creds = list_acl_credentials(&pool, acl_id).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].id, id);
        assert_eq!(creds[0].username, "alice");
        assert_eq!(creds[0].description.as_deref(), Some("contractor"));
    }

    #[tokio::test]
    async fn acl_credential_update_without_a_new_password_preserves_the_existing_hash() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "viewers", AclKind::Login, Utc::now())
            .await
            .unwrap();
        let id = add_acl_credential(&pool, acl_id, "alice", "original-hash", None)
            .await
            .unwrap();

        let updated = update_acl_credential(&pool, id, "alice2", None, Some("renamed"))
            .await
            .unwrap();
        assert!(updated);

        let resolved = resolve_acl_ids(&pool, &[acl_id]).await.unwrap();
        assert_eq!(resolved.credentials[0].username, "alice2");
        assert_eq!(
            resolved.credentials[0].password_hash, "original-hash",
            "an update with password_hash=None must not clobber the existing hash"
        );
        let creds = list_acl_credentials(&pool, acl_id).await.unwrap();
        assert_eq!(creds[0].description.as_deref(), Some("renamed"));
    }

    #[tokio::test]
    async fn acl_credential_delete_removes_a_single_row() {
        let pool = memory_pool().await;
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "viewers", AclKind::Login, Utc::now())
            .await
            .unwrap();
        let id1 = add_acl_credential(&pool, acl_id, "alice", "hash1", None)
            .await
            .unwrap();
        let _id2 = add_acl_credential(&pool, acl_id, "bob", "hash2", None)
            .await
            .unwrap();

        assert!(delete_acl_credential(&pool, id1).await.unwrap());
        let creds = list_acl_credentials(&pool, acl_id).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "bob");
    }

    #[tokio::test]
    async fn get_acl_list_returns_none_for_an_unknown_id() {
        let pool = memory_pool().await;
        assert!(get_acl_list(&pool, Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expose_admin_port_defaults_to_none_and_round_trips_once_set() {
        let pool = memory_pool().await;
        assert_eq!(load_expose_admin_port(&pool).await.unwrap(), None);

        set_expose_admin_port(&pool, false).await.unwrap();
        assert_eq!(load_expose_admin_port(&pool).await.unwrap(), Some(false));

        set_expose_admin_port(&pool, true).await.unwrap();
        assert_eq!(
            load_expose_admin_port(&pool).await.unwrap(),
            Some(true),
            "a second call must update the existing row, not fail on the unique id"
        );
    }

    #[tokio::test]
    async fn backup_to_produces_a_real_readable_copy_with_the_same_data() {
        let src = std::env::temp_dir().join(format!("rust-proxy-backup-src-{}.db", Uuid::new_v4()));
        let _ = std::fs::remove_file(&src);
        let pool = connect(&src).await.unwrap();
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "backup test", AclKind::IpAllow, Utc::now())
            .await
            .unwrap();

        let dest =
            std::env::temp_dir().join(format!("rust-proxy-backup-test-{}.db", Uuid::new_v4()));
        let _ = std::fs::remove_file(&dest);

        backup_to(&pool, &dest).await.unwrap();
        assert!(dest.is_file(), "backup_to must have written a real file");

        let backup_pool = connect(&dest).await.unwrap();
        assert!(
            acl_list_name_exists(&backup_pool, "backup test")
                .await
                .unwrap(),
            "the backup must contain the same data as the live DB at the moment it was taken"
        );

        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_file(&src);
    }

    #[tokio::test]
    async fn backup_to_refuses_to_overwrite_an_existing_destination() {
        let src = std::env::temp_dir().join(format!("rust-proxy-backup-src-{}.db", Uuid::new_v4()));
        let _ = std::fs::remove_file(&src);
        let pool = connect(&src).await.unwrap();
        let dest =
            std::env::temp_dir().join(format!("rust-proxy-backup-test-{}.db", Uuid::new_v4()));
        std::fs::write(&dest, b"not a real backup").unwrap();

        let result = backup_to(&pool, &dest).await;
        assert!(
            result.is_err(),
            "VACUUM INTO must refuse an already-existing destination, not silently overwrite it"
        );

        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_file(&src);
    }

    #[tokio::test]
    async fn vacuum_compacts_the_live_db_and_leaves_its_data_intact() {
        let src = std::env::temp_dir().join(format!("rust-proxy-vacuum-src-{}.db", Uuid::new_v4()));
        let _ = std::fs::remove_file(&src);
        let pool = connect(&src).await.unwrap();
        let acl_id = Uuid::new_v4();
        create_acl_list(&pool, acl_id, "vacuum test", AclKind::IpAllow, Utc::now())
            .await
            .unwrap();
        // Delete-then-recreate a bunch of rows so there's real freed
        // space for VACUUM to actually reclaim, not just a no-op on an
        // already-minimal file.
        for _ in 0..50 {
            let id = Uuid::new_v4();
            create_acl_list(
                &pool,
                id,
                &format!("throwaway {id}"),
                AclKind::IpAllow,
                Utc::now(),
            )
            .await
            .unwrap();
            delete_acl_list(&pool, id).await.unwrap();
        }

        vacuum(&pool).await.unwrap();

        assert!(
            acl_list_name_exists(&pool, "vacuum test").await.unwrap(),
            "VACUUM must never lose live data"
        );
        let _ = std::fs::remove_file(&src);
    }

    #[tokio::test]
    async fn rate_limit_round_trips_through_the_hosts_table() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.rate_limit_per_minute = 600;
        host.rate_limit_burst = 40;
        save_hosts(&pool, &[host, sample_host()]).await.unwrap();
        let mut limits: Vec<u32> = load_hosts(&pool)
            .await
            .unwrap()
            .iter()
            .map(|h| h.rate_limit_per_minute)
            .collect();
        limits.sort();
        assert_eq!(limits, [0, 600]);
        let bursts: Vec<u32> = load_hosts(&pool)
            .await
            .unwrap()
            .iter()
            .map(|h| h.rate_limit_burst)
            .filter(|b| *b > 0)
            .collect();
        assert_eq!(bursts, [40]);
    }

    #[tokio::test]
    async fn hsts_flags_round_trip_through_the_hosts_table() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.hsts = true;
        host.hsts_subdomains = true;
        save_hosts(&pool, &[host]).await.unwrap();
        let loaded = load_hosts(&pool).await.unwrap();
        assert!(loaded[0].hsts && loaded[0].hsts_subdomains);

        let mut plain = sample_host();
        plain.hsts = true;
        save_hosts(&pool, &[plain]).await.unwrap();
        let loaded = load_hosts(&pool).await.unwrap();
        assert!(loaded[0].hsts && !loaded[0].hsts_subdomains);
    }

    #[tokio::test]
    async fn admin_allowed_ips_round_trip_without_disturbing_expose_admin_port() {
        let pool = memory_pool().await;
        assert!(load_admin_allowed_ips(&pool).await.unwrap().is_empty());
        set_admin_allowed_ips(
            &pool,
            &[
                "192.168.1.0/24".parse().unwrap(),
                "2001:db8::1/128".parse().unwrap(),
            ],
        )
        .await
        .unwrap();
        assert_eq!(load_admin_allowed_ips(&pool).await.unwrap().len(), 2);
        set_expose_admin_port(&pool, false).await.unwrap();
        assert_eq!(load_expose_admin_port(&pool).await.unwrap(), Some(false));
        assert_eq!(
            load_admin_allowed_ips(&pool).await.unwrap().len(),
            2,
            "setting expose must not clear the list"
        );
        set_admin_allowed_ips(&pool, &[]).await.unwrap();
        assert!(load_admin_allowed_ips(&pool).await.unwrap().is_empty());
        assert_eq!(load_expose_admin_port(&pool).await.unwrap(), Some(false));
    }

    #[tokio::test]
    async fn default_site_round_trips_and_is_absent_until_set() {
        use crate::config::{DefaultSite, DefaultSiteMode};
        let pool = memory_pool().await;
        assert!(load_default_site(&pool).await.unwrap().is_none());
        let site = DefaultSite {
            mode: DefaultSiteMode::Redirect,
            redirect_url: "https://www.example.com".into(),
            custom_html: String::new(),
        };
        set_default_site(&pool, &site).await.unwrap();
        assert_eq!(load_default_site(&pool).await.unwrap(), Some(site));
        let html = DefaultSite {
            mode: DefaultSiteMode::CustomHtml,
            redirect_url: String::new(),
            custom_html: "<p>hi</p>".into(),
        };
        set_default_site(&pool, &html).await.unwrap();
        assert_eq!(load_default_site(&pool).await.unwrap(), Some(html));
    }

    #[tokio::test]
    async fn commercial_license_round_trips_replaces_and_clears() {
        let pool = memory_pool().await;
        assert!(load_commercial_license(&pool).await.unwrap().is_none());
        let lic = CommercialLicense {
            license_key: "lic-aaaa".into(),
            licensee: "Acme".into(),
            expires_at: Some("2126-01-01T00:00:00Z".into()),
            lifetime: true,
            validated_at: "2026-10-14T00:00:00Z".into(),
        };
        set_commercial_license(&pool, &lic).await.unwrap();
        assert_eq!(
            load_commercial_license(&pool).await.unwrap(),
            Some(lic.clone())
        );
        let newer = CommercialLicense {
            license_key: "lic-bbbb".into(),
            expires_at: None,
            lifetime: false,
            ..lic
        };
        set_commercial_license(&pool, &newer).await.unwrap();
        assert_eq!(load_commercial_license(&pool).await.unwrap(), Some(newer));
        clear_commercial_license(&pool).await.unwrap();
        assert!(load_commercial_license(&pool).await.unwrap().is_none());
    }
}
