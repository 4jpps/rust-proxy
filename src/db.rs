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

use crate::config::{AcmeChallengeType, HostAuth, PortRule, Protocol, ProxyHost};

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
            websockets INTEGER NOT NULL,
            force_https INTEGER NOT NULL,
            acme_enabled INTEGER NOT NULL,
            acme_challenge_type TEXT NOT NULL DEFAULT 'auto',
            access_allow_ips TEXT NOT NULL DEFAULT '',
            access_login_username TEXT,
            access_login_password_hash TEXT,
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

pub async fn load_hosts(pool: &SqlitePool) -> Result<Vec<ProxyHost>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, domain, bind_ip, bind_port, upstream, websockets, force_https, acme_enabled, acme_challenge_type, \
         access_allow_ips, access_login_username, access_login_password_hash, enabled FROM hosts",
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
            let access_allow_ips = row
                .get::<String, _>("access_allow_ips")
                .split(',')
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            let access_login = match (
                row.get::<Option<String>, _>("access_login_username"),
                row.get::<Option<String>, _>("access_login_password_hash"),
            ) {
                (Some(username), Some(password_hash)) => Some(HostAuth { username, password_hash }),
                _ => None,
            };
            Ok(ProxyHost {
                id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or_else(|_| uuid::Uuid::new_v4()),
                domain: row.get("domain"),
                bind_ip: row.get::<String, _>("bind_ip").parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
                bind_port: row.get::<i64, _>("bind_port") as u16,
                upstream: row.get("upstream"),
                websockets: row.get::<i64, _>("websockets") != 0,
                force_https: row.get::<i64, _>("force_https") != 0,
                acme_enabled: row.get::<i64, _>("acme_enabled") != 0,
                acme_challenge_type: challenge_type,
                access_allow_ips,
                access_login,
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
        let access_allow_ips = h.access_allow_ips.iter().map(|net| net.to_string()).collect::<Vec<_>>().join(",");
        let (login_username, login_password_hash) = match &h.access_login {
            Some(auth) => (Some(auth.username.as_str()), Some(auth.password_hash.as_str())),
            None => (None, None),
        };
        sqlx::query(
            "INSERT INTO hosts (id, domain, bind_ip, bind_port, upstream, websockets, force_https, acme_enabled, \
             acme_challenge_type, access_allow_ips, access_login_username, access_login_password_hash, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(h.id.to_string())
        .bind(&h.domain)
        .bind(h.bind_ip.to_string())
        .bind(h.bind_port as i64)
        .bind(&h.upstream)
        .bind(h.websockets as i64)
        .bind(h.force_https as i64)
        .bind(h.acme_enabled as i64)
        .bind(challenge_type)
        .bind(access_allow_ips)
        .bind(login_username)
        .bind(login_password_hash)
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
            websockets: true,
            force_https: true,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            access_allow_ips: vec![],
            access_login: None,
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
    async fn access_control_fields_round_trip_through_sqlite() {
        let pool = memory_pool().await;
        let mut host = sample_host();
        host.access_allow_ips = vec!["10.0.0.0/24".parse().unwrap(), "192.168.1.0/24".parse().unwrap()];
        host.access_login = Some(crate::config::HostAuth {
            username: "viewer".into(),
            password_hash: "$argon2id$fake$hash".into(),
        });
        save_hosts(&pool, std::slice::from_ref(&host)).await.unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert_eq!(loaded[0].access_allow_ips, host.access_allow_ips);
        assert_eq!(loaded[0].access_login, host.access_login);
    }

    #[tokio::test]
    async fn access_control_fields_default_to_unrestricted_when_absent() {
        let pool = memory_pool().await;
        save_hosts(&pool, std::slice::from_ref(&sample_host())).await.unwrap();

        let loaded = load_hosts(&pool).await.unwrap();
        assert!(loaded[0].access_allow_ips.is_empty());
        assert!(loaded[0].access_login.is_none());
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
}
