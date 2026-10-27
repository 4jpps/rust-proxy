//! System > Server: every config.toml setting, editable from the admin UI so
//! nothing needs a shell. config.toml stays the place these live; this edits
//! it in place (comments and layout kept), after checking the result with the
//! same rules startup uses. Only the primary admin -- the owner account,
//! signed in with its password -- can change anything here; everyone else
//! with access to the admin API can read it. Secrets are never sent out.
//!
//! These settings are read at startup, so a change applies after a restart.
//! The page's Restart button runs the pre-flight first and refuses if it
//! fails; the daemon then exits with `RESTART_EXIT_CODE` and systemd starts
//! it again (see deploy/rust-proxy.service).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{ConnectInfo, Extension, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use toml_edit::DocumentMut;

use super::routes::{ApiError, Principal};
use crate::config::Config;
use crate::state::AppState;

/// Exit status that tells systemd "restart me" (`RestartForceExitStatus`).
pub const RESTART_EXIT_CODE: i32 = 75;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A list of strings, one per line in the UI.
    List,
    Int,
    Text,
    /// Text that may be left blank (removes the key; the default applies).
    OptText,
    /// On, off, or unset (the matching UI page's setting applies).
    OptBool,
    /// Never sent out; can be replaced, generated or removed.
    Secret,
    /// Shown, not editable here.
    ReadOnly,
}

pub struct Field {
    pub key: &'static str,
    pub kind: Kind,
    pub group: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    /// Another page manages this setting when config.toml leaves it out;
    /// such a setting can be moved there (see `move_setting`).
    pub page: Option<&'static str>,
}

const fn f(
    key: &'static str,
    kind: Kind,
    group: &'static str,
    label: &'static str,
    help: &'static str,
) -> Field {
    Field {
        key,
        kind,
        group,
        label,
        help,
        page: None,
    }
}

const fn managed(
    key: &'static str,
    kind: Kind,
    group: &'static str,
    label: &'static str,
    help: &'static str,
    page: &'static str,
) -> Field {
    Field {
        key,
        kind,
        group,
        label,
        help,
        page: Some(page),
    }
}

pub const FIELDS: &[Field] = &[
    f(
        "network.bind_ranges",
        Kind::List,
        "Network",
        "Allowed bind ranges",
        "IP ranges every site, port rule and the admin UI must bind inside, one CIDR per line. Empty allows any address this machine has.",
    ),
    f(
        "network.dedicated_ips",
        Kind::List,
        "Network",
        "Dedicated addresses",
        "Addresses that serve only what is explicitly bound to them, one per line. Everything else to them is dropped.",
    ),
    f(
        "network.dhcp_interfaces",
        Kind::List,
        "Network",
        "DHCP server interfaces",
        "Interfaces where this machine runs a DHCP server, one per line, so the firewall lets client broadcasts in.",
    ),
    f(
        "network.max_connections_per_ip",
        Kind::Int,
        "Network",
        "Connections per visitor",
        "Most connections one address (or IPv6 /64) may hold open at once. 0 means no limit. Default 256.",
    ),
    f(
        "network.udp_idle_timeout_seconds",
        Kind::Int,
        "Network",
        "UDP idle timeout (seconds)",
        "How long a UDP port-rule session may sit silent before it is closed. Default 120.",
    ),
    f(
        "admin.bind_ip_v4",
        Kind::OptText,
        "Admin UI",
        "Admin UI IPv4 address",
        "Blank listens on every IPv4 address.",
    ),
    f(
        "admin.bind_ip_v6",
        Kind::OptText,
        "Admin UI",
        "Admin UI IPv6 address",
        "Blank listens on every IPv6 address.",
    ),
    f(
        "admin.bind_port",
        Kind::Int,
        "Admin UI",
        "Admin UI port",
        "Default 8084. After a restart the admin UI is only at the new port.",
    ),
    managed(
        "admin.allowed_ips",
        Kind::List,
        "Admin UI",
        "Allowed addresses",
        "Addresses allowed to reach the admin UI, one IP or CIDR per line. Set here, this overrides Network > Firewall settings.",
        "Network > Firewall settings",
    ),
    managed(
        "admin.expose_admin_port",
        Kind::OptBool,
        "Admin UI",
        "Expose the admin port",
        "Set here, this overrides Network > Firewall settings.",
        "Network > Firewall settings",
    ),
    f(
        "admin.client_cert_subjects",
        Kind::List,
        "Admin UI",
        "Client certificate names",
        "Names on client certificates that sign in to the admin UI without a password, one per line.",
    ),
    f(
        "admin.log_dir",
        Kind::OptText,
        "Admin UI",
        "Log folder",
        "Where the log files go. Blank keeps them next to the database.",
    ),
    f(
        "admin.db_path",
        Kind::ReadOnly,
        "Admin UI",
        "Database file",
        "Set at install.",
    ),
    managed(
        "acme.contact_email",
        Kind::OptText,
        "Certificates",
        "ACME contact email",
        "Set here, this overrides System > ACME.",
        "System > ACME",
    ),
    f(
        "acme.directory_url",
        Kind::Text,
        "Certificates",
        "ACME directory",
        "The certificate authority's ACME directory URL. Default Let's Encrypt.",
    ),
    f(
        "acme.renew_before_days",
        Kind::Int,
        "Certificates",
        "Renew before (days)",
        "Renew a certificate this many days before it expires. Default 30.",
    ),
    f(
        "acme.organization",
        Kind::OptText,
        "Certificates",
        "Organization",
        "Organization name put in certificate requests. Blank leaves it out.",
    ),
    f(
        "acme.organizational_unit",
        Kind::OptText,
        "Certificates",
        "Organizational unit",
        "Unit name put in certificate requests. Blank leaves it out.",
    ),
    f(
        "acme.cert_dir",
        Kind::Text,
        "Certificates",
        "Certificate folder",
        "Where issued certificates are stored.",
    ),
    f(
        "acme.account_key_path",
        Kind::Text,
        "Certificates",
        "ACME account key file",
        "Where the ACME account key is stored.",
    ),
    f(
        "client_cert_forward_token",
        Kind::Secret,
        "Identity headers",
        "Identity forward token",
        "Shared secret sent to upstreams with client-certificate identity headers, so they can trust them.",
    ),
];

fn field(key: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|f| f.key == key)
}

#[derive(Serialize)]
struct FieldView {
    key: &'static str,
    kind: Kind,
    group: &'static str,
    label: &'static str,
    help: &'static str,
    page: Option<&'static str>,
    /// The value in effect from the file (defaults filled in); null for a
    /// secret or an unset optional.
    value: Value,
    /// Whether config.toml itself sets this key.
    in_file: bool,
}

#[derive(Serialize)]
pub struct ServerSettingsView {
    /// Whether the caller may change anything here.
    can_edit: bool,
    config_path: String,
    /// config.toml differs from what this process started with.
    restart_pending: bool,
    /// config.toml has a [siem] section, which overrides System > SIEM.
    siem_in_file: bool,
    fields: Vec<FieldView>,
}

fn config_path(state: &AppState) -> Result<&Path, ApiError> {
    state
        .config_file()
        .map(|(p, _)| p.as_path())
        .ok_or_else(|| {
            ApiError::Internal("the config file path was not recorded at startup".into())
        })
}

fn read_file(path: &Path) -> Result<String, ApiError> {
    std::fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("cannot read {}: {e}", path.display())))
}

fn parse_doc(text: &str) -> Result<DocumentMut, ApiError> {
    text.parse::<DocumentMut>()
        .map_err(|e| ApiError::Internal(format!("config.toml is not valid TOML: {e}")))
}

/// The item at `section.key` (or a top-level `key`), if the file sets it.
fn get_item<'a>(doc: &'a DocumentMut, key: &str) -> Option<&'a toml_edit::Item> {
    match key.split_once('.') {
        Some((section, k)) => doc.get(section)?.as_table_like()?.get(k),
        None => doc.get(key),
    }
}

fn view(
    state: &AppState,
    principal: &Principal,
    text: &str,
) -> Result<ServerSettingsView, ApiError> {
    let doc = parse_doc(text)?;
    let cfg = Config::parse(text)
        .map_err(|e| ApiError::Internal(format!("config.toml does not load: {e}")))?;
    let json = serde_json::to_value(&cfg).map_err(|e| ApiError::Internal(e.to_string()))?;
    let fields = FIELDS
        .iter()
        .map(|f| {
            let in_file = get_item(&doc, f.key).is_some();
            let value = if f.kind == Kind::Secret {
                Value::Null
            } else {
                json.pointer(&format!("/{}", f.key.replace('.', "/")))
                    .cloned()
                    .unwrap_or(Value::Null)
            };
            // An optional setting the file leaves out shows as unset, so
            // the UI can say which page manages it instead.
            let value = if !in_file && f.page.is_some() {
                Value::Null
            } else {
                value
            };
            FieldView {
                key: f.key,
                kind: f.kind,
                group: f.group,
                label: f.label,
                help: f.help,
                page: f.page,
                value,
                in_file,
            }
        })
        .collect();
    let loaded = state.config_file().map(|(_, t)| t.as_str()).unwrap_or(text);
    Ok(ServerSettingsView {
        can_edit: principal.is_primary(state),
        config_path: config_path(state)?.display().to_string(),
        restart_pending: loaded != text,
        siem_in_file: doc.get("siem").is_some(),
        fields,
    })
}

/// `GET /api/server-settings`
pub async fn get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<ServerSettingsView>, ApiError> {
    let text = read_file(config_path(&state)?)?;
    Ok(Json(view(&state, &principal, &text)?))
}

fn require_primary(state: &AppState, principal: &Principal) -> Result<(), ApiError> {
    if principal.is_primary(state) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "only the primary admin, signed in with a password, can change server settings".into(),
        ))
    }
}

/// Sets (or, for `null`, removes) one key in the document after checking
/// the JSON value fits the field's kind.
fn apply_change(doc: &mut DocumentMut, f: &Field, value: &Value) -> Result<(), ApiError> {
    let bad = |what: &str| ApiError::BadRequest(format!("{}: {what}", f.label));
    let item = match (f.kind, value) {
        (Kind::ReadOnly, _) => return Err(bad("can't be changed here")),
        (Kind::List, Value::Array(items)) => {
            let mut arr = toml_edit::Array::new();
            for it in items {
                let s = it
                    .as_str()
                    .ok_or_else(|| bad("every entry must be text"))?
                    .trim();
                if s.chars().any(char::is_control) {
                    return Err(bad("entries must be single lines"));
                }
                if !s.is_empty() {
                    arr.push(s);
                }
            }
            Some(toml_edit::value(arr))
        }
        (Kind::Int, Value::Number(n)) => {
            let n = n
                .as_i64()
                .filter(|n| *n >= 0)
                .ok_or_else(|| bad("must be a whole number, 0 or more"))?;
            Some(toml_edit::value(n))
        }
        (Kind::Text | Kind::OptText | Kind::Secret, Value::String(s)) => {
            let s = s.trim();
            if s.chars().any(char::is_control) {
                return Err(bad("must be a single line"));
            }
            if s.is_empty() {
                if f.kind == Kind::Text {
                    return Err(bad("can't be blank"));
                }
                None
            } else {
                Some(toml_edit::value(s))
            }
        }
        (Kind::OptBool, Value::Bool(b)) => Some(toml_edit::value(*b)),
        (Kind::List | Kind::OptText | Kind::OptBool | Kind::Secret | Kind::Int, Value::Null) => {
            None
        }
        _ => return Err(bad("has the wrong type")),
    };
    let (section, key) = match f.key.split_once('.') {
        Some((s, k)) => (Some(s), k),
        None => (None, f.key),
    };
    let table: &mut dyn toml_edit::TableLike = match section {
        Some(s) => doc
            .entry(s)
            .or_insert(toml_edit::table())
            .as_table_like_mut()
            .ok_or_else(|| ApiError::Internal(format!("[{s}] in config.toml is not a table")))?,
        None => doc.as_table_mut(),
    };
    match item {
        Some(item) => {
            table.insert(key, item);
        }
        None => {
            table.remove(key);
        }
    }
    Ok(())
}

/// Writes `text` to `path` atomically (temp file in the same folder, then
/// rename), keeping the previous file as `<name>.bak`. The new file keeps
/// the old one's permissions.
fn write_config(path: &Path, text: &str) -> Result<(), ApiError> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let io = |what: &str, e: std::io::Error| {
        ApiError::Internal(format!(
            "{what} {}: {e}. The service needs write access to that folder (see the deployment docs).",
            path.display()
        ))
    };
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.toml");
    let tmp = dir.join(format!(".{name}.tmp-{:08x}", rand::random::<u32>()));
    let mode = std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o640);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::copy(path, dir.join(format!("{name}.bak")))?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        std::fs::remove_file(&tmp).ok();
        return Err(io("cannot write", e));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct SaveRequest {
    /// `"section.key": value` for each changed setting; `null` removes it.
    changes: serde_json::Map<String, Value>,
}

/// Would the caller still reach the admin UI under `cfg`'s admin settings?
/// Values config.toml leaves out fall back to the Firewall settings page's.
fn caller_keeps_access(state: &AppState, cfg: &Config, caller: std::net::IpAddr) -> bool {
    let allowed = if cfg.admin.allowed_ips.is_empty() {
        state.admin_allowed_ips_db()
    } else {
        cfg.admin.allowed_ips.clone()
    };
    let expose = cfg
        .admin
        .expose_admin_port
        .unwrap_or_else(|| state.expose_admin_port_db());
    super::health::admin_reachable(
        caller.to_canonical(),
        &allowed,
        expose,
        state.block_index().global_nets(),
    )
}

/// `PUT /api/server-settings`
pub async fn save(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<SaveRequest>,
) -> Result<Json<ServerSettingsView>, ApiError> {
    require_primary(&state, &principal)?;
    let path = config_path(&state)?.to_path_buf();
    let text = read_file(&path)?;
    let mut doc = parse_doc(&text)?;
    for (key, value) in &body.changes {
        let f = field(key).ok_or_else(|| ApiError::BadRequest(format!("unknown setting {key}")))?;
        apply_change(&mut doc, f, value)?;
    }
    let new_text = doc.to_string();
    let cfg =
        Config::parse(&new_text).map_err(|e| ApiError::BadRequest(format!("not saved: {e}")))?;
    if !caller_keeps_access(&state, &cfg, peer.ip()) {
        return Err(ApiError::BadRequest(
            "not saved: with these admin settings your own address could not reach the admin UI"
                .into(),
        ));
    }
    if new_text != text {
        write_config(&path, &new_text)?;
        tracing::info!(target: "rust_proxy::access", user = %principal.username, keys = ?body.changes.keys().collect::<Vec<_>>(), "server settings saved to config.toml");
    }
    Ok(Json(view(&state, &principal, &new_text)?))
}

#[derive(Deserialize)]
pub struct MoveRequest {
    /// `admin.allowed_ips`, `admin.expose_admin_port`, `acme.contact_email`
    /// or `siem`.
    key: String,
}

/// `POST /api/server-settings/move`: hands a setting from config.toml to
/// the page that manages it otherwise -- its current value is copied into
/// that page's stored setting first, so nothing changes in effect, then
/// the key is removed from config.toml.
pub async fn move_setting(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<MoveRequest>,
) -> Result<Json<ServerSettingsView>, ApiError> {
    require_primary(&state, &principal)?;
    let path = config_path(&state)?.to_path_buf();
    let text = read_file(&path)?;
    let cfg = Config::parse(&text)
        .map_err(|e| ApiError::Internal(format!("config.toml does not load: {e}")))?;
    let mut doc = parse_doc(&text)?;
    match body.key.as_str() {
        "admin.allowed_ips" => {
            crate::db::set_admin_allowed_ips(state.db(), &cfg.admin.allowed_ips).await?
        }
        "admin.expose_admin_port" => {
            if let Some(v) = cfg.admin.expose_admin_port {
                crate::db::set_expose_admin_port(state.db(), v).await?;
            }
        }
        "acme.contact_email" => {
            if !cfg.acme.contact_email.trim().is_empty() {
                crate::db::set_acme_contact_email(state.db(), &cfg.acme.contact_email).await?;
            }
        }
        "siem" => {
            if let Some(siem) = &cfg.siem {
                crate::db::set_siem_settings(state.db(), siem).await?;
            }
            doc.remove("siem");
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "{other} has no other page to move to"
            )));
        }
    }
    if body.key != "siem" {
        let f = field(&body.key).expect("listed above");
        apply_change(&mut doc, f, &Value::Null)?;
    }
    let new_text = doc.to_string();
    Config::parse(&new_text).map_err(|e| ApiError::BadRequest(format!("not saved: {e}")))?;
    if new_text != text {
        write_config(&path, &new_text)?;
        tracing::info!(target: "rust_proxy::access", user = %principal.username, key = %body.key, "server setting moved out of config.toml");
    }
    Ok(Json(view(&state, &principal, &new_text)?))
}

/// `POST /api/server-settings/generate-token`: a new random identity forward
/// token, saved to config.toml and shown once.
pub async fn generate_token(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, ApiError> {
    require_primary(&state, &principal)?;
    use base64::Engine as _;
    let bytes: [u8; 32] = rand::random();
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let path = config_path(&state)?.to_path_buf();
    let text = read_file(&path)?;
    let mut doc = parse_doc(&text)?;
    apply_change(
        &mut doc,
        field("client_cert_forward_token").expect("listed"),
        &Value::String(token.clone()),
    )?;
    let new_text = doc.to_string();
    Config::parse(&new_text).map_err(|e| ApiError::BadRequest(format!("not saved: {e}")))?;
    write_config(&path, &new_text)?;
    Ok(Json(serde_json::json!({ "token": token })))
}

/// The config.toml on disk, parsed and validated.
fn load_current(state: &AppState) -> Result<Config, ApiError> {
    let text = read_file(config_path(state)?)?;
    Config::parse(&text)
        .map_err(|e| ApiError::BadRequest(format!("config.toml does not load: {e}")))
}

/// `POST /api/server/preflight`: the same checks as `rust-proxy check`,
/// against config.toml as it is on disk now.
pub async fn preflight(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<crate::check::Report>, ApiError> {
    require_primary(&state, &principal)?;
    let cfg = load_current(&state)?;
    Ok(Json(crate::check::preflight(cfg).await.0))
}

/// `POST /api/server/restart`: runs the pre-flight; if it passes, answers
/// and then exits so systemd starts the daemon again on the saved settings.
/// `restarting` is false (and nothing happens) when the pre-flight fails.
pub async fn restart(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, ApiError> {
    require_primary(&state, &principal)?;
    let cfg = load_current(&state)?;
    let (report, _) = crate::check::preflight(cfg).await;
    if report.ok {
        tracing::warn!(user = %principal.username, "restart requested from the admin UI");
        tokio::spawn(async {
            // Let the response reach the browser first.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            std::process::exit(RESTART_EXIT_CODE);
        });
    }
    Ok(Json(
        serde_json::json!({ "restarting": report.ok, "report": report }),
    ))
}

/// `POST /api/server/backup`: a consistent copy of the database in a
/// `backups` folder next to it, named by time.
pub async fn backup(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, ApiError> {
    require_primary(&state, &principal)?;
    let dir = super::health::db_dir(&state.admin().db_path).join("backups");
    std::fs::create_dir_all(&dir)
        .map_err(|e| ApiError::Internal(format!("cannot create {}: {e}", dir.display())))?;
    let dest: PathBuf = dir.join(format!(
        "rust-proxy-{}.db",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    ));
    crate::db::backup_to(state.db(), &dest).await?;
    let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    Ok(Json(
        serde_json::json!({ "path": dest.display().to_string(), "bytes": size }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# kept comment
[network]
dedicated_ips = ["10.0.0.9"]

[admin]
db_path = "/var/lib/rust-proxy/rust-proxy.db"

[acme]
cert_dir = "/var/lib/rust-proxy/certs"
account_key_path = "/var/lib/rust-proxy/acme-account.key"
"#;

    fn change(doc: &mut DocumentMut, key: &str, v: Value) -> Result<(), ApiError> {
        apply_change(doc, field(key).unwrap(), &v)
    }

    #[test]
    fn edits_keep_comments_and_validate() {
        let mut doc: DocumentMut = SAMPLE.parse().unwrap();
        change(
            &mut doc,
            "network.max_connections_per_ip",
            serde_json::json!(50),
        )
        .unwrap();
        change(
            &mut doc,
            "network.dedicated_ips",
            serde_json::json!(["10.0.0.9", " ", "10.0.0.10"]),
        )
        .unwrap();
        change(
            &mut doc,
            "admin.log_dir",
            serde_json::json!("/var/log/rust-proxy"),
        )
        .unwrap();
        let text = doc.to_string();
        assert!(text.starts_with("# kept comment"));
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.network.max_connections_per_ip, 50);
        assert_eq!(cfg.network.dedicated_ips.len(), 2);
        // Blank optional text removes the key again.
        change(&mut doc, "admin.log_dir", serde_json::json!("")).unwrap();
        assert!(
            Config::parse(&doc.to_string())
                .unwrap()
                .admin
                .log_dir
                .is_none()
        );
    }

    #[test]
    fn bad_values_are_refused_before_anything_is_written() {
        let mut doc: DocumentMut = SAMPLE.parse().unwrap();
        assert!(
            change(
                &mut doc,
                "network.max_connections_per_ip",
                serde_json::json!(-1)
            )
            .is_err()
        );
        assert!(
            change(
                &mut doc,
                "network.max_connections_per_ip",
                serde_json::json!("ten")
            )
            .is_err()
        );
        assert!(change(&mut doc, "acme.cert_dir", serde_json::json!("")).is_err());
        assert!(change(&mut doc, "admin.db_path", serde_json::json!("/tmp/x.db")).is_err());
        assert!(change(&mut doc, "admin.log_dir", serde_json::json!("a\nb")).is_err());
        // Type-correct but semantically wrong: caught by Config::parse.
        change(
            &mut doc,
            "network.dedicated_ips",
            serde_json::json!(["not-an-ip"]),
        )
        .unwrap();
        assert!(Config::parse(&doc.to_string()).is_err());
    }

    #[test]
    fn atomic_write_keeps_a_backup_and_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rp-settings-{:x}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        write_config(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(
            std::fs::read_to_string(dir.join("config.toml.bak")).unwrap(),
            "old"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o660
        );
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            2,
            "no temp file left behind"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_listed_key_exists_in_the_config_model() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let json = serde_json::to_value(&cfg).unwrap();
        for f in FIELDS {
            assert!(
                json.pointer(&format!("/{}", f.key.replace('.', "/")))
                    .is_some()
                    || f.kind == Kind::Secret
                    || matches!(f.kind, Kind::OptText | Kind::OptBool),
                "{} is not a config.toml setting",
                f.key
            );
        }
    }
}
