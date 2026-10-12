//! Optional security-event forwarding to a syslog collector / SIEM.
//!
//! Vendor-neutral on purpose: events leave as plain syslog (RFC 5424 or
//! RFC 3164) over UDP, TCP or TLS, with the message body as `key=value`
//! pairs, flat JSON, or CEF. Wazuh, Splunk, Graylog, rsyslog and
//! friends all ingest at least one of those. Nothing here knows about
//! any particular product, and the whole feature is inert (a single
//! atomic load per call site) until a config with `enabled = true` is
//! applied.
//!
//! Delivery never touches the request path: call sites format one line
//! and `try_send` it into a bounded queue; a background task owns the
//! socket, reconnects with backoff, and a full queue drops the newest
//! event (counted in `stats()`) instead of waiting.
//!
//! Secrets: call sites pass explicit fields (never headers, bodies or
//! query strings), and the formatter additionally redacts the value of
//! any field whose name looks credential-like.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use chrono::{DateTime, Utc};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

use crate::config::{SiemConfig, SiemMessageFormat, SiemProtocol, SyslogFormat};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// One event per proxied request (high volume, opt-in).
    Access,
    /// A request or login refused: ACL mismatch, bad credentials.
    Denied,
    /// Admin API activity and authentication failures.
    Admin,
    /// Certificate issuance / renewal.
    Cert,
    /// Daemon lifecycle and forwarder self-reports.
    System,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Category::Access => "access",
            Category::Denied => "denied",
            Category::Admin => "admin",
            Category::Cert => "cert",
            Category::System => "system",
        }
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// Syslog severities (the subset this daemon uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
}

impl Severity {
    fn name(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Notice => "notice",
            Severity::Info => "info",
        }
    }

    fn cef(self) -> u8 {
        match self {
            Severity::Error => 7,
            Severity::Warning => 5,
            Severity::Notice => 3,
            Severity::Info => 1,
        }
    }
}

const MAX_VALUE_LEN: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const UDP_REFRESH: Duration = Duration::from_secs(300);

static SENT: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
static SINK: ArcSwapOption<Sink> = ArcSwapOption::const_empty();

#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub active: bool,
    pub sent: u64,
    pub dropped: u64,
    pub errors: u64,
    pub last_error: Option<String>,
}

pub fn stats() -> Stats {
    Stats {
        active: SINK.load().is_some(),
        sent: SENT.load(Ordering::Relaxed),
        dropped: DROPPED.load(Ordering::Relaxed),
        errors: ERRORS.load(Ordering::Relaxed),
        last_error: LAST_ERROR.lock().ok().and_then(|g| g.clone()),
    }
}

fn record_error(msg: String) {
    ERRORS.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut g) = LAST_ERROR.lock() {
        *g = Some(msg);
    }
}

struct FormatCfg {
    facility: u8,
    syslog: SyslogFormat,
    body: SiemMessageFormat,
    app_name: String,
    hostname: String,
}

struct Sink {
    tx: mpsc::Sender<String>,
    fmt: FormatCfg,
    categories: u8,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Sink {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl Sink {
    fn new(cfg: &SiemConfig, tx: mpsc::Sender<String>) -> Result<Self, String> {
        let mut categories = 0u8;
        for c in &cfg.categories {
            categories |= match c.as_str() {
                "access" => Category::Access.bit(),
                "denied" => Category::Denied.bit(),
                "admin" => Category::Admin.bit(),
                "cert" => Category::Cert.bit(),
                "system" => Category::System.bit(),
                other => return Err(format!("unknown siem category \"{other}\"")),
            };
        }
        Ok(Sink {
            tx,
            fmt: FormatCfg {
                facility: cfg.facility_number()?,
                syslog: cfg.syslog_format,
                body: cfg.message_format,
                app_name: cfg.app_name.trim().to_string(),
                hostname: cfg.hostname.clone().unwrap_or_else(local_hostname),
            },
            categories,
            task: None,
        })
    }

    /// Returns whether the event was queued.
    fn submit(
        &self,
        force: bool,
        cat: Category,
        sev: Severity,
        event: &str,
        message: &str,
        fields: &[(&str, &str)],
    ) -> bool {
        if !force && self.categories & cat.bit() == 0 {
            return false;
        }
        let line = format_event(&self.fmt, Utc::now(), cat, sev, event, message, fields);
        match self.tx.try_send(line) {
            Ok(()) => true,
            Err(_) => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

fn local_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic()))
        .unwrap_or_else(|| "-".into())
}

/// True when forwarding is active and `cat` is selected. Cheap enough to
/// guard allocation-heavy call sites (e.g. per-request access events).
pub fn wants(cat: Category) -> bool {
    SINK.load()
        .as_ref()
        .is_some_and(|s| s.categories & cat.bit() != 0)
}

/// Queue one event. A no-op when forwarding is off or `cat` is not
/// selected. Never blocks and never fails.
pub fn emit(cat: Category, sev: Severity, event: &str, message: &str, fields: &[(&str, &str)]) {
    if let Some(sink) = SINK.load().as_ref() {
        sink.submit(false, cat, sev, event, message, fields);
    }
}

/// Queue a test event regardless of the category selection. Returns
/// whether forwarding is active and the event was queued.
pub fn emit_test(message: &str) -> bool {
    match SINK.load().as_ref() {
        Some(sink) => sink.submit(
            true,
            Category::System,
            Severity::Notice,
            "siem_test",
            message,
            &[],
        ),
        None => false,
    }
}

/// Install (or, when `cfg` is disabled, remove) the forwarder. Must be
/// called from within the tokio runtime.
pub fn apply(cfg: &SiemConfig) -> Result<(), String> {
    cfg.validate()?;
    if !cfg.enabled {
        SINK.store(None);
        return Ok(());
    }
    let handle = tokio::runtime::Handle::try_current()
        .map_err(|_| "siem::apply must run inside the tokio runtime".to_string())?;
    let tls = if cfg.protocol == SiemProtocol::Tls {
        Some(TlsConnector::from(tls_config(cfg)?))
    } else {
        None
    };
    let (tx, rx) = mpsc::channel(cfg.queue_size);
    let mut sink = Sink::new(cfg, tx)?;
    sink.task = Some(handle.spawn(run_sender(cfg.clone(), rx, tls)));
    SINK.store(Some(Arc::new(sink)));
    Ok(())
}

fn tls_config(cfg: &SiemConfig) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = &cfg.tls_ca_file {
        let pem =
            std::fs::read(path).map_err(|e| format!("siem.tls_ca_file {}: {e}", path.display()))?;
        let mut added = 0;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert = cert.map_err(|e| format!("siem.tls_ca_file {}: {e}", path.display()))?;
            roots
                .add(cert)
                .map_err(|e| format!("siem.tls_ca_file {}: {e}", path.display()))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!(
                "siem.tls_ca_file {} contains no certificates",
                path.display()
            ));
        }
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

enum Conn {
    Udp(tokio::net::UdpSocket, std::time::Instant),
    Tcp(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl Conn {
    async fn send(&mut self, line: &str) -> std::io::Result<()> {
        match self {
            Conn::Udp(sock, _) => sock.send(line.as_bytes()).await.map(|_| ()),
            Conn::Tcp(s) => write_framed(s, line).await,
            Conn::Tls(s) => write_framed(s.as_mut(), line).await,
        }
    }

    fn stale(&self) -> bool {
        matches!(self, Conn::Udp(_, at) if at.elapsed() > UDP_REFRESH)
    }

    /// True when a plain TCP peer has already closed its end, so the next
    /// write would be swallowed by the kernel instead of failing.
    fn peer_closed(&self) -> bool {
        match self {
            Conn::Tcp(s) => matches!(s.try_read(&mut [0u8; 1]), Ok(0)),
            _ => false,
        }
    }

    fn is_udp(&self) -> bool {
        matches!(self, Conn::Udp(..))
    }
}

async fn write_framed<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    line: &str,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
    w.write_all(&buf).await?;
    w.flush().await
}

async fn connect(cfg: &SiemConfig, tls: &Option<TlsConnector>) -> Result<Conn, String> {
    let target = format!("{}:{}", cfg.host.trim(), cfg.port);
    let addr = tokio::net::lookup_host(&target)
        .await
        .map_err(|e| format!("resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("resolve {target}: no addresses"))?;
    match cfg.protocol {
        SiemProtocol::Udp => {
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let sock = tokio::net::UdpSocket::bind(bind)
                .await
                .map_err(|e| format!("udp bind: {e}"))?;
            sock.connect(addr)
                .await
                .map_err(|e| format!("udp connect {addr}: {e}"))?;
            Ok(Conn::Udp(sock, std::time::Instant::now()))
        }
        SiemProtocol::Tcp | SiemProtocol::Tls => {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("tcp connect {addr}: {e}"))?;
            let _ = stream.set_nodelay(true);
            match tls {
                None => Ok(Conn::Tcp(stream)),
                Some(connector) => {
                    let name = rustls_pki_types::ServerName::try_from(cfg.host.trim().to_string())
                        .map_err(|e| format!("tls server name {}: {e}", cfg.host))?;
                    let s = connector
                        .connect(name, stream)
                        .await
                        .map_err(|e| format!("tls handshake with {addr}: {e}"))?;
                    Ok(Conn::Tls(Box::new(s)))
                }
            }
        }
    }
}

async fn run_sender(cfg: SiemConfig, mut rx: mpsc::Receiver<String>, tls: Option<TlsConnector>) {
    let mut conn: Option<Conn> = None;
    let mut backoff = Duration::from_secs(1);
    let mut reported_down = false;
    while let Some(line) = rx.recv().await {
        loop {
            if conn.as_ref().is_some_and(Conn::stale) {
                conn = None;
            }
            if conn.is_none() {
                match tokio::time::timeout(IO_TIMEOUT, connect(&cfg, &tls)).await {
                    Ok(Ok(c)) => {
                        conn = Some(c);
                        backoff = Duration::from_secs(1);
                        if reported_down {
                            reported_down = false;
                            tracing::info!(host = %cfg.host, port = cfg.port, "siem collector connection restored");
                        }
                    }
                    other => {
                        let msg = match other {
                            Ok(Err(e)) => e,
                            _ => "connect timed out".to_string(),
                        };
                        record_error(msg.clone());
                        if !reported_down {
                            reported_down = true;
                            tracing::warn!(error = %msg, "siem collector unreachable -- events are buffered, then dropped, until it returns");
                        }
                        let jitter = Duration::from_millis(u64::from(rand::random::<u8>()) * 4);
                        tokio::time::sleep(backoff + jitter).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                }
            }
            if conn.as_ref().is_some_and(Conn::peer_closed) {
                conn = None;
                continue;
            }
            let c = conn.as_mut().expect("connection established above");
            match tokio::time::timeout(IO_TIMEOUT, c.send(&line)).await {
                Ok(Ok(())) => {
                    SENT.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                other => {
                    let msg = match other {
                        Ok(Err(e)) => format!("send: {e}"),
                        _ => "send timed out".to_string(),
                    };
                    record_error(msg);
                    let udp = c.is_udp();
                    conn = None;
                    if udp {
                        // Datagram loss is expected; do not stall on it.
                        DROPPED.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    // Stream: retry this line on a fresh connection.
                }
            }
        }
    }
}

const RESERVED_JSON_KEYS: [&str; 5] = ["event", "category", "severity", "message", "app"];
const SECRET_KEY_HINTS: [&str; 10] = [
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "credential",
    "apikey",
    "api_key",
    "private",
];

fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_KEY_HINTS.iter().any(|h| k.contains(h))
}

fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_VALUE_LEN));
    for ch in s.chars() {
        if out.len() + ch.len_utf8() > MAX_VALUE_LEN {
            out.push_str("...");
            break;
        }
        out.push(if ch.is_control() { ' ' } else { ch });
    }
    out
}

fn field_value(key: &str, value: &str) -> String {
    if is_secret_key(key) {
        "[redacted]".into()
    } else {
        clean(value)
    }
}

fn kv_quote(v: &str) -> String {
    if !v.is_empty() && !v.contains([' ', '"', '=', '\\']) {
        return v.to_string();
    }
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

fn cef_header_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

fn cef_ext_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=")
}

fn cef_key(key: &str) -> &str {
    match key {
        "client_ip" | "src_ip" => "src",
        "domain" => "dhost",
        "method" => "requestMethod",
        "path" => "request",
        "user" => "suser",
        "status" | "http_status" => "outcome",
        "user_agent" => "requestClientApplication",
        "bytes" => "out",
        other => other,
    }
}

fn format_body(
    fmt: &FormatCfg,
    cat: Category,
    sev: Severity,
    event: &str,
    message: &str,
    fields: &[(&str, &str)],
) -> String {
    let message = clean(message);
    match fmt.body {
        SiemMessageFormat::Kv => {
            let mut out = format!(
                "event={} category={} severity={} message={}",
                kv_quote(event),
                cat.name(),
                sev.name(),
                kv_quote(&message)
            );
            for (k, v) in fields {
                out.push(' ');
                out.push_str(&clean(k).replace([' ', '='], "_"));
                out.push('=');
                out.push_str(&kv_quote(&field_value(k, v)));
            }
            out
        }
        SiemMessageFormat::Json => {
            let mut map = serde_json::Map::new();
            map.insert("app".into(), fmt.app_name.clone().into());
            map.insert("event".into(), event.into());
            map.insert("category".into(), cat.name().into());
            map.insert("severity".into(), sev.name().into());
            map.insert("message".into(), message.into());
            for (k, v) in fields {
                let key = if RESERVED_JSON_KEYS.contains(k) {
                    format!("field_{k}")
                } else {
                    (*k).to_string()
                };
                map.insert(key, field_value(k, v).into());
            }
            serde_json::Value::Object(map).to_string()
        }
        SiemMessageFormat::Cef => {
            let mut out = format!(
                "CEF:0|rust-proxy|{}|{}|{}|{}|{}|cat={}",
                cef_header_escape(&fmt.app_name),
                env!("CARGO_PKG_VERSION"),
                cef_header_escape(event),
                cef_header_escape(&message),
                sev.cef(),
                cat.name()
            );
            for (k, v) in fields {
                out.push(' ');
                out.push_str(&cef_key(&clean(k)).replace([' ', '='], "_"));
                out.push('=');
                out.push_str(&cef_ext_escape(&field_value(k, v)));
            }
            out
        }
    }
}

fn format_event(
    fmt: &FormatCfg,
    ts: DateTime<Utc>,
    cat: Category,
    sev: Severity,
    event: &str,
    message: &str,
    fields: &[(&str, &str)],
) -> String {
    let pri = u16::from(fmt.facility) * 8 + sev as u16;
    let body = format_body(fmt, cat, sev, event, message, fields);
    let pid = std::process::id();
    match fmt.syslog {
        SyslogFormat::Rfc5424 => {
            let msgid: String = event
                .chars()
                .filter(|c| c.is_ascii_graphic())
                .take(32)
                .collect();
            let msgid = if msgid.is_empty() {
                "-".to_string()
            } else {
                msgid
            };
            format!(
                "<{pri}>1 {} {} {} {pid} {msgid} - {body}",
                ts.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                fmt.hostname,
                fmt.app_name,
            )
        }
        SyslogFormat::Rfc3164 => format!(
            "<{pri}>{} {} {}[{pid}]: {body}",
            ts.format("%b %e %H:%M:%S"),
            fmt.hostname,
            fmt.app_name,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tokio::io::{AsyncBufReadExt, BufReader};

    fn fmt(syslog: SyslogFormat, body: SiemMessageFormat) -> FormatCfg {
        FormatCfg {
            facility: 16,
            syslog,
            body,
            app_name: "rust-proxy".into(),
            hostname: "proxy".into(),
        }
    }

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 12, 3, 4, 5).unwrap()
    }

    fn cfg(host: &str, port: u16, protocol: SiemProtocol) -> SiemConfig {
        SiemConfig {
            enabled: true,
            host: host.into(),
            port,
            protocol,
            categories: vec!["denied".into(), "system".into()],
            ..SiemConfig::default()
        }
    }

    #[test]
    fn rfc5424_json_has_header_and_flat_body() {
        let line = format_event(
            &fmt(SyslogFormat::Rfc5424, SiemMessageFormat::Json),
            ts(),
            Category::Denied,
            Severity::Warning,
            "ip_denied",
            "blocked",
            &[("client_ip", "203.0.113.9"), ("domain", "a.example")],
        );
        let (head, body) = line.split_once(" - ").unwrap();
        assert!(
            head.starts_with("<132>1 2026-10-12T03:04:05.000Z proxy rust-proxy "),
            "{head}"
        );
        assert!(head.ends_with(" ip_denied"), "{head}");
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["event"], "ip_denied");
        assert_eq!(v["category"], "denied");
        assert_eq!(v["severity"], "warning");
        assert_eq!(v["client_ip"], "203.0.113.9");
        assert_eq!(v["domain"], "a.example");
    }

    #[test]
    fn rfc3164_header_shape() {
        let line = format_event(
            &fmt(SyslogFormat::Rfc3164, SiemMessageFormat::Kv),
            ts(),
            Category::Admin,
            Severity::Info,
            "admin_request",
            "ok",
            &[],
        );
        assert!(
            line.starts_with("<134>Oct 12 03:04:05 proxy rust-proxy["),
            "{line}"
        );
        assert!(line.contains("]: event=admin_request category=admin severity=info message=ok"));
    }

    #[test]
    fn kv_quotes_and_escapes_values() {
        let line = format_event(
            &fmt(SyslogFormat::Rfc5424, SiemMessageFormat::Kv),
            ts(),
            Category::Admin,
            Severity::Info,
            "e",
            "two words",
            &[("path", "/a b"), ("q", "say \"hi\""), ("empty", "")],
        );
        assert!(line.contains("message=\"two words\""));
        assert!(line.contains("path=\"/a b\""));
        assert!(line.contains("q=\"say \\\"hi\\\"\""));
        assert!(line.contains("empty=\"\""));
    }

    #[test]
    fn cef_header_and_extension_escaping() {
        let line = format_event(
            &fmt(SyslogFormat::Rfc5424, SiemMessageFormat::Cef),
            ts(),
            Category::Denied,
            Severity::Warning,
            "ip_denied",
            "a|b",
            &[("client_ip", "1.2.3.4"), ("path", "/x?a=b")],
        );
        let body = line.split_once(" - ").unwrap().1;
        assert!(body.starts_with("CEF:0|rust-proxy|rust-proxy|"), "{body}");
        assert!(body.contains("|ip_denied|a\\|b|5|cat=denied"), "{body}");
        assert!(body.contains("src=1.2.3.4"));
        assert!(body.contains("request=/x?a\\=b"));
    }

    #[test]
    fn secret_looking_fields_are_redacted_in_every_format() {
        for body in [
            SiemMessageFormat::Kv,
            SiemMessageFormat::Json,
            SiemMessageFormat::Cef,
        ] {
            let line = format_event(
                &fmt(SyslogFormat::Rfc5424, body),
                ts(),
                Category::Admin,
                Severity::Info,
                "e",
                "m",
                &[
                    ("password", "hunter2"),
                    ("Authorization", "Bearer abc123"),
                    ("session_cookie", "xyz"),
                    ("api_token_id", "t1"),
                    ("user", "alice"),
                ],
            );
            for leaked in ["hunter2", "abc123", "xyz", "t1\""] {
                assert!(!line.contains(leaked), "{body:?} leaked {leaked}: {line}");
            }
            assert!(line.contains("[redacted]"));
            assert!(line.contains("alice"));
        }
    }

    #[test]
    fn control_characters_cannot_split_or_forge_a_log_line() {
        let line = format_event(
            &fmt(SyslogFormat::Rfc5424, SiemMessageFormat::Kv),
            ts(),
            Category::Denied,
            Severity::Warning,
            "e",
            "x\n<134>1 forged",
            &[("path", "/a\r\nb")],
        );
        assert!(!line.contains('\n') && !line.contains('\r'));
    }

    #[test]
    fn long_values_are_truncated_on_a_char_boundary() {
        let long = "é".repeat(5000);
        let out = clean(&long);
        assert!(out.len() <= MAX_VALUE_LEN + 3);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn json_user_fields_cannot_overwrite_reserved_keys() {
        let line = format_event(
            &fmt(SyslogFormat::Rfc5424, SiemMessageFormat::Json),
            ts(),
            Category::Denied,
            Severity::Warning,
            "real_event",
            "m",
            &[("event", "forged")],
        );
        let v: serde_json::Value = serde_json::from_str(line.split_once(" - ").unwrap().1).unwrap();
        assert_eq!(v["event"], "real_event");
        assert_eq!(v["field_event"], "forged");
    }

    #[test]
    fn facility_names_and_numbers_parse() {
        let mut c = SiemConfig::default();
        assert_eq!(c.facility_number().unwrap(), 16);
        c.facility = "authpriv".into();
        assert_eq!(c.facility_number().unwrap(), 10);
        c.facility = "23".into();
        assert_eq!(c.facility_number().unwrap(), 23);
        c.facility = "24".into();
        assert!(c.facility_number().is_err());
        c.facility = "bogus".into();
        assert!(c.facility_number().is_err());
    }

    #[test]
    fn config_validation() {
        assert!(
            SiemConfig::default().validate().is_ok(),
            "disabled blank config is valid"
        );
        let mut c = cfg("collector.example", 514, SiemProtocol::Udp);
        assert!(c.validate().is_ok());
        c.host = " ".into();
        assert!(c.validate().is_err());
        let mut c = cfg("h", 514, SiemProtocol::Udp);
        c.categories = vec!["nope".into()];
        assert!(c.validate().is_err());
        c.categories = vec![];
        assert!(c.validate().is_err());
        let mut c = cfg("h", 514, SiemProtocol::Udp);
        c.queue_size = 0;
        assert!(c.validate().is_err());
        let mut c = cfg("h", 0, SiemProtocol::Udp);
        assert!(c.validate().is_err());
        c.port = 514;
        c.app_name = "has space".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_toml_section_parses_with_defaults() {
        let c: SiemConfig = toml::from_str("enabled = true\nhost = \"10.0.0.5\"\n").unwrap();
        assert_eq!(c.port, 514);
        assert_eq!(c.protocol, SiemProtocol::Udp);
        assert_eq!(c.message_format, SiemMessageFormat::Json);
        assert_eq!(c.categories, vec!["denied", "admin", "cert", "system"]);
        assert!(c.validate().is_ok());
    }

    #[tokio::test]
    async fn category_filter_and_full_queue_drop_without_blocking() {
        let (tx, mut rx) = mpsc::channel(2);
        let sink = Sink::new(&cfg("h", 514, SiemProtocol::Udp), tx).unwrap();
        // "admin" is not selected by cfg(): filtered out.
        assert!(!sink.submit(false, Category::Admin, Severity::Info, "e", "m", &[]));
        // Forced events bypass the filter.
        assert!(sink.submit(true, Category::Admin, Severity::Info, "e", "m", &[]));
        assert!(sink.submit(false, Category::Denied, Severity::Info, "e", "m", &[]));
        let before = DROPPED.load(Ordering::Relaxed);
        // Queue (capacity 2) is now full: dropped, not blocked.
        assert!(!sink.submit(false, Category::Denied, Severity::Info, "e", "m", &[]));
        assert!(DROPPED.load(Ordering::Relaxed) > before);
        assert!(rx.recv().await.is_some());
    }

    async fn run_with_sink(cfg: SiemConfig, tls: Option<TlsConnector>) -> Sink {
        let (tx, rx) = mpsc::channel(cfg.queue_size);
        let mut sink = Sink::new(&cfg, tx).unwrap();
        sink.task = Some(tokio::spawn(run_sender(cfg, rx, tls)));
        sink
    }

    #[tokio::test]
    async fn udp_delivery_end_to_end() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let sink = run_with_sink(cfg("127.0.0.1", port, SiemProtocol::Udp), None).await;
        assert!(sink.submit(
            false,
            Category::Denied,
            Severity::Warning,
            "ip_denied",
            "blocked",
            &[("domain", "a.example")]
        ));
        let mut buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
            .await
            .expect("datagram arrived")
            .unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.starts_with("<132>1 "), "{got}");
        assert!(got.contains("\"domain\":\"a.example\""));
    }

    #[tokio::test]
    async fn tcp_delivery_is_newline_framed_and_reconnects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let sink = run_with_sink(cfg("127.0.0.1", port, SiemProtocol::Tcp), None).await;

        for round in 0..2 {
            assert!(sink.submit(
                false,
                Category::System,
                Severity::Info,
                "round",
                &format!("r{round}"),
                &[]
            ));
            let (sock, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("collector got a connection")
                .unwrap();
            let mut lines = BufReader::new(sock).lines();
            let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                .await
                .expect("line arrived")
                .unwrap()
                .unwrap();
            assert!(
                line.contains(&format!("\"message\":\"r{round}\"")),
                "{line}"
            );
            drop(lines);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
