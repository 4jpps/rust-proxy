//! HTTP request forwarding to an upstream, including WebSocket upgrade
//! passthrough. One upstream TCP connection per proxied request (no
//! pooling yet -- see the module-level TODO in `mod.rs` if this becomes
//! a bottleneck) so there's no shared connection state to reason about
//! under concurrent hot-reloads.

use std::net::SocketAddr;
use std::path::Path;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, UPGRADE};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

use crate::config::{RedirectStatus, RedirectTarget};
use crate::state::AppState;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Both a plain `TcpStream` and a `tokio_rustls` TLS-wrapped one need to
/// end up as the same `TokioIo<_>` type for `hyper::client::conn::http1`
/// -- this trait lets `forward_http` box either behind one type instead
/// of duplicating the whole handshake/send/upgrade sequence per branch.
trait UpstreamIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> UpstreamIo for T {}

/// Everything about how to reach and speak to one host's upstream,
/// beyond the already-resolved `SocketAddr` -- grouped so `forward_http`
/// doesn't need a five-argument signature; see each field's own comment
/// for what it controls.
pub struct UpstreamOptions<'a> {
    pub websockets_enabled: bool,
    /// Whether to speak TLS to the upstream at all -- `config::ProxyHost::upstream_https`.
    pub https: bool,
    /// Only consulted when `https` is set -- `config::ProxyHost::upstream_tls_verify`.
    pub tls_verify: bool,
    /// The original `host:port` string from `ProxyHost.upstream` (not
    /// the resolved `SocketAddr`) -- the host part (port stripped) is
    /// used as the TLS SNI/certificate-name when `https` is set, and
    /// the whole string is used as the literal `Host` header sent to
    /// the upstream when `preserve_host` is false.
    pub upstream_host_port: &'a str,
    /// `true` forwards the client's original `Host` header unmodified
    /// (the existing, unchanged behavior). `false` rewrites it to
    /// `upstream_host_port` instead -- `config::ProxyHost::upstream_preserve_host`.
    pub preserve_host: bool,
    /// The real client's connecting IP (`peer_ip` in `handle_https_request`)
    /// -- appended to `X-Forwarded-For` and used to synthesize
    /// `X-Forwarded-Proto`/`X-Forwarded-Host` so upstream applications can
    /// see who actually made the request instead of every request
    /// appearing to originate from this proxy's own IP. Every host this
    /// proxy forwards to sits behind it -- there's no config knob to
    /// disable this, unlike `preserve_host` (which controls the `Host`
    /// header's own semantics for routing, a separate concern).
    pub client_ip: std::net::IpAddr,
    /// `config::ProxyHost::rewrite_samesite_none_cookies` -- see that
    /// field's doc comment for why this exists, and
    /// `rewrite_samesite_none_to_lax`'s doc comment for the real
    /// production incident that led to building it.
    pub rewrite_samesite_none_cookies: bool,
}

pub fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    let has_upgrade_header = req
        .headers()
        .get(UPGRADE)
        .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .unwrap_or(false);
    let has_connection_upgrade = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    has_upgrade_header && has_connection_upgrade
}

/// Merges any split `cookie` request headers into a single header line
/// before the request is forwarded to an HTTP/1.1 upstream.
///
/// RFC 7540 §8.1.2.5 explicitly permits an HTTP/2 client to split the
/// `Cookie` header into multiple separate HTTP/2 header fields (it
/// improves HPACK compression), and REQUIRES an intermediary that
/// translates the request to HTTP/1.1 -- exactly what this proxy does,
/// since it always speaks HTTP/1.1 upstream regardless of what the
/// client used -- to reconstitute a single `Cookie` header by joining
/// the field values with `"; "` before forwarding. Real Chromium and
/// Firefox both split cookies this way over h2; curl, httpx, and
/// Node's `fetch` do not, which is exactly why this went undetected by
/// every scripted reproduction attempt and only ever failed for real
/// browser users.
///
/// Real production incident this exists for: GitLab logins behind this
/// proxy failed with a 422 `InvalidAuthenticityToken` for every real
/// browser, 100% reproducibly, while the identical token+cookie pair
/// replayed via httpx always succeeded. A raw TCP byte capture of what
/// this proxy actually forwarded showed the client's real session
/// cookie arriving as the *second* of four separate `cookie:` header
/// lines on the wire; Rack (GitLab's HTTP layer, like most HTTP/1.1
/// server frameworks) only reads the first `Cookie:` line, so the
/// session cookie was completely invisible to GitLab -- it saw no
/// session at all, and rejected the CSRF token that had been issued
/// for a session it could no longer see. Bypassing this proxy entirely
/// with a minimal from-scratch HTTP/2 proxy that correctly merges
/// cookies fixed the same request instantly, confirming this proxy was
/// the faulty component.
///
/// A no-op when the request had zero or one `cookie` header to begin
/// with (the common case for HTTP/1.1 clients, and any h2 client that
/// didn't choose to split its cookies).
fn merge_split_cookie_headers(req: &mut Request<Incoming>) {
    let mut values = req.headers().get_all(hyper::header::COOKIE).iter();
    let Some(first) = values.next() else { return };
    let Some(second) = values.next() else { return };

    let mut merged = Vec::new();
    if let Ok(s) = first.to_str() {
        merged.push(s.to_string());
    }
    if let Ok(s) = second.to_str() {
        merged.push(s.to_string());
    }
    for value in values {
        if let Ok(s) = value.to_str() {
            merged.push(s.to_string());
        }
    }

    let Ok(value) = hyper::header::HeaderValue::from_str(&merged.join("; ")) else {
        return;
    };
    req.headers_mut().remove(hyper::header::COOKIE);
    req.headers_mut().insert(hyper::header::COOKIE, value);
}

/// Downgrades `SameSite=None` to `SameSite=Lax` on every `Set-Cookie`
/// response header -- see `config::ProxyHost::rewrite_samesite_none_cookies`'s
/// doc comment for why an operator would opt a host into this. Every
/// other `Set-Cookie` attribute (`Secure`, `HttpOnly`, `Path`,
/// `Expires`, the cookie's own name/value, which may itself
/// legitimately contain mixed-case text) is left completely
/// untouched -- only the literal `SameSite=None` substring, matched
/// case-insensitively, is replaced. A cookie with no `SameSite`
/// attribute at all, or one already set to `Lax`/`Strict`, is left
/// exactly as the upstream sent it.
///
/// Real production incident this exists for: a GitLab instance behind
/// this proxy set `SameSite=None` on its session cookie
/// unconditionally -- a since-obsoleted Chrome-v80-era browser-compat
/// workaround baked into GitLab's own code, not anything this proxy or
/// its operator controlled. That cookie reliably vanished from one
/// real user's browser between the page load that set it and their
/// very next request -- confirmed via temporary server-side logging
/// showing a valid session cookie in GitLab's response but completely
/// absent from the client's next request -- while no server-side
/// reproduction attempt (curl, httpx -- neither enforces `SameSite`
/// policy at all) ever reproduced it, since this is purely a real
/// browser privacy/tracking-protection feature silently dropping
/// exactly the kind of cookie `SameSite=None` marks as tracking-
/// capable, even in ordinary first-party same-site use. This can't be
/// fixed once upstream for every application a jpps/proxy operator
/// might put behind it -- hence a per-host proxy-level option instead
/// of a GitLab-specific patch.
fn rewrite_samesite_none_to_lax(headers: &mut hyper::HeaderMap) {
    let mut changed = false;
    let rewritten: Vec<hyper::header::HeaderValue> = headers
        .get_all(hyper::header::SET_COOKIE)
        .iter()
        .map(|value| {
            let Ok(s) = value.to_str() else {
                return value.clone();
            };
            let Some(idx) = s.to_ascii_lowercase().find("samesite=none") else {
                return value.clone();
            };
            let mut new_value = String::with_capacity(s.len());
            new_value.push_str(&s[..idx]);
            new_value.push_str("SameSite=Lax");
            new_value.push_str(&s[idx + "samesite=none".len()..]);
            match hyper::header::HeaderValue::from_str(&new_value) {
                Ok(v) => {
                    changed = true;
                    v
                }
                Err(_) => value.clone(),
            }
        })
        .collect();

    if !changed {
        return;
    }

    headers.remove(hyper::header::SET_COOKIE);
    for value in rewritten {
        headers.append(hyper::header::SET_COOKIE, value);
    }
}

/// Forwards `req` to `upstream`, streaming the response body back
/// unmodified. If `opts.websockets_enabled` and the request is a
/// WebSocket upgrade, splices the client and upstream connections
/// together after the 101 response instead of treating it as a normal
/// request/response. See `UpstreamOptions` for the HTTPS-upstream/
/// `Host`-header-rewrite knobs.
pub async fn forward_http(
    mut req: Request<Incoming>,
    upstream: SocketAddr,
    opts: UpstreamOptions<'_>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, BoxError> {
    merge_split_cookie_headers(&mut req);

    // Captured before any Host-header rewriting below so `X-Forwarded-Host`
    // always reflects what the client actually declared, even when
    // `preserve_host` is false and the literal `Host` header sent
    // upstream gets rewritten to the upstream's own address instead.
    let original_host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            req.uri().host().map(|h| match req.uri().port_u16() {
                Some(port) => format!("{h}:{port}"),
                None => h.to_string(),
            })
        });

    if !opts.preserve_host {
        let value = hyper::header::HeaderValue::from_str(opts.upstream_host_port)?;
        req.headers_mut().insert(hyper::header::HOST, value);
    } else if req.headers().get(hyper::header::HOST).is_none() {
        // A genuine HTTP/2 request (every modern browser) carries its
        // target host as the `:authority` pseudo-header, not a literal
        // `Host:` header -- hyper/h2 surfaces that via `req.uri()`, so
        // `req.headers()` can be legitimately empty of it even though
        // the request unambiguously declares one. That's fine for the
        // client-facing side, but this connection to the upstream is
        // always plain HTTP/1.1 (`hyper::client::conn::http1` below),
        // which requires a literal `Host` header on the wire -- confirmed
        // as a real bug via a real upstream that correctly rejected the
        // resulting Host-less request with its own 400. `preserve_host`
        // still means "forward what the client actually declared, don't
        // rewrite it to the upstream's own address" -- this only ever
        // synthesizes the header from the request's own declared
        // authority, never substitutes anything else.
        if let Some(host) = req.uri().host() {
            let value = match req.uri().port_u16() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            if let Ok(value) = hyper::header::HeaderValue::from_str(&value) {
                req.headers_mut().insert(hyper::header::HOST, value);
            }
        }
    }

    // Every proxied host sits behind this proxy from the upstream's point
    // of view, so without this every request would appear to originate
    // from this proxy's own IP -- breaking any upstream feature that
    // reasons about the real client (audit logs, IP-based rate limiting,
    // abuse detection). `X-Forwarded-For` is appended to (not replacing)
    // any value the client already sent, matching standard proxy
    // convention -- a well-behaved upstream configured with this proxy's
    // IP as a trusted proxy hop reads the right-most/newest entry as the
    // real client, so an earlier hop's genuine chain is preserved and a
    // client-spoofed value can't be passed off as this proxy's own
    // trusted observation. `handle_https_request` (this function's only
    // caller) only ever runs for genuine HTTPS client connections --
    // the plain-HTTP listener is redirect-only (`https_redirect_response`)
    // and never reaches here -- so `X-Forwarded-Proto` is always `https`.
    let xff_value = match req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        Some(existing) if !existing.is_empty() => format!("{existing}, {}", opts.client_ip),
        _ => opts.client_ip.to_string(),
    };
    if let Ok(value) = hyper::header::HeaderValue::from_str(&xff_value) {
        req.headers_mut().insert("x-forwarded-for", value);
    }
    req.headers_mut().insert(
        "x-forwarded-proto",
        hyper::header::HeaderValue::from_static("https"),
    );
    if let Some(host) = original_host
        && let Ok(value) = hyper::header::HeaderValue::from_str(&host)
    {
        req.headers_mut().insert("x-forwarded-host", value);
    }

    // A genuine HTTP/2 request's `req.uri()` is absolute-form (hyper/h2
    // builds it from the `:scheme`/`:authority`/`:path` pseudo-headers,
    // same reason the Host-header synthesis above has to exist at all)
    // -- but the upstream connection below always speaks plain
    // HTTP/1.1, where an absolute-form request line ("POST
    // https://host/path HTTP/1.1") is syntactically legal yet means
    // something different: it's specifically the form a client uses to
    // address a forward proxy, not an origin server. Must be downgraded
    // to origin-form (path+query only) before forwarding, done here
    // (after the Host header above still had `req.uri().host()`/
    // `port_u16()` available) or the outgoing request line silently
    // carries the wrong semantics. Confirmed as a real bug via a real
    // upstream (Proxmox's pveproxy) that rejected the resulting
    // absolute-form POST outright with its own 400 ("invalid proxy
    // uri") -- nginx (another real upstream, gitlab.jpps.us) tolerates
    // an absolute-form request line silently, which is exactly why
    // this went unnoticed until a POST to a stricter upstream hit it.
    if req.uri().authority().is_some()
        && let Some(path_and_query) = req.uri().path_and_query().cloned()
    {
        let mut parts = hyper::http::uri::Parts::default();
        parts.path_and_query = Some(path_and_query);
        if let Ok(origin_form) = hyper::Uri::from_parts(parts) {
            *req.uri_mut() = origin_form;
        }
    }

    // The upstream connection always speaks HTTP/1.1, so the forwarded request must say so. hyper's
    // HTTP/1 client only adds `Transfer-Encoding: chunked` to an HTTP/1.1 request; an HTTP/2
    // request without a Content-Length (git sends large pushes that way) was forwarded with no
    // framing at all, which HTTP/1.1 reads as an empty body, so the upstream got nothing (seen as a
    // large git push reaching GitLab as 483 bytes and failing with a 500).
    *req.version_mut() = hyper::Version::HTTP_11;

    let want_upgrade = opts.websockets_enabled && is_websocket_upgrade(&req);
    let client_upgrade = want_upgrade.then(|| hyper::upgrade::on(&mut req));

    let tcp = super::connect::connect_upstream(upstream).await?;
    let io: TokioIo<Box<dyn UpstreamIo>> = if opts.https {
        let host_only = opts
            .upstream_host_port
            .rsplit_once(':')
            .map_or(opts.upstream_host_port, |(host, _)| host);
        let server_name = rustls_pki_types::ServerName::try_from(host_only.to_string())?;
        let config = if opts.tls_verify {
            super::upstream_tls::verified_client_config()
        } else {
            super::upstream_tls::insecure_client_config()
        };
        let tls_stream = tokio_rustls::TlsConnector::from(config)
            .connect(server_name, tcp)
            .await?;
        TokioIo::new(Box::new(tls_stream) as Box<dyn UpstreamIo>)
    } else {
        TokioIo::new(Box::new(tcp) as Box<dyn UpstreamIo>)
    };
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            tracing::debug!(error = %err, "upstream connection closed");
        }
    });

    let mut resp = sender.send_request(req).await?;

    if opts.rewrite_samesite_none_cookies {
        rewrite_samesite_none_to_lax(resp.headers_mut());
    }

    if let (true, Some(client_upgrade)) = (
        resp.status() == hyper::StatusCode::SWITCHING_PROTOCOLS,
        client_upgrade,
    ) {
        let upstream_upgrade = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            match (client_upgrade.await, upstream_upgrade.await) {
                (Ok(client), Ok(upstream)) => {
                    let mut client = TokioIo::new(client);
                    let mut upstream = TokioIo::new(upstream);
                    if let Err(err) =
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        tracing::debug!(error = %err, "websocket passthrough ended");
                    }
                }
                _ => tracing::warn!("websocket upgrade failed on client or upstream side"),
            }
        });
        let (parts, _empty) = resp.into_parts();
        return Ok(Response::from_parts(
            parts,
            http_body_util::Empty::new()
                .map_err(|never: std::convert::Infallible| match never {})
                .boxed(),
        ));
    }

    let (parts, body) = resp.into_parts();
    Ok(Response::from_parts(parts, body.map_err(|e| e).boxed()))
}

/// Plain 301 redirect from `http://<host><path>` to the same on `https`,
/// used for `force_https` hosts' port-80 listener.
pub fn https_redirect_response<B>(req: &Request<B>) -> Response<BoxBody<Bytes, hyper::Error>> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host_no_port = host.split(':').next().unwrap_or(host);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let location = format!("https://{host_no_port}{path_and_query}");

    Response::builder()
        .status(hyper::StatusCode::MOVED_PERMANENTLY)
        .header(hyper::header::LOCATION, location)
        .body(
            http_body_util::Empty::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .expect("static redirect response is always valid")
}

/// Serves a `redirect` host's response -- the request never reaches an
/// upstream at all. `target.target` is an admin-configured absolute URL
/// (validated by `config::validate_redirect_target`), not something
/// reflected from request input, so -- unlike `proxy::login`'s
/// `return_to` -- it's fine for this to leave the site; that's the whole
/// point of the feature.
pub fn redirect_target_response<B>(
    req: &Request<B>,
    target: &RedirectTarget,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let location = if target.preserve_path {
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        format!("{}{}", target.target.trim_end_matches('/'), path_and_query)
    } else {
        target.target.clone()
    };
    let status = match target.status {
        RedirectStatus::Permanent => hyper::StatusCode::MOVED_PERMANENTLY,
        RedirectStatus::Temporary => hyper::StatusCode::FOUND,
    };

    Response::builder()
        .status(status)
        .header(hyper::header::LOCATION, location)
        .body(
            http_body_util::Empty::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .expect("static redirect response is always valid")
}

/// If `req`'s path is an ACME http-01 challenge fetch
/// (`/.well-known/acme-challenge/<token>`) for a token `state` currently
/// has a pending key authorization for, serves it directly per RFC 8555
/// SS8.3. This must be checked before `https_redirect_response` on a
/// `force_https` host's port-80 listener -- the CA's validator speaks
/// plain HTTP and never follows a redirect to `https`.
pub fn http01_challenge_response<B>(
    state: &AppState,
    req: &Request<B>,
) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
    let token = req
        .uri()
        .path()
        .strip_prefix(crate::acme::http01::CHALLENGE_PATH_PREFIX)?;
    let key_authorization = state.get_http01_challenge(token)?;
    Some(
        Response::builder()
            .status(hyper::StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(
                http_body_util::Full::new(Bytes::from(key_authorization))
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed(),
            )
            .expect("static challenge response is always valid"),
    )
}

/// Minimal percent-decoder for request paths -- just enough to stop
/// `%2e%2e%2f`-style encoded traversal from slipping past the plain
/// string checks below before the real guard (canonicalize + prefix
/// check) runs. Invalid/incomplete escapes are left as-is rather than
/// rejected outright; the canonicalize check downstream is the actual
/// security boundary, this only normalizes the common encoded case.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn content_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn static_not_found_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = "<!doctype html><html><head><title>Not found</title></head>\
        <body><h1>404 Not Found</h1></body></html>";
    Response::builder()
        .status(hyper::StatusCode::NOT_FOUND)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(
            http_body_util::Full::new(Bytes::from(body))
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .expect("static 404 response is always valid")
}

/// Serves a `static_root` host's response by resolving the request path
/// against `root` on disk. A directory or extensionless path falls back
/// to `index.html` inside it; anything that resolves outside `root`
/// (traversal via `../` or its percent-encoded form) or that doesn't
/// exist as a file is a plain 404 -- never a directory listing.
pub async fn serve_static_response<B>(
    req: &Request<B>,
    root: &Path,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let root = match tokio::fs::canonicalize(root).await {
        Ok(root) => root,
        Err(_) => return static_not_found_response(),
    };

    let decoded_path = percent_decode(req.uri().path());
    let relative = decoded_path.trim_start_matches('/');
    let mut candidate = root.clone();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        candidate.push(segment);
    }

    let resolved = match tokio::fs::canonicalize(&candidate).await {
        Ok(resolved) => resolved,
        Err(_) => return static_not_found_response(),
    };
    if !resolved.starts_with(&root) {
        return static_not_found_response();
    }

    let file_path = if resolved.is_dir() {
        resolved.join("index.html")
    } else {
        resolved
    };
    let file_path = match tokio::fs::canonicalize(&file_path).await {
        Ok(p) if p.starts_with(&root) && p.is_file() => p,
        _ => return static_not_found_response(),
    };

    match tokio::fs::read(&file_path).await {
        Ok(contents) => Response::builder()
            .status(hyper::StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, content_type_for(&file_path))
            .body(
                http_body_util::Full::new(Bytes::from(contents))
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed(),
            )
            .expect("static file response is always valid"),
        Err(_) => static_not_found_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn detects_websocket_upgrade_headers() {
        let req = Request::builder()
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .body(())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn plain_request_is_not_a_websocket_upgrade() {
        let req = Request::builder().body(()).unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn rewrite_samesite_none_downgrades_to_lax_and_preserves_other_attributes() {
        let mut headers = hyper::HeaderMap::new();
        headers.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static(
                "_gitlab_session=abc123; path=/; secure; HttpOnly; SameSite=None",
            ),
        );

        rewrite_samesite_none_to_lax(&mut headers);

        let value = headers
            .get(hyper::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            value,
            "_gitlab_session=abc123; path=/; secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn rewrite_samesite_none_is_case_insensitive() {
        let mut headers = hyper::HeaderMap::new();
        headers.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static("foo=bar; samesite=none"),
        );

        rewrite_samesite_none_to_lax(&mut headers);

        assert_eq!(
            headers
                .get(hyper::header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap(),
            "foo=bar; SameSite=Lax"
        );
    }

    #[test]
    fn rewrite_samesite_none_leaves_lax_and_strict_cookies_untouched() {
        let mut headers = hyper::HeaderMap::new();
        headers.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static("a=1; SameSite=Lax"),
        );
        headers.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static("b=2; SameSite=Strict"),
        );
        headers.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static("c=3"),
        );

        rewrite_samesite_none_to_lax(&mut headers);

        let values: Vec<&str> = headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            values,
            vec!["a=1; SameSite=Lax", "b=2; SameSite=Strict", "c=3"]
        );
    }

    #[test]
    fn rewrite_samesite_none_handles_multiple_set_cookie_headers_independently() {
        let mut headers = hyper::HeaderMap::new();
        headers.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static("session=x; SameSite=None; Secure"),
        );
        headers.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static("pref=en; path=/"),
        );
        headers.append(
            hyper::header::SET_COOKIE,
            hyper::header::HeaderValue::from_static("other=y; SameSite=None; Secure"),
        );

        rewrite_samesite_none_to_lax(&mut headers);

        let values: Vec<&str> = headers
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            values,
            vec![
                "session=x; SameSite=Lax; Secure",
                "pref=en; path=/",
                "other=y; SameSite=Lax; Secure"
            ]
        );
    }

    #[tokio::test]
    async fn forward_http_rewrites_samesite_none_cookies_only_when_the_host_option_is_enabled() {
        async fn run(rewrite_enabled: bool) -> String {
            let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_addr = upstream_listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (stream, _) = upstream_listener.accept().await.unwrap();
                let io = TokioIo::new(stream);
                let service = service_fn(|_req: Request<Incoming>| async move {
                    let body: BoxBody<Bytes, hyper::Error> = Empty::<Bytes>::new()
                        .map_err(|e: std::convert::Infallible| match e {})
                        .boxed();
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(200)
                            .header(
                                hyper::header::SET_COOKIE,
                                "session=x; Secure; SameSite=None",
                            )
                            .body(body)
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });

            let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy_listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (stream, _) = proxy_listener.accept().await.unwrap();
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| async move {
                    let opts = UpstreamOptions {
                        websockets_enabled: false,
                        https: false,
                        tls_verify: true,
                        upstream_host_port: "unused:0",
                        preserve_host: true,
                        client_ip: "203.0.113.42".parse().unwrap(),
                        rewrite_samesite_none_cookies: rewrite_enabled,
                    };
                    forward_http(req, upstream_addr, opts)
                        .await
                        .map_err(|e| e.to_string())
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });

            let stream = TcpStream::connect(proxy_addr).await.unwrap();
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            tokio::spawn(conn);
            let req = Request::builder()
                .uri("/")
                .header(hyper::header::HOST, "example.com")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let resp = sender.send_request(req).await.unwrap();
            resp.headers()
                .get(hyper::header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        }

        assert_eq!(
            run(true).await,
            "session=x; Secure; SameSite=Lax",
            "enabled must downgrade the upstream's SameSite=None"
        );
        assert_eq!(
            run(false).await,
            "session=x; Secure; SameSite=None",
            "disabled (the default) must leave the upstream's cookie untouched"
        );
    }

    #[test]
    fn connection_header_with_multiple_tokens_still_detected() {
        let req = Request::builder()
            .header(CONNECTION, "keep-alive, Upgrade")
            .header(UPGRADE, "websocket")
            .body(())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn redirect_response_preserves_host_and_path() {
        let req = Request::builder()
            .uri("/some/path?x=1")
            .header(hyper::header::HOST, "example.com")
            .body(())
            .unwrap();
        let resp = https_redirect_response(&req);
        assert_eq!(resp.status(), hyper::StatusCode::MOVED_PERMANENTLY);
        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "https://example.com/some/path?x=1");
    }

    async fn test_state() -> AppState {
        use crate::config::{AcmeConfig, AdminConfig, Config, DnsProviderKind, NetworkConfig};
        use std::path::PathBuf;

        let cfg = Config {
            network: NetworkConfig {
                bind_ranges: vec![],
                dedicated_ips: vec![],
                dhcp_interfaces: vec![],
                max_connections_per_ip: crate::config::DEFAULT_MAX_CONNECTIONS_PER_IP,
            },
            admin: AdminConfig {
                bind_ip_v4: Some("127.0.0.1".parse().unwrap()),
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
                dns_provider: DnsProviderKind::Cloudflare,
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
            siem: None,
            hosting: None,
        };
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        AppState::new(cfg, pool, vec![], vec![], None, None, None)
    }

    #[tokio::test]
    async fn http01_challenge_response_serves_a_pending_key_authorization() {
        let state = test_state().await;
        state.set_http01_challenge("tok-1".into(), "tok-1.thumbprint".into());

        let req = Request::builder()
            .uri("/.well-known/acme-challenge/tok-1")
            .body(())
            .unwrap();
        let resp = http01_challenge_response(&state, &req).unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("tok-1.thumbprint"));
    }

    #[tokio::test]
    async fn http01_challenge_response_is_none_for_an_unknown_token() {
        let state = test_state().await;
        let req = Request::builder()
            .uri("/.well-known/acme-challenge/unknown")
            .body(())
            .unwrap();
        assert!(http01_challenge_response(&state, &req).is_none());
    }

    #[tokio::test]
    async fn http01_challenge_response_is_none_for_unrelated_paths() {
        let state = test_state().await;
        state.set_http01_challenge("tok-1".into(), "tok-1.thumbprint".into());
        let req = Request::builder().uri("/some/other/path").body(()).unwrap();
        assert!(http01_challenge_response(&state, &req).is_none());
    }

    #[test]
    fn redirect_strips_port_from_host_header() {
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "example.com:80")
            .body(())
            .unwrap();
        let resp = https_redirect_response(&req);
        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "https://example.com/");
    }

    fn redirect_target(
        target: &str,
        preserve_path: bool,
        status: RedirectStatus,
    ) -> RedirectTarget {
        RedirectTarget {
            target: target.into(),
            preserve_path,
            status,
        }
    }

    #[test]
    fn redirect_target_response_appends_the_request_path_when_preserving_it() {
        let req = Request::builder().uri("/blog/post?x=1").body(()).unwrap();
        let target = redirect_target("https://new.example.com", true, RedirectStatus::Permanent);
        let resp = redirect_target_response(&req, &target);
        assert_eq!(resp.status(), hyper::StatusCode::MOVED_PERMANENTLY);
        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "https://new.example.com/blog/post?x=1");
    }

    #[test]
    fn redirect_target_response_does_not_double_up_a_trailing_slash() {
        let req = Request::builder().uri("/post").body(()).unwrap();
        let target = redirect_target("https://new.example.com/", true, RedirectStatus::Permanent);
        let resp = redirect_target_response(&req, &target);
        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "https://new.example.com/post");
    }

    #[test]
    fn redirect_target_response_ignores_the_request_path_when_not_preserving_it() {
        let req = Request::builder().uri("/whatever/path").body(()).unwrap();
        let target = redirect_target(
            "https://new.example.com/landing",
            false,
            RedirectStatus::Permanent,
        );
        let resp = redirect_target_response(&req, &target);
        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "https://new.example.com/landing");
    }

    #[test]
    fn redirect_target_response_uses_302_for_a_temporary_redirect() {
        let req = Request::builder().uri("/").body(()).unwrap();
        let target = redirect_target("https://new.example.com", true, RedirectStatus::Temporary);
        let resp = redirect_target_response(&req, &target);
        assert_eq!(resp.status(), hyper::StatusCode::FOUND);
    }

    /// End-to-end: a real fake upstream on loopback, our proxy server
    /// (using `forward_http` in its service_fn) in front of it, and a
    /// real client request driven all the way through -- proves the
    /// forwarding path actually works, not just that it compiles.
    #[tokio::test]
    async fn forward_http_proxies_a_real_request_to_a_loopback_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(|_req: Request<Incoming>| async {
                let body: BoxBody<Bytes, hyper::Error> = Empty::<Bytes>::new()
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(200)
                        .header("x-upstream", "yes")
                        .body(body)
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let upstream_host_port = upstream_addr.to_string();
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: &upstream_host_port,
                    preserve_host: true,
                    client_ip: "127.0.0.1".parse().unwrap(),
                    rewrite_samesite_none_cookies: false,
                };
                forward_http(req, upstream_addr, opts)
                    .await
                    .map_err(|e| e.to_string())
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "example.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-upstream").unwrap(), "yes");
    }

    /// Starts an upstream that counts the request-body bytes it receives, and a proxy in front of
    /// it speaking HTTP/1.1 or (prior-knowledge) HTTP/2 to the client. Returns the proxy address and
    /// a receiver for the byte count.
    async fn counting_upstream_behind_proxy(
        client_h2: bool,
    ) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<usize>) {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let (count_tx, count_rx) = tokio::sync::oneshot::channel::<usize>();
        let count_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(count_tx)));
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let service = service_fn(move |req: Request<Incoming>| {
                let count_tx = count_tx.clone();
                async move {
                    let n = req
                        .into_body()
                        .collect()
                        .await
                        .map(|b| b.to_bytes().len())
                        .unwrap_or(0);
                    if let Some(tx) = count_tx.lock().unwrap().take() {
                        let _ = tx.send(n);
                    }
                    Ok::<_, std::convert::Infallible>(Response::new(
                        Empty::<Bytes>::new()
                            .map_err(|e: std::convert::Infallible| match e {})
                            .boxed(),
                    ))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let service = service_fn(move |req: Request<Incoming>| async move {
                let upstream_host_port = upstream_addr.to_string();
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: &upstream_host_port,
                    preserve_host: true,
                    client_ip: "127.0.0.1".parse().unwrap(),
                    rewrite_samesite_none_cookies: false,
                };
                forward_http(req, upstream_addr, opts)
                    .await
                    .map_err(|e| e.to_string())
            });
            if client_h2 {
                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
            } else {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        });
        (proxy_addr, count_rx)
    }

    /// An 8 MB body sent in 64 KB pieces with no Content-Length (how git sends a large push).
    struct StreamedBody(usize);

    impl hyper::body::Body for StreamedBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            if self.0 == 0 {
                return std::task::Poll::Ready(None);
            }
            self.0 -= 1;
            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(
                vec![7u8; 64 * 1024],
            )))))
        }
    }

    fn streamed_body() -> StreamedBody {
        StreamedBody(128)
    }

    /// Regression test: a large git push through the proxy reached GitLab as 483 bytes.
    #[tokio::test]
    async fn forward_http_streams_a_large_chunked_body_with_expect_continue_from_an_http1_client() {
        let (proxy_addr, count_rx) = counting_upstream_behind_proxy(false).await;
        let io = TokioIo::new(TcpStream::connect(proxy_addr).await.unwrap());
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .method("POST")
            .uri("/repo.git/git-receive-pack")
            .header(hyper::header::HOST, "example.com")
            .header(hyper::header::TRANSFER_ENCODING, "chunked")
            .header(hyper::header::EXPECT, "100-continue")
            .body(streamed_body())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(count_rx.await.unwrap(), 8 * 1024 * 1024);
    }

    #[tokio::test]
    async fn forward_http_streams_a_large_body_from_an_http2_client() {
        let (proxy_addr, count_rx) = counting_upstream_behind_proxy(true).await;
        let io = TokioIo::new(TcpStream::connect(proxy_addr).await.unwrap());
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/repo.git/git-receive-pack")
            .body(streamed_body())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(count_rx.await.unwrap(), 8 * 1024 * 1024);
    }

    /// `preserve_host: false` must rewrite the `Host` header the
    /// upstream actually receives to `upstream_host_port`, not just
    /// leave the client's original value on the request untouched.
    #[tokio::test]
    async fn forward_http_rewrites_the_host_header_when_preserve_host_is_disabled() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(|req: Request<Incoming>| async move {
                let seen_host = req
                    .headers()
                    .get(hyper::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body: BoxBody<Bytes, hyper::Error> = Empty::<Bytes>::new()
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(200)
                        .header("x-seen-host", seen_host)
                        .body(body)
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: "backend.internal:9999",
                    preserve_host: false,
                    client_ip: "127.0.0.1".parse().unwrap(),
                    rewrite_samesite_none_cookies: false,
                };
                forward_http(req, upstream_addr, opts)
                    .await
                    .map_err(|e| e.to_string())
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "public.example.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-seen-host").unwrap(),
            "backend.internal:9999",
            "the upstream must see its own host:port, not the client's original Host header"
        );
    }

    /// Real production bug this guards against: a genuine HTTP/2 request
    /// (every modern browser) carries its target host as the
    /// `:authority` pseudo-header, never a literal `Host:` header --
    /// confirmed live via a real upstream that correctly rejected the
    /// resulting Host-less forwarded request with its own 400 "missing
    /// required Host header". `preserve_host: true` must still result in
    /// *some* `Host` header reaching the upstream (this connection is
    /// always plain HTTP/1.1, which requires one on the wire), synthesized
    /// from the request's own declared authority -- not the client's
    /// literal header, since here there isn't one.
    #[tokio::test]
    async fn forward_http_synthesizes_a_host_header_from_an_h2_requests_authority_when_preserve_host_is_enabled()
     {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(|req: Request<Incoming>| async move {
                let seen_host = req
                    .headers()
                    .get(hyper::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body: BoxBody<Bytes, hyper::Error> = Empty::<Bytes>::new()
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(200)
                        .header("x-seen-host", seen_host)
                        .body(body)
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        // The "proxy" hop here speaks h2 cleartext (prior-knowledge,
        // no TLS/ALPN needed for a direct back-to-back test) so the
        // incoming `Request<Incoming>` forward_http receives is a real
        // h2 request with no literal Host header, exactly like a real
        // browser's request would be.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: "unused:0",
                    preserve_host: true,
                    client_ip: "127.0.0.1".parse().unwrap(),
                    rewrite_samesite_none_cookies: false,
                };
                forward_http(req, upstream_addr, opts)
                    .await
                    .map_err(|e| e.to_string())
            });
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
                .unwrap();
        });

        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(tcp);
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .unwrap();
        tokio::spawn(conn);

        // Absolute-form URI, no Host header at all -- hyper's h2 client
        // derives the :authority pseudo-header from the URI itself.
        let req = Request::builder()
            .uri("https://real.example.com/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-seen-host").unwrap(),
            "real.example.com",
            "the upstream must still receive a Host header, synthesized from the h2 request's own :authority"
        );
    }

    /// Real production bug this guards against: forwarding a genuine
    /// HTTP/2 client request (absolute-form `req.uri()`, e.g.
    /// `https://pve.jpps.us/api2/json/access/ticket` -- see the
    /// `_synthesizes_a_host_header_..._h2_..._` test above for why h2
    /// requests carry an absolute URI at all) straight through to the
    /// upstream's HTTP/1.1 connection produced an absolute-form request
    /// line on the wire ("POST https://host/path HTTP/1.1"), which is
    /// syntactically legal HTTP/1.1 but specifically means "this
    /// request is addressed to a forward proxy," not an origin server.
    /// Confirmed live: Proxmox's `pveproxy` rejected exactly this shape
    /// of forwarded POST outright with its own `400 invalid proxy uri`
    /// (a real origin server correctly refusing to guess what an
    /// absolute-form POST addressed to it as if it were a proxy should
    /// mean) -- while GET requests to the same path and nginx-backed
    /// upstreams (gitlab.jpps.us) both silently tolerated it, which is
    /// exactly why this went unnoticed until a POST hit a stricter
    /// upstream. This test inspects the literal bytes written to the
    /// upstream socket (not `Request::uri()` as re-parsed by a hyper
    /// H1 *server*, which could silently normalize the very thing under
    /// test) to prove the request line is origin-form on the wire.
    /// Every proxied host's upstream must see who really made the
    /// request -- without this, every request looks like it came from
    /// this proxy's own IP, breaking any upstream feature that reasons
    /// about the real client (audit logs, IP-based rate limiting, abuse
    /// detection). Also verifies `X-Forwarded-For` is appended to (not
    /// clobbering) a value the client already sent, and that
    /// `X-Forwarded-Proto`/`X-Forwarded-Host` are set correctly.
    #[tokio::test]
    async fn forward_http_sets_x_forwarded_headers_for_the_real_client() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(|req: Request<Incoming>| async move {
                let xff = req
                    .headers()
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let xfp = req
                    .headers()
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let xfh = req
                    .headers()
                    .get("x-forwarded-host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body: BoxBody<Bytes, hyper::Error> = Empty::<Bytes>::new()
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(200)
                        .header("x-seen-xff", xff)
                        .header("x-seen-xfp", xfp)
                        .header("x-seen-xfh", xfh)
                        .body(body)
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: "unused:0",
                    preserve_host: true,
                    client_ip: "203.0.113.42".parse().unwrap(),
                    rewrite_samesite_none_cookies: false,
                };
                forward_http(req, upstream_addr, opts)
                    .await
                    .map_err(|e| e.to_string())
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        // The client already declares an (untrusted) X-Forwarded-For --
        // this proxy's own observed IP must be appended, not substituted.
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "public.example.com")
            .header("x-forwarded-for", "198.51.100.7")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-seen-xff").unwrap(),
            "198.51.100.7, 203.0.113.42",
            "must append the real peer IP, not replace an existing chain"
        );
        assert_eq!(resp.headers().get("x-seen-xfp").unwrap(), "https");
        assert_eq!(
            resp.headers().get("x-seen-xfh").unwrap(),
            "public.example.com"
        );
    }

    #[tokio::test]
    async fn forward_http_downgrades_an_h2_requests_absolute_form_uri_to_origin_form_for_the_http1_upstream()
     {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request_text = String::from_utf8_lossy(&buf[..n]);
            let request_line = request_text.lines().next().unwrap_or("");
            let response = if request_line == "POST /api2/json/access/ticket HTTP/1.1" {
                "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n"
            };
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: "unused:0",
                    preserve_host: true,
                    client_ip: "127.0.0.1".parse().unwrap(),
                    rewrite_samesite_none_cookies: false,
                };
                forward_http(req, upstream_addr, opts)
                    .await
                    .map_err(|e| e.to_string())
            });
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
                .unwrap();
        });

        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(tcp);
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .unwrap();
        tokio::spawn(conn);

        // Absolute-form URI, exactly what a real HTTP/2 client (every
        // modern browser) sends -- hyper's h2 client builds the request
        // from this directly, no literal Host header involved.
        let req = Request::builder()
            .method("POST")
            .uri("https://pve.jpps.us/api2/json/access/ticket")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        assert_eq!(
            resp.status(),
            200,
            "upstream only returns 200 if it saw an origin-form request line -- see the mock's own check"
        );
    }

    #[tokio::test]
    async fn forward_http_merges_an_h2_requests_split_cookie_headers_into_one_http1_cookie_line() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request_text = String::from_utf8_lossy(&buf[..n]);
            let cookie_lines: Vec<&str> = request_text
                .lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("cookie:"))
                .collect();
            let response = if cookie_lines.len() == 1
                && cookie_lines[0]
                    == "cookie: preferred_language=en; _gitlab_session=abc123; other=xyz"
            {
                "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n"
            };
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: "unused:0",
                    preserve_host: true,
                    client_ip: "127.0.0.1".parse().unwrap(),
                    rewrite_samesite_none_cookies: false,
                };
                forward_http(req, upstream_addr, opts)
                    .await
                    .map_err(|e| e.to_string())
            });
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
                .unwrap();
        });

        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(tcp);
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .unwrap();
        tokio::spawn(conn);

        // Real HTTP/2 clients (RFC 7540 §8.1.2.5) may split Cookie into
        // several header fields for better HPACK compression -- hyper's
        // h2 client lets us build a request with multiple `cookie`
        // header values the same way.
        let req = Request::builder()
            .method("GET")
            .uri("https://gitlab.jpps.us/users/sign_in")
            .header(hyper::header::COOKIE, "preferred_language=en")
            .header(hyper::header::COOKIE, "_gitlab_session=abc123")
            .header(hyper::header::COOKIE, "other=xyz")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        assert_eq!(
            resp.status(),
            200,
            "upstream only returns 200 if it saw a single merged Cookie header -- see the mock's own check"
        );
    }

    fn self_signed_server_config(domain: &str) -> rustls::ServerConfig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let entry = crate::proxy::tls::self_signed_entry(domain);
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(entry.cert_chain.clone(), entry.private_key.clone_key())
            .unwrap()
    }

    /// Same three-hop shape as `forward_http_proxies_a_real_request_to_a_loopback_upstream`
    /// (real client -> real "proxy" listener running `forward_http` in
    /// its `service_fn` -> real upstream), except the upstream here
    /// speaks real self-signed TLS -- proves `https: true` actually
    /// completes a real TLS handshake and forwards the request, not
    /// just that the code compiles or that a verifier type is wired in
    /// somewhere. `verify: false` accepts it; `verify: true` (the next
    /// test) must reject the same upstream.
    async fn run_https_upstream_round_trip(
        tls_verify: bool,
    ) -> Result<Response<Incoming>, BoxError> {
        let tls_config = Arc::new(self_signed_server_config("upstream.internal"));
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = upstream_listener.accept().await else {
                return;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let io = TokioIo::new(tls_stream);
            let service = service_fn(|_req: Request<Incoming>| async {
                let body: BoxBody<Bytes, hyper::Error> = Empty::<Bytes>::new()
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(200)
                        .header("x-upstream-tls", "yes")
                        .body(body)
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: true,
                    tls_verify,
                    upstream_host_port: "upstream.internal:0",
                    preserve_host: true,
                    client_ip: "127.0.0.1".parse().unwrap(),
                    rewrite_samesite_none_cookies: false,
                };
                forward_http(req, upstream_addr, opts)
                    .await
                    .map_err(|e| e.to_string())
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "example.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        sender
            .send_request(req)
            .await
            .map_err(|e| Box::new(e) as BoxError)
    }

    #[tokio::test]
    async fn forward_http_reaches_a_self_signed_https_upstream_when_verify_is_disabled() {
        let resp = run_https_upstream_round_trip(false).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-upstream-tls").unwrap(), "yes");
    }

    /// When `forward_http` fails inside the "proxy" hop's `service_fn`,
    /// hyper aborts that connection rather than synthesizing a response
    /// (same reason `handle_https_request` in production converts this
    /// into an explicit 502 itself instead of relying on hyper to do
    /// it) -- so from the real client's side, a rejected upstream
    /// certificate surfaces as the request itself failing, not as a
    /// successful response carrying an error body.
    #[tokio::test]
    async fn forward_http_rejects_a_self_signed_https_upstream_when_verify_is_enabled() {
        let result = run_https_upstream_round_trip(true).await;
        assert!(
            result.is_err(),
            "a self-signed cert must be rejected when tls_verify is enabled, not silently accepted"
        );
    }

    /// Mirrors this codebase's existing convention for filesystem-backed
    /// tests (see `db.rs`'s `backup_to`/`vacuum` tests) -- a uniquely
    /// named directory under `std::env::temp_dir()`, left on disk after
    /// the test (the OS temp dir is periodically cleaned; nothing here
    /// depends on cleanup happening promptly).
    struct StaticRootFixture {
        root: std::path::PathBuf,
        parent: std::path::PathBuf,
    }

    fn static_root_fixture() -> StaticRootFixture {
        let base = std::env::temp_dir().join(format!(
            "rust-proxy-static-root-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
        std::fs::write(root.join("style.css"), "body{}").unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub").join("index.html"), "<h1>sub</h1>").unwrap();
        std::fs::write(base.join("secret.txt"), "top secret").unwrap();
        StaticRootFixture { root, parent: base }
    }

    impl Drop for StaticRootFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.parent);
        }
    }

    impl StaticRootFixture {
        fn path(&self) -> &std::path::Path {
            &self.root
        }
    }

    async fn body_string(resp: Response<BoxBody<Bytes, hyper::Error>>) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn serve_static_response_serves_a_real_file_with_the_right_content_type() {
        let root = static_root_fixture();
        let req = Request::builder().uri("/style.css").body(()).unwrap();
        let resp = serve_static_response(&req, root.path()).await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/css; charset=utf-8"
        );
        assert_eq!(body_string(resp).await, "body{}");
    }

    #[tokio::test]
    async fn serve_static_response_falls_back_to_index_html_for_the_root_path() {
        let root = static_root_fixture();
        let req = Request::builder().uri("/").body(()).unwrap();
        let resp = serve_static_response(&req, root.path()).await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert_eq!(body_string(resp).await, "<h1>home</h1>");
    }

    #[tokio::test]
    async fn serve_static_response_falls_back_to_index_html_for_a_subdirectory() {
        let root = static_root_fixture();
        let req = Request::builder().uri("/sub").body(()).unwrap();
        let resp = serve_static_response(&req, root.path()).await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert_eq!(body_string(resp).await, "<h1>sub</h1>");
    }

    #[tokio::test]
    async fn serve_static_response_404s_a_missing_file() {
        let root = static_root_fixture();
        let req = Request::builder().uri("/nope.html").body(()).unwrap();
        let resp = serve_static_response(&req, root.path()).await;
        assert_eq!(resp.status(), hyper::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serve_static_response_refuses_a_plain_traversal_path() {
        let root = static_root_fixture();
        let req = Request::builder().uri("/../secret.txt").body(()).unwrap();
        let resp = serve_static_response(&req, root.path()).await;
        assert_eq!(resp.status(), hyper::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serve_static_response_refuses_a_percent_encoded_traversal_path() {
        let root = static_root_fixture();
        let req = Request::builder()
            .uri("/%2e%2e/%2e%2e/etc/passwd")
            .body(())
            .unwrap();
        let resp = serve_static_response(&req, root.path()).await;
        assert_eq!(resp.status(), hyper::StatusCode::NOT_FOUND);
    }
}
