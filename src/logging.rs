//! Splits tracing output into three purpose-scoped files under
//! `<log_dir>` -- `proxy.log` (the data plane: listeners, TLS,
//! forwarding, WebSocket/passthrough, plus ACME issuance/renewal, since
//! that's squarely "why isn't this host serving traffic" territory
//! too), `access.log` (every admin API request, see
//! `api::routes::access_log`), and `server.log` (everything else --
//! startup/bootstrap, nftables sync, config loading) -- so debugging
//! one of "the proxy itself," "who changed what in the admin API," or
//! "the daemon's own lifecycle" means reading one focused file instead
//! of grepping a single interleaved stream. stdout (journald under
//! systemd) keeps behaving exactly as before -- unified, `info`-level
//! by default, still overridable via `RUST_LOG` -- these files are
//! additive, not a replacement.
//!
//! Routing is purely by tracing `target` (which defaults to the
//! module path), not a new concept -- `rust_proxy::proxy::*` and
//! `rust_proxy::acme::*` go to `proxy.log`, `rust_proxy::access` (the
//! one dedicated target `api::routes::access_log` emits under) goes to
//! `access.log`, everything else lands in `server.log`. The proxy
//! file additionally accepts `debug`-level events (there are real
//! `tracing::debug!` calls on the connection-handling hot paths in
//! `proxy::{mod,http,passthrough}`) -- exactly the detail "especially
//! for debugging" wants, without changing stdout/journald's own
//! default verbosity or volume.

use std::path::Path;

use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Keeps each file appender's background flush thread alive -- dropping
/// this early would silently stop that file from being written to.
/// `main` holds the return value for the whole process lifetime.
pub struct LogGuards {
    _proxy: tracing_appender::non_blocking::WorkerGuard,
    _access: tracing_appender::non_blocking::WorkerGuard,
    _server: tracing_appender::non_blocking::WorkerGuard,
}

fn is_proxy_target(target: &str) -> bool {
    target.starts_with("rust_proxy::proxy") || target.starts_with("rust_proxy::acme")
}

fn is_access_target(target: &str) -> bool {
    target.starts_with("rust_proxy::access")
}

/// Sets the global tracing subscriber (stdout + the three files below)
/// and creates `log_dir` if it doesn't exist yet. Call at most once --
/// same one-shot requirement `tracing_subscriber`'s own `.init()` has.
pub fn init(log_dir: &Path) -> anyhow::Result<LogGuards> {
    std::fs::create_dir_all(log_dir)?;

    let stdout_layer = tracing_subscriber::fmt::layer().with_filter(
        EnvFilter::from_default_env().add_directive("rust_proxy=info".parse().expect("valid built-in directive")),
    );

    let (proxy_writer, proxy_guard) = tracing_appender::non_blocking(tracing_appender::rolling::daily(log_dir, "proxy.log"));
    let proxy_layer = tracing_subscriber::fmt::layer().with_writer(proxy_writer).with_ansi(false).with_filter(FilterFn::new(|meta| {
        is_proxy_target(meta.target()) && *meta.level() <= tracing::Level::DEBUG
    }));

    let (access_writer, access_guard) = tracing_appender::non_blocking(tracing_appender::rolling::daily(log_dir, "access.log"));
    let access_layer = tracing_subscriber::fmt::layer()
        .with_writer(access_writer)
        .with_ansi(false)
        .with_filter(FilterFn::new(|meta| is_access_target(meta.target())));

    let (server_writer, server_guard) = tracing_appender::non_blocking(tracing_appender::rolling::daily(log_dir, "server.log"));
    let server_layer = tracing_subscriber::fmt::layer().with_writer(server_writer).with_ansi(false).with_filter(FilterFn::new(|meta| {
        !is_proxy_target(meta.target()) && !is_access_target(meta.target()) && *meta.level() <= tracing::Level::INFO
    }));

    tracing_subscriber::registry().with(stdout_layer).with(proxy_layer).with(access_layer).with(server_layer).init();

    Ok(LogGuards {
        _proxy: proxy_guard,
        _access: access_guard,
        _server: server_guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_targets_are_recognized() {
        assert!(is_proxy_target("rust_proxy::proxy"));
        assert!(is_proxy_target("rust_proxy::proxy::http"));
        assert!(is_proxy_target("rust_proxy::acme"));
        assert!(is_proxy_target("rust_proxy::acme::dns01::cloudflare"));
    }

    #[test]
    fn access_target_is_recognized_and_not_confused_with_proxy() {
        assert!(is_access_target("rust_proxy::access"));
        assert!(!is_proxy_target("rust_proxy::access"));
    }

    #[test]
    fn unrelated_targets_are_neither_proxy_nor_access() {
        for target in ["rust_proxy::nftables", "rust_proxy::db", "rust_proxy::api::routes", "rust_proxy::bootstrap", "rust_proxy"] {
            assert!(!is_proxy_target(target), "{target} should not be a proxy target");
            assert!(!is_access_target(target), "{target} should not be an access target");
        }
    }
}
