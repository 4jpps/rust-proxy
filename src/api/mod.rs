//! Axum admin REST API + embedded web UI, bound to the management
//! address/port from `admin.bind_ip`/`admin.bind_port`. Access beyond
//! that bind is also restricted at the firewall layer (see
//! `nftables::generator::write_admin_rule`) -- this listener only
//! enforces authentication, not source-IP restriction, since that's
//! nftables' job.

pub mod auth;
pub mod default_site;
pub mod health;
pub mod hosting;
pub mod license;
pub mod metrics;
pub mod routes;
pub mod server_settings;
pub mod trustbridge;

use std::net::{IpAddr, SocketAddr};

use crate::state::AppState;

async fn serve_one(ip: IpAddr, port: u16, state: AppState) -> anyhow::Result<()> {
    let addr = SocketAddr::from((ip, port));
    let router = routes::build_router(state);
    let listener = crate::netbind::bind_tcp_listener(addr)?;
    tracing::info!(%addr, "admin API listening");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Binds a real listener for each of `bind_ip_v4`/`bind_ip_v6` that's
/// set (at least one always is -- see `config::validate_dual_bind`) and
/// serves the same router on both, so the admin UI/API is reachable over
/// whichever family(ies) were configured. If both are set, the first one
/// to exit (normally or on error) takes the whole process down, same
/// failure semantics a single listener would have had.
pub async fn run(state: AppState) -> anyhow::Result<()> {
    let (v4, v6, bind_port) = {
        let admin = state.admin();
        (admin.bind_ip_v4, admin.bind_ip_v6, admin.bind_port)
    };

    match (v4, v6) {
        (Some(v4), Some(v6)) => {
            tokio::select! {
                res = serve_one(IpAddr::V4(v4), bind_port, state.clone()) => res,
                res = serve_one(IpAddr::V6(v6), bind_port, state) => res,
            }
        }
        (Some(v4), None) => serve_one(IpAddr::V4(v4), bind_port, state).await,
        (None, Some(v6)) => serve_one(IpAddr::V6(v6), bind_port, state).await,
        (None, None) => {
            anyhow::bail!("admin.bind_ip_v4 and admin.bind_ip_v6 are both unset -- nothing to bind")
        }
    }
}
