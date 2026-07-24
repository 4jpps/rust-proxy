//! Axum admin REST API + embedded web UI, bound to the management
//! address/port from `admin.bind_ip`/`admin.bind_port`. Access beyond
//! that bind is also restricted at the firewall layer (see
//! `nftables::generator::write_admin_rule`) -- this listener only
//! enforces authentication, not source-IP restriction, since that's
//! nftables' job.

pub mod auth;
pub mod routes;

use std::net::SocketAddr;

use crate::state::AppState;

pub async fn run(state: AppState) -> anyhow::Result<()> {
    let addr = SocketAddr::from((state.admin().bind_ip, state.admin().bind_port));
    let router = routes::build_router(state);

    tracing::info!(%addr, "admin API listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
