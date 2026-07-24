//! Axum admin REST API + embedded web UI. Built out in a later checklist
//! step; stubbed for now so the daemon skeleton compiles and runs.

pub mod auth;

use crate::state::AppState;

pub async fn run(_state: AppState) -> anyhow::Result<()> {
    std::future::pending::<()>().await;
    Ok(())
}
