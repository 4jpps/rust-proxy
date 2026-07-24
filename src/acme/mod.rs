//! Native RFC 8555 ACME v2 engine. Built out in a later checklist step;
//! stubbed for now so the daemon skeleton compiles and runs.

use crate::state::AppState;

pub async fn run_renewal_loop(_state: AppState) -> anyhow::Result<()> {
    std::future::pending::<()>().await;
    Ok(())
}
