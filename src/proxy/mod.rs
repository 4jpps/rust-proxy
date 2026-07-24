//! L7 proxy data plane / multi-IP listener engine. Built out in a later
//! checklist step; stubbed for now so the daemon skeleton compiles and runs.

use crate::state::AppState;

pub async fn run(_state: AppState) -> anyhow::Result<()> {
    std::future::pending::<()>().await;
    Ok(())
}
