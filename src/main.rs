mod acme;
mod api;
mod config;
mod nftables;
mod proxy;
mod state;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rust-proxy", about = "Lightweight L7 reverse proxy daemon")]
struct Args {
    /// Path to the TOML config file
    #[arg(long, default_value = "/etc/rust-proxy/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("rust_proxy=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    tracing::info!(config = %args.config.display(), "starting rust-proxy");

    let cfg = config::Config::load(&args.config)?;
    let state = state::AppState::new(cfg);

    tokio::try_join!(
        proxy::run(state.clone()),
        api::run(state.clone()),
        nftables::run_sync_loop(state.clone()),
        acme::run_renewal_loop(state.clone()),
    )?;

    Ok(())
}
