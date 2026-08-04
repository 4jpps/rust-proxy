mod acme;
mod api;
mod config;
mod db;
mod nftables;
mod proxy;
mod state;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "rust-proxy", about = "Lightweight L7 reverse proxy daemon")]
struct Args {
    /// Path to the TOML config file
    #[arg(long, default_value = "/etc/rust-proxy/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Hashes a password with argon2 for `admin.admin_password_hash` in
    /// config.toml -- the daemon never accepts a plaintext password there.
    HashPassword {
        password: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(Command::HashPassword { password }) = args.command {
        let hash = api::auth::hash_password(&password).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("{hash}");
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("rust_proxy=info".parse().unwrap()),
        )
        .init();

    tracing::info!(config = %args.config.display(), "starting rust-proxy");

    let cfg = config::Config::load(&args.config)?;
    let db_pool = db::connect(&cfg.admin.db_path).await?;

    // sqlite is the source of truth for hosts/port_rules after first boot;
    // config.toml's inline entries (if any) only ever seed an empty DB so
    // day-one deployments don't have to start from a blank admin UI.
    let mut hosts = db::load_hosts(&db_pool).await?;
    let mut port_rules = db::load_port_rules(&db_pool).await?;
    if hosts.is_empty() && !cfg.hosts.is_empty() {
        db::save_hosts(&db_pool, &cfg.hosts).await?;
        hosts = cfg.hosts.clone();
    }
    if port_rules.is_empty() && !cfg.port_rules.is_empty() {
        db::save_port_rules(&db_pool, &cfg.port_rules).await?;
        port_rules = cfg.port_rules.clone();
    }

    // config.toml's dns_provider/dns_api_token (if set) seed a "default"
    // dns_credentials row, idempotently -- zero config.toml changes
    // needed for an existing single-provider deployment. Omitted/blank
    // dns_api_token means no implicit row; credentials must then come
    // from the DB (admin UI or setup wizard) instead.
    if !cfg.acme.dns_api_token.trim().is_empty() {
        db::seed_default_dns_credential(&db_pool, cfg.acme.dns_provider, &cfg.acme.dns_api_token).await?;
    }

    let db_admin_identity = db::load_admin_identity(&db_pool).await?.map(|row| state::AdminIdentity {
        username: row.username,
        password_hash: row.password_hash,
        session_secret: row.session_secret,
    });

    let state = state::AppState::new(cfg, db_pool, hosts, port_rules, db_admin_identity);
    acme::load_certs_from_disk(&state)?;

    tokio::try_join!(
        proxy::run(state.clone()),
        api::run(state.clone()),
        nftables::run_sync_loop(state.clone()),
        acme::run_renewal_loop(state.clone()),
    )?;

    Ok(())
}
