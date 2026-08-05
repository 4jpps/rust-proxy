mod acme;
mod api;
mod bootstrap;
mod config;
mod db;
mod localip;
mod logging;
mod netbind;
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
    /// Safely snapshots the live sqlite DB to `destination` -- a full,
    /// consistent copy even while the daemon is running and actively
    /// writing, via sqlite's own `VACUUM INTO` (not a raw file copy,
    /// which could catch the DB mid-write, especially under WAL mode,
    /// and produce a corrupt copy). `destination` must not already
    /// exist -- `VACUUM INTO` refuses to overwrite. Driven by
    /// `rust-proxy-backup.timer` (see deploy/) for the nightly
    /// automated backup every install gets out of the box; also usable
    /// by hand before a risky manual change.
    Backup {
        destination: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(Command::HashPassword { password }) = &args.command {
        let hash = api::auth::hash_password(password).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("{hash}");
        return Ok(());
    }

    let cfg = config::Config::load(&args.config)?;

    if let Some(Command::Backup { destination }) = &args.command {
        if destination.exists() {
            anyhow::bail!("{} already exists -- refusing to overwrite (VACUUM INTO doesn't support it)", destination.display());
        }
        let pool = db::connect(&cfg.admin.db_path).await?;
        db::backup_to(&pool, destination).await?;
        println!("backed up {} to {}", cfg.admin.db_path.display(), destination.display());
        return Ok(());
    }

    // Split into proxy.log/access.log/server.log under the same
    // directory as the sqlite DB (already read-write for this daemon,
    // no new config surface or packaging change needed) -- see
    // logging.rs's own doc comment for the split's rationale. `_guards`
    // must stay alive for the whole process; dropping it early would
    // silently stop these files from being written to.
    let log_dir = cfg.admin.db_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| std::path::PathBuf::from("."));
    let _log_guards = logging::init(&log_dir)?;

    tracing::info!(config = %args.config.display(), "starting rust-proxy");
    // Everything needed before the long-running service tasks can
    // start (DB connect, seed/load hosts+port_rules+the default DNS
    // credential, resolve the admin identity, load certs from disk) --
    // see bootstrap.rs, which exists specifically so each of those
    // steps is independently named, reviewed, and unit-tested rather
    // than inlined here.
    let state = bootstrap::build_app_state(cfg).await?;

    // One clear, loud message right at boot if nftables isn't usable,
    // instead of that only surfacing buried in `nftables sync failed`
    // error lines once run_sync_loop's first iteration gets to it (and
    // repeating on every fallback resync/hosts change after that with
    // no clearer explanation). Deliberately non-fatal -- see
    // nftables::validate_environment's own doc comment for why this
    // must never abort startup.
    if let Err(err) = nftables::validate_environment().await {
        tracing::error!(error = %err, "nftables is not usable -- the firewall will not be enforced until this is fixed");
    }

    tokio::try_join!(
        proxy::run(state.clone()),
        api::run(state.clone()),
        nftables::run_sync_loop(state.clone()),
        acme::run_renewal_loop(state.clone()),
    )?;

    Ok(())
}
