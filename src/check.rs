//! `rust-proxy check`: the pre-flight a manual deploy runs with the new
//! binary before swapping it in. Everything happens against a throwaway
//! snapshot of the database; nothing live is written, applied or bound.

use crate::config::Config;

pub async fn run(mut cfg: Config, print_ruleset: bool) -> anyhow::Result<()> {
    println!(
        "config: ok ({} hosts, {} port rules in config.toml)",
        cfg.hosts.len(),
        cfg.port_rules.len()
    );

    let live = cfg.admin.db_path.clone();
    // The snapshot holds password hashes, API tokens and DNS credentials:
    // it goes in a fresh 0700 directory with an unguessable name (create
    // fails if it already exists), removed whole on every exit path.
    let dir = private_dir()?;
    let snapshot = dir.join("snapshot.db");
    if live.exists() {
        if let Err(err) = crate::db::snapshot_unmigrated(&live, &snapshot).await {
            std::fs::remove_dir_all(&dir).ok();
            return Err(err.into());
        }
        cfg.admin.db_path = snapshot.clone();
        println!("database: snapshot of {} taken", live.display());
    } else {
        cfg.admin.db_path = ":memory:".into();
        println!(
            "database: {} does not exist yet (fresh install), using an empty one",
            live.display()
        );
    }
    let result = run_on_snapshot(cfg, print_ruleset).await;
    std::fs::remove_dir_all(&dir).ok();
    if result.is_ok() {
        println!("check passed");
    }
    result
}

fn private_dir() -> anyhow::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let name = format!("rust-proxy-check-{:016x}", rand::random::<u64>());
    let dir = std::env::temp_dir().join(name);
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

async fn run_on_snapshot(cfg: Config, print_ruleset: bool) -> anyhow::Result<()> {
    let state = crate::bootstrap::build_app_state_with(cfg, false).await?;
    println!(
        "migrations + load: ok ({} hosts, {} port rules)",
        state.hosts().len(),
        state.port_rules().len()
    );

    let certs = state.certs();
    match certs.values().map(|c| c.not_after).min() {
        Some(soonest) => println!(
            "certificates: {} loaded, nearest expiry in {} days",
            certs.len(),
            (soonest - chrono::Utc::now()).num_days()
        ),
        None => println!("certificates: none loaded"),
    }

    let ruleset = crate::nftables::build_ruleset(&state).await?;
    if print_ruleset {
        println!("{ruleset}");
    }
    crate::nftables::check(&ruleset)
        .await
        .map_err(|e| anyhow::anyhow!("firewall ruleset rejected by nft: {e}"))?;
    println!(
        "firewall: {} lines, accepted by nft -c",
        ruleset.lines().count()
    );
    Ok(())
}
