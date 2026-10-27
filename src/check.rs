//! The pre-flight: `rust-proxy check` before a manual binary swap, and the
//! admin UI's "Run pre-flight" / "Restart" buttons (`api::server_settings`).
//! Everything happens against a throwaway snapshot of the database;
//! nothing live is written, applied or bound.

use crate::config::Config;

/// One pre-flight run: a line per step, and whether everything passed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub ok: bool,
    pub lines: Vec<String>,
}

/// `rust-proxy check` from the command line.
pub async fn run(cfg: Config, print_ruleset: bool) -> anyhow::Result<()> {
    let (report, ruleset) = preflight(cfg).await;
    for line in &report.lines {
        println!("{line}");
    }
    if let (true, Some(r)) = (print_ruleset, ruleset) {
        println!("{r}");
    }
    if report.ok {
        Ok(())
    } else {
        anyhow::bail!("check failed")
    }
}

/// Runs every step against `cfg`, collecting what happened; the generated
/// ruleset comes back too when it was built.
pub async fn preflight(mut cfg: Config) -> (Report, Option<String>) {
    let mut lines = vec![format!(
        "config: ok ({} hosts, {} port rules in config.toml)",
        cfg.hosts.len(),
        cfg.port_rules.len()
    )];
    let live = cfg.admin.db_path.clone();
    // The snapshot holds password hashes, API tokens and DNS credentials:
    // it goes in a fresh 0700 directory with an unguessable name (create
    // fails if it already exists), removed whole on every exit path.
    let dir = match private_dir() {
        Ok(d) => d,
        Err(e) => return fail(lines, format!("database: no private temp directory: {e}")),
    };
    let snapshot = dir.join("snapshot.db");
    if live.exists() {
        if let Err(err) = crate::db::snapshot_unmigrated(&live, &snapshot).await {
            std::fs::remove_dir_all(&dir).ok();
            return fail(
                lines,
                format!("database: snapshot of {} failed: {err}", live.display()),
            );
        }
        cfg.admin.db_path = snapshot.clone();
        lines.push(format!("database: snapshot of {} taken", live.display()));
    } else {
        cfg.admin.db_path = ":memory:".into();
        lines.push(format!(
            "database: {} does not exist yet (fresh install), using an empty one",
            live.display()
        ));
    }
    let result = on_snapshot(cfg, &mut lines).await;
    std::fs::remove_dir_all(&dir).ok();
    match result {
        Ok(ruleset) => {
            lines.push("check passed".into());
            (Report { ok: true, lines }, Some(ruleset))
        }
        Err(e) => fail(lines, e.to_string()),
    }
}

fn fail(mut lines: Vec<String>, why: String) -> (Report, Option<String>) {
    lines.push(format!("FAILED: {why}"));
    (Report { ok: false, lines }, None)
}

fn private_dir() -> anyhow::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let name = format!("rust-proxy-check-{:016x}", rand::random::<u64>());
    let dir = std::env::temp_dir().join(name);
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

async fn on_snapshot(cfg: Config, lines: &mut Vec<String>) -> anyhow::Result<String> {
    let state = crate::bootstrap::build_app_state_with(cfg, false).await?;
    lines.push(format!(
        "migrations + load: ok ({} hosts, {} port rules)",
        state.hosts().len(),
        state.port_rules().len()
    ));
    let certs = state.certs();
    lines.push(match certs.values().map(|c| c.not_after).min() {
        Some(soonest) => format!(
            "certificates: {} loaded, nearest expiry in {} days",
            certs.len(),
            (soonest - chrono::Utc::now()).num_days()
        ),
        None => "certificates: none loaded".into(),
    });
    let ruleset = crate::nftables::build_ruleset(&state).await?;
    crate::nftables::check(&ruleset)
        .await
        .map_err(|e| anyhow::anyhow!("firewall ruleset rejected by nft: {e}"))?;
    lines.push(format!(
        "firewall: {} lines, accepted by nft -c",
        ruleset.lines().count()
    ));
    Ok(ruleset)
}
