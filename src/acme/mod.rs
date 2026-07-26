//! Native RFC 8555 ACME v2 engine: JWS framing (`jws`), protocol wire
//! types (`types`), the HTTP client/state machine (`client`), pluggable
//! dns-01 fulfillment (`dns01`, one `DnsProvider` impl per supported DNS
//! host), and CSR/certificate handling (`cert`). `run_renewal_loop` is
//! what `main.rs` spawns; `issue_certificate` is the single-domain
//! issuance flow it (and a future manual "trigger ACME validation" admin
//! API call) drives.

pub mod cert;
pub mod client;
pub mod dns01;
pub mod jws;
pub mod types;

use std::time::Duration;

use thiserror::Error;

use crate::config::{DnsProviderKind, ProxyHost};
use crate::state::AppState;
use client::{AcmeClient, AcmeError};
use dns01::{acme_challenge_record_name, dns01_txt_value, CloudflareDns01, DigitalOceanDns01, Dns01Error, DnsProvider, HetznerDns01};
use jws::{AccountKey, JwsError};
use types::{AuthorizationStatus, OrderStatus};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const POLL_MAX_ATTEMPTS: u32 = 40; // ~2 minutes at 3s each
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(3600 * 12);
/// How often to retry ACME account setup (key load/generate, directory
/// fetch, account registration) after it fails -- deliberately much
/// shorter than `RENEWAL_CHECK_INTERVAL`. A misconfigured or blank
/// `acme.dns_api_token`/`contact_email` (a real, supported "I haven't
/// set up ACME yet" state -- see deploy/debian/postinst) or a
/// transient Let's Encrypt outage shouldn't take 12h to notice was
/// fixed.
const ACME_INIT_RETRY_INTERVAL: Duration = Duration::from_secs(300);
/// Real DNS propagation before an authoritative resolver-facing CA check
/// succeeds is minutes, not seconds -- this is deliberately generous.
const DNS_PROPAGATION_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error(transparent)]
    Acme(#[from] AcmeError),
    #[error(transparent)]
    Dns01(#[from] Dns01Error),
    #[error(transparent)]
    Jws(#[from] JwsError),
    #[error(transparent)]
    Cert(#[from] cert::CertError),
    #[error("no dns-01 challenge offered for {0}")]
    NoDns01Challenge(String),
    #[error("authorization for {0} did not become valid (status: {1:?})")]
    AuthorizationFailed(String, AuthorizationStatus),
    #[error("order did not finalize (status: {0:?})")]
    OrderNotFinalized(OrderStatus),
    #[error("timed out waiting for {0} to become ready")]
    Timeout(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Runs the full issue/renew flow for one domain: order -> dns-01 ->
/// finalize -> download -> persist to disk (0600) -> publish into
/// `state`'s hot-reloadable cert map for SNI dispatch. The Cloudflare TXT
/// record is always cleaned up on the way out, success or failure.
pub async fn issue_certificate(
    state: &AppState,
    client: &AcmeClient,
    dns01: &dyn DnsProvider,
    domain: &str,
) -> Result<(), IssuanceError> {
    let (order_url, order) = client.new_order(&[domain.to_string()]).await?;
    let authz_url = order
        .authorizations
        .first()
        .ok_or_else(|| IssuanceError::NoDns01Challenge(domain.to_string()))?;

    let authz = client.get_authorization(authz_url).await?;
    let challenge = authz
        .challenges
        .iter()
        .find(|c| c.typ == "dns-01")
        .ok_or_else(|| IssuanceError::NoDns01Challenge(domain.to_string()))?;

    let txt_value = dns01_txt_value(&challenge.token, client.account_key());
    let record_name = acme_challenge_record_name(domain);
    // Zone lookup wants the real domain, not the wildcard label -- no
    // DNS zone is ever literally named "*.something".
    let zone_lookup_domain = domain.strip_prefix("*.").unwrap_or(domain);
    let zone = dns01.find_zone(zone_lookup_domain).await?;
    let record_id = dns01.create_txt_record(&zone, &record_name, &txt_value).await?;

    // Everything from here on must still clean up the TXT record even on
    // failure -- run the rest of the flow and clean up unconditionally
    // afterward rather than threading `?` straight through.
    let result = complete_order(client, &challenge.url, authz_url, &order_url, &order.finalize, domain).await;

    if let Err(err) = dns01.delete_txt_record(&zone, &record_id).await {
        tracing::warn!(domain, error = %err, "failed to clean up ACME challenge TXT record (left dangling with the DNS provider)");
    }

    let issued = result?;
    publish_cert(state, domain, &issued).await
}

struct IssuedCert {
    chain_pem: String,
    key_pem: String,
}

/// Waits for the DNS-01 challenge to validate, then finalizes the order
/// and downloads the full chain PEM.
///
/// `finalize_url` (the order's own `finalize` field) and `order_url` (its
/// `Location`, used for polling) are two distinct RFC 8555 endpoints --
/// conflating them is a real interop risk even though some servers are
/// lenient about it.
async fn complete_order(
    client: &AcmeClient,
    challenge_url: &str,
    authz_url: &str,
    order_url: &str,
    finalize_url: &str,
    domain: &str,
) -> Result<IssuedCert, IssuanceError> {
    tokio::time::sleep(DNS_PROPAGATION_WAIT).await;
    client.notify_challenge_ready(challenge_url).await?;

    let authz = poll_until(
        || client.get_authorization(authz_url),
        |a| a.status != AuthorizationStatus::Pending,
        "authorization",
    )
    .await?;
    if authz.status != AuthorizationStatus::Valid {
        return Err(IssuanceError::AuthorizationFailed(domain.to_string(), authz.status));
    }

    let csr = cert::generate_csr(&[domain.to_string()])?;
    let order = client.finalize(finalize_url, &csr.der).await?;
    let order = poll_until(
        || client.poll_order(order_url),
        |o| !matches!(o.status, OrderStatus::Processing),
        "order finalization",
    )
    .await
    .unwrap_or(order);

    if order.status != OrderStatus::Valid {
        return Err(IssuanceError::OrderNotFinalized(order.status));
    }
    let cert_url = order.certificate.ok_or(IssuanceError::OrderNotFinalized(order.status))?;
    let chain_pem = client.download_certificate(&cert_url).await?;

    Ok(IssuedCert {
        chain_pem,
        key_pem: csr.key_pair_pem,
    })
}

async fn publish_cert(state: &AppState, domain: &str, issued: &IssuedCert) -> Result<(), IssuanceError> {
    let entry = cert::build_cert_entry(&issued.chain_pem, &issued.key_pem)?;

    let cert_dir = state.acme().cert_dir.join(domain);
    std::fs::create_dir_all(&cert_dir)?;
    write_secure(&cert_dir.join("fullchain.pem"), &issued.chain_pem)?;
    write_secure(&cert_dir.join("privkey.pem"), &issued.key_pem)?;

    state.upsert_cert(domain.to_string(), entry);
    tracing::info!(domain, "certificate issued and published");
    Ok(())
}

fn write_secure(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn poll_until<T, F, Fut, P>(mut fetch: F, done: P, what: &'static str) -> Result<T, IssuanceError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, AcmeError>>,
    P: Fn(&T) -> bool,
{
    for _ in 0..POLL_MAX_ATTEMPTS {
        let value = fetch().await?;
        if done(&value) {
            return Ok(value);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Err(IssuanceError::Timeout(what))
}

/// Background task: registers/reuses the ACME account, then periodically
/// checks every ACME-enabled host's live cert against
/// `acme.renew_before_days` and re-issues anything close to expiry (or
/// missing entirely, e.g. first boot).
pub async fn run_renewal_loop(state: AppState) -> anyhow::Result<()> {
    let http = reqwest::Client::new();
    let dns01: Box<dyn DnsProvider> = match state.acme().dns_provider {
        DnsProviderKind::Cloudflare => Box::new(CloudflareDns01::new(http.clone(), state.acme().dns_api_token.clone())),
        DnsProviderKind::DigitalOcean => Box::new(DigitalOceanDns01::new(http.clone(), state.acme().dns_api_token.clone())),
        DnsProviderKind::Hetzner => Box::new(HetznerDns01::new(http.clone(), state.acme().dns_api_token.clone())),
    };

    // Account setup failing (blank/invalid contact_email or
    // dns_api_token, Let's Encrypt briefly unreachable, ...) must
    // never take down the whole daemon -- `proxy::run`/`api::run` run
    // alongside this in `main.rs`'s `tokio::try_join!`, and an `Err`
    // from any one of them cancels the others too. Plain HTTP/TCP/UDP
    // hosts with `acme_enabled = false` have nothing to do with ACME
    // at all and must keep working regardless of this loop's state.
    let client = loop {
        match init_acme_client(&state).await {
            Ok(client) => break client,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "ACME account setup failed -- certificates for ACME-enabled hosts won't be issued until this is fixed; retrying in {}s",
                    ACME_INIT_RETRY_INTERVAL.as_secs()
                );
                tokio::time::sleep(ACME_INIT_RETRY_INTERVAL).await;
            }
        }
    };

    loop {
        for host in state.hosts().iter().filter(|h| h.acme_enabled && h.enabled) {
            if let Err(err) = renew_if_needed(&state, &client, dns01.as_ref(), host).await {
                tracing::error!(domain = %host.domain, error = %err, "certificate issuance/renewal failed");
            }
        }
        tokio::time::sleep(RENEWAL_CHECK_INTERVAL).await;
    }
}

async fn init_acme_client(state: &AppState) -> Result<AcmeClient, IssuanceError> {
    let account_key = AccountKey::load_or_generate(&state.acme().account_key_path)?;
    let client = AcmeClient::new(&state.acme().directory_url, account_key).await?;
    client.new_account(&state.acme().contact_email).await?;
    Ok(client)
}

async fn renew_if_needed(
    state: &AppState,
    client: &AcmeClient,
    dns01: &dyn DnsProvider,
    host: &ProxyHost,
) -> Result<(), IssuanceError> {
    let renew_before = chrono::Duration::days(state.acme().renew_before_days);
    let needs_issuance = match state.certs().get(&host.domain) {
        Some(entry) => entry.not_after - chrono::Utc::now() < renew_before,
        None => true,
    };
    if !needs_issuance {
        return Ok(());
    }
    tracing::info!(domain = %host.domain, "issuing/renewing certificate");
    issue_certificate(state, client, dns01, &host.domain).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeConfig, AdminConfig, Config, NetworkConfig};
    use std::path::PathBuf;
    use wiremock::MockServer;

    async fn test_state(directory_url: String) -> AppState {
        let tmp = std::env::temp_dir().join(format!("rust-proxy-acme-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = Config {
            network: NetworkConfig { bind_ranges: vec![] },
            admin: AdminConfig {
                bind_ip: "127.0.0.1".parse().unwrap(),
                bind_port: 8080,
                allowed_ips: vec![],
                session_secret: "test-secret".into(),
                admin_username: "admin".into(),
                admin_password_hash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into(),
                db_path: PathBuf::from(":memory:"),
            },
            acme: AcmeConfig {
                directory_url,
                contact_email: "".into(), // deliberately blank, like an unconfigured install
                dns_provider: DnsProviderKind::Cloudflare,
                dns_api_token: "".into(),
                cert_dir: tmp.join("certs"),
                account_key_path: tmp.join("account.key"),
                renew_before_days: 30,
            },
            hosts: vec![],
            port_rules: vec![],
        };
        let pool = crate::db::connect(&PathBuf::from(":memory:")).await.unwrap();
        AppState::new(cfg, pool, vec![], vec![])
    }

    // The bug this guards against: a blank/invalid `acme.contact_email`
    // or `dns_api_token` (a real, supported "haven't set up ACME yet"
    // state -- see deploy/debian/postinst) used to propagate an `Err`
    // straight out of `run_renewal_loop`, which -- via `main.rs`'s
    // `tokio::try_join!` -- took the *entire* daemon down with it,
    // including the proxy data plane and admin API, neither of which
    // have anything to do with ACME. Found by actually running a
    // freshly-generated, ACME-unconfigured config.toml through the
    // real binary while building the .deb packaging, not by reasoning
    // about the code in the abstract.
    #[tokio::test]
    async fn acme_setup_failure_does_not_return_an_error_from_the_renewal_loop() {
        // A MockServer with no mounted mocks 404s any request, so the
        // directory fetch inside `init_acme_client` fails every time --
        // exactly the "ACME isn't usable yet" condition this test cares
        // about, without needing to model why (many real causes: blank
        // contact_email, blank/invalid dns_api_token, Let's Encrypt
        // itself unreachable -- all end up here as an `Err` from
        // `init_acme_client`).
        let server = MockServer::start().await;
        let state = test_state(format!("{}/directory", server.uri())).await;

        let handle = tokio::spawn(run_renewal_loop(state));

        // `run_renewal_loop` should still be in its retry-sleep, not
        // resolved, well before `ACME_INIT_RETRY_INTERVAL` (5 minutes)
        // -- if it had returned (crashing the real daemon's
        // `try_join!`), this `timeout` would see the task finish
        // immediately instead of timing out.
        let result = tokio::time::timeout(Duration::from_millis(300), handle).await;
        assert!(result.is_err(), "run_renewal_loop returned instead of retrying -- this would crash the whole daemon");
    }
}
