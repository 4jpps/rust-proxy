//! Native RFC 8555 ACME v2 engine: JWS framing (`jws`), protocol wire
//! types (`types`), the HTTP client/state machine (`client`), pluggable
//! dns-01 fulfillment (`dns01`, one `DnsProvider` impl per supported DNS
//! host), http-01 fulfillment (`http01`, no third-party credentials
//! needed at all), and CSR/certificate handling (`cert`).
//! `run_renewal_loop` is what `main.rs` spawns; `issue_certificate` is
//! the single-domain issuance flow it (and a future manual "trigger ACME
//! validation" admin API call) drives, picking dns-01 or http-01 per
//! host via `resolve_challenge_type`.

pub mod cert;
pub mod client;
pub mod dns01;
pub mod http01;
pub mod jws;
pub mod types;

use std::time::Duration;

use thiserror::Error;

use crate::config::{AcmeChallengeType, ProxyHost};

#[cfg(test)]
use crate::config::DnsProviderKind;
use crate::state::AppState;
use client::{AcmeClient, AcmeError};
use dns01::{acme_challenge_record_name, dns01_txt_value, Dns01Error, DnsProvider};
use jws::{AccountKey, JwsError};
use types::{Authorization, AuthorizationStatus, OrderStatus};

#[derive(Debug, Error)]
pub enum DnsCredentialError {
    #[error("host {0} needs a dns-01 DNS credential but dns_credential_id is unset and no DNS credentials are configured -- add one first")]
    NoneConfigured(String),
    #[error("host {0} needs a dns-01 DNS credential but dns_credential_id is unset and multiple DNS credentials exist -- set dns_credential_id explicitly")]
    Ambiguous(String),
    #[error("host {0}'s dns_credential_id does not match any existing DNS credential")]
    NotFound(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Resolves which `dns_credentials` DB row a host should use for dns-01
/// issuance. `Some(id)` always wins outright. `None` falls back to "the
/// single configured credential" only when it's genuinely unambiguous
/// (exactly one row exists) -- zero or multiple rows with no explicit
/// choice is a clear error rather than a silent wrong guess.
pub async fn resolve_dns_credential(
    pool: &sqlx::SqlitePool,
    domain: &str,
    dns_credential_id: Option<uuid::Uuid>,
) -> Result<crate::db::DnsCredential, DnsCredentialError> {
    match dns_credential_id {
        Some(id) => crate::db::get_dns_credential(pool, id)
            .await?
            .ok_or_else(|| DnsCredentialError::NotFound(domain.to_string())),
        None => {
            let metas = crate::db::list_dns_credentials(pool).await?;
            match metas.len() {
                0 => Err(DnsCredentialError::NoneConfigured(domain.to_string())),
                1 => Ok(crate::db::get_dns_credential(pool, metas[0].id)
                    .await?
                    .expect(
                        "just listed this row, it cannot have vanished between the two queries",
                    )),
                _ => Err(DnsCredentialError::Ambiguous(domain.to_string())),
            }
        }
    }
}

/// Which ACME challenge type actually gets used for one host --
/// `AcmeChallengeType::Auto` resolves here rather than being stored
/// pre-resolved, so flipping a host's `force_https`/`acme_challenge_type`
/// takes effect on the next issuance/renewal with no separate migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeMethod {
    Http01,
    Dns01,
}

pub fn resolve_challenge_type(host: &ProxyHost) -> ChallengeMethod {
    // RFC 8555 SS8.3: CAs never offer http-01 for a wildcard identifier --
    // dns-01 is the only option regardless of the host's own setting.
    if crate::config::is_wildcard_domain(&host.domain) {
        return ChallengeMethod::Dns01;
    }
    match host.acme_challenge_type {
        AcmeChallengeType::Http01 => ChallengeMethod::Http01,
        AcmeChallengeType::Dns01 => ChallengeMethod::Dns01,
        // dns-01 doesn't depend on this daemon's own port 80 actually
        // being publicly reachable for this exact domain (NAT, a
        // firewall, or the domain's own DNS not routing to this host
        // yet can all silently break http-01 in ways that are opaque
        // from here -- confirmed live: a real host's http-01
        // authorization failed outright, fast, with nothing on this
        // end to show why). dns-01 only depends on a working DNS
        // provider credential, already required for any wildcard host
        // anyway. Auto prefers dns-01 and `issue_certificate` falls back
        // to http-01 if that fails (`http01_fallback_allowed`); explicit
        // `http01` remains available for anyone who genuinely wants it
        // (no DNS provider credentials needed at all, at the cost of
        // requiring port 80 to actually be reachable).
        AcmeChallengeType::Auto => ChallengeMethod::Dns01,
    }
}

/// Whether `proxy::run`'s port-80 listener (and the matching nftables
/// rule) needs to exist purely to serve an http-01 challenge for this
/// host -- independent of `force_https`, which already opens port 80 for
/// its own, unrelated reason (the redirect).
pub fn opens_port_80_for_acme(host: &ProxyHost) -> bool {
    host.acme_enabled
        && (resolve_challenge_type(host) == ChallengeMethod::Http01
            || http01_fallback_allowed(host))
}

/// `auto` tries dns-01 first and, if that issuance attempt fails for any
/// reason (no usable DNS credential, provider error, validation failure),
/// retries once with http-01. Never for a wildcard (CAs refuse http-01 for
/// one) and never for an explicit `dns01`/`http01` choice.
pub fn http01_fallback_allowed(host: &ProxyHost) -> bool {
    host.acme_enabled
        && host.acme_challenge_type == AcmeChallengeType::Auto
        && !crate::config::is_wildcard_domain(&host.domain)
}

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
    #[error("order for {0} has no authorizations")]
    NoAuthorization(String),
    #[error("no dns-01 challenge offered for {0}")]
    NoDns01Challenge(String),
    #[error("no http-01 challenge offered for {0}")]
    NoHttp01Challenge(String),
    #[error("authorization for {0} did not become valid (status: {1:?})")]
    AuthorizationFailed(String, AuthorizationStatus),
    #[error("order did not finalize (status: {0:?})")]
    OrderNotFinalized(OrderStatus),
    #[error("timed out waiting for {0} to become ready")]
    Timeout(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    DnsCredential(#[from] DnsCredentialError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Runs the full issue/renew flow for one host: order -> dns-01 or
/// http-01 (per `resolve_challenge_type`) -> finalize -> download ->
/// persist to disk (0600) -> publish into `state`'s hot-reloadable cert
/// map for SNI dispatch. Whichever challenge fulfillment was published
/// (a DNS TXT record, or an in-memory http-01 token) is always cleaned
/// up on the way out, success or failure.
pub async fn issue_certificate(
    state: &AppState,
    client: &AcmeClient,
    http: &reqwest::Client,
    host: &ProxyHost,
) -> Result<(), IssuanceError> {
    let method = resolve_challenge_type(host);
    match issue_certificate_with(state, client, http, host, method).await {
        Err(e) if method == ChallengeMethod::Dns01 && http01_fallback_allowed(host) => {
            tracing::warn!(
                domain = %host.domain,
                error = %e,
                "dns-01 issuance failed, falling back to http-01"
            );
            issue_certificate_with(state, client, http, host, ChallengeMethod::Http01).await
        }
        result => result,
    }
}

async fn issue_certificate_with(
    state: &AppState,
    client: &AcmeClient,
    http: &reqwest::Client,
    host: &ProxyHost,
    method: ChallengeMethod,
) -> Result<(), IssuanceError> {
    let domain = &host.domain;
    let domains = domains_for_issuance(domain);
    let (order_url, order, authzs) = create_order_and_authzs(client, &domains).await?;
    let identity = csr_identity(state);

    let issued = match method {
        ChallengeMethod::Dns01 => {
            let credential =
                resolve_dns_credential(state.db(), domain, host.dns_credential_id).await?;
            let dns01 = dns01::build_provider(credential.provider, http.clone(), credential.token);
            issue_via_dns01(
                client,
                dns01.as_ref(),
                &domains,
                &authzs,
                &order_url,
                &order.finalize,
                identity,
            )
            .await?
        }
        // Never wildcard here -- resolve_challenge_type always forces
        // Dns01 for a wildcard domain, so domains_for_issuance never
        // added a second SAN and authzs has exactly one entry.
        ChallengeMethod::Http01 => {
            let (authz_url, authz) = &authzs[0];
            issue_via_http01(
                state,
                client,
                domain,
                authz,
                authz_url,
                &order_url,
                &order.finalize,
                identity,
            )
            .await?
        }
    };
    publish_cert(state, &domains, &issued).await
}

/// Optional Subject O/OU to request in every CSR this issuance flow
/// generates -- see `cert::generate_csr`'s doc comment for why this is
/// only ever a request, never a guarantee, against most public CAs.
#[derive(Debug, Clone, Default)]
struct CsrIdentity {
    organization: Option<String>,
    organizational_unit: Option<String>,
}

fn csr_identity(state: &AppState) -> CsrIdentity {
    CsrIdentity {
        organization: state.acme().organization.clone(),
        organizational_unit: state.acme().organizational_unit.clone(),
    }
}

/// The domain(s) to actually request from the CA for one issuance -- a
/// wildcard domain also requests its own bare apex as a second SAN in
/// the same certificate (`*.example.com` + `example.com`), matching how
/// certbot/acme.sh commonly issue combined wildcard+apex certificates:
/// a wildcard alone never covers its own apex (standard X.509 wildcard
/// semantics -- `*.example.com` doesn't match `example.com`), so most
/// operators want both from one order rather than two separately
/// managed certificates. A non-wildcard domain is unaffected.
fn domains_for_issuance(domain: &str) -> Vec<String> {
    match domain.strip_prefix("*.") {
        Some(apex) => vec![domain.to_string(), apex.to_string()],
        None => vec![domain.to_string()],
    }
}

/// Same dns-01 issuance flow as `issue_certificate`, but for a domain
/// with no `ProxyHost` at all -- the standalone-cert feature this backs
/// (`api::routes`'s `/api/dns01-certs`) exists specifically for
/// wildcards: issue `*.example.com` once here, and every subdomain host
/// under it just works via `proxy::tls::select_cert_for_sni`'s existing
/// wildcard fallback, with no separate "attach this cert to that host"
/// step needed. http-01 is never an option here (there's no host to
/// open a port-80 listener for, and CAs refuse http-01 for a wildcard
/// identifier anyway), so this always goes through dns-01.
/// `organization`/`organizational_unit` override the global
/// `acme.organization`/`acme.organizational_unit` config.toml defaults
/// for this one cert -- resolved by the caller (`api::routes::create_standalone_cert`)
/// against whatever it decides to persist for future renewals, not
/// re-resolved here.
pub async fn issue_standalone_dns01_certificate(
    state: &AppState,
    client: &AcmeClient,
    http: &reqwest::Client,
    domain: &str,
    dns_credential_id: Option<uuid::Uuid>,
    organization: Option<String>,
    organizational_unit: Option<String>,
) -> Result<(), IssuanceError> {
    let domains = domains_for_issuance(domain);
    let (order_url, order, authzs) = create_order_and_authzs(client, &domains).await?;
    let credential = resolve_dns_credential(state.db(), domain, dns_credential_id).await?;
    let dns01 = dns01::build_provider(credential.provider, http.clone(), credential.token);
    let identity = CsrIdentity {
        organization,
        organizational_unit,
    };
    let issued = issue_via_dns01(
        client,
        dns01.as_ref(),
        &domains,
        &authzs,
        &order_url,
        &order.finalize,
        identity,
    )
    .await?;
    publish_cert(state, &domains, &issued).await
}

/// Fetches every authorization the order actually contains -- one per
/// requested identifier (see `domains_for_issuance`: a wildcard+apex
/// combined order has two), in the same order `domains` lists them
/// (RFC 8555 doesn't guarantee this ordering itself, but nothing here
/// currently depends on it -- each authorization carries its own
/// `identifier`/`wildcard` fields, which is what `issue_via_dns01` keys
/// off of).
async fn create_order_and_authzs(
    client: &AcmeClient,
    domains: &[String],
) -> Result<(String, types::Order, Vec<(String, Authorization)>), IssuanceError> {
    let (order_url, order) = client.new_order(domains).await?;
    if order.authorizations.is_empty() {
        return Err(IssuanceError::NoAuthorization(domains.join(", ")));
    }
    let mut authzs = Vec::with_capacity(order.authorizations.len());
    for url in &order.authorizations {
        let authz = client.get_authorization(url).await?;
        authzs.push((url.clone(), authz));
    }
    Ok((order_url, order, authzs))
}

/// Fulfills every authorization in `authzs` via dns-01 -- for a combined
/// wildcard+apex order this means two TXT records at the *same* record
/// name (`_acme-challenge.example.com`, since a wildcard authorization's
/// `identifier.value` per RFC 8555 is already the bare apex) but with
/// different content, since each authorization has its own challenge
/// token. Real DNS providers' "create record" APIs add a new record
/// rather than overwrite (confirmed against Cloudflare's own API
/// shape), so both coexist and are cleaned up independently by their
/// own record ids. If creating any record fails partway through,
/// whatever was already created is still cleaned up before returning.
async fn issue_via_dns01(
    client: &AcmeClient,
    dns01: &dyn DnsProvider,
    domains: &[String],
    authzs: &[(String, Authorization)],
    order_url: &str,
    finalize_url: &str,
    identity: CsrIdentity,
) -> Result<IssuedCert, IssuanceError> {
    // Zone lookup wants a real domain, not the wildcard label -- no DNS
    // zone is ever literally named "*.something". `domains[0]` always
    // exists (`domains_for_issuance` never returns empty).
    let zone_lookup_domain = domains[0].strip_prefix("*.").unwrap_or(&domains[0]);
    let zone = dns01.find_zone(zone_lookup_domain).await?;

    let mut pending: Vec<(String, String)> = Vec::with_capacity(authzs.len());
    let mut record_ids: Vec<String> = Vec::with_capacity(authzs.len());
    let create_result: Result<(), IssuanceError> = async {
        for (authz_url, authz) in authzs {
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.typ == "dns-01")
                .ok_or_else(|| IssuanceError::NoDns01Challenge(authz.identifier.value.clone()))?;
            let txt_value = dns01_txt_value(&challenge.token, client.account_key());
            let record_name = acme_challenge_record_name(&authz.identifier.value);
            let record_id = dns01
                .create_txt_record(&zone, &record_name, &txt_value)
                .await?;
            record_ids.push(record_id);
            pending.push((authz_url.clone(), challenge.url.clone()));
        }
        Ok(())
    }
    .await;

    // Everything from here on must still clean up every TXT record
    // created so far, even on failure -- run the rest of the flow and
    // clean up unconditionally afterward rather than threading `?`
    // straight through.
    let result = match create_result {
        Ok(()) => {
            // Real DNS propagation before an authoritative resolver-facing
            // CA check succeeds is minutes, not seconds; http-01 has no
            // equivalent wait since the challenge is served straight from
            // memory.
            tokio::time::sleep(DNS_PROPAGATION_WAIT).await;
            complete_order(client, &pending, order_url, finalize_url, domains, identity).await
        }
        Err(err) => Err(err),
    };

    for record_id in &record_ids {
        if let Err(err) = dns01.delete_txt_record(&zone, record_id).await {
            tracing::warn!(domains = %domains.join(", "), error = %err, "failed to clean up ACME challenge TXT record (left dangling with the DNS provider)");
        }
    }
    result
}

// http-01 never applies to a wildcard (resolve_challenge_type forces
// dns-01 for those), so this never needs the CsrIdentity/pending-list
// generality issue_via_dns01 does -- one extra param over clippy's
// default threshold, all of them meaningfully distinct.
#[allow(clippy::too_many_arguments)]
async fn issue_via_http01(
    state: &AppState,
    client: &AcmeClient,
    domain: &str,
    authz: &Authorization,
    authz_url: &str,
    order_url: &str,
    finalize_url: &str,
    identity: CsrIdentity,
) -> Result<IssuedCert, IssuanceError> {
    let challenge = authz
        .challenges
        .iter()
        .find(|c| c.typ == "http-01")
        .ok_or_else(|| IssuanceError::NoHttp01Challenge(domain.to_string()))?;

    let key_authorization = http01::key_authorization(&challenge.token, client.account_key());
    state.set_http01_challenge(challenge.token.clone(), key_authorization);

    // Same unconditional-cleanup shape as dns-01's TXT record(s) -- the
    // in-memory token must not outlive this one validation attempt,
    // success or failure.
    let pending = vec![(authz_url.to_string(), challenge.url.clone())];
    let domains = vec![domain.to_string()];
    let result = complete_order(
        client,
        &pending,
        order_url,
        finalize_url,
        &domains,
        identity,
    )
    .await;
    state.remove_http01_challenge(&challenge.token);
    result
}

struct IssuedCert {
    chain_pem: String,
    key_pem: String,
}

/// Waits for every `(authz_url, challenge_url)` pair in `pending` to
/// validate (notifying each challenge first, then polling each
/// authorization -- a combined wildcard+apex order has two of these,
/// everything else has exactly one), then finalizes the order with a
/// CSR covering every domain and downloads the full chain PEM.
///
/// `finalize_url` (the order's own `finalize` field) and `order_url` (its
/// `Location`, used for polling) are two distinct RFC 8555 endpoints --
/// conflating them is a real interop risk even though some servers are
/// lenient about it.
async fn complete_order(
    client: &AcmeClient,
    pending: &[(String, String)],
    order_url: &str,
    finalize_url: &str,
    domains: &[String],
    identity: CsrIdentity,
) -> Result<IssuedCert, IssuanceError> {
    for (_, challenge_url) in pending {
        client.notify_challenge_ready(challenge_url).await?;
    }

    for (authz_url, _) in pending {
        let authz = poll_until(
            || client.get_authorization(authz_url),
            |a| a.status != AuthorizationStatus::Pending,
            "authorization",
        )
        .await?;
        if authz.status != AuthorizationStatus::Valid {
            return Err(IssuanceError::AuthorizationFailed(
                domains.join(", "),
                authz.status,
            ));
        }
    }

    let csr = cert::generate_csr(
        domains,
        identity.organization.as_deref(),
        identity.organizational_unit.as_deref(),
    )?;
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
    let cert_url = order
        .certificate
        .ok_or(IssuanceError::OrderNotFinalized(order.status))?;
    let chain_pem = client.download_certificate(&cert_url).await?;

    Ok(IssuedCert {
        chain_pem,
        key_pem: csr.key_pair_pem,
    })
}

/// Publishes the issued cert under every requested domain -- for a
/// combined wildcard+apex order (`domains_for_issuance`) that's both
/// `*.example.com` and `example.com`. This matters beyond bookkeeping:
/// `proxy::tls::select_cert_for_sni` only ever falls back from an exact
/// SNI match to a `*.parent` wildcard cert, *never* to the bare parent
/// itself (standard X.509 wildcard semantics -- confirmed by
/// `wildcard_host_does_not_match_the_bare_parent_domain`), so a cert
/// published only under the wildcard key would leave the apex SAN
/// entirely unreachable for TLS despite being right there in the
/// certificate. Persisted to disk under each domain's own directory
/// too, so `load_certs_from_disk` restores every entry after a restart
/// the same way live issuance published them.
async fn publish_cert(
    state: &AppState,
    domains: &[String],
    issued: &IssuedCert,
) -> Result<(), IssuanceError> {
    let entry = cert::build_cert_entry(&issued.chain_pem, &issued.key_pem)?;
    for domain in domains {
        persist_cert_files(
            &state.acme().cert_dir,
            domain,
            &issued.chain_pem,
            &issued.key_pem,
        )?;
        state.upsert_cert(domain.clone(), entry.clone());
    }
    tracing::info!(domains = %domains.join(", "), "certificate issued and published");
    Ok(())
}

/// Writes a cert+key pair to `<cert_dir>/<domain>/{fullchain,privkey}.pem`
/// (0600) -- shared by the ACME issuance flow and the admin API's
/// custom-cert upload (`api::routes::upload_cert`), since both need the
/// exact same on-disk layout for `load_certs_from_disk` to find them
/// again after a restart.
pub(crate) fn persist_cert_files(
    cert_dir: &std::path::Path,
    domain: &str,
    chain_pem: &str,
    key_pem: &str,
) -> std::io::Result<()> {
    let dir = cert_dir.join(domain);
    std::fs::create_dir_all(&dir)?;
    write_secure(&dir.join("fullchain.pem"), chain_pem)?;
    write_secure(&dir.join("privkey.pem"), key_pem)?;
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

/// Loads every already-issued/uploaded cert from `cert_dir` into
/// `state`'s in-memory map at startup. Without this, a restart would
/// otherwise "forget" every cert (custom-uploaded ones permanently --
/// nothing else remembers them -- and ACME-issued ones until the next
/// renewal check re-issues them, wasting a real issuance against Let's
/// Encrypt's rate limits for no reason). One subdirectory per domain,
/// same layout `persist_cert_files` writes; a subdirectory missing
/// either file, or containing something that fails to parse, is skipped
/// with a warning rather than failing startup -- one bad/partial cert
/// directory shouldn't take down the whole daemon.
pub fn load_certs_from_disk(state: &AppState) -> std::io::Result<()> {
    let cert_dir = &state.acme().cert_dir;
    let entries = match std::fs::read_dir(cert_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let domain = entry.file_name().to_string_lossy().into_owned();
        let dir = entry.path();
        let (Ok(chain_pem), Ok(key_pem)) = (
            std::fs::read_to_string(dir.join("fullchain.pem")),
            std::fs::read_to_string(dir.join("privkey.pem")),
        ) else {
            continue;
        };
        match cert::build_cert_entry(&chain_pem, &key_pem) {
            Ok(entry) => {
                state.upsert_cert(domain.clone(), entry);
                tracing::info!(domain, "loaded existing certificate from disk");
            }
            Err(err) => {
                tracing::warn!(domain, error = %err, "failed to parse existing certificate on disk, skipping");
            }
        }
    }
    Ok(())
}

async fn poll_until<T, F, Fut, P>(
    mut fetch: F,
    done: P,
    what: &'static str,
) -> Result<T, IssuanceError>
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
            if let Err(err) = renew_if_needed(&state, &client, &http, host).await {
                tracing::error!(domain = %host.domain, error = %err, "certificate issuance/renewal failed");
            }
        }
        if let Err(err) = renew_standalone_certs_if_needed(&state, &client, &http).await {
            tracing::error!(error = %err, "failed to check standalone DNS-01 certs for renewal");
        }
        tokio::time::sleep(RENEWAL_CHECK_INTERVAL).await;
    }
}

/// Same expiry check as `renew_if_needed`, applied to every tracked
/// standalone cert (see `issue_standalone_dns01_certificate`) instead of
/// a host's own domain -- these have no `ProxyHost.acme_enabled`/
/// `enabled` gate to filter on, since there's no host at all.
async fn renew_standalone_certs_if_needed(
    state: &AppState,
    client: &AcmeClient,
    http: &reqwest::Client,
) -> Result<(), IssuanceError> {
    let renew_before = chrono::Duration::days(state.acme().renew_before_days);
    for standalone in crate::db::list_standalone_certs(state.db()).await? {
        let needs_issuance = match state.certs().get(&standalone.domain) {
            Some(entry) => entry.not_after - chrono::Utc::now() < renew_before,
            None => true,
        };
        if !needs_issuance {
            continue;
        }
        tracing::info!(domain = %standalone.domain, "issuing/renewing standalone certificate");
        if let Err(err) = issue_standalone_dns01_certificate(
            state,
            client,
            http,
            &standalone.domain,
            standalone.dns_credential_id,
            standalone.organization.clone(),
            standalone.organizational_unit.clone(),
        )
        .await
        {
            tracing::error!(domain = %standalone.domain, error = %err, "standalone certificate issuance/renewal failed");
        }
    }
    Ok(())
}

/// `pub` (not module-private) so `api::routes`'s standalone DNS-01 cert
/// endpoint can build its own client and issue synchronously within the
/// HTTP request, instead of only ever going through `run_renewal_loop`'s
/// long-lived one -- a manually-triggered one-off issuance needs
/// immediate success/failure feedback, not "check back within 12h".
pub async fn init_acme_client(state: &AppState) -> Result<AcmeClient, IssuanceError> {
    let account_key = AccountKey::load_or_generate(&state.acme().account_key_path)?;
    let client = AcmeClient::new(&state.acme().directory_url, account_key).await?;
    let contact_email = state.acme_contact_email().unwrap_or_default();
    client.new_account(&contact_email).await?;
    Ok(client)
}

async fn renew_if_needed(
    state: &AppState,
    client: &AcmeClient,
    http: &reqwest::Client,
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
    issue_certificate(state, client, http, host).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeConfig, AdminConfig, Config, NetworkConfig};
    use std::path::PathBuf;
    use wiremock::MockServer;

    fn host(domain: &str, force_https: bool, challenge_type: AcmeChallengeType) -> ProxyHost {
        ProxyHost {
            id: uuid::Uuid::new_v4(),
            domain: domain.into(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: "127.0.0.1:8000".into(),
            upstream_https: false,
            upstream_tls_verify: true,
            upstream_preserve_host: true,
            websockets: false,
            force_https,
            acme_enabled: true,
            acme_challenge_type: challenge_type,
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: None,
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            pass_client_cert_header: false,
            enabled: true,
        }
    }

    #[test]
    fn auto_resolves_to_dns01_regardless_of_force_https() {
        // dns-01 doesn't depend on this daemon's own port 80 being
        // publicly reachable for the exact domain, unlike http-01 --
        // Auto prefers it unconditionally now, force_https no longer
        // factors in at all. Explicit `http01` still opts in to the
        // old behavior for anyone who wants it.
        let h = host("example.com", true, AcmeChallengeType::Auto);
        assert_eq!(resolve_challenge_type(&h), ChallengeMethod::Dns01);
        let h = host("example.com", false, AcmeChallengeType::Auto);
        assert_eq!(resolve_challenge_type(&h), ChallengeMethod::Dns01);
    }

    #[test]
    fn wildcard_domains_always_use_dns01_regardless_of_setting() {
        let h = host("*.pages.example.com", true, AcmeChallengeType::Http01);
        assert_eq!(resolve_challenge_type(&h), ChallengeMethod::Dns01);
    }

    #[test]
    fn explicit_http01_wins_even_without_force_https() {
        let h = host("example.com", false, AcmeChallengeType::Http01);
        assert_eq!(resolve_challenge_type(&h), ChallengeMethod::Http01);
    }

    #[test]
    fn explicit_dns01_wins_even_with_force_https() {
        let h = host("example.com", true, AcmeChallengeType::Dns01);
        assert_eq!(resolve_challenge_type(&h), ChallengeMethod::Dns01);
    }

    #[test]
    fn port_80_is_needed_for_acme_only_when_http01_is_resolved() {
        assert!(opens_port_80_for_acme(&host(
            "example.com",
            false,
            AcmeChallengeType::Http01
        )));
        assert!(!opens_port_80_for_acme(&host(
            "example.com",
            false,
            AcmeChallengeType::Dns01
        )));
        // Auto falls back to http-01 if dns-01 fails, so it needs port 80 too.
        assert!(opens_port_80_for_acme(&host(
            "example.com",
            false,
            AcmeChallengeType::Auto
        )));
        assert!(!opens_port_80_for_acme(&host(
            "*.example.com",
            false,
            AcmeChallengeType::Auto
        )));
    }

    #[test]
    fn http01_fallback_only_applies_to_auto_non_wildcard_hosts() {
        assert!(http01_fallback_allowed(&host(
            "example.com",
            false,
            AcmeChallengeType::Auto
        )));
        assert!(!http01_fallback_allowed(&host(
            "example.com",
            false,
            AcmeChallengeType::Dns01
        )));
        assert!(!http01_fallback_allowed(&host(
            "example.com",
            false,
            AcmeChallengeType::Http01
        )));
        assert!(!http01_fallback_allowed(&host(
            "*.example.com",
            false,
            AcmeChallengeType::Auto
        )));
    }

    #[test]
    fn port_80_is_not_needed_for_acme_when_acme_is_disabled() {
        let mut h = host("example.com", true, AcmeChallengeType::Http01);
        h.acme_enabled = false;
        assert!(!opens_port_80_for_acme(&h));
    }

    #[test]
    fn domains_for_issuance_adds_the_bare_apex_for_a_wildcard_domain() {
        assert_eq!(
            domains_for_issuance("*.example.com"),
            vec!["*.example.com".to_string(), "example.com".to_string()]
        );
    }

    #[test]
    fn domains_for_issuance_is_unchanged_for_a_non_wildcard_domain() {
        assert_eq!(
            domains_for_issuance("app.example.com"),
            vec!["app.example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn resolve_dns_credential_uses_the_single_existing_credential_when_none_is_specified() {
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        crate::db::create_dns_credential(
            &pool,
            uuid::Uuid::new_v4(),
            "only-one",
            DnsProviderKind::Hetzner,
            "tok",
            chrono::Utc::now(),
        )
        .await
        .unwrap();

        let cred = resolve_dns_credential(&pool, "example.com", None)
            .await
            .unwrap();
        assert_eq!(cred.name, "only-one");
    }

    #[tokio::test]
    async fn resolve_dns_credential_errors_when_none_exist_and_none_is_specified() {
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        let err = resolve_dns_credential(&pool, "example.com", None)
            .await
            .unwrap_err();
        assert!(matches!(err, DnsCredentialError::NoneConfigured(_)));
    }

    #[tokio::test]
    async fn resolve_dns_credential_errors_when_ambiguous_and_none_is_specified() {
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        crate::db::create_dns_credential(
            &pool,
            uuid::Uuid::new_v4(),
            "one",
            DnsProviderKind::Hetzner,
            "tok1",
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        crate::db::create_dns_credential(
            &pool,
            uuid::Uuid::new_v4(),
            "two",
            DnsProviderKind::Cloudflare,
            "tok2",
            chrono::Utc::now(),
        )
        .await
        .unwrap();

        let err = resolve_dns_credential(&pool, "example.com", None)
            .await
            .unwrap_err();
        assert!(matches!(err, DnsCredentialError::Ambiguous(_)));
    }

    #[tokio::test]
    async fn resolve_dns_credential_uses_the_explicitly_specified_credential_even_when_others_exist(
    ) {
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        let wanted_id = uuid::Uuid::new_v4();
        crate::db::create_dns_credential(
            &pool,
            wanted_id,
            "wanted",
            DnsProviderKind::Hetzner,
            "tok1",
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        crate::db::create_dns_credential(
            &pool,
            uuid::Uuid::new_v4(),
            "other",
            DnsProviderKind::Cloudflare,
            "tok2",
            chrono::Utc::now(),
        )
        .await
        .unwrap();

        let cred = resolve_dns_credential(&pool, "example.com", Some(wanted_id))
            .await
            .unwrap();
        assert_eq!(cred.name, "wanted");
    }

    #[tokio::test]
    async fn resolve_dns_credential_errors_when_the_specified_id_does_not_exist() {
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        let err = resolve_dns_credential(&pool, "example.com", Some(uuid::Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(matches!(err, DnsCredentialError::NotFound(_)));
    }

    async fn test_state(directory_url: String) -> AppState {
        let tmp =
            std::env::temp_dir().join(format!("rust-proxy-acme-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = Config {
            network: NetworkConfig {
                bind_ranges: vec![],
                dedicated_ips: vec![],
            },
            admin: AdminConfig {
                bind_ip_v4: Some("127.0.0.1".parse().unwrap()),
                bind_ip_v6: None,
                bind_port: 8080,
                allowed_ips: vec![],
                expose_admin_port: None,
                session_secret: Some("test-secret".into()),
                admin_username: Some("admin".into()),
                admin_password_hash: Some(
                    "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into(),
                ),
                db_path: PathBuf::from(":memory:"),
                log_dir: None,
                client_cert_subjects: vec![],
            },
            acme: AcmeConfig {
                directory_url,
                contact_email: "".into(), // deliberately blank, like an unconfigured install
                dns_provider: DnsProviderKind::Cloudflare,
                dns_api_token: "".into(),
                cert_dir: tmp.join("certs"),
                account_key_path: tmp.join("account.key"),
                renew_before_days: 30,
                organization: None,
                organizational_unit: None,
            },
            hosts: vec![],
            port_rules: vec![],
            client_cert_forward_token: None,
        };
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
        AppState::new(cfg, pool, vec![], vec![], None, None, None)
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
        assert!(
            result.is_err(),
            "run_renewal_loop returned instead of retrying -- this would crash the whole daemon"
        );
    }

    fn self_signed_pair(domain: &str) -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[tokio::test]
    async fn load_certs_from_disk_restores_a_previously_persisted_cert() {
        let state = test_state("https://example.invalid/directory".to_string()).await;
        let (chain_pem, key_pem) = self_signed_pair("example.com");
        persist_cert_files(&state.acme().cert_dir, "example.com", &chain_pem, &key_pem).unwrap();
        assert!(
            state.certs().is_empty(),
            "sanity check: nothing loaded into memory yet"
        );

        load_certs_from_disk(&state).unwrap();
        assert!(state.certs().contains_key("example.com"));
    }

    #[tokio::test]
    async fn load_certs_from_disk_is_a_noop_when_cert_dir_does_not_exist_yet() {
        let state = test_state("https://example.invalid/directory".to_string()).await;
        // First boot: nothing has ever been issued, cert_dir doesn't
        // exist on disk at all -- must not error.
        load_certs_from_disk(&state).unwrap();
        assert!(state.certs().is_empty());
    }

    #[tokio::test]
    async fn load_certs_from_disk_skips_a_directory_missing_one_of_the_two_files() {
        let state = test_state("https://example.invalid/directory".to_string()).await;
        let dir = state.acme().cert_dir.join("partial.example.com");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("fullchain.pem"),
            "not-even-checked-since-privkey-is-missing",
        )
        .unwrap();

        load_certs_from_disk(&state).unwrap();
        assert!(state.certs().is_empty());
    }
}
