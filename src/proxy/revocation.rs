//! OCSP revocation checking for TrustBridge client certificates.
//!
//! rustls validates the chain and expiry at the handshake but cannot check
//! revocation, so this module asks TrustBridge's OCSP responder about each
//! client certificate and the proxy treats a revoked one as "no certificate
//! presented" (the host falls back to its login page).
//!
//! Policy, as chosen by the operator:
//!
//!   * **Fail open.** If the responder is unreachable, slow, answers
//!     "unknown", or gives a response that does not verify, the certificate
//!     is allowed and the check is retried after a short delay. A responder
//!     outage must not lock everyone out.
//!   * **A revocation, once seen, is permanent.** The serial goes into an
//!     in-memory set and a sqlite table (reloaded at startup), and is never
//!     removed, even if the responder later fails or answers differently.
//!
//! Responses are accepted only if signed by the TrustBridge intermediate
//! (the responder signs with the CA key directly). The request is sent with
//! `Connection: close` and no connection pooling: `openssl ocsp -port`
//! serves one connection at a time, so an idle kept-alive connection would
//! wedge it for every other client.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ring::{digest, signature};
use sqlx::SqlitePool;

const TRUSTBRIDGE_INTERMEDIATE_PEM: &str = include_str!("trustbridge_intermediate.crt");

pub const DEFAULT_OCSP_URL: &str = "https://ocsp.pki.jpps.us";
const GOOD_TTL: Duration = Duration::from_secs(300);
const UNAVAILABLE_TTL: Duration = Duration::from_secs(30);
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const CACHE_MAX: usize = 4096;

// AlgorithmIdentifier { sha1, NULL }
const SHA1_ALG_ID: &[u8] = &[0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00];
// OID ecdsa-with-SHA256
const ECDSA_SHA256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Good,
    Revoked,
    /// Anything that is not a verified good/revoked answer. Treated as allowed.
    Unavailable,
}

/// The CA that issues (and signs OCSP answers for) the client certificates.
pub struct Issuer {
    name_der: Vec<u8>,
    key_bytes: Vec<u8>,
}

impl Issuer {
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
        Some(Self {
            name_der: cert.subject().as_raw().to_vec(),
            key_bytes: cert.public_key().subject_public_key.data.to_vec(),
        })
    }

    fn trustbridge() -> Option<Self> {
        let mut reader = std::io::Cursor::new(TRUSTBRIDGE_INTERMEDIATE_PEM.as_bytes());
        let der = rustls_pemfile::certs(&mut reader).next()?.ok()?;
        Self::from_der(der.as_ref())
    }
}

pub struct RevocationChecker {
    url: Option<String>,
    issuer: Option<Issuer>,
    http: reqwest::Client,
    db: Option<SqlitePool>,
    revoked: Mutex<HashSet<String>>,
    cache: Mutex<HashMap<String, (Verdict, Instant)>>,
}

impl RevocationChecker {
    /// Uses `RUST_PROXY_OCSP_URL` if set (an empty value disables checking),
    /// otherwise TrustBridge's public responder.
    pub fn new(db: Option<SqlitePool>) -> Self {
        let url = match std::env::var("RUST_PROXY_OCSP_URL") {
            Ok(v) if v.trim().is_empty() => None,
            Ok(v) => Some(v.trim().to_string()),
            Err(_) => Some(DEFAULT_OCSP_URL.to_string()),
        };
        Self::with_parts(url, Issuer::trustbridge(), db)
    }

    pub fn with_parts(url: Option<String>, issuer: Option<Issuer>, db: Option<SqlitePool>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(QUERY_TIMEOUT)
            .pool_max_idle_per_host(0)
            .build()
            .expect("OCSP http client must build");
        Self {
            url,
            issuer,
            http,
            db,
            revoked: Mutex::new(HashSet::new()),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Restores serials revoked in earlier runs so they stay revoked.
    pub async fn load_revoked(&self) {
        let Some(db) = &self.db else { return };
        match sqlx::query_scalar::<_, String>("SELECT serial FROM revoked_client_certs")
            .fetch_all(db)
            .await
        {
            Ok(rows) => {
                let n = rows.len();
                self.revoked.lock().unwrap().extend(rows);
                tracing::info!(count = n, "loaded known-revoked client certificates");
            }
            Err(err) => tracing::warn!(error = %err, "could not load revoked client certificates"),
        }
    }

    /// True if this leaf certificate is known to be revoked. Never errors:
    /// every failure to find out is treated as "not revoked" (fail open).
    pub async fn is_revoked(&self, leaf_der: &[u8]) -> bool {
        let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf_der) else {
            return false;
        };
        let serial = cert.raw_serial().to_vec();
        let key = hex(&serial);
        if self.revoked.lock().unwrap().contains(&key) {
            return true;
        }
        let (Some(url), Some(issuer)) = (&self.url, &self.issuer) else {
            return false;
        };
        if cert.issuer().as_raw() != issuer.name_der.as_slice() {
            return false;
        }
        if let Some((verdict, at)) = self.cache.lock().unwrap().get(&key).copied() {
            let ttl = if verdict == Verdict::Good { GOOD_TTL } else { UNAVAILABLE_TTL };
            if at.elapsed() < ttl {
                return false;
            }
        }
        let verdict = self.query(url, issuer, cert.issuer().as_raw(), &serial).await;
        match verdict {
            Verdict::Revoked => {
                self.mark_revoked(&key).await;
                true
            }
            other => {
                if other == Verdict::Unavailable {
                    tracing::warn!(serial = %key, "OCSP status unavailable; allowing the client certificate (fail open)");
                }
                let mut cache = self.cache.lock().unwrap();
                if cache.len() >= CACHE_MAX {
                    cache.retain(|_, (_, at)| at.elapsed() < GOOD_TTL);
                    if cache.len() >= CACHE_MAX {
                        cache.clear();
                    }
                }
                cache.insert(key, (other, Instant::now()));
                false
            }
        }
    }

    async fn mark_revoked(&self, key: &str) {
        self.revoked.lock().unwrap().insert(key.to_string());
        tracing::warn!(serial = %key, "client certificate is revoked; it will no longer be accepted");
        if let Some(db) = &self.db {
            let _ = sqlx::query("INSERT OR IGNORE INTO revoked_client_certs (serial, first_seen) VALUES (?, ?)")
                .bind(key)
                .bind(chrono::Utc::now().to_rfc3339())
                .execute(db)
                .await;
        }
    }

    async fn query(&self, url: &str, issuer: &Issuer, issuer_name_der: &[u8], serial: &[u8]) -> Verdict {
        let body = build_request(issuer, issuer_name_der, serial);
        let resp = self
            .http
            .post(url)
            .header("content-type", "application/ocsp-request")
            .header("connection", "close")
            .body(body)
            .send()
            .await;
        let bytes = match resp {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(b) => b,
                Err(_) => return Verdict::Unavailable,
            },
            _ => return Verdict::Unavailable,
        };
        parse_response(&bytes, &issuer.key_bytes, serial)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let l = content.len();
    if l < 128 {
        v.push(l as u8);
    } else if l < 256 {
        v.extend([0x81, l as u8]);
    } else {
        v.extend([0x82, (l >> 8) as u8, l as u8]);
    }
    v.extend_from_slice(content);
    v
}

fn build_request(issuer: &Issuer, issuer_name_der: &[u8], serial: &[u8]) -> Vec<u8> {
    let name_hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, issuer_name_der);
    let key_hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &issuer.key_bytes);
    let mut cert_id = SHA1_ALG_ID.to_vec();
    cert_id.extend(tlv(0x04, name_hash.as_ref()));
    cert_id.extend(tlv(0x04, key_hash.as_ref()));
    cert_id.extend(tlv(0x02, serial));
    let request = tlv(0x30, &tlv(0x30, &cert_id));
    let request_list = tlv(0x30, &request);
    let tbs = tlv(0x30, &request_list);
    tlv(0x30, &tbs)
}

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    rest: &'a [u8],
    raw: &'a [u8],
}

fn read_tlv(buf: &[u8]) -> Option<Tlv<'_>> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 3 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *buf.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some(Tlv { tag, content: &buf[header..end], rest: &buf[end..], raw: &buf[..end] })
}

fn trim_zeros(b: &[u8]) -> &[u8] {
    let mut b = b;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    b
}

/// Parses and signature-verifies an OCSPResponse for `serial`. Anything
/// malformed, unsigned by the issuer, or not a clear good/revoked answer
/// becomes `Unavailable`.
pub fn parse_response(resp: &[u8], issuer_key: &[u8], serial: &[u8]) -> Verdict {
    parse_inner(resp, issuer_key, serial).unwrap_or(Verdict::Unavailable)
}

fn parse_inner(resp: &[u8], issuer_key: &[u8], serial: &[u8]) -> Option<Verdict> {
    let top = read_tlv(resp)?;
    if top.tag != 0x30 {
        return None;
    }
    let status = read_tlv(top.content)?;
    if status.tag != 0x0A || status.content != [0] {
        return None;
    }
    let response_bytes = read_tlv(status.rest)?;
    if response_bytes.tag != 0xA0 {
        return None;
    }
    let rb_seq = read_tlv(response_bytes.content)?;
    let oid = read_tlv(rb_seq.content)?;
    let octets = read_tlv(oid.rest)?;
    if octets.tag != 0x04 {
        return None;
    }
    let basic = read_tlv(octets.content)?;
    let tbs = read_tlv(basic.content)?;
    let sig_alg = read_tlv(tbs.rest)?;
    let sig = read_tlv(sig_alg.rest)?;
    if tbs.tag != 0x30 || sig_alg.tag != 0x30 || sig.tag != 0x03 {
        return None;
    }
    if !sig_alg.content.windows(ECDSA_SHA256_OID.len()).any(|w| w == ECDSA_SHA256_OID) {
        return None;
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, issuer_key)
        .verify(tbs.raw, sig.content.get(1..)?)
        .ok()?;

    let mut first = read_tlv(tbs.content)?;
    if first.tag == 0xA0 {
        first = read_tlv(first.rest)?;
    }
    let produced = read_tlv(first.rest)?;
    let responses = read_tlv(produced.rest)?;
    if responses.tag != 0x30 {
        return None;
    }
    let mut items = responses.content;
    while !items.is_empty() {
        let single = read_tlv(items)?;
        items = single.rest;
        let cert_id = read_tlv(single.content)?;
        let alg = read_tlv(cert_id.content)?;
        let name_hash = read_tlv(alg.rest)?;
        let key_hash = read_tlv(name_hash.rest)?;
        let sn = read_tlv(key_hash.rest)?;
        if sn.tag != 0x02 || trim_zeros(sn.content) != trim_zeros(serial) {
            continue;
        }
        let cert_status = read_tlv(cert_id.rest)?;
        return Some(match cert_status.tag {
            0x80 => Verdict::Good,
            0xA1 => Verdict::Revoked,
            _ => Verdict::Unavailable,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, SerialNumber};
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct Pki {
        issuer_der: Vec<u8>,
        signer: EcdsaKeyPair,
        leaf_der: Vec<u8>,
        serial: Vec<u8>,
    }

    fn make_pki() -> Pki {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ca_kp = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, format!("Test Intermediate {n}"));
        let ca = ca_params.self_signed(&ca_kp).unwrap();

        let leaf_kp = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params.distinguished_name.push(rcgen::DnType::CommonName, "Jeff");
        leaf_params.serial_number = Some(SerialNumber::from(vec![0x12, 0x34, 0x56]));
        let leaf = leaf_params.signed_by(&leaf_kp, &ca, &ca_kp).unwrap();

        let signer = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &ca_kp.serialize_der(),
            &SystemRandom::new(),
        )
        .unwrap();
        Pki {
            issuer_der: ca.der().to_vec(),
            signer,
            leaf_der: leaf.der().to_vec(),
            serial: vec![0x12, 0x34, 0x56],
        }
    }

    /// Builds a signed OCSPResponse. `status_tag`: 0x80 good, 0xA1 revoked, 0x82 unknown.
    fn signed_response(pki: &Pki, serial: &[u8], status_tag: u8) -> Vec<u8> {
        let mut cert_id = SHA1_ALG_ID.to_vec();
        cert_id.extend(tlv(0x04, &[0u8; 20]));
        cert_id.extend(tlv(0x04, &[0u8; 20]));
        cert_id.extend(tlv(0x02, serial));
        let status = if status_tag == 0xA1 {
            tlv(0xA1, &tlv(0x18, b"20261014000000Z"))
        } else {
            tlv(status_tag, &[])
        };
        let mut single = tlv(0x30, &cert_id);
        single.extend(status);
        single.extend(tlv(0x18, b"20261014000000Z"));
        let mut tbs = tlv(0xA2, &tlv(0x04, &[0u8; 20]));
        tbs.extend(tlv(0x18, b"20261014000000Z"));
        tbs.extend(tlv(0x30, &tlv(0x30, &single)));
        let tbs = tlv(0x30, &tbs);
        let sig = pki.signer.sign(&SystemRandom::new(), &tbs).unwrap();
        let mut sig_bits = vec![0u8];
        sig_bits.extend_from_slice(sig.as_ref());
        let mut basic = tbs;
        basic.extend(tlv(0x30, &tlv(0x06, ECDSA_SHA256_OID)));
        basic.extend(tlv(0x03, &sig_bits));
        let basic = tlv(0x30, &basic);
        let mut rb = tlv(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]);
        rb.extend(tlv(0x04, &basic));
        let mut out = tlv(0x0A, &[0]);
        out.extend(tlv(0xA0, &tlv(0x30, &rb)));
        tlv(0x30, &out)
    }

    fn checker(pki: &Pki, url: Option<String>) -> RevocationChecker {
        RevocationChecker::with_parts(url, Issuer::from_der(&pki.issuer_der), None)
    }

    async fn serve(body: Vec<u8>) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        server
    }

    #[test]
    fn a_real_trustbridge_response_verifies_and_reads_as_revoked() {
        let issuer = Issuer::trustbridge().expect("embedded intermediate parses");
        let serial = [
            0x0C, 0xA2, 0x8A, 0xE4, 0xA2, 0xB4, 0x4F, 0xBC, 0xCD, 0x92, 0x86, 0xCB, 0xBF, 0x51, 0x50, 0xD4,
        ];
        let resp = include_bytes!("testdata/trustbridge_ocsp_revoked.der");
        assert_eq!(parse_response(resp, &issuer.key_bytes, &serial), Verdict::Revoked);
        let other = [1u8, 2, 3];
        assert_eq!(parse_response(resp, &issuer.key_bytes, &other), Verdict::Unavailable);
    }

    #[test]
    fn request_has_the_expected_shape() {
        let pki = make_pki();
        let issuer = Issuer::from_der(&pki.issuer_der).unwrap();
        let req = build_request(&issuer, &issuer.name_der, &pki.serial);
        let top = read_tlv(&req).unwrap();
        assert_eq!(top.tag, 0x30);
        assert!(top.rest.is_empty());
        assert!(req.windows(3).any(|w| w == [0x02, 0x03, 0x12]), "serial is encoded as an INTEGER");
    }

    #[test]
    fn a_good_signed_response_is_good() {
        let pki = make_pki();
        let key = pki.signer.public_key().as_ref().to_vec();
        assert_eq!(parse_response(&signed_response(&pki, &pki.serial, 0x80), &key, &pki.serial), Verdict::Good);
    }

    #[test]
    fn a_revoked_signed_response_is_revoked() {
        let pki = make_pki();
        let key = pki.signer.public_key().as_ref().to_vec();
        assert_eq!(parse_response(&signed_response(&pki, &pki.serial, 0xA1), &key, &pki.serial), Verdict::Revoked);
    }

    #[test]
    fn unknown_wrong_serial_garbage_and_forged_responses_are_unavailable() {
        let pki = make_pki();
        let other = make_pki();
        let key = pki.signer.public_key().as_ref().to_vec();
        assert_eq!(parse_response(&signed_response(&pki, &pki.serial, 0x82), &key, &pki.serial), Verdict::Unavailable);
        assert_eq!(parse_response(&signed_response(&pki, &[9, 9], 0xA1), &key, &pki.serial), Verdict::Unavailable);
        assert_eq!(parse_response(b"not der", &key, &pki.serial), Verdict::Unavailable);
        assert_eq!(parse_response(&[], &key, &pki.serial), Verdict::Unavailable);
        let forged = signed_response(&other, &pki.serial, 0xA1);
        assert_eq!(parse_response(&forged, &key, &pki.serial), Verdict::Unavailable, "signed by the wrong key");
    }

    #[tokio::test]
    async fn a_revoked_answer_marks_the_cert_revoked_and_it_stays_revoked() {
        let pki = make_pki();
        let server = serve(signed_response(&pki, &pki.serial, 0xA1)).await;
        let c = checker(&pki, Some(server.uri()));
        assert!(c.is_revoked(&pki.leaf_der).await);
        drop(server);
        assert!(c.is_revoked(&pki.leaf_der).await, "known revocation survives the responder disappearing");
    }

    #[tokio::test]
    async fn a_known_revoked_serial_wins_over_a_later_good_answer() {
        let pki = make_pki();
        let server = serve(signed_response(&pki, &pki.serial, 0x80)).await;
        let c = checker(&pki, Some(server.uri()));
        c.revoked.lock().unwrap().insert(hex(&pki.serial));
        assert!(c.is_revoked(&pki.leaf_der).await);
    }

    #[tokio::test]
    async fn a_good_answer_is_allowed_and_cached() {
        let pki = make_pki();
        let server = serve(signed_response(&pki, &pki.serial, 0x80)).await;
        let c = checker(&pki, Some(server.uri()));
        assert!(!c.is_revoked(&pki.leaf_der).await);
        assert!(!c.is_revoked(&pki.leaf_der).await);
        assert_eq!(server.received_requests().await.unwrap().len(), 1, "second check served from cache");
    }

    #[tokio::test]
    async fn an_unreachable_responder_fails_open() {
        let pki = make_pki();
        let c = checker(&pki, Some("http://127.0.0.1:1".to_string()));
        assert!(!c.is_revoked(&pki.leaf_der).await);
    }

    #[tokio::test]
    async fn a_garbage_or_error_response_fails_open() {
        let pki = make_pki();
        let server = serve(b"nonsense".to_vec()).await;
        let c = checker(&pki, Some(server.uri()));
        assert!(!c.is_revoked(&pki.leaf_der).await);
        let server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(500)).mount(&server).await;
        let c = checker(&pki, Some(server.uri()));
        assert!(!c.is_revoked(&pki.leaf_der).await);
    }

    #[tokio::test]
    async fn a_cert_from_another_issuer_is_never_queried() {
        let pki = make_pki();
        let other = make_pki();
        let server = serve(signed_response(&pki, &other.serial, 0xA1)).await;
        let c = checker(&pki, Some(server.uri()));
        assert!(!c.is_revoked(&other.leaf_der).await);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn checking_can_be_disabled() {
        let pki = make_pki();
        let c = checker(&pki, None);
        assert!(!c.is_revoked(&pki.leaf_der).await);
    }

    #[tokio::test]
    async fn revocations_persist_across_restarts() {
        let pki = make_pki();
        let db = crate::db::connect(&std::path::PathBuf::from(":memory:")).await.unwrap();
        let server = serve(signed_response(&pki, &pki.serial, 0xA1)).await;
        let c = RevocationChecker::with_parts(Some(server.uri()), Issuer::from_der(&pki.issuer_der), Some(db.clone()));
        assert!(c.is_revoked(&pki.leaf_der).await);
        let fresh = RevocationChecker::with_parts(None, Issuer::from_der(&pki.issuer_der), Some(db));
        assert!(!fresh.is_revoked(&pki.leaf_der).await, "not loaded yet");
        fresh.load_revoked().await;
        assert!(fresh.is_revoked(&pki.leaf_der).await);
    }
}
