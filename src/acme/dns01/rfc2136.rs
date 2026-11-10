//! RFC 2136 DNS-01 provider -- TSIG-signed (RFC 8945) DNS UPDATE messages
//! sent straight to an authoritative server you run yourself (Knot, BIND,
//! PowerDNS, ...), over TCP. No DNS crate: the handful of message shapes
//! needed (one SOA query, one UPDATE add, one UPDATE delete) are encoded
//! here by hand, and HMAC comes from `ring`, already a dependency.
//!
//! Credential: the single `token` string packs the fields separated by `|`
//! (`|` never occurs in a hostname, key name or base64 secret; `:` can't be
//! the separator because an IPv6 server address contains it):
//!
//! `server|key_name|algorithm|secret_base64[|zone]`
//!
//! * `server` -- `host`, `host:port`, `v4:port` or `[v6]:port`; port 53 if absent.
//! * `algorithm` -- `hmac-sha256` (recommended), `hmac-sha384` or `hmac-sha512`.
//! * `zone` -- optional. Without it the zone is found by asking the server
//!   for the challenge name's SOA (the owner of the SOA it returns, in the
//!   answer or the authority section, is the zone apex).
//!
//! Every UPDATE is signed and the response's TSIG is verified before a
//! NOERROR is believed, so an on-path forgery can't fake a successful update.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{Dns01Error, DnsProvider, DnsZone};

const TYPE_SOA: u16 = 6;
const TYPE_TXT: u16 = 16;
const TYPE_TSIG: u16 = 250;
const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;
const OPCODE_UPDATE: u16 = 5;
const FUDGE: u16 = 300;
const TXT_TTL: u32 = 60;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().trim_end_matches('.').to_ascii_lowercase().as_str() {
            "hmac-sha256" | "sha256" => Some(Self::Sha256),
            "hmac-sha384" | "sha384" => Some(Self::Sha384),
            "hmac-sha512" | "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "hmac-sha256",
            Self::Sha384 => "hmac-sha384",
            Self::Sha512 => "hmac-sha512",
        }
    }
    fn ring(self) -> ring::hmac::Algorithm {
        match self {
            Self::Sha256 => ring::hmac::HMAC_SHA256,
            Self::Sha384 => ring::hmac::HMAC_SHA384,
            Self::Sha512 => ring::hmac::HMAC_SHA512,
        }
    }
}

pub struct Rfc2136Dns01 {
    server: String,
    key_name: String,
    algorithm: Option<Algorithm>,
    secret: Option<Vec<u8>>,
    zone: Option<String>,
}

impl Rfc2136Dns01 {
    /// Never fails: a malformed credential is reported by the first call that
    /// needs it (same as every other provider with a bad token).
    pub fn new(token: String) -> Self {
        let parts: Vec<&str> = token.split('|').map(str::trim).collect();
        let get = |i: usize| parts.get(i).copied().unwrap_or_default();
        let server = get(0);
        let server = if server.is_empty() {
            String::new()
        } else if server.starts_with('[') {
            if server.contains("]:") {
                server.to_string()
            } else {
                format!("{server}:53")
            }
        } else if server.matches(':').count() == 1 {
            server.to_string()
        } else if server.contains(':') {
            format!("[{server}]:53")
        } else {
            format!("{server}:53")
        };
        Self {
            server,
            key_name: normalize(get(1)),
            algorithm: Algorithm::parse(get(2)),
            secret: STANDARD.decode(get(3)).ok().filter(|s| !s.is_empty()),
            zone: Some(normalize(get(4))).filter(|z| !z.is_empty()),
        }
    }

    fn key(&self) -> Result<(Algorithm, ring::hmac::Key), Dns01Error> {
        if self.server.is_empty() || self.key_name.is_empty() {
            return Err(Dns01Error::Api(
                "RFC 2136 credential needs server|key_name|algorithm|secret[|zone]".into(),
            ));
        }
        let alg = self.algorithm.ok_or_else(|| {
            Dns01Error::Api(
                "RFC 2136 algorithm must be hmac-sha256, hmac-sha384 or hmac-sha512".into(),
            )
        })?;
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| Dns01Error::Api("RFC 2136 TSIG secret is not valid base64".into()))?;
        Ok((alg, ring::hmac::Key::new(alg.ring(), secret)))
    }

    async fn exchange(&self, msg: &[u8]) -> Result<Vec<u8>, Dns01Error> {
        let io = async {
            let mut stream = TcpStream::connect(&self.server).await?;
            let mut framed = Vec::with_capacity(msg.len() + 2);
            framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            framed.extend_from_slice(msg);
            stream.write_all(&framed).await?;
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await?;
            let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut reply).await?;
            Ok::<_, std::io::Error>(reply)
        };
        match tokio::time::timeout(TIMEOUT, io).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(e)) => Err(Dns01Error::Api(format!("DNS server {}: {e}", self.server))),
            Err(_) => Err(Dns01Error::Api(format!(
                "DNS server {} timed out",
                self.server
            ))),
        }
    }

    /// Build, sign, send one UPDATE and check the signed answer.
    async fn update(&self, zone: &str, rr: &[u8]) -> Result<(), Dns01Error> {
        let (alg, key) = self.key()?;
        let id: u16 = rand::random();
        let mut msg = Vec::new();
        header(&mut msg, id, OPCODE_UPDATE << 11, [1, 0, 1, 0]);
        put_name(&mut msg, zone)?;
        msg.extend_from_slice(&TYPE_SOA.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(rr);
        let now = unix_now();
        let mac = sign(&key, alg, &self.key_name, &[], &msg, now)?;
        append_tsig(&mut msg, &self.key_name, alg, now, &mac, id)?;

        let reply = self.exchange(&msg).await?;
        let parsed = parse(&reply)?;
        if parsed.id != id {
            return Err(Dns01Error::Api(
                "DNS server answered a different message".into(),
            ));
        }
        let tsig = parsed.tsig.as_ref().ok_or_else(|| {
            let rcode = parsed.rcode;
            Dns01Error::Api(format!(
                "DNS server refused the update ({})",
                rcode_name(rcode)
            ))
        })?;
        if tsig.error != 0 {
            return Err(Dns01Error::Api(format!(
                "DNS server rejected the TSIG signature ({})",
                tsig_error_name(tsig.error)
            )));
        }
        // RFC 8945 5.3: response MAC covers the request MAC, the response
        // without its TSIG (original ID, ARCOUNT - 1) and the TSIG variables.
        let mut unsigned = reply[..tsig.start].to_vec();
        unsigned[0..2].copy_from_slice(&tsig.original_id.to_be_bytes());
        let ar = u16::from_be_bytes([unsigned[10], unsigned[11]]).saturating_sub(1);
        unsigned[10..12].copy_from_slice(&ar.to_be_bytes());
        let expected = sign_vars(&key, &mac, &unsigned, &tsig.vars);
        if !constant_time_eq(&expected, &tsig.mac) {
            return Err(Dns01Error::Api(
                "DNS server's reply signature did not verify".into(),
            ));
        }
        if unix_now().abs_diff(tsig.time) > u64::from(tsig.fudge) {
            return Err(Dns01Error::Api(
                "DNS server's reply is outside the TSIG time window".into(),
            ));
        }
        if parsed.rcode != 0 {
            return Err(Dns01Error::Api(format!(
                "DNS server refused the update ({})",
                rcode_name(parsed.rcode)
            )));
        }
        Ok(())
    }

    async fn discover_zone(&self, name: &str) -> Result<String, Dns01Error> {
        let id: u16 = rand::random();
        let mut msg = Vec::new();
        header(&mut msg, id, 0, [1, 0, 0, 0]);
        put_name(&mut msg, name)?;
        msg.extend_from_slice(&TYPE_SOA.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        let reply = self.exchange(&msg).await?;
        let parsed = parse(&reply)?;
        parsed
            .soa_owner
            .ok_or_else(|| Dns01Error::ZoneNotFound(name.to_string()))
    }
}

#[async_trait]
impl DnsProvider for Rfc2136Dns01 {
    async fn find_zone(&self, domain: &str) -> Result<DnsZone, Dns01Error> {
        let domain = normalize(domain);
        let zone = match &self.zone {
            Some(z) if domain == *z || domain.ends_with(&format!(".{z}")) => z.clone(),
            Some(z) => {
                return Err(Dns01Error::Api(format!(
                    "{domain} is not inside the credential's zone {z}"
                )));
            }
            None => self.discover_zone(&domain).await?,
        };
        Ok(DnsZone {
            id: zone.clone(),
            name: zone,
        })
    }

    async fn create_txt_record(
        &self,
        zone: &DnsZone,
        name: &str,
        content: &str,
    ) -> Result<String, Dns01Error> {
        let name = normalize(name);
        let rr = txt_rr(&name, CLASS_IN, TXT_TTL, content)?;
        self.update(&zone.name, &rr).await?;
        // The "record id" is what the delete needs to name this exact RR.
        Ok(format!("{name} {content}"))
    }

    async fn delete_txt_record(&self, zone: &DnsZone, record_id: &str) -> Result<(), Dns01Error> {
        let (name, content) = record_id
            .split_once(' ')
            .ok_or_else(|| Dns01Error::Api("malformed RFC 2136 record id".into()))?;
        // RFC 2136 2.5.4: class NONE, TTL 0 deletes just this RR.
        let rr = txt_rr(name, CLASS_NONE, 0, content)?;
        self.update(&zone.name, &rr).await
    }
}

// --- wire format ---------------------------------------------------------

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn header(msg: &mut Vec<u8>, id: u16, flags: u16, counts: [u16; 4]) {
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&flags.to_be_bytes());
    for c in counts {
        msg.extend_from_slice(&c.to_be_bytes());
    }
}

/// Uncompressed, lower-case (canonical, as TSIG requires) wire name.
fn put_name(out: &mut Vec<u8>, name: &str) -> Result<(), Dns01Error> {
    let name = normalize(name);
    let start = out.len();
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(Dns01Error::Api(format!("invalid DNS name {name:?}")));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() - start > 255 {
        return Err(Dns01Error::Api(format!("DNS name too long: {name}")));
    }
    Ok(())
}

fn txt_rr(name: &str, class: u16, ttl: u32, content: &str) -> Result<Vec<u8>, Dns01Error> {
    let mut rdata = Vec::new();
    for chunk in content.as_bytes().chunks(255) {
        rdata.push(chunk.len() as u8);
        rdata.extend_from_slice(chunk);
    }
    let mut rr = Vec::new();
    put_name(&mut rr, name)?;
    rr.extend_from_slice(&TYPE_TXT.to_be_bytes());
    rr.extend_from_slice(&class.to_be_bytes());
    rr.extend_from_slice(&ttl.to_be_bytes());
    rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    rr.extend_from_slice(&rdata);
    Ok(rr)
}

/// The TSIG variables block (RFC 8945 4.3.3) for an unextended request.
fn tsig_vars(key_name: &str, alg: Algorithm, time: u64) -> Result<Vec<u8>, Dns01Error> {
    let mut v = Vec::new();
    put_name(&mut v, key_name)?;
    v.extend_from_slice(&CLASS_ANY.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    put_name(&mut v, alg.name())?;
    v.extend_from_slice(&time.to_be_bytes()[2..]);
    v.extend_from_slice(&FUDGE.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes()); // error
    v.extend_from_slice(&0u16.to_be_bytes()); // other len
    Ok(v)
}

fn sign(
    key: &ring::hmac::Key,
    alg: Algorithm,
    key_name: &str,
    request_mac: &[u8],
    msg: &[u8],
    time: u64,
) -> Result<Vec<u8>, Dns01Error> {
    Ok(sign_vars(
        key,
        request_mac,
        msg,
        &tsig_vars(key_name, alg, time)?,
    ))
}

fn sign_vars(key: &ring::hmac::Key, request_mac: &[u8], msg: &[u8], vars: &[u8]) -> Vec<u8> {
    let mut ctx = ring::hmac::Context::with_key(key);
    if !request_mac.is_empty() {
        ctx.update(&(request_mac.len() as u16).to_be_bytes());
        ctx.update(request_mac);
    }
    ctx.update(msg);
    ctx.update(vars);
    ctx.sign().as_ref().to_vec()
}

fn append_tsig(
    msg: &mut Vec<u8>,
    key_name: &str,
    alg: Algorithm,
    time: u64,
    mac: &[u8],
    id: u16,
) -> Result<(), Dns01Error> {
    let mut rdata = Vec::new();
    put_name(&mut rdata, alg.name())?;
    rdata.extend_from_slice(&time.to_be_bytes()[2..]);
    rdata.extend_from_slice(&FUDGE.to_be_bytes());
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(mac);
    rdata.extend_from_slice(&id.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes());
    put_name(msg, key_name)?;
    msg.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    msg.extend_from_slice(&CLASS_ANY.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    msg.extend_from_slice(&rdata);
    let ar = u16::from_be_bytes([msg[10], msg[11]]) + 1;
    msg[10..12].copy_from_slice(&ar.to_be_bytes());
    Ok(())
}

struct Tsig {
    /// Offset of the TSIG RR in the message.
    start: usize,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
    time: u64,
    fudge: u16,
    /// The variables block rebuilt from the RR, for verifying it.
    vars: Vec<u8>,
}

struct Parsed {
    id: u16,
    rcode: u16,
    soa_owner: Option<String>,
    tsig: Option<Tsig>,
}

fn bad() -> Dns01Error {
    Dns01Error::Api("malformed reply from the DNS server".into())
}

/// Read a (possibly compressed) name at `pos`; returns it and the offset
/// just past it in the original position.
fn read_name(msg: &[u8], mut pos: usize) -> Result<(String, usize), Dns01Error> {
    let mut labels = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos).ok_or_else(bad)? as usize;
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *msg.get(pos + 1).ok_or_else(bad)? as usize;
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > 32 {
                return Err(bad());
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            let end = end.unwrap_or(pos + 1);
            return Ok((labels.join(".").to_ascii_lowercase(), end));
        }
        let label = msg.get(pos + 1..pos + 1 + len).ok_or_else(bad)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
    }
}

fn u16_at(msg: &[u8], pos: usize) -> Result<u16, Dns01Error> {
    Ok(u16::from_be_bytes(
        msg.get(pos..pos + 2).ok_or_else(bad)?.try_into().unwrap(),
    ))
}

fn parse(msg: &[u8]) -> Result<Parsed, Dns01Error> {
    if msg.len() < 12 {
        return Err(bad());
    }
    let id = u16_at(msg, 0)?;
    let rcode = u16_at(msg, 2)? & 0x0F;
    let counts = [
        u16_at(msg, 4)?,
        u16_at(msg, 6)?,
        u16_at(msg, 8)?,
        u16_at(msg, 10)?,
    ];
    let mut pos = 12;
    for _ in 0..counts[0] {
        let (_, next) = read_name(msg, pos)?;
        pos = next + 4;
    }
    let mut soa_owner = None;
    let mut tsig = None;
    let records = counts[1] as usize + counts[2] as usize + counts[3] as usize;
    for _ in 0..records {
        let start = pos;
        let (owner, next) = read_name(msg, pos)?;
        let rtype = u16_at(msg, next)?;
        let rdlen = u16_at(msg, next + 8)? as usize;
        let rdata = next + 10;
        if msg.len() < rdata + rdlen {
            return Err(bad());
        }
        if rtype == TYPE_SOA && soa_owner.is_none() {
            soa_owner = Some(owner.clone());
        }
        if rtype == TYPE_TSIG {
            let (alg, p) = read_name(msg, rdata)?;
            let time_bytes = msg.get(p..p + 6).ok_or_else(bad)?;
            let mut t = [0u8; 8];
            t[2..].copy_from_slice(time_bytes);
            let time = u64::from_be_bytes(t);
            let fudge = u16_at(msg, p + 6)?;
            let mac_len = u16_at(msg, p + 8)? as usize;
            let mac = msg.get(p + 10..p + 10 + mac_len).ok_or_else(bad)?.to_vec();
            let q = p + 10 + mac_len;
            let original_id = u16_at(msg, q)?;
            let error = u16_at(msg, q + 2)?;
            let other_len = u16_at(msg, q + 4)? as usize;
            let other = msg.get(q + 6..q + 6 + other_len).ok_or_else(bad)?;
            let mut vars = Vec::new();
            put_name(&mut vars, &owner)?;
            vars.extend_from_slice(&CLASS_ANY.to_be_bytes());
            vars.extend_from_slice(&0u32.to_be_bytes());
            put_name(&mut vars, &alg)?;
            vars.extend_from_slice(time_bytes);
            vars.extend_from_slice(&fudge.to_be_bytes());
            vars.extend_from_slice(&error.to_be_bytes());
            vars.extend_from_slice(&(other_len as u16).to_be_bytes());
            vars.extend_from_slice(other);
            tsig = Some(Tsig {
                start,
                mac,
                original_id,
                error,
                time,
                fudge,
                vars,
            });
        }
        pos = rdata + rdlen;
    }
    Ok(Parsed {
        id,
        rcode,
        soa_owner,
        tsig,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn rcode_name(rcode: u16) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED: the key is not allowed to update this name".into(),
        9 => "NOTAUTH: the key may not change this name, or the server doesn't know the key or serve the zone".into(),
        10 => "NOTZONE".into(),
        n => format!("rcode {n}"),
    }
}

fn tsig_error_name(err: u16) -> &'static str {
    match err {
        16 => "BADSIG: wrong secret or algorithm",
        17 => "BADKEY: the server has no key by that name",
        18 => "BADTIME: this host's clock is off",
        _ => "TSIG error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const SECRET: &str = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA==";

    #[test]
    fn token_parsing_handles_every_server_form() {
        let p = |s: &str| Rfc2136Dns01::new(format!("{s}|k|hmac-sha256|{SECRET}")).server;
        assert_eq!(p("ns1.example.com"), "ns1.example.com:53");
        assert_eq!(p("ns1.example.com:5353"), "ns1.example.com:5353");
        assert_eq!(p("192.0.2.1"), "192.0.2.1:53");
        assert_eq!(p("2001:db8::1"), "[2001:db8::1]:53");
        assert_eq!(p("[2001:db8::1]:5300"), "[2001:db8::1]:5300");
        let c = Rfc2136Dns01::new(format!(
            "ns|Key.Name.|HMAC-SHA512|{SECRET}|Portal.Example.com."
        ));
        assert_eq!(c.key_name, "key.name");
        assert_eq!(c.algorithm, Some(Algorithm::Sha512));
        assert_eq!(c.zone.as_deref(), Some("portal.example.com"));
    }

    #[test]
    fn bad_credentials_are_reported_not_panicked() {
        assert!(Rfc2136Dns01::new("".into()).key().is_err());
        assert!(Rfc2136Dns01::new("ns|k|md5|abc".into()).key().is_err());
        assert!(
            Rfc2136Dns01::new("ns|k|hmac-sha256|!!!".into())
                .key()
                .is_err()
        );
    }

    #[test]
    fn txt_rr_splits_long_content_into_strings() {
        let rr = txt_rr("a.example", CLASS_IN, 60, &"x".repeat(300)).unwrap();
        // name(11) type class ttl rdlen, then 255 + 45 byte strings
        let rdlen = u16::from_be_bytes([rr[19], rr[20]]) as usize;
        assert_eq!(rdlen, 1 + 255 + 1 + 45);
        assert_eq!(rr[21], 255);
    }

    /// Known-answer test: the MAC must match an independent HMAC over the
    /// same bytes, and the appended TSIG must parse back to the same fields.
    #[test]
    fn signed_update_round_trips_through_the_parser() {
        let c = Rfc2136Dns01::new(format!("ns|rust-proxy|hmac-sha256|{SECRET}|example.com"));
        let (alg, key) = c.key().unwrap();
        let mut msg = Vec::new();
        header(&mut msg, 0x1234, OPCODE_UPDATE << 11, [1, 0, 1, 0]);
        put_name(&mut msg, "example.com").unwrap();
        msg.extend_from_slice(&TYPE_SOA.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&txt_rr("_acme-challenge.example.com", CLASS_IN, 60, "v").unwrap());
        let time = 1_700_000_000;
        let mac = sign(&key, alg, "rust-proxy", &[], &msg, time).unwrap();
        let unsigned = msg.clone();
        append_tsig(&mut msg, "rust-proxy", alg, time, &mac, 0x1234).unwrap();
        let parsed = parse(&msg).unwrap();
        let tsig = parsed.tsig.unwrap();
        assert_eq!(tsig.start, unsigned.len());
        assert_eq!(tsig.mac, mac);
        assert_eq!(tsig.time, time);
        assert_eq!(tsig.vars, tsig_vars("rust-proxy", alg, time).unwrap());
        // Recompute independently.
        let mut data = unsigned.clone();
        data.extend_from_slice(&tsig_vars("rust-proxy", alg, time).unwrap());
        let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &STANDARD.decode(SECRET).unwrap());
        assert_eq!(ring::hmac::sign(&k, &data).as_ref(), mac.as_slice());
    }

    #[test]
    fn compressed_names_are_followed() {
        // header + question "a.example" + answer owner = pointer to 12
        let mut msg = Vec::new();
        header(&mut msg, 1, 0x8400, [1, 1, 0, 0]);
        put_name(&mut msg, "a.example").unwrap();
        msg.extend_from_slice(&TYPE_SOA.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&[0xC0, 14]); // "example" inside the question
        msg.extend_from_slice(&TYPE_SOA.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse(&msg).unwrap().soa_owner.as_deref(), Some("example"));
    }

    /// A minimal fake server: answers the SOA query with an authority SOA,
    /// and signs its UPDATE reply with the same key, as Knot would.
    #[tokio::test]
    async fn update_against_a_signing_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let key =
                ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &STANDARD.decode(SECRET).unwrap());
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut len = [0u8; 2];
                s.read_exact(&mut len).await.unwrap();
                let mut req = vec![0u8; u16::from_be_bytes(len) as usize];
                s.read_exact(&mut req).await.unwrap();
                let parsed = parse(&req).unwrap();
                let mut reply = Vec::new();
                match parsed.tsig {
                    None => {
                        header(&mut reply, parsed.id, 0x8400, [0, 0, 1, 0]);
                        put_name(&mut reply, "example.com").unwrap();
                        reply.extend_from_slice(&TYPE_SOA.to_be_bytes());
                        reply.extend_from_slice(&CLASS_IN.to_be_bytes());
                        reply.extend_from_slice(&60u32.to_be_bytes());
                        reply.extend_from_slice(&0u16.to_be_bytes());
                    }
                    Some(t) => {
                        let mut ok_req = req[..t.start].to_vec();
                        ok_req[10..12].copy_from_slice(&0u16.to_be_bytes());
                        let expect = sign_vars(&key, &[], &ok_req, &t.vars);
                        assert_eq!(expect, t.mac, "client MAC");
                        header(&mut reply, parsed.id, 0xA800, [0, 0, 0, 0]);
                        let now = unix_now();
                        let mac = sign(&key, Algorithm::Sha256, "rust-proxy", &t.mac, &reply, now)
                            .unwrap();
                        append_tsig(
                            &mut reply,
                            "rust-proxy",
                            Algorithm::Sha256,
                            now,
                            &mac,
                            parsed.id,
                        )
                        .unwrap();
                    }
                }
                let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                s.write_all(&framed).await.unwrap();
            }
        });
        let c = Rfc2136Dns01::new(format!("{addr}|rust-proxy|hmac-sha256|{SECRET}"));
        let zone = c
            .find_zone("_acme-challenge.store.example.com")
            .await
            .unwrap();
        assert_eq!(zone.name, "example.com");
        let id = c
            .create_txt_record(&zone, "_acme-challenge.store.example.com", "token")
            .await
            .unwrap();
        c.delete_txt_record(&zone, &id).await.unwrap();
    }
}

/// Live check against a real server: `RFC2136_TOKEN=... cargo test -- --ignored live_`
#[cfg(test)]
mod live {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn live_add_and_remove_a_challenge_record() {
        let token = std::env::var("RFC2136_TOKEN").expect("RFC2136_TOKEN");
        let name = std::env::var("RFC2136_NAME").expect("RFC2136_NAME");
        let c = Rfc2136Dns01::new(token);
        let zone = c.find_zone(&name).await.unwrap();
        eprintln!("zone {}", zone.name);
        let id = c
            .create_txt_record(&zone, &name, "rust-proxy-live-test")
            .await
            .unwrap();
        eprintln!("added {id}");
        if std::env::var("RFC2136_KEEP").is_err() {
            c.delete_txt_record(&zone, &id).await.unwrap();
            eprintln!("removed");
        }
    }

    #[tokio::test]
    #[ignore]
    async fn live_refused_outside_acme_names() {
        let token = std::env::var("RFC2136_TOKEN").expect("RFC2136_TOKEN");
        let c = Rfc2136Dns01::new(token);
        let zone = c.find_zone("vpn.portal.jpps.us").await.unwrap();
        let err = c
            .create_txt_record(&zone, "evil.portal.jpps.us", "x")
            .await
            .unwrap_err();
        eprintln!("refused as expected: {err}");
    }
}
