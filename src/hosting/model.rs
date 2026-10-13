//! Hosting data model plus every validation rule. Pure functions only (no
//! I/O, no state), so the API handlers and the unit tests exercise exactly
//! the same code.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Protocol;

#[derive(Debug, PartialEq, Eq)]
pub enum HostingError {
    /// The request itself is malformed or breaks a rule (HTTP 400).
    Invalid(String),
    /// The request is well-formed but clashes with existing state (HTTP 409).
    Conflict(String),
}

type Check = Result<(), HostingError>;

fn invalid<T>(msg: impl Into<String>) -> Result<T, HostingError> {
    Err(HostingError::Invalid(msg.into()))
}

fn conflict<T>(msg: impl Into<String>) -> Result<T, HostingError> {
    Err(HostingError::Conflict(msg.into()))
}

/// A block of public addresses routed to this host (for example a /28)
/// from which customer-facing addresses are handed out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingPool {
    /// Short slug that doubles as the class name: `standard`, `ham`, ...
    pub name: String,
    pub cidr: Ipv4Net,
    #[serde(default)]
    pub description: String,
    /// Addresses in `cidr` that are never handed out automatically or on
    /// request (kept for the proxy's own use).
    #[serde(default)]
    pub reserved: Vec<Ipv4Addr>,
    /// Private network the hosted VMs live in. When set, every allocation's
    /// `vm_ip` must be inside it.
    #[serde(default)]
    pub vm_cidr: Option<Ipv4Net>,
    /// The proxy's own address on `vm_cidr`; the default gateway a hosted VM
    /// must be configured with. Informational for provisioning tools.
    #[serde(default)]
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardMode {
    /// Every protocol and port on the public address maps 1:1 to the VM.
    All,
    /// Only the listed ports are forwarded; everything else to the public
    /// address is dropped.
    Ports,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSpec {
    pub protocol: Protocol,
    pub port_start: u16,
    pub port_end: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    pub id: Uuid,
    pub pool: String,
    pub public_ip: Ipv4Addr,
    pub name: String,
    #[serde(default)]
    pub customer: String,
    #[serde(default)]
    pub notes: String,
    /// The VM's private address. Until it is set the public IP is merely
    /// reserved: nothing answers on it.
    pub vm_ip: Option<Ipv4Addr>,
    /// Proxmox VMID, informational.
    pub vm_id: Option<u32>,
    pub forward: ForwardMode,
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

impl Allocation {
    /// Forwarding is live only for an enabled allocation that has a VM.
    pub fn is_active(&self) -> bool {
        self.enabled && self.vm_ip.is_some()
    }

    pub fn state(&self) -> &'static str {
        if !self.enabled {
            "disabled"
        } else if self.vm_ip.is_none() {
            "reserved"
        } else {
            "active"
        }
    }
}

const MAX_PORT_SPECS: usize = 64;

pub fn validate_slug(name: &str) -> Check {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if ok {
        Ok(())
    } else {
        invalid("pool name must be 1-32 characters of a-z, 0-9 and '-' (not starting or ending with '-')")
    }
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

fn is_publicly_routable(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || is_cgnat(ip)
        || ip.octets()[0] >= 240)
}

fn dedicated_v4(dedicated: &[IpAddr]) -> Vec<Ipv4Addr> {
    dedicated
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .collect()
}

fn nets_overlap(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Addresses in `pool` that may be handed out: the network and broadcast
/// addresses are skipped for anything larger than a /31, and `reserved`
/// entries never qualify.
pub fn usable_addresses(pool: &HostingPool) -> Vec<Ipv4Addr> {
    let all: Vec<Ipv4Addr> = pool.cidr.hosts().collect();
    all.into_iter()
        .filter(|ip| !pool.reserved.contains(ip))
        .collect()
}

pub fn is_usable(pool: &HostingPool, ip: Ipv4Addr) -> bool {
    pool.cidr.contains(&ip) && usable_addresses(pool).contains(&ip)
}

/// The lowest address in `pool` that no allocation holds yet.
pub fn next_free_ip(pool: &HostingPool, allocations: &[Allocation]) -> Option<Ipv4Addr> {
    let taken: HashSet<Ipv4Addr> = allocations.iter().map(|a| a.public_ip).collect();
    usable_addresses(pool)
        .into_iter()
        .find(|ip| !taken.contains(ip))
}

/// The lowest private address in the pool's `vm_cidr` that is neither the
/// network/broadcast address, any pool's gateway, nor already used by an
/// allocation. `None` when the pool has no `vm_cidr` or it is full.
pub fn next_free_vm_ip(
    pool: &HostingPool,
    all_pools: &[HostingPool],
    allocations: &[Allocation],
) -> Option<Ipv4Addr> {
    let net = pool.vm_cidr?;
    let taken: HashSet<Ipv4Addr> = allocations.iter().filter_map(|a| a.vm_ip).collect();
    net.hosts().find(|ip| {
        !taken.contains(ip)
            && pool.gateway != Some(*ip)
            && !all_pools.iter().any(|p| p.gateway == Some(*ip))
    })
}

/// `others` are the pools other than the one being validated.
pub fn validate_pool(candidate: &HostingPool, others: &[HostingPool], dedicated: &[IpAddr]) -> Check {
    validate_slug(&candidate.name)?;
    if candidate.description.len() > 256 {
        return invalid("description must be at most 256 characters");
    }
    let net = candidate.cidr;
    if net.prefix_len() < 24 {
        return invalid("pool cidr must be a /24 or smaller");
    }
    if net != net.trunc() {
        return invalid(format!(
            "pool cidr has host bits set (did you mean {}?)",
            net.trunc()
        ));
    }
    if !is_publicly_routable(net.network()) || !is_publicly_routable(net.broadcast()) {
        return invalid("pool cidr must be publicly routable address space");
    }
    for other in others {
        if nets_overlap(&net, &other.cidr) {
            return conflict(format!(
                "pool cidr overlaps pool '{}' ({})",
                other.name, other.cidr
            ));
        }
    }
    // The dedicated addresses are the proxy's own sites; a pool covering one
    // would let an allocation take it over.
    if let Some(ip) = dedicated_v4(dedicated).into_iter().find(|ip| net.contains(ip)) {
        return invalid(format!(
            "pool cidr contains network.dedicated_ips address {ip}, which hosting must never touch"
        ));
    }
    for ip in &candidate.reserved {
        if !net.contains(ip) {
            return invalid(format!("reserved address {ip} is outside the pool"));
        }
    }
    if candidate.reserved.len() > 256 {
        return invalid("too many reserved addresses");
    }
    if candidate.gateway.is_some() != candidate.vm_cidr.is_some() {
        return invalid("vm_cidr and gateway must be set together or both left out");
    }
    if let (Some(vm_net), Some(gw)) = (candidate.vm_cidr, candidate.gateway) {
        if !vm_net.network().is_private() || !vm_net.broadcast().is_private() {
            return invalid("vm_cidr must be a private (RFC 1918) network");
        }
        if vm_net.prefix_len() > 29 {
            return invalid("vm_cidr must be a /29 or larger");
        }
        if !vm_net.contains(&gw) || gw == vm_net.network() || gw == vm_net.broadcast() {
            return invalid("gateway must be a host address inside vm_cidr");
        }
        for other in others {
            if let Some(other_net) = other.vm_cidr {
                if nets_overlap(&vm_net, &other_net) {
                    return conflict(format!(
                        "vm_cidr overlaps pool '{}' vm_cidr {}",
                        other.name, other_net
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn validate_text_fields(a: &Allocation) -> Check {
    let bad = |s: &str| s.chars().any(|c| c.is_control());
    if a.name.trim().is_empty() || a.name.chars().count() > 64 || bad(&a.name) {
        return invalid("name must be 1-64 characters with no control characters");
    }
    if a.customer.chars().count() > 128 || bad(&a.customer) {
        return invalid("customer must be at most 128 characters with no control characters");
    }
    if a.notes.chars().count() > 512 || a.notes.chars().any(|c| c.is_control() && c != '\n') {
        return invalid("notes must be at most 512 characters");
    }
    Ok(())
}

pub fn validate_ports(forward: ForwardMode, ports: &[PortSpec]) -> Check {
    match forward {
        ForwardMode::All => {
            if !ports.is_empty() {
                return invalid("ports must be empty when forward is \"all\"");
            }
            Ok(())
        }
        ForwardMode::Ports => {
            if ports.is_empty() {
                return invalid("forward \"ports\" needs at least one port entry");
            }
            if ports.len() > MAX_PORT_SPECS {
                return invalid(format!("at most {MAX_PORT_SPECS} port entries are allowed"));
            }
            for p in ports {
                if p.port_start == 0 || p.port_end == 0 {
                    return invalid("ports must not be 0");
                }
                if p.port_start > p.port_end {
                    return invalid("port_start must be <= port_end");
                }
            }
            // Overlapping intervals in one nft set are a hard load error, so
            // refuse them here rather than let a sync fail later.
            for (i, a) in ports.iter().enumerate() {
                for b in &ports[i + 1..] {
                    if a.protocol == b.protocol
                        && a.port_start <= b.port_end
                        && b.port_start <= a.port_end
                    {
                        return invalid(format!(
                            "overlapping {:?} port ranges {}-{} and {}-{}",
                            a.protocol, a.port_start, a.port_end, b.port_start, b.port_end
                        ));
                    }
                }
            }
            Ok(())
        }
    }
}

/// Everything an allocation is checked against. `others` excludes the
/// allocation itself (by id) so an update does not collide with its own
/// previous version; `bound_ips` are the IPv4 addresses existing hosts and
/// port rules are explicitly bound to.
pub struct AllocationContext<'a> {
    pub pool: &'a HostingPool,
    pub all_pools: &'a [HostingPool],
    pub others: &'a [Allocation],
    pub dedicated: &'a [IpAddr],
    pub bound_ips: &'a HashSet<Ipv4Addr>,
}

pub fn validate_allocation(a: &Allocation, ctx: &AllocationContext<'_>) -> Check {
    validate_text_fields(a)?;
    validate_ports(a.forward, &a.ports)?;

    if a.pool != ctx.pool.name {
        return invalid("allocation pool does not match the pool it was validated against");
    }
    if !ctx.pool.cidr.contains(&a.public_ip) {
        return invalid(format!(
            "{} is not inside pool '{}' ({})",
            a.public_ip, ctx.pool.name, ctx.pool.cidr
        ));
    }
    if !is_usable(ctx.pool, a.public_ip) {
        return invalid(format!(
            "{} is not allocatable in pool '{}' (network, broadcast or reserved address)",
            a.public_ip, ctx.pool.name
        ));
    }
    if dedicated_v4(ctx.dedicated).contains(&a.public_ip) {
        return invalid(format!(
            "{} is a network.dedicated_ips address and can never be hosted",
            a.public_ip
        ));
    }
    if ctx.bound_ips.contains(&a.public_ip) {
        return conflict(format!(
            "{} is already the bind address of a host or port rule",
            a.public_ip
        ));
    }
    if ctx.others.iter().any(|o| o.public_ip == a.public_ip) {
        return conflict(format!("{} is already allocated", a.public_ip));
    }
    if let Some(vm_ip) = a.vm_ip {
        if !vm_ip.is_private() {
            return invalid("vm_ip must be a private (RFC 1918) address");
        }
        if ctx.all_pools.iter().any(|p| p.cidr.contains(&vm_ip)) {
            return invalid("vm_ip must not be inside a hosting pool");
        }
        if dedicated_v4(ctx.dedicated).contains(&vm_ip) {
            return invalid("vm_ip must not be a network.dedicated_ips address");
        }
        if let Some(vm_net) = ctx.pool.vm_cidr {
            if !vm_net.contains(&vm_ip) {
                return invalid(format!(
                    "vm_ip {vm_ip} is outside pool '{}' vm_cidr {vm_net}",
                    ctx.pool.name
                ));
            }
            if vm_ip == vm_net.network() || vm_ip == vm_net.broadcast() {
                return invalid("vm_ip must be a host address, not the network or broadcast address");
            }
        }
        if ctx.pool.gateway == Some(vm_ip) {
            return invalid("vm_ip must not be the pool gateway");
        }
        if ctx.all_pools.iter().any(|p| p.gateway == Some(vm_ip)) {
            return invalid("vm_ip must not be a pool gateway");
        }
        if ctx.others.iter().any(|o| o.vm_ip == Some(vm_ip)) {
            return conflict(format!("vm_ip {vm_ip} is already used by another allocation"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn pool(name: &str, cidr: &str) -> HostingPool {
        HostingPool {
            name: name.into(),
            cidr: cidr.parse().unwrap(),
            description: String::new(),
            reserved: vec![],
            vm_cidr: None,
            gateway: None,
        }
    }

    pub(crate) fn alloc(pool: &str, public_ip: &str, vm_ip: Option<&str>) -> Allocation {
        Allocation {
            id: Uuid::new_v4(),
            pool: pool.into(),
            public_ip: public_ip.parse().unwrap(),
            name: "vm".into(),
            customer: String::new(),
            notes: String::new(),
            vm_ip: vm_ip.map(|s| s.parse().unwrap()),
            vm_id: None,
            forward: ForwardMode::All,
            ports: vec![],
            enabled: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn next_free_vm_ip_skips_gateway_network_and_used() {
        let mut p = pool("standard", "204.52.221.224/28");
        p.vm_cidr = Some("172.16.63.0/29".parse().unwrap());
        p.gateway = Some("172.16.63.1".parse().unwrap());
        let pools = vec![p.clone()];
        assert_eq!(next_free_vm_ip(&p, &pools, &[]), Some("172.16.63.2".parse().unwrap()));
        let used = vec![alloc("standard", "204.52.221.226", Some("172.16.63.2"))];
        assert_eq!(next_free_vm_ip(&p, &pools, &used), Some("172.16.63.3".parse().unwrap()));
        let all: Vec<Allocation> = (2..=6)
            .map(|i| alloc("standard", &format!("204.52.221.{}", 224 + i), Some(&format!("172.16.63.{i}"))))
            .collect();
        assert_eq!(next_free_vm_ip(&p, &pools, &all), None, "/29 holds .1 gateway + .2-.6");
        p.vm_cidr = None;
        assert_eq!(next_free_vm_ip(&p, &pools, &[]), None);
    }

    fn check(a: &Allocation, p: &HostingPool, others: &[Allocation]) -> Check {
        let pools = vec![p.clone()];
        let bound = HashSet::new();
        validate_allocation(
            a,
            &AllocationContext {
                pool: p,
                all_pools: &pools,
                others,
                dedicated: &[],
                bound_ips: &bound,
            },
        )
    }

    #[test]
    fn slug_rules() {
        assert!(validate_slug("standard").is_ok());
        assert!(validate_slug("ham-2").is_ok());
        for bad in ["", "Standard", "-a", "a-", "a b", "a_b", &"x".repeat(33)] {
            assert!(validate_slug(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn pool_must_be_public_aligned_and_small() {
        let none: Vec<HostingPool> = vec![];
        assert!(validate_pool(&pool("standard", "204.52.221.224/28"), &none, &[]).is_ok());
        assert!(validate_pool(&pool("ham", "44.30.51.224/28"), &none, &[]).is_ok());
        for bad in ["10.0.0.0/28", "192.168.1.0/28", "100.64.0.0/28", "127.0.0.0/28", "224.0.0.0/28"] {
            assert!(
                validate_pool(&pool("p", bad), &none, &[]).is_err(),
                "{bad} should be rejected"
            );
        }
        assert!(validate_pool(&pool("p", "204.52.0.0/16"), &none, &[]).is_err());
        assert!(validate_pool(&pool("p", "204.52.221.225/28"), &none, &[]).is_err());
    }

    #[test]
    fn pools_may_not_overlap() {
        let existing = vec![pool("standard", "204.52.221.224/28")];
        let err = validate_pool(&pool("other", "204.52.221.232/29"), &existing, &[]).unwrap_err();
        assert!(matches!(err, HostingError::Conflict(_)));
        assert!(validate_pool(&pool("other", "204.52.221.240/28"), &existing, &[]).is_ok());
    }

    #[test]
    fn pool_may_not_cover_a_dedicated_ip() {
        let dedicated: Vec<IpAddr> = vec!["204.52.221.250".parse().unwrap()];
        assert!(validate_pool(&pool("p", "204.52.221.240/28"), &[], &dedicated).is_err());
        assert!(validate_pool(&pool("p", "204.52.221.224/28"), &[], &dedicated).is_ok());
    }

    #[test]
    fn vm_network_and_gateway_are_validated_together() {
        let mut p = pool("standard", "204.52.221.224/28");
        p.vm_cidr = Some("172.16.63.0/24".parse().unwrap());
        assert!(validate_pool(&p, &[], &[]).is_err(), "gateway required with vm_cidr");
        p.gateway = Some("172.16.63.1".parse().unwrap());
        assert!(validate_pool(&p, &[], &[]).is_ok());
        p.gateway = Some("172.16.64.1".parse().unwrap());
        assert!(validate_pool(&p, &[], &[]).is_err(), "gateway outside vm_cidr");
        p.gateway = Some("172.16.63.255".parse().unwrap());
        assert!(validate_pool(&p, &[], &[]).is_err(), "gateway is the broadcast address");
        p.gateway = Some("172.16.63.1".parse().unwrap());
        p.vm_cidr = Some("8.8.8.0/24".parse().unwrap());
        assert!(validate_pool(&p, &[], &[]).is_err(), "vm_cidr must be private");
        let mut q = pool("ham", "44.30.51.224/28");
        q.vm_cidr = Some("172.16.63.0/25".parse().unwrap());
        q.gateway = Some("172.16.63.1".parse().unwrap());
        let mut first = pool("standard", "204.52.221.224/28");
        first.vm_cidr = Some("172.16.63.0/24".parse().unwrap());
        first.gateway = Some("172.16.63.1".parse().unwrap());
        assert!(matches!(
            validate_pool(&q, &[first], &[]).unwrap_err(),
            HostingError::Conflict(_)
        ));
    }

    #[test]
    fn usable_addresses_skip_network_broadcast_and_reserved() {
        let mut p = pool("standard", "204.52.221.224/28");
        p.reserved = vec!["204.52.221.225".parse().unwrap()];
        let usable = usable_addresses(&p);
        assert_eq!(usable.len(), 13);
        assert_eq!(usable[0], "204.52.221.226".parse::<Ipv4Addr>().unwrap());
        assert_eq!(*usable.last().unwrap(), "204.52.221.238".parse::<Ipv4Addr>().unwrap());
        assert!(!is_usable(&p, "204.52.221.224".parse().unwrap()));
        assert!(!is_usable(&p, "204.52.221.239".parse().unwrap()));
        assert!(!is_usable(&p, "204.52.221.225".parse().unwrap()));
    }

    #[test]
    fn next_free_ip_picks_the_lowest_unallocated_and_runs_out() {
        let p = pool("tiny", "204.52.221.224/30");
        assert_eq!(next_free_ip(&p, &[]), Some("204.52.221.225".parse().unwrap()));
        let taken = vec![alloc("tiny", "204.52.221.225", None)];
        assert_eq!(next_free_ip(&p, &taken), Some("204.52.221.226".parse().unwrap()));
        let full = vec![
            alloc("tiny", "204.52.221.225", None),
            alloc("tiny", "204.52.221.226", None),
        ];
        assert_eq!(next_free_ip(&p, &full), None);
    }

    #[test]
    fn allocation_public_ip_rules() {
        let p = pool("standard", "204.52.221.224/28");
        assert!(check(&alloc("standard", "204.52.221.226", None), &p, &[]).is_ok());
        assert!(check(&alloc("standard", "204.52.221.224", None), &p, &[]).is_err());
        assert!(check(&alloc("standard", "204.52.221.239", None), &p, &[]).is_err());
        assert!(check(&alloc("standard", "204.52.221.250", None), &p, &[]).is_err());
        let existing = vec![alloc("standard", "204.52.221.226", None)];
        assert!(matches!(
            check(&alloc("standard", "204.52.221.226", None), &p, &existing).unwrap_err(),
            HostingError::Conflict(_)
        ));
    }

    #[test]
    fn allocation_refuses_dedicated_and_bound_addresses() {
        let p = pool("standard", "204.52.221.224/28");
        let pools = vec![p.clone()];
        let dedicated: Vec<IpAddr> = vec!["204.52.221.226".parse().unwrap()];
        let a = alloc("standard", "204.52.221.226", None);
        let bound = HashSet::new();
        let err = validate_allocation(
            &a,
            &AllocationContext { pool: &p, all_pools: &pools, others: &[], dedicated: &dedicated, bound_ips: &bound },
        )
        .unwrap_err();
        assert!(matches!(err, HostingError::Invalid(_)));
        let bound: HashSet<Ipv4Addr> = ["204.52.221.226".parse().unwrap()].into_iter().collect();
        let err = validate_allocation(
            &a,
            &AllocationContext { pool: &p, all_pools: &pools, others: &[], dedicated: &[], bound_ips: &bound },
        )
        .unwrap_err();
        assert!(matches!(err, HostingError::Conflict(_)));
    }

    #[test]
    fn vm_ip_rules() {
        let mut p = pool("standard", "204.52.221.224/28");
        p.vm_cidr = Some("172.16.63.0/24".parse().unwrap());
        p.gateway = Some("172.16.63.1".parse().unwrap());
        assert!(check(&alloc("standard", "204.52.221.226", Some("172.16.63.10")), &p, &[]).is_ok());
        for bad in ["8.8.8.8", "172.16.64.10", "172.16.63.1", "172.16.63.0", "172.16.63.255", "204.52.221.230"] {
            assert!(
                check(&alloc("standard", "204.52.221.226", Some(bad)), &p, &[]).is_err(),
                "vm_ip {bad} should be rejected"
            );
        }
        let existing = vec![alloc("standard", "204.52.221.227", Some("172.16.63.10"))];
        assert!(matches!(
            check(&alloc("standard", "204.52.221.226", Some("172.16.63.10")), &p, &existing).unwrap_err(),
            HostingError::Conflict(_)
        ));
    }

    #[test]
    fn port_forward_rules() {
        let tcp = |s, e| PortSpec { protocol: Protocol::Tcp, port_start: s, port_end: e };
        let udp = |s, e| PortSpec { protocol: Protocol::Udp, port_start: s, port_end: e };
        assert!(validate_ports(ForwardMode::All, &[]).is_ok());
        assert!(validate_ports(ForwardMode::All, &[tcp(22, 22)]).is_err());
        assert!(validate_ports(ForwardMode::Ports, &[]).is_err());
        assert!(validate_ports(ForwardMode::Ports, &[tcp(22, 22), tcp(80, 443), udp(53, 53)]).is_ok());
        assert!(validate_ports(ForwardMode::Ports, &[tcp(0, 10)]).is_err());
        assert!(validate_ports(ForwardMode::Ports, &[tcp(10, 5)]).is_err());
        assert!(validate_ports(ForwardMode::Ports, &[tcp(80, 90), tcp(90, 100)]).is_err());
        assert!(validate_ports(ForwardMode::Ports, &[tcp(53, 53), udp(53, 53)]).is_ok());
        let many: Vec<PortSpec> = (1..=65u16).map(|p| tcp(p * 2, p * 2)).collect();
        assert!(validate_ports(ForwardMode::Ports, &many).is_err());
    }

    #[test]
    fn text_fields_reject_control_characters_and_blank_names() {
        let p = pool("standard", "204.52.221.224/28");
        let mut a = alloc("standard", "204.52.221.226", None);
        a.name = "  ".into();
        assert!(check(&a, &p, &[]).is_err());
        a.name = "web\u{0}01".into();
        assert!(check(&a, &p, &[]).is_err());
        a.name = "web01".into();
        a.customer = "x".repeat(129);
        assert!(check(&a, &p, &[]).is_err());
    }

    #[test]
    fn allocation_state_reflects_vm_and_enabled() {
        let mut a = alloc("standard", "204.52.221.226", None);
        assert_eq!(a.state(), "reserved");
        assert!(!a.is_active());
        a.vm_ip = Some("172.16.63.10".parse().unwrap());
        assert_eq!(a.state(), "active");
        assert!(a.is_active());
        a.enabled = false;
        assert_eq!(a.state(), "disabled");
        assert!(!a.is_active());
    }
}
