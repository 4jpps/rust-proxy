//! Deny lists: `AclKind::IpBlock` entries (CIDRs, single IPs, `AS<n>`)
//! compiled into an in-memory index that the accept loops and the
//! per-host request handler consult. ASN entries are expanded from the
//! prefixes the AS announces (RIPEstat), cached in sqlite and refreshed
//! daily; a failed refresh keeps the last good prefixes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use uuid::Uuid;

use crate::state::AppState;

const REFRESH_AFTER: chrono::Duration = chrono::Duration::hours(24);
const RETRY_AFTER: chrono::Duration = chrono::Duration::minutes(15);
const LOOP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Parses `AS13238`, `as13238` or `ASN13238` into the AS number.
pub fn parse_asn(s: &str) -> Option<u32> {
    let t = s.trim();
    let digits = t
        .strip_prefix("ASN")
        .or_else(|| t.strip_prefix("asn"))
        .or_else(|| t.strip_prefix("AS"))
        .or_else(|| t.strip_prefix("as"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|n| *n != 0)
}

/// Sorted, non-overlapping address ranges for binary-search lookups.
#[derive(Debug, Default, Clone)]
pub struct NetSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl NetSet {
    pub fn from_nets(nets: Vec<IpNet>) -> Self {
        let mut set = NetSet::default();
        for net in IpNet::aggregate(&nets) {
            match net {
                IpNet::V4(n) => set.v4.push((u32::from(n.network()), u32::from(n.broadcast()))),
                IpNet::V6(n) => set.v6.push((u128::from(n.network()), u128::from(n.broadcast()))),
            }
        }
        set.v4.sort_unstable();
        set.v6.sort_unstable();
        set
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                let i = self.v4.partition_point(|r| r.0 <= x);
                i > 0 && self.v4[i - 1].1 >= x
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                let i = self.v6.partition_point(|r| r.0 <= x);
                i > 0 && self.v6[i - 1].1 >= x
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct BlockIndex {
    lists: HashMap<Uuid, NetSet>,
    global: NetSet,
    /// Aggregated prefixes for the firewall layer, which blocks the
    /// non-HTTP paths (passthrough listeners, port rules, hosted VMs).
    list_nets: HashMap<Uuid, Vec<IpNet>>,
    global_nets: Vec<IpNet>,
}

impl BlockIndex {
    #[cfg(test)]
    pub fn global_prefix_count(&self) -> usize {
        self.global.len()
    }

    /// Prefixes every global list blocks, aggregated.
    pub fn global_nets(&self) -> &[IpNet] {
        &self.global_nets
    }

    /// Union of the prefixes in the given lists, aggregated.
    pub fn nets_for(&self, acl_ids: &[Uuid]) -> Vec<IpNet> {
        let all: Vec<IpNet> = acl_ids
            .iter()
            .filter_map(|id| self.list_nets.get(id))
            .flatten()
            .copied()
            .collect();
        IpNet::aggregate(&all)
    }

    /// Whether the firewall-visible data is identical, so a refresh that
    /// changed nothing does not rewrite the ruleset.
    pub fn firewall_equal(&self, other: &BlockIndex) -> bool {
        self.global_nets == other.global_nets && self.list_nets == other.list_nets
    }

    pub fn is_globally_blocked(&self, ip: IpAddr) -> bool {
        self.global.contains(ip)
    }

    /// Whether any block list among `acl_ids` (a host's selected ACLs)
    /// contains `ip`.
    pub fn is_blocked_for(&self, acl_ids: &[Uuid], ip: IpAddr) -> bool {
        acl_ids.iter().any(|id| self.lists.get(id).is_some_and(|s| s.contains(ip)))
    }

    pub fn from_lists(
        lists: Vec<(Uuid, bool, Vec<String>)>,
        asn_prefixes: &HashMap<u32, Vec<String>>,
    ) -> Self {
        let mut index = BlockIndex::default();
        let mut global_nets: Vec<IpNet> = Vec::new();
        for (id, global, entries) in lists {
            let mut nets: Vec<IpNet> = Vec::new();
            for entry in entries {
                if let Some(asn) = parse_asn(&entry) {
                    if let Some(prefixes) = asn_prefixes.get(&asn) {
                        nets.extend(prefixes.iter().filter_map(|p| p.parse::<IpNet>().ok()));
                    }
                } else if let Ok(net) = entry.parse::<IpNet>() {
                    nets.push(net);
                } else if let Ok(addr) = entry.parse::<IpAddr>() {
                    nets.push(IpNet::from(addr));
                }
            }
            if global {
                global_nets.extend(nets.iter().copied());
            }
            index.list_nets.insert(id, IpNet::aggregate(&nets));
            index.lists.insert(id, NetSet::from_nets(nets));
        }
        index.global_nets = IpNet::aggregate(&global_nets);
        index.global = NetSet::from_nets(global_nets);
        index
    }
}

pub async fn build_index(pool: &sqlx::SqlitePool) -> Result<BlockIndex, sqlx::Error> {
    let lists = crate::db::load_block_lists(pool).await?;
    let prefixes = crate::db::load_asn_prefixes(pool).await?;
    Ok(BlockIndex::from_lists(lists, &prefixes))
}

pub async fn rebuild(state: &AppState) {
    match build_index(state.db()).await {
        Ok(index) => {
            let changed = !state.block_index().firewall_equal(&index);
            state.set_block_index(index);
            if changed {
                state.notify_config_change();
            }
        }
        Err(err) => tracing::error!(error = %err, "failed to rebuild the block index"),
    }
}

pub async fn fetch_announced_prefixes(client: &reqwest::Client, asn: u32) -> Result<Vec<String>, String> {
    let url = format!("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}");
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("RIPEstat answered HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let prefixes: Vec<String> = body["data"]["prefixes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p["prefix"].as_str())
                .filter(|p| p.parse::<IpNet>().is_ok())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if prefixes.is_empty() {
        return Err("RIPEstat returned no announced prefixes for this AS".into());
    }
    Ok(prefixes)
}

/// Fetches every referenced AS that has never been fetched or is stale,
/// then rebuilds the index if anything changed.
pub async fn refresh_stale(state: &AppState) {
    let lists = match crate::db::load_block_lists(state.db()).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!(error = %err, "asn refresh: failed to load block lists");
            return;
        }
    };
    let mut wanted: Vec<u32> = lists
        .iter()
        .flat_map(|(_, _, entries)| entries.iter().filter_map(|e| parse_asn(e)))
        .collect();
    wanted.sort_unstable();
    wanted.dedup();
    if wanted.is_empty() {
        return;
    }
    let status: HashMap<u32, crate::db::AsnStatus> = crate::db::load_asn_status(state.db())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| (s.asn, s))
        .collect();
    let now = chrono::Utc::now();
    let parse = |s: &str| chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&chrono::Utc));
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("rust-proxy asn-blocklist")
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(error = %err, "asn refresh: failed to build http client");
            return;
        }
    };
    let mut changed = false;
    for asn in wanted {
        let due = match status.get(&asn) {
            None => true,
            Some(s) => match (&s.fetched_at, &s.error) {
                (Some(f), None) => parse(f).is_none_or(|t| now - t >= REFRESH_AFTER),
                _ => parse(&s.attempted_at).is_none_or(|t| now - t >= RETRY_AFTER),
            },
        };
        if !due {
            continue;
        }
        match fetch_announced_prefixes(&client, asn).await {
            Ok(prefixes) => {
                tracing::info!(asn, prefixes = prefixes.len(), "asn prefixes refreshed");
                match crate::db::store_asn_prefixes(state.db(), asn, &prefixes).await { Err(err) => {
                    tracing::error!(asn, error = %err, "asn refresh: failed to store prefixes");
                } _ => {
                    changed = true;
                }}
            }
            Err(err) => {
                tracing::warn!(asn, error = %err, "asn prefix fetch failed; keeping previous prefixes");
                let _ = crate::db::record_asn_failure(state.db(), asn, &err).await;
            }
        }
    }
    if changed {
        rebuild(state).await;
    }
}

pub async fn run_refresh_loop(state: AppState) {
    loop {
        refresh_stale(&state).await;
        tokio::time::sleep(LOOP_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_asn_spellings() {
        assert_eq!(parse_asn("AS13238"), Some(13238));
        assert_eq!(parse_asn(" as13238 "), Some(13238));
        assert_eq!(parse_asn("ASN13238"), Some(13238));
        assert_eq!(parse_asn("AS"), None);
        assert_eq!(parse_asn("AS0"), None);
        assert_eq!(parse_asn("10.0.0.0/8"), None);
        assert_eq!(parse_asn("AS12x"), None);
    }

    #[test]
    fn netset_matches_v4_v6_and_mapped_addresses() {
        let set = NetSet::from_nets(vec![
            "5.45.192.0/18".parse().unwrap(),
            "203.0.113.7/32".parse().unwrap(),
            "2a02:6b8::/32".parse().unwrap(),
        ]);
        assert!(set.contains(ip("5.45.200.1")));
        assert!(!set.contains(ip("5.45.191.255")));
        assert!(!set.contains(ip("5.46.0.0")));
        assert!(set.contains(ip("203.0.113.7")));
        assert!(!set.contains(ip("203.0.113.8")));
        assert!(set.contains(ip("2a02:6b8:1::1")));
        assert!(!set.contains(ip("2a02:6b9::1")));
        assert!(set.contains(ip("::ffff:5.45.200.1")));
        assert!(!NetSet::default().contains(ip("1.2.3.4")));
    }

    #[test]
    fn overlapping_nets_are_merged() {
        let set = NetSet::from_nets(vec!["10.0.0.0/8".parse().unwrap(), "10.1.0.0/16".parse().unwrap()]);
        assert_eq!(set.len(), 1);
        assert!(set.contains(ip("10.1.2.3")));
    }

    #[test]
    fn index_expands_asns_and_separates_global_from_per_host() {
        let host_list = Uuid::new_v4();
        let global_list = Uuid::new_v4();
        let mut asn = HashMap::new();
        asn.insert(13238, vec!["5.45.192.0/18".to_string(), "bogus".to_string()]);
        let index = BlockIndex::from_lists(
            vec![
                (host_list, false, vec!["AS13238".into()]),
                (global_list, true, vec!["198.51.100.4".into(), "AS99999".into()]),
            ],
            &asn,
        );
        assert!(index.is_blocked_for(&[host_list], ip("5.45.200.1")));
        assert!(!index.is_blocked_for(&[], ip("5.45.200.1")));
        assert!(!index.is_blocked_for(&[global_list], ip("5.45.200.1")));
        assert!(!index.is_globally_blocked(ip("5.45.200.1")), "a per-host list is not global");
        assert!(index.is_globally_blocked(ip("198.51.100.4")));
        assert!(!index.is_globally_blocked(ip("198.51.100.5")));
        assert_eq!(index.global_prefix_count(), 1);
    }
}
