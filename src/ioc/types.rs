use ipnetwork::IpNetwork;
use regex::RegexSet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct IocMatch {
    pub kind: IocKind,
    pub indicator: String,
    pub observed: String,
    pub comment: Option<String>,
    pub source: String,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    Md5,
    Sha1,
    Sha256,
    Ip,
    Domain,
    PathRegex,
}

impl IocKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IocKind::Md5 => "md5",
            IocKind::Sha1 => "sha1",
            IocKind::Sha256 => "sha256",
            IocKind::Ip => "ip",
            IocKind::Domain => "domain",
            IocKind::PathRegex => "path_regex",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct IocMeta {
    pub(crate) comment: Option<Arc<str>>,
    pub(crate) source: Arc<str>,
    pub(crate) line: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct HashIocs {
    pub(crate) md5: HashMap<String, IocMeta>,
    pub(crate) sha1: HashMap<String, IocMeta>,
    pub(crate) sha256: HashMap<String, IocMeta>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct IpIocs {
    pub(crate) exact: HashMap<IpAddr, IocMeta>,
    pub(crate) cidr: CidrIndex,
}

/// CIDR indicators grouped by address family and prefix length.
///
/// Each network bucket stores positions into `entries`. This keeps metadata in
/// one place and lets lookup restore feed order after probing the active prefix
/// lengths for an address.
#[derive(Debug, Clone)]
pub(crate) struct CidrIndex {
    entries: Vec<CidrEntry>,
    v4: [HashMap<Ipv4Addr, Vec<u32>>; 33],
    v6: [HashMap<Ipv6Addr, Vec<u32>>; 129],
    v4_prefixes: Vec<u8>,
    v6_prefixes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CidrEntry {
    network: IpNetwork,
    meta: IocMeta,
}

impl Default for CidrIndex {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            v4: std::array::from_fn(|_| HashMap::new()),
            v6: std::array::from_fn(|_| HashMap::new()),
            v4_prefixes: Vec::new(),
            v6_prefixes: Vec::new(),
        }
    }
}

impl CidrIndex {
    /// Adds one network. Returns `false` if the position cannot fit in the
    /// compact bucket representation.
    pub(crate) fn insert(&mut self, network: IpNetwork, meta: IocMeta) -> bool {
        let Ok(position) = u32::try_from(self.entries.len()) else {
            return false;
        };

        match network {
            IpNetwork::V4(network) => {
                let prefix = network.prefix();
                let bucket = &mut self.v4[prefix as usize];
                if bucket.is_empty() {
                    self.v4_prefixes.push(prefix);
                }
                bucket.entry(network.network()).or_default().push(position);
            }
            IpNetwork::V6(network) => {
                let prefix = network.prefix();
                let bucket = &mut self.v6[prefix as usize];
                if bucket.is_empty() {
                    self.v6_prefixes.push(prefix);
                }
                bucket.entry(network.network()).or_default().push(position);
            }
        }

        self.entries.push(CidrEntry { network, meta });
        true
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns every matching indicator in feed order.
    pub(crate) fn lookup(&self, ip: IpAddr) -> Vec<(&IpNetwork, &IocMeta)> {
        let mut positions = Vec::new();

        match ip {
            IpAddr::V4(ip) => {
                let value = u32::from(ip);
                for &prefix in &self.v4_prefixes {
                    let network = Ipv4Addr::from(value & ipv4_mask(prefix));
                    if let Some(bucket) = self.v4[prefix as usize].get(&network) {
                        positions.extend(bucket.iter().copied());
                    }
                }
            }
            IpAddr::V6(ip) => {
                let value = u128::from(ip);
                for &prefix in &self.v6_prefixes {
                    let network = Ipv6Addr::from(value & ipv6_mask(prefix));
                    if let Some(bucket) = self.v6[prefix as usize].get(&network) {
                        positions.extend(bucket.iter().copied());
                    }
                }
            }
        }

        positions.sort_unstable();
        positions
            .into_iter()
            .map(|position| {
                let entry = &self.entries[position as usize];
                (&entry.network, &entry.meta)
            })
            .collect()
    }
}

fn ipv4_mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0)
}

fn ipv6_mask(prefix: u8) -> u128 {
    u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0)
}

/// Wildcard (`*.example.com` / `.example.com`) domain indicators, indexed by
/// their normalized suffix so a hostname is matched by walking its own DNS
/// label boundaries instead of scanning the whole feed.
///
/// Feeds routinely carry millions of suffixes, so the layout stays flat: every
/// indicator lives in `entries`, and `heads` maps a suffix to the first and
/// last entry of its chain. The same suffix can appear on several feed lines
/// and each line keeps its own metadata, so those lines are chained through
/// `next` in feed order. An entry's position in `entries` is its feed order,
/// which lets a hostname's hits be restored to feed order after lookup.
#[derive(Debug, Clone, Default)]
pub(crate) struct SuffixIndex {
    heads: HashMap<Box<str>, SuffixChainEnds>,
    entries: Vec<SuffixEntry>,
}

#[derive(Debug, Clone, Copy)]
struct SuffixChainEnds {
    first: u32,
    last: u32,
}

#[derive(Debug, Clone)]
struct SuffixEntry {
    meta: IocMeta,
    /// The next feed line carrying this same suffix, if any.
    next: Option<u32>,
}

impl SuffixIndex {
    /// Adds one indicator. Returns `false` when the index is full, which takes
    /// more than four billion suffixes and so never happens in practice.
    pub(crate) fn insert(&mut self, suffix: &str, meta: IocMeta) -> bool {
        let Ok(position) = u32::try_from(self.entries.len()) else {
            return false;
        };

        self.entries.push(SuffixEntry { meta, next: None });

        match self.heads.get_mut(suffix) {
            Some(ends) => {
                self.entries[ends.last as usize].next = Some(position);
                ends.last = position;
            }
            None => {
                self.heads.insert(
                    suffix.into(),
                    SuffixChainEnds {
                        first: position,
                        last: position,
                    },
                );
            }
        }

        true
    }

    /// Number of indicators loaded, counting repeated suffixes separately.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every indicator registered for `suffix`, in feed order, paired with its
    /// feed position.
    pub(crate) fn lookup(&self, suffix: &str) -> SuffixChain<'_> {
        SuffixChain {
            index: self,
            next: self.heads.get(suffix).map(|ends| ends.first),
        }
    }
}

pub(crate) struct SuffixChain<'a> {
    index: &'a SuffixIndex,
    next: Option<u32>,
}

impl<'a> Iterator for SuffixChain<'a> {
    type Item = (u32, &'a IocMeta);

    fn next(&mut self) -> Option<Self::Item> {
        let position = self.next?;
        let entry = &self.index.entries[position as usize];
        self.next = entry.next;
        Some((position, &entry.meta))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DomainIocs {
    pub(crate) exact: HashMap<String, IocMeta>,
    pub(crate) suffix: SuffixIndex,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PathIocs {
    pub(crate) regex_set: Option<RegexSet>,
    pub(crate) patterns: Vec<(String, IocMeta)>,
}
