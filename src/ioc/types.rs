use ipnetwork::IpNetwork;
use regex::RegexSet;
use std::collections::HashMap;
use std::net::IpAddr;

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
    pub(crate) comment: Option<String>,
    pub(crate) source: String,
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
    pub(crate) cidr: Vec<(IpNetwork, IocMeta)>,
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
