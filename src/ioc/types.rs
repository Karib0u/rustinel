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

#[derive(Debug, Clone, Default)]
pub(crate) struct DomainIocs {
    pub(crate) exact: HashMap<String, IocMeta>,
    pub(crate) suffix: Vec<(String, IocMeta)>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PathIocs {
    pub(crate) regex_set: Option<RegexSet>,
    pub(crate) patterns: Vec<(String, IocMeta)>,
}
