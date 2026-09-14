use super::alert::{build_match, push_match_unique};
use super::types::{IocKind, IocMatch, IocMeta};
use super::IocEngine;
use crate::observable::Observable;
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;

impl IocEngine {
    /// Match observables against the loaded indicators.
    ///
    /// Matches are reported by indicator kind (domains, IPs, paths, then
    /// hashes) and, within a kind, in observable order, so the same event
    /// always yields the same alert sequence.
    pub(crate) fn match_observables(&self, observables: &[Observable<'_>]) -> Vec<IocMatch> {
        let mut matches = Vec::new();
        let mut seen = HashSet::new();

        for observable in observables {
            if let Observable::Domain(host) = observable {
                self.match_domain(host, &mut matches, &mut seen);
            }
        }
        for observable in observables {
            if let Observable::Ip(ip) = observable {
                self.match_ip(*ip, &mut matches, &mut seen);
            }
        }
        if let Some(regex_set) = &self.path_iocs.regex_set {
            for observable in observables {
                // `matches` allocates a slot per pattern, so a miss, which is
                // nearly every path, is decided by `is_match` alone.
                if let Observable::Path(path) = observable {
                    if !regex_set.is_match(path) {
                        continue;
                    }
                    for idx in regex_set.matches(path).iter() {
                        if let Some((pattern, meta)) = self.path_iocs.patterns.get(idx) {
                            push_match_unique(
                                &mut matches,
                                &mut seen,
                                build_match(IocKind::PathRegex, pattern, path, meta),
                            );
                        }
                    }
                }
            }
        }
        for observable in observables {
            let (kind, value, table) = match observable {
                Observable::Md5(value) => (IocKind::Md5, value, &self.hash_iocs.md5),
                Observable::Sha1(value) => (IocKind::Sha1, value, &self.hash_iocs.sha1),
                Observable::Sha256(value) => (IocKind::Sha256, value, &self.hash_iocs.sha256),
                _ => continue,
            };
            if let Some(meta) = table.get(*value) {
                push_match_unique(
                    &mut matches,
                    &mut seen,
                    build_match(kind, value, value, meta),
                );
            }
        }

        matches
    }

    fn match_domain(&self, host: &str, matches: &mut Vec<IocMatch>, seen: &mut HashSet<String>) {
        if self.domain_iocs.exact.is_empty() && self.domain_iocs.suffix.is_empty() {
            return;
        }
        let host: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };

        if let Some(meta) = self.domain_iocs.exact.get(host.as_ref()) {
            push_match_unique(
                matches,
                seen,
                build_match(IocKind::Domain, &host, &host, meta),
            );
        }

        // Wildcard indicators are indexed by suffix, so only the hostname's own
        // label boundaries are probed: `a.b.example.com` looks up
        // `a.b.example.com`, `b.example.com`, `example.com`, `com`. Work scales
        // with hostname depth instead of feed size, and no temporary string is
        // built for a lookup.
        let mut hits: Vec<(u32, &str, &IocMeta)> = Vec::new();
        let mut offset = 0;
        loop {
            let suffix = &host[offset..];
            hits.extend(
                self.domain_iocs
                    .suffix
                    .lookup(suffix)
                    .map(|(order, meta)| (order, suffix, meta)),
            );
            match suffix.find('.') {
                Some(idx) => offset += idx + 1,
                None => break,
            }
        }

        // Restore feed order, which is what the linear scan produced when a
        // hostname hit several overlapping indicators.
        hits.sort_unstable_by_key(|(order, _, _)| *order);

        for (_, suffix, meta) in hits {
            let indicator = format!(".{}", suffix);
            push_match_unique(
                matches,
                seen,
                build_match(IocKind::Domain, &indicator, &host, meta),
            );
        }
    }

    fn match_ip(&self, ip: IpAddr, matches: &mut Vec<IocMatch>, seen: &mut HashSet<String>) {
        if self.ip_iocs.exact.is_empty() && self.ip_iocs.cidr.is_empty() {
            return;
        }
        let observed = || ip.to_string();

        if let Some(meta) = self.ip_iocs.exact.get(&ip) {
            let observed = observed();
            push_match_unique(
                matches,
                seen,
                build_match(IocKind::Ip, &observed, &observed, meta),
            );
        }

        for (network, meta) in &self.ip_iocs.cidr {
            if network.contains(ip) {
                let indicator = network.to_string();
                push_match_unique(
                    matches,
                    seen,
                    build_match(IocKind::Ip, &indicator, &observed(), meta),
                );
            }
        }
    }
}
