use super::alert::{build_match, push_match_unique};
use super::types::{IocKind, IocMatch};
use super::IocEngine;
use crate::models::{EventFields, NormalizedEvent};
use std::collections::HashSet;
use std::net::IpAddr;

fn normalize_domain(value: &str) -> Option<String> {
    let host = value.trim().trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

impl IocEngine {
    pub(crate) fn match_domains(
        &self,
        event: &NormalizedEvent,
        matches: &mut Vec<IocMatch>,
        seen: &mut HashSet<String>,
    ) {
        let candidate = match &event.fields {
            EventFields::DnsQuery(f) => f.query_name.as_deref(),
            EventFields::NetworkConnection(f) => f.destination_hostname.as_deref(),
            EventFields::WmiEvent(f) => f.destination_hostname.as_deref(),
            _ => None,
        };
        let Some(host) = candidate.and_then(normalize_domain) else {
            return;
        };

        if let Some(meta) = self.domain_iocs.exact.get(&host) {
            push_match_unique(
                matches,
                seen,
                build_match(IocKind::Domain, &host, &host, meta),
            );
        }

        for (suffix, meta) in &self.domain_iocs.suffix {
            if host == *suffix || host.ends_with(&format!(".{}", suffix)) {
                let indicator = format!(".{}", suffix);
                push_match_unique(
                    matches,
                    seen,
                    build_match(IocKind::Domain, &indicator, &host, meta),
                );
            }
        }
    }

    pub(crate) fn match_ips(
        &self,
        event: &NormalizedEvent,
        matches: &mut Vec<IocMatch>,
        seen: &mut HashSet<String>,
    ) {
        let mut candidates = Vec::new();

        match &event.fields {
            EventFields::NetworkConnection(f) => {
                if let Some(v) = &f.destination_ip {
                    candidates.push(v.as_str());
                }
                if let Some(v) = &f.source_ip {
                    candidates.push(v.as_str());
                }
            }
            EventFields::DnsQuery(f) => {
                if let Some(v) = &f.query_results {
                    candidates.extend(
                        v.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                            .filter(|token| !token.is_empty()),
                    );
                }
            }
            _ => {}
        }

        for candidate in candidates {
            if let Ok(ip) = candidate.parse::<IpAddr>() {
                if let Some(meta) = self.ip_iocs.exact.get(&ip) {
                    let indicator = ip.to_string();
                    push_match_unique(
                        matches,
                        seen,
                        build_match(IocKind::Ip, &indicator, candidate, meta),
                    );
                }

                for (network, meta) in &self.ip_iocs.cidr {
                    if network.contains(ip) {
                        let indicator = network.to_string();
                        push_match_unique(
                            matches,
                            seen,
                            build_match(IocKind::Ip, &indicator, candidate, meta),
                        );
                    }
                }
            }
        }
    }

    pub(crate) fn match_paths(
        &self,
        event: &NormalizedEvent,
        matches: &mut Vec<IocMatch>,
        seen: &mut HashSet<String>,
    ) {
        let Some(regex_set) = &self.path_iocs.regex_set else {
            tracing::trace!(target: "ioc", "match_paths: regex_set is None, skipping");
            return;
        };

        let candidates = match &event.fields {
            EventFields::ProcessCreation(f) => [f.image.as_deref(), f.target_image.as_deref()],
            EventFields::FileEvent(f) => [f.target_filename.as_deref(), None],
            EventFields::ImageLoad(f) => [f.image_loaded.as_deref(), None],
            EventFields::PowerShellScript(f) => [f.path.as_deref(), None],
            EventFields::ServiceCreation(f) => [f.service_file_name.as_deref(), None],
            _ => [None, None],
        };

        for candidate in candidates.into_iter().flatten() {
            tracing::trace!(
                target: "ioc",
                candidate = %candidate,
                patterns = self.path_iocs.patterns.len(),
                "match_paths: testing candidate against regex set"
            );
            for idx in regex_set.matches(candidate).iter() {
                if let Some((pattern, meta)) = self.path_iocs.patterns.get(idx) {
                    push_match_unique(
                        matches,
                        seen,
                        build_match(IocKind::PathRegex, pattern, candidate, meta),
                    );
                }
            }
        }
    }
}
