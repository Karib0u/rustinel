use super::alert::{build_match, push_match_unique};
use super::types::{IocKind, IocMatch};
use super::IocEngine;
use crate::models::{EventFields, NormalizedEvent};
use std::collections::HashSet;
use std::net::IpAddr;

fn normalize_domain(value: &str) -> Option<String> {
    let mut host = value.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    host = host.trim_end_matches('.').to_string();
    if host.is_empty() {
        return None;
    }
    Some(host)
}

fn extract_ips(value: &str) -> Vec<&str> {
    value
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|token| !token.is_empty())
        .collect()
}

impl IocEngine {
    pub(crate) fn match_domains(
        &self,
        event: &NormalizedEvent,
        matches: &mut Vec<IocMatch>,
        seen: &mut HashSet<String>,
    ) {
        let mut candidates = Vec::new();

        match &event.fields {
            EventFields::DnsQuery(f) => {
                if let Some(v) = &f.query_name {
                    candidates.push(v.as_str());
                }
            }
            EventFields::NetworkConnection(f) => {
                if let Some(v) = &f.destination_hostname {
                    candidates.push(v.as_str());
                }
            }
            EventFields::WmiEvent(f) => {
                if let Some(v) = &f.destination_hostname {
                    candidates.push(v.as_str());
                }
            }
            _ => {}
        }

        for candidate in candidates {
            let normalized = normalize_domain(candidate);
            let Some(host) = normalized else { continue };

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
                    for ip in extract_ips(v) {
                        candidates.push(ip);
                    }
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

        let mut candidates = Vec::new();

        match &event.fields {
            EventFields::ProcessCreation(f) => {
                if let Some(v) = &f.image {
                    candidates.push(v.as_str());
                }
                if let Some(v) = &f.target_image {
                    candidates.push(v.as_str());
                }
            }
            EventFields::FileEvent(f) => {
                if let Some(v) = &f.target_filename {
                    candidates.push(v.as_str());
                }
            }
            EventFields::ImageLoad(f) => {
                if let Some(v) = &f.image_loaded {
                    candidates.push(v.as_str());
                }
            }
            EventFields::PowerShellScript(f) => {
                if let Some(v) = &f.path {
                    candidates.push(v.as_str());
                }
            }
            EventFields::ServiceCreation(f) => {
                if let Some(v) = &f.service_file_name {
                    candidates.push(v.as_str());
                }
            }
            _ => {}
        }

        for candidate in candidates {
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
