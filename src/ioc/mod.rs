//! Atomic IOC detection engine.
//!
//! Supports hash, IP/CIDR, domain, and path-regex matching.

mod alert;
mod hash;
mod load;
mod matchers;
mod types;

pub use hash::{ComputedHashes, HashCache, HashRequirements};
pub use types::{IocKind, IocMatch};

use crate::config::IocConfig;
use crate::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
    ProcessCreationFields,
};
use crate::sensor::Platform;
use std::collections::HashSet;
use tracing::info;

use alert::{build_match, ioc_rule_description, ioc_rule_name};
use hash::normalize_allowlist_path;
use load::{load_domains, load_hashes, load_ips, load_path_regexes, parse_severity};
use types::{DomainIocs, HashIocs, IpIocs, PathIocs};

#[derive(Debug, Clone)]
pub struct IocStats {
    pub md5: usize,
    pub sha1: usize,
    pub sha256: usize,
    pub ip: usize,
    pub cidr: usize,
    pub domain_exact: usize,
    pub domain_suffix: usize,
    pub path_regex: usize,
}

pub struct IocEngine {
    enabled: bool,
    severity: AlertSeverity,
    hash_iocs: HashIocs,
    ip_iocs: IpIocs,
    domain_iocs: DomainIocs,
    path_iocs: PathIocs,
    max_file_size_bytes: u64,
    hash_allowlist_paths: Vec<String>,
}

impl IocEngine {
    pub fn load(cfg: &IocConfig) -> Self {
        if !cfg.enabled {
            return Self::disabled();
        }

        let severity = parse_severity(&cfg.default_severity);

        let hash_iocs = load_hashes(&cfg.hashes_path);
        let ip_iocs = load_ips(&cfg.ips_path);
        let domain_iocs = load_domains(&cfg.domains_path);
        let path_iocs = load_path_regexes(&cfg.paths_regex_path);

        let max_file_size_bytes = cfg.max_file_size_mb * 1024 * 1024;
        let hash_allowlist_paths: Vec<String> = cfg
            .hash_allowlist_paths
            .iter()
            .map(|p| normalize_allowlist_path(p))
            .collect();

        if !hash_allowlist_paths.is_empty() {
            info!(
                target: "ioc",
                count = hash_allowlist_paths.len(),
                "Hash allowlist paths loaded (files under these paths will NOT be hashed)"
            );
        }

        Self {
            enabled: true,
            severity,
            hash_iocs,
            ip_iocs,
            domain_iocs,
            path_iocs,
            max_file_size_bytes,
            hash_allowlist_paths,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            severity: AlertSeverity::Low,
            hash_iocs: HashIocs::default(),
            ip_iocs: IpIocs::default(),
            domain_iocs: DomainIocs::default(),
            path_iocs: PathIocs::default(),
            max_file_size_bytes: 0,
            hash_allowlist_paths: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn stats(&self) -> IocStats {
        IocStats {
            md5: self.hash_iocs.md5.len(),
            sha1: self.hash_iocs.sha1.len(),
            sha256: self.hash_iocs.sha256.len(),
            ip: self.ip_iocs.exact.len(),
            cidr: self.ip_iocs.cidr.len(),
            domain_exact: self.domain_iocs.exact.len(),
            domain_suffix: self.domain_iocs.suffix.len(),
            path_regex: self.path_iocs.patterns.len(),
        }
    }

    pub fn hash_requirements(&self) -> HashRequirements {
        HashRequirements {
            md5: !self.hash_iocs.md5.is_empty(),
            sha1: !self.hash_iocs.sha1.is_empty(),
            sha256: !self.hash_iocs.sha256.is_empty(),
        }
    }

    pub fn wants_hashing(&self) -> bool {
        let req = self.hash_requirements();
        req.md5 || req.sha1 || req.sha256
    }

    pub fn max_file_size_bytes(&self) -> u64 {
        self.max_file_size_bytes
    }

    pub fn is_hash_allowlisted(&self, path: &str) -> bool {
        let normalized = normalize_allowlist_path(path);
        self.hash_allowlist_paths
            .iter()
            .any(|prefix| normalized.starts_with(prefix.as_str()))
    }

    pub fn check_event(&self, event: &NormalizedEvent) -> Vec<IocMatch> {
        if !self.enabled {
            return Vec::new();
        }

        let mut matches = Vec::new();
        let mut seen = HashSet::new();

        self.match_domains(event, &mut matches, &mut seen);
        self.match_ips(event, &mut matches, &mut seen);
        self.match_paths(event, &mut matches, &mut seen);

        matches
    }

    pub fn match_hashes(&self, hashes: &ComputedHashes) -> Vec<IocMatch> {
        if !self.enabled {
            return Vec::new();
        }

        let mut matches = Vec::new();

        if let Some(value) = hashes.md5.as_deref() {
            if let Some(meta) = self.hash_iocs.md5.get(value) {
                matches.push(build_match(IocKind::Md5, value, value, meta));
            }
        }

        if let Some(value) = hashes.sha1.as_deref() {
            if let Some(meta) = self.hash_iocs.sha1.get(value) {
                matches.push(build_match(IocKind::Sha1, value, value, meta));
            }
        }

        if let Some(value) = hashes.sha256.as_deref() {
            if let Some(meta) = self.hash_iocs.sha256.get(value) {
                matches.push(build_match(IocKind::Sha256, value, value, meta));
            }
        }

        matches
    }

    pub fn build_alert_for_match(&self, m: &IocMatch, event: &NormalizedEvent) -> Alert {
        let name = ioc_rule_name(m);
        let ioc_id = format!("ioc::{}::{}", m.kind.as_str(), m.indicator);
        Alert {
            severity: self.severity,
            rule_name: name,
            rule_description: ioc_rule_description(m),
            rule_id: Some(ioc_id),
            engine: DetectionEngine::Ioc,
            event: event.clone(),
            match_details: None,
        }
    }

    pub fn build_alert_for_hash_match(
        &self,
        m: &IocMatch,
        path: &str,
        pid: u32,
        platform: Platform,
        provider: &str,
    ) -> Alert {
        let name = ioc_rule_name(m);
        let ioc_id = format!("ioc::{}::{}", m.kind.as_str(), m.indicator);
        Alert {
            severity: self.severity,
            rule_name: name,
            rule_description: ioc_rule_description(m),
            rule_id: Some(ioc_id),
            engine: DetectionEngine::Ioc,
            event: NormalizedEvent {
                timestamp: crate::utils::now_timestamp_string(),
                platform,
                provider: provider.to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some(path.to_string()),
                    original_file_name: None,
                    product: None,
                    description: None,
                    target_image: None,
                    command_line: None,
                    process_id: Some(pid.to_string()),
                    process_start_time: None,
                    parent_process_id: None,
                    parent_image: None,
                    parent_command_line: None,
                    current_directory: None,
                    integrity_level: None,
                    user: None,
                    logon_id: None,
                    logon_guid: None,
                }),
                process_context: None,
            },
            match_details: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::types::IocMeta;
    use crate::models::{EventCategory, EventFields};
    use crate::sensor::Platform;

    #[test]
    fn test_domain_suffix_match() {
        let mut domains = DomainIocs::default();
        domains.suffix.push((
            "example.com".to_string(),
            IocMeta {
                comment: None,
                source: "test".to_string(),
                line: 1,
            },
        ));

        let engine = IocEngine {
            enabled: true,
            severity: AlertSeverity::High,
            hash_iocs: HashIocs::default(),
            ip_iocs: IpIocs::default(),
            domain_iocs: domains,
            path_iocs: PathIocs::default(),
            max_file_size_bytes: 0,
            hash_allowlist_paths: Vec::new(),
        };

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Dns,
            event_id: 22,
            event_id_string: "22".to_string(),
            opcode: 0,
            fields: EventFields::DnsQuery(crate::models::DnsQueryFields {
                query_name: Some("foo.example.com".to_string()),
                query_results: None,
                record_type: None,
                query_status: None,
                process_id: None,
                image: None,
            }),
            process_context: None,
        };

        let matches = engine.check_event(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, IocKind::Domain);
    }

    #[test]
    fn test_hash_length_detection() {
        let mut hashes = HashIocs::default();
        hashes.md5.insert(
            "0c2674c3a97c53082187d930efb645c2".to_string(),
            IocMeta {
                comment: None,
                source: "test".to_string(),
                line: 1,
            },
        );

        let engine = IocEngine {
            enabled: true,
            severity: AlertSeverity::High,
            hash_iocs: hashes,
            ip_iocs: IpIocs::default(),
            domain_iocs: DomainIocs::default(),
            path_iocs: PathIocs::default(),
            max_file_size_bytes: 0,
            hash_allowlist_paths: Vec::new(),
        };

        let matches = engine.match_hashes(&ComputedHashes {
            md5: Some("0c2674c3a97c53082187d930efb645c2".to_string()),
            sha1: None,
            sha256: None,
        });

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, IocKind::Md5);
    }
}
