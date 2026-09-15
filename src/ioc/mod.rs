//! Atomic IOC detection engine.
//!
//! Supports hash, IP/CIDR, domain, and path-regex matching.

mod alert;
mod hash;
mod load;
mod matchers;
mod types;

pub(crate) use hash::compute_hashes_from_bytes;
pub use hash::{ComputedHashes, HashCache, HashRequirements};
pub use types::{IocKind, IocMatch};

use crate::config::IocConfig;
use crate::models::{
    Alert, AlertSeverity, CanonicalEvent, DetectionEngine, EventCategory, EventFields,
    NormalizedEvent, ProcessCreationFields, Provenance,
};
use crate::sensor::Platform;
use tracing::info;

use crate::utils::path_allowlist::PathAllowlistPolicy;
use alert::{ioc_rule_description, ioc_rule_name};
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
        let hash_allowlist_paths =
            PathAllowlistPolicy::IocPrefix.normalize_prefixes(&cfg.hash_allowlist_paths);

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
        PathAllowlistPolicy::IocPrefix.is_match(path, &self.hash_allowlist_paths)
    }

    pub fn check_event(&self, event: &CanonicalEvent) -> Vec<IocMatch> {
        // Hash indicators are matched from file contents, not event fields, so
        // a hash-only feed has no reason to walk the event at all.
        if !self.enabled || !self.has_event_indicators() {
            return Vec::new();
        }

        self.match_observables(&event.observables())
    }

    fn has_event_indicators(&self) -> bool {
        !self.domain_iocs.exact.is_empty()
            || !self.domain_iocs.suffix.is_empty()
            || !self.ip_iocs.exact.is_empty()
            || !self.ip_iocs.cidr.is_empty()
            || self.path_iocs.regex_set.is_some()
    }

    pub fn match_hashes(&self, hashes: &ComputedHashes) -> Vec<IocMatch> {
        if !self.enabled {
            return Vec::new();
        }

        self.match_observables(&crate::observable::hashes(
            hashes.md5.as_deref(),
            hashes.sha1.as_deref(),
            hashes.sha256.as_deref(),
        ))
    }

    pub fn build_alert_for_match(&self, m: &IocMatch, event: &CanonicalEvent) -> Alert {
        let name = ioc_rule_name(m);
        let ioc_id = format!("ioc::{}::{}", m.kind.as_str(), m.indicator);
        Alert {
            severity: self.severity,
            rule_name: name,
            rule_description: ioc_rule_description(m),
            rule_id: Some(ioc_id),
            sigma_metadata: None,
            engine: DetectionEngine::Ioc,
            event: event.normalized().clone(),
            match_details: None,
        }
    }

    pub fn build_alert_for_hash_match(
        &self,
        m: &IocMatch,
        path: &str,
        pid: u32,
        provenance: &Provenance,
        platform: Platform,
        provider: &str,
    ) -> Alert {
        let name = ioc_rule_name(m);
        let ioc_id = format!("ioc::{}::{}", m.kind.as_str(), m.indicator);
        let mut alert = Alert {
            severity: self.severity,
            rule_name: name,
            rule_description: ioc_rule_description(m),
            rule_id: Some(ioc_id),
            sigma_metadata: None,
            engine: DetectionEngine::Ioc,
            event: NormalizedEvent {
                timestamp: crate::utils::now_timestamp_string(),
                source_seq: None,
                ingest_seq: 0,
                platform,
                provider: provider.to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    hashes: None,
                    imphash: None,
                    linux_identity: Default::default(),
                    cgroup_id: None,
                    exec: Default::default(),
                    parent_process_id_derived: false,
                    windows: Default::default(),
                    image: Some(path.to_string()),
                    image_source: None,
                    image_truncated: None,
                    original_file_name: None,
                    product: None,
                    description: None,
                    company: None,
                    file_version: None,
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
                }),
                process_name: None,
                provenance: Default::default(),
                process_context: None,
            },
            match_details: None,
        };
        alert.event.inherit_populated_provenance(provenance);
        alert
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
        domains.suffix.insert(
            "example.com",
            IocMeta {
                comment: None,
                source: "test".into(),
                line: 1,
            },
        );

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

        let event = CanonicalEvent::from_normalized(NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            source_seq: None,
            ingest_seq: 0,
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Dns,
            event_id: 22,
            event_id_string: "22".to_string(),
            opcode: 0,
            fields: EventFields::DnsQuery(crate::models::DnsQueryFields {
                user: None,
                query_name: Some("foo.example.com".to_string()),
                query_results: None,
                record_type: None,
                query_status: None,
                process_id: None,
                image: None,
            }),
            process_name: None,
            provenance: Default::default(),
            process_context: None,
        });

        let matches = engine.check_event(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, IocKind::Domain);
    }

    fn suffix_engine(suffixes: &[(&str, usize)]) -> IocEngine {
        let mut domains = DomainIocs::default();
        for (suffix, line) in suffixes {
            domains.suffix.insert(
                suffix,
                IocMeta {
                    comment: None,
                    source: "test".into(),
                    line: *line,
                },
            );
        }

        IocEngine {
            enabled: true,
            severity: AlertSeverity::High,
            hash_iocs: HashIocs::default(),
            ip_iocs: IpIocs::default(),
            domain_iocs: domains,
            path_iocs: PathIocs::default(),
            max_file_size_bytes: 0,
            hash_allowlist_paths: Vec::new(),
        }
    }

    fn dns_event(query_name: &str) -> CanonicalEvent {
        CanonicalEvent::from_normalized(NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            source_seq: None,
            ingest_seq: 0,
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Dns,
            event_id: 22,
            event_id_string: "22".to_string(),
            opcode: 0,
            fields: EventFields::DnsQuery(crate::models::DnsQueryFields {
                user: None,
                query_name: Some(query_name.to_string()),
                query_results: None,
                record_type: None,
                query_status: None,
                process_id: None,
                image: None,
            }),
            process_name: None,
            provenance: Default::default(),
            process_context: None,
        })
    }

    #[test]
    fn test_domain_suffix_matches_the_suffix_itself() {
        let engine = suffix_engine(&[("example.com", 1)]);
        let matches = engine.check_event(&dns_event("example.com"));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator, ".example.com");
        assert_eq!(matches[0].observed, "example.com");
    }

    #[test]
    fn test_domain_suffix_requires_a_label_boundary() {
        let engine = suffix_engine(&[("example.com", 1)]);
        assert!(engine.check_event(&dns_event("notexample.com")).is_empty());
        assert!(engine
            .check_event(&dns_event("example.com.evil"))
            .is_empty());
    }

    #[test]
    fn test_overlapping_domain_suffixes_report_in_feed_order() {
        // `com` is loaded after `example.com`, so it is reported second, as the
        // linear scan over the feed used to do.
        let engine = suffix_engine(&[("example.com", 7), ("com", 9)]);
        let matches = engine.check_event(&dns_event("a.b.example.com"));
        let indicators: Vec<&str> = matches.iter().map(|m| m.indicator.as_str()).collect();
        assert_eq!(indicators, vec![".example.com", ".com"]);
    }

    #[test]
    fn test_duplicate_domain_suffix_lines_each_report() {
        // The same suffix on two feed lines stays two matches: they differ by
        // the reported source line, as before the suffix index.
        let engine = suffix_engine(&[("example.com", 3), ("example.com", 12)]);
        let matches = engine.check_event(&dns_event("host.example.com"));
        let lines: Vec<usize> = matches.iter().map(|m| m.line).collect();
        assert_eq!(lines, vec![3, 12]);
    }

    #[test]
    fn test_domain_suffix_stats_count_every_line() {
        let engine = suffix_engine(&[("example.com", 1), ("example.com", 2), ("evil.test", 3)]);
        assert_eq!(engine.stats().domain_suffix, 3);
    }

    #[test]
    fn test_hash_length_detection() {
        let mut hashes = HashIocs::default();
        hashes.md5.insert(
            "0c2674c3a97c53082187d930efb645c2".to_string(),
            IocMeta {
                comment: None,
                source: "test".into(),
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
