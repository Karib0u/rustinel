//! Sigma detection engine module
//!
//! Rustinel evaluates Sigma with the RSigma library: `rsigma-parser` for rule
//! parsing and `rsigma-eval` for matching. Rustinel keeps ownership of the
//! surrounding machinery — event normalization, logsource classification and
//! routing, ECS alerts, hot reload, and the IOC/YARA detectors — and hands
//! RSigma only the detection logic.
//!
//! The module is laid out as:
//!
//! - `logsource` — logsource normalization, platform filtering, and the
//!   event → candidate-logsource routing both loading and matching share.
//! - `loader` — the rules-directory walk and collection load.
//! - `store` — one synchronized `rsigma_eval::CorrelationEngine` and the
//!   descriptions and counts Rustinel keeps beside it.
//! - `alert` — mapping RSigma evaluation results onto Rustinel's [`Alert`].

mod alert;
mod detect;
mod detectors;
mod event;
mod handler;
mod loader;
mod logsource;
mod stats;
mod store;

pub use detect::EventDetectors;
pub use detectors::DetectorStore;
pub use handler::{DetectionPipeline, NormalizedEventHandler};
pub(crate) use logsource::{current_platform, RuleLoadDecision};
pub use logsource::{LogSource, LogSourceClassification, LogSourceKey, LogSourceStatus};
pub use stats::{EngineStats, UnsupportedRule, UnsupportedRuleKind};

use rsigma_eval::EvaluationResult;
use std::collections::{HashMap, HashSet};

use crate::models::{Alert, AlertSeverity, MatchDebugLevel, NormalizedEvent};
use crate::sensor::Platform;

/// Ranking key for the default one-Sigma-alert-per-event policy.
///
/// Several rules can match the same event, and Rustinel emits a single Sigma
/// alert, so the engine needs a total order over matches. The policy is:
///
/// 1. Highest normalized severity (`critical > high > medium > low`).
/// 2. On equal severity, rules carrying an `id` win over rules without one.
/// 3. Then the lexicographically smallest rule id, and finally the smallest
///    rule title, both compared as byte order.
///
/// The tie-breaker deliberately never consults rule load order or directory
/// traversal order, so the emitted alert is identical no matter how the
/// ruleset was loaded. The best match is the *smallest* `MatchRank`; a fully
/// equal rank keeps the first candidate seen.
///
/// Correlation results are appended after this single detection result.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MatchRank<'a> {
    /// Reversed so that a higher severity yields a smaller rank.
    severity: std::cmp::Reverse<AlertSeverity>,
    /// `0` for rules with an id, `1` for rules without, then the id itself.
    rule_id: (u8, &'a str),
    rule_title: &'a str,
}

impl<'a> MatchRank<'a> {
    pub(crate) fn new(
        severity: AlertSeverity,
        rule_id: Option<&'a str>,
        rule_title: &'a str,
    ) -> Self {
        Self {
            severity: std::cmp::Reverse(severity),
            rule_id: match rule_id {
                Some(id) => (0, id),
                None => (1, ""),
            },
            rule_title,
        }
    }
}

pub struct Engine {
    /// Platform whose Sigma logsource rules should be accepted.
    platform: Platform,

    /// One synchronized RSigma detection and correlation engine.
    store: store::RuleStore,

    /// Total number of loaded rules
    rule_count: usize,

    /// Total number of rule files found
    rule_files_found: usize,

    /// Failed rule paths and error messages (for diagnostics)
    failed_rules: Vec<(String, String)>,

    /// Parsed documents dropped because their rule references do not resolve.
    unsupported_rules: Vec<UnsupportedRule>,

    /// Rules skipped at load time due to unsupported logsource product.
    skipped_product_rules: usize,

    /// Rules skipped at load time because the logsource family is explicitly deferred.
    skipped_deferred_rules: usize,

    /// Rules skipped at load time because the logsource shape is unknown.
    skipped_unknown_logsource_rules: usize,

    /// Rules that loaded successfully but do not currently have an active collector.
    inactive_collector_rules: usize,

    /// Deferred logsource counts by normalized tuple.
    deferred_logsource_counts: HashMap<LogSourceKey, usize>,

    /// Unknown logsource counts by normalized tuple.
    unknown_logsource_counts: HashMap<LogSourceKey, usize>,

    /// Controls whether match debug details are attached to alerts.
    match_debug: MatchDebugLevel,
}

impl Engine {
    /// Creates a new engine instance
    pub fn new() -> Self {
        Self::new_for_platform(current_platform())
    }

    /// Creates a new engine instance for an explicit sensor platform.
    pub fn new_for_platform(platform: Platform) -> Self {
        Self::new_inner(platform, MatchDebugLevel::Off)
    }

    /// Creates a new engine instance for the current platform with an explicit
    /// match-debug verbosity. Used by the hot-reload worker.
    pub fn new_with_match_debug(match_debug: MatchDebugLevel) -> Self {
        Self::new_inner(current_platform(), match_debug)
    }

    /// Creates a new engine instance for an explicit platform and match-debug
    /// setting. Used at runtime startup and by `rustinel replay`.
    pub fn new_for_platform_with_match_debug(
        platform: Platform,
        match_debug: MatchDebugLevel,
    ) -> Self {
        Self::new_inner(platform, match_debug)
    }

    fn new_inner(platform: Platform, match_debug: MatchDebugLevel) -> Self {
        Self {
            platform,
            store: store::RuleStore::new(match_debug),
            rule_count: 0,
            rule_files_found: 0,
            failed_rules: Vec::new(),
            unsupported_rules: Vec::new(),
            skipped_product_rules: 0,
            skipped_deferred_rules: 0,
            skipped_unknown_logsource_rules: 0,
            inactive_collector_rules: 0,
            deferred_logsource_counts: HashMap::new(),
            unknown_logsource_counts: HashMap::new(),
            match_debug,
        }
    }

    /// Evaluate an event against the loaded rules.
    ///
    /// The result contains at most one detection alert, selected by
    /// `MatchRank`, followed by every correlation alert that fired while the
    /// event was processed. Detection results are deduplicated before they
    /// reach the stateful correlation engine because a partial logsource can
    /// match through more than one concrete event alias.
    pub fn evaluate_event(&self, event: &NormalizedEvent) -> Vec<Alert> {
        let results = {
            let mut engine = self.store.lock();
            let adapter = event::RsigmaEvent::new(event);
            let mut detections = Vec::new();
            let mut seen = HashSet::new();

            for alias in Self::concrete_logsource_aliases_for_event(event) {
                let logsource = rsigma_parser::LogSource {
                    product: alias.product,
                    service: alias.service,
                    category: alias.category,
                    ..Default::default()
                };

                for result in engine
                    .engine()
                    .evaluate_with_logsource(&adapter, &logsource)
                    .into_iter()
                    .filter(EvaluationResult::is_detection)
                {
                    let identity = (
                        result.header.rule_id.clone(),
                        result.header.rule_title.clone(),
                    );
                    if seen.insert(identity) {
                        detections.push(result);
                    }
                }
            }

            engine.correlate_detections(&adapter, detections)
        };

        let mut best: Option<EvaluationResult> = None;
        let mut correlations = Vec::new();
        for mut result in results {
            self.store.restore_synthetic_detection_id(&mut result);
            if result.is_detection() {
                let is_better = match &best {
                    Some(current) => alert::result_rank(&result) < alert::result_rank(current),
                    None => true,
                };
                if is_better {
                    best = Some(result);
                }
            } else if result.is_correlation() {
                correlations.push(result);
            }
        }

        let mut alerts = Vec::with_capacity(usize::from(best.is_some()) + correlations.len());
        if let Some(result) = best {
            alerts.push(self.build_alert(result, event));
        }
        alerts.extend(
            correlations
                .into_iter()
                .map(|result| self.build_alert(result, event)),
        );
        alerts
    }

    /// Compatibility alias for callers that used the pre-correlation name.
    pub fn check_event(&self, event: &NormalizedEvent) -> Vec<Alert> {
        self.evaluate_event(event)
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventFields, ProcessCreationFields};

    fn windows_engine() -> Engine {
        Engine::new_for_platform(Platform::Windows)
    }

    fn linux_engine() -> Engine {
        Engine::new_for_platform(Platform::Linux)
    }

    fn macos_engine() -> Engine {
        Engine::new_for_platform(Platform::MacOS)
    }

    fn logsource(
        product: Option<&str>,
        service: Option<&str>,
        category: Option<&str>,
    ) -> LogSource {
        LogSource {
            product: product.map(ToString::to_string),
            service: service.map(ToString::to_string),
            category: category.map(ToString::to_string),
        }
    }

    /// Load one rule from a temporary file, exercising the real loader.
    fn engine_with_rule(platform: Platform, rule_yaml: &str) -> Engine {
        let dir = tempfile::tempdir().expect("temporary rule directory");
        std::fs::write(dir.path().join("rule.yml"), rule_yaml).expect("write rule");
        let mut engine = Engine::new_for_platform(platform);
        engine.load_rules(dir.path()).expect("rules should load");
        assert_eq!(
            engine.stats().failed_rules,
            Vec::<(String, String)>::new(),
            "the fixture rule should load cleanly"
        );
        engine
    }

    #[test]
    fn new_engine_has_no_rules() {
        let engine = Engine::new();
        assert_eq!(engine.rule_count, 0);
        assert_eq!(engine.stats().total_rules, 0);
    }

    #[test]
    fn check_event_without_rules_does_not_alert() {
        let engine = Engine::new_for_platform(Platform::Windows);
        let event = process_event(
            Platform::Windows,
            r"C:\Windows\System32\whoami.exe",
            "whoami",
        );

        assert!(engine.check_event(&event).is_empty());
    }

    #[test]
    fn non_matching_product_is_classified_as_a_mismatch() {
        let source = logsource(Some("linux"), None, Some("process_creation"));

        assert_eq!(
            windows_engine().classify_logsource(&source).status,
            LogSourceStatus::ProductMismatch
        );
        assert_eq!(
            linux_engine().classify_logsource(&source).status,
            LogSourceStatus::Supported
        );
    }

    #[test]
    fn unrecognized_service_is_classified_as_unknown() {
        let source = logsource(
            Some("windows"),
            Some("cloudtrail"),
            Some("process_creation"),
        );

        assert_eq!(
            windows_engine().classify_logsource(&source).status,
            LogSourceStatus::Unknown
        );
        assert_eq!(
            linux_engine().classify_logsource(&source).status,
            LogSourceStatus::ProductMismatch
        );
    }

    #[test]
    fn unsupported_category_is_classified_as_unknown() {
        let source = logsource(Some("windows"), None, Some("process_tampering"));

        assert_eq!(
            windows_engine().classify_logsource(&source).status,
            LogSourceStatus::Unknown
        );
    }

    #[test]
    fn service_only_logsource_loads_without_a_category() {
        let classification =
            linux_engine().classify_logsource(&logsource(Some("linux"), Some("sysmon"), None));

        assert_eq!(classification.status, LogSourceStatus::Supported);
        assert_eq!(classification.collector_active, Some(true));
    }

    #[test]
    fn file_change_has_no_backing_collector_off_windows() {
        // Sysmon Event ID 2 is a metadata change; neither the eBPF nor the ESF
        // sensor emits it, so its rules load but are reported as unbacked
        // rather than counted as covered (issue #293).
        let source = logsource(None, Some("sysmon"), Some("file_change"));

        for engine in [linux_engine(), macos_engine()] {
            let classification = engine.classify_logsource(&source);
            assert_eq!(classification.status, LogSourceStatus::Supported);
            assert_eq!(classification.collector_active, Some(false));
        }

        let windows = windows_engine().classify_logsource(&source);
        assert_eq!(windows.status, LogSourceStatus::Supported);
        assert_eq!(windows.collector_active, Some(true));
    }

    #[test]
    fn platform_qualified_file_change_has_no_backing_collector_off_windows() {
        for (engine, product) in [(linux_engine(), "linux"), (macos_engine(), "macos")] {
            let classification = engine.classify_logsource(&logsource(
                Some(product),
                Some("sysmon"),
                Some("file_change"),
            ));

            assert_eq!(classification.status, LogSourceStatus::Supported);
            assert_eq!(classification.collector_active, Some(false));
        }
    }

    #[test]
    fn sibling_file_categories_stay_active_off_windows() {
        // Only `file_change` loses its collector: the rest of the file family
        // is still emitted by both sensors.
        for (engine, product) in [(linux_engine(), "linux"), (macos_engine(), "macos")] {
            for category in ["file_event", "file_create", "file_delete", "file_rename"] {
                let classification = engine.classify_logsource(&logsource(
                    Some(product),
                    Some("sysmon"),
                    Some(category),
                ));

                assert_eq!(
                    classification.collector_active,
                    Some(true),
                    "{product}/{category} should stay backed by a collector"
                );
            }
        }
    }

    #[test]
    fn linux_file_change_rule_is_counted_as_inactive() {
        let engine = engine_with_rule(
            Platform::Linux,
            r#"title: Linux Timestomp
logsource:
  product: linux
  service: sysmon
  category: file_change
detection:
  selection:
    TargetFilename|endswith: ".sh"
  condition: selection
level: medium
"#,
        );

        let stats = engine.stats();
        assert_eq!(stats.total_rules, 1, "the rule still loads");
        assert_eq!(stats.inactive_collector_rules, 1);
    }

    #[test]
    fn deferred_linux_logsource_is_reported() {
        let classification = linux_engine().classify_logsource(&logsource(
            Some("linux"),
            Some("auditd"),
            Some("process_creation"),
        ));

        assert_eq!(classification.status, LogSourceStatus::Deferred);
        assert_eq!(classification.collector_active, None);
    }

    #[test]
    fn linux_sysmon_process_rule_matches_a_process_event() {
        let engine = engine_with_rule(
            Platform::Linux,
            r#"title: Linux Sysmon Process
logsource:
  product: linux
  service: sysmon
  category: process_creation
detection:
  selection:
    Image|endswith: bash
  condition: selection
"#,
        );
        let event = process_event(Platform::Linux, "/usr/bin/bash", "/usr/bin/bash -c id");

        assert!(!engine.check_event(&event).is_empty());
    }

    #[test]
    fn generic_network_rule_matches_a_linux_network_event() {
        let engine = engine_with_rule(
            Platform::Linux,
            r#"title: Generic Network Connection
logsource:
  category: network
  service: connection
detection:
  selection:
    DestinationPort: "443"
  condition: selection
"#,
        );

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "ebpf".to_string(),
            category: crate::models::EventCategory::Network,
            event_id: 3,
            event_id_string: "3".to_string(),
            opcode: 12,
            fields: EventFields::NetworkConnection(crate::models::NetworkConnectionFields {
                destination_ip: Some("198.51.100.10".to_string()),
                source_ip: Some("10.0.0.5".to_string()),
                destination_port: Some("443".to_string()),
                source_port: Some("51234".to_string()),
                process_id: Some("99".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                user: Some("alice".to_string()),
                destination_hostname: None,
                protocol: Some("tcp".to_string()),
                initiated: Some(true),
            }),
            process_context: None,
        };

        assert!(!engine.check_event(&event).is_empty());
    }

    #[test]
    fn file_rename_rule_matches_source_and_target_fields() {
        let engine = engine_with_rule(
            Platform::Linux,
            r#"title: Linux File Rename
logsource:
  product: linux
  category: file_rename
detection:
  selection:
    SourceFilename|endswith: "/old.txt"
    TargetFilename|endswith: "/new.txt"
  condition: selection
"#,
        );

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "ebpf".to_string(),
            category: crate::models::EventCategory::File,
            event_id: 71,
            event_id_string: "71".to_string(),
            opcode: 71,
            fields: EventFields::FileEvent(crate::models::FileEventFields {
                source_filename: Some("/tmp/old.txt".to_string()),
                target_filename: Some("/tmp/new.txt".to_string()),
                process_id: Some("101".to_string()),
                image: Some("/usr/bin/mv".to_string()),
                creation_utc_time: None,
                previous_creation_utc_time: None,
                user: Some("alice".to_string()),
                path_truncated: None,
            }),
            process_context: None,
        };

        assert!(!engine.check_event(&event).is_empty());
    }

    #[test]
    fn generic_dns_rule_matches_via_alias_fields() {
        let engine = engine_with_rule(
            Platform::Linux,
            r#"title: Generic DNS Query
logsource:
  category: dns
detection:
  selection:
    query: "example.com"
    record_type: "A"
  condition: selection
"#,
        );

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "ebpf".to_string(),
            category: crate::models::EventCategory::Dns,
            event_id: 22,
            event_id_string: "22".to_string(),
            opcode: 0,
            fields: EventFields::DnsQuery(crate::models::DnsQueryFields {
                query_name: Some("example.com".to_string()),
                query_results: Some("1.1.1.1".to_string()),
                record_type: Some("A".to_string()),
                query_status: None,
                process_id: Some("202".to_string()),
                image: Some("/usr/bin/dig".to_string()),
            }),
            process_context: None,
        };

        assert!(!engine.check_event(&event).is_empty());
    }

    #[test]
    fn product_mismatched_rules_are_skipped_at_load_time() {
        let engine = engine_with_rule(
            Platform::Windows,
            r#"title: Linux Only
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: bash
  condition: selection
"#,
        );

        let stats = engine.stats();
        assert_eq!(stats.total_rules, 0);
        assert_eq!(stats.skipped_product_rules, 1);
    }

    fn process_event(platform: Platform, image: &str, command_line: &str) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform,
            provider: "test".to_string(),
            category: crate::models::EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(image.to_string()),
                image_source: None,
                command_line: Some(command_line.to_string()),
                process_id: Some("1234".to_string()),
                process_start_time: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some("TestUser".to_string()),
            }),
            process_context: None,
        }
    }
}
