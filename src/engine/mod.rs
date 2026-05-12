//! Sigma detection engine module
//!
//! Integrates Sigma rule engine and handles rule loading.
//! Checks normalized events against Sigma rules filtered by logsource.

mod alert;
mod condition;
mod handler;
mod loader;
mod logsource;
mod matcher;
mod rule;
mod stats;

pub(crate) use condition::RuleLogicErrorLogLevel;
pub use handler::SigmaDetectionHandler;
pub(crate) use logsource::{current_platform, platform_product, RuleLoadDecision};
pub use logsource::{LogSource, LogSourceClassification, LogSourceKey, LogSourceStatus};
pub(crate) use matcher::{FieldPattern, NumericOp, PatternMatcher};
pub(crate) use rule::CompiledRule;
pub use rule::{Detection, FieldCriterion, Selection, SigmaRule};
pub use stats::EngineStats;

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use evalexpr::*;
use ipnetwork::IpNetwork;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::LazyLock;
use tracing::{debug, info, warn};

use crate::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, MatchDebugLevel, MatchDetails,
    NormalizedEvent, SigmaFieldMatch, SigmaKeywordMatch, SigmaMatchDetails,
};
use crate::sensor::Platform;

const MAX_SIGMA_MATCHES: usize = 16;
const MAX_SIGMA_KEYWORD_MATCHES: usize = 8;
const MAX_MATCH_VALUE_LEN: usize = 160;
const MAX_PATTERN_LEN: usize = 160;
pub struct Engine {
    /// Platform whose Sigma logsource rules should be accepted.
    platform: Platform,
    /// Compiled rules indexed by normalized logsource.
    rules_by_logsource: HashMap<LogSourceKey, Vec<CompiledRule>>,

    /// Total number of loaded rules
    rule_count: usize,

    /// Failed rule paths and error messages (for diagnostics)
    failed_rules: Vec<(String, String)>,

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

    /// Controls logging for rule logic evaluation errors.
    rule_logic_error_log_level: RuleLogicErrorLogLevel,

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
        Self::new_for_platform_with_rule_logic_error_log_level_and_match_debug(
            platform,
            RuleLogicErrorLogLevel::Warn,
            MatchDebugLevel::Off,
        )
    }

    /// Creates a new engine instance that derives rule-logic error logging
    /// behavior from the provided logging level string.
    #[allow(dead_code)]
    pub fn new_with_logging_level(logging_level: &str) -> Self {
        let level = RuleLogicErrorLogLevel::from_logging_level(logging_level);
        Self::new_for_platform_with_rule_logic_error_log_level_and_match_debug(
            current_platform(),
            level,
            MatchDebugLevel::Off,
        )
    }

    /// Creates a new engine instance that also configures match debug verbosity.
    pub fn new_with_logging_level_and_match_debug(
        logging_level: &str,
        match_debug: MatchDebugLevel,
    ) -> Self {
        Self::new_for_platform_with_logging_level_and_match_debug(
            current_platform(),
            logging_level,
            match_debug,
        )
    }

    /// Creates a new engine instance for an explicit platform and match-debug setting.
    pub fn new_for_platform_with_logging_level_and_match_debug(
        platform: Platform,
        logging_level: &str,
        match_debug: MatchDebugLevel,
    ) -> Self {
        let level = RuleLogicErrorLogLevel::from_logging_level(logging_level);
        Self::new_for_platform_with_rule_logic_error_log_level_and_match_debug(
            platform,
            level,
            match_debug,
        )
    }

    fn new_for_platform_with_rule_logic_error_log_level_and_match_debug(
        platform: Platform,
        level: RuleLogicErrorLogLevel,
        match_debug: MatchDebugLevel,
    ) -> Self {
        Self {
            platform,
            rules_by_logsource: HashMap::new(),
            rule_count: 0,
            failed_rules: Vec::new(),
            skipped_product_rules: 0,
            skipped_deferred_rules: 0,
            skipped_unknown_logsource_rules: 0,
            inactive_collector_rules: 0,
            deferred_logsource_counts: HashMap::new(),
            unknown_logsource_counts: HashMap::new(),
            rule_logic_error_log_level: level,
            match_debug,
        }
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

    #[test]
    fn test_engine_creation() {
        let engine = Engine::new();
        assert_eq!(engine.rule_count, 0);
    }

    #[test]
    fn test_pattern_matching() {
        let engine = Engine::new();

        // Test exact match (case-insensitive by default)
        let pattern = FieldPattern::Exact("whoami.exe".to_string(), false);
        assert!(engine.matches_pattern("whoami.exe", &pattern, None));
        assert!(engine.matches_pattern("WHOAMI.EXE", &pattern, None));
        assert!(!engine.matches_pattern("cmd.exe", &pattern, None));

        // Test exact match (case-sensitive)
        let pattern = FieldPattern::Exact("whoami.exe".to_string(), true);
        assert!(engine.matches_pattern("whoami.exe", &pattern, None));
        assert!(!engine.matches_pattern("WHOAMI.EXE", &pattern, None));

        // Test contains (case-insensitive)
        let pattern = FieldPattern::Contains("whoami".to_string(), false);
        assert!(engine.matches_pattern("whoami.exe", &pattern, None));
        assert!(engine.matches_pattern("C:\\Windows\\System32\\whoami.exe", &pattern, None));

        // Test starts with
        let pattern = FieldPattern::StartsWith("C:\\Windows".to_string(), false);
        assert!(engine.matches_pattern("C:\\Windows\\System32\\cmd.exe", &pattern, None));
        assert!(!engine.matches_pattern("C:\\Temp\\test.exe", &pattern, None));
    }

    #[test]
    fn test_string_pattern_parsing() {
        let engine = Engine::new();

        // Wildcard pattern
        let pattern = engine.parse_string_pattern("*whoami*");
        match pattern {
            FieldPattern::Regex(_) => {}
            _ => panic!("Expected regex pattern"),
        }

        // Exact pattern (default is case-insensitive)
        let pattern = engine.parse_string_pattern("whoami.exe");
        match pattern {
            FieldPattern::Exact(s, cased) => {
                assert_eq!(s, "whoami.exe");
                assert!(!cased); // Default is case-insensitive
            }
            _ => panic!("Expected exact pattern"),
        }
    }

    #[test]
    fn test_sequence_endswith_modifier_respected() {
        let engine = Engine::new();
        let rule_yaml = r#"
title: EndsWithList
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '.exe'
      - '.com'
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();

        let mut engine = Engine::new();
        engine
            .rules_by_logsource
            .entry(compiled.logsource.clone())
            .or_default()
            .push(compiled);

        let mut event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some("1234".to_string()),
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
        };

        assert!(engine.check_event(&event).is_some());

        if let EventFields::ProcessCreation(ref mut fields) = event.fields {
            fields.image = Some("C:\\Windows\\System32\\cmd.exe.bak".to_string());
        }

        assert!(engine.check_event(&event).is_none());
    }

    #[test]
    fn test_contains_all_modifier_requires_all_tokens() {
        let engine = Engine::new();
        let rule_yaml = r#"
title: ContainsAllTokens
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - 'foo'
      - 'bar'
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();

        let mut engine = Engine::new();
        engine
            .rules_by_logsource
            .entry(compiled.logsource.clone())
            .or_default()
            .push(compiled);

        let mut event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
                command_line: Some("foo baz".to_string()),
                process_id: Some("1234".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
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
        };

        assert!(engine.check_event(&event).is_none());

        if let EventFields::ProcessCreation(ref mut fields) = event.fields {
            fields.command_line = Some("foo bar baz".to_string());
        }

        assert!(engine.check_event(&event).is_some());
    }

    #[test]
    fn test_cased_sequence_respects_case() {
        let engine = Engine::new();
        let rule_yaml = r#"
title: CaseSensitiveList
logsource:
  category: process_creation
detection:
  selection:
    Image|cased:
      - C:\Windows\System32\cmd.exe
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();

        let mut engine = Engine::new();
        engine
            .rules_by_logsource
            .entry(compiled.logsource.clone())
            .or_default()
            .push(compiled);

        let mut event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("c:\\windows\\system32\\cmd.exe".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: None,
                process_id: Some("1234".to_string()),
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
        };

        // Case should NOT match with different casing.
        assert!(engine.check_event(&event).is_none());

        if let EventFields::ProcessCreation(ref mut fields) = event.fields {
            fields.image = Some("C:\\Windows\\System32\\cmd.exe".to_string());
        }

        // Exact case should match.
        assert!(engine.check_event(&event).is_some());
    }

    #[test]
    fn test_rule_loading() {
        let mut engine = Engine::new();

        // Try to load rules from the rules/sigma directory
        // This test will pass even if the directory doesn't exist
        let _ = engine.load_rules("rules/sigma");

        // Get stats
        let stats = engine.stats();

        // If rules loaded, verify they're categorized
        if stats.total_rules > 0 {
            assert!(
                !stats.rules_by_category.is_empty(),
                "Rules should be categorized"
            );
        }
    }

    #[test]
    fn test_event_matching() {
        use crate::models::*;

        let engine = Engine::new();

        // Create a mock normalized event for whoami.exe
        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("C:\\Windows\\System32\\whoami.exe".to_string()),
                command_line: Some("whoami".to_string()),
                process_id: Some("1234".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some("TestUser".to_string()),
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        };

        // Check event (should return None since we haven't loaded rules in this test)
        let result = engine.check_event(&event);

        // In a test without rules loaded, this should be None
        assert!(result.is_none());
    }

    // ===== NEW TESTS FOR ENHANCED SIGMA LOGIC =====

    #[test]
    fn test_transpile_basic_operators() {
        let engine = Engine::new();
        let keys = vec!["sel1".to_string(), "sel2".to_string()];

        // Test AND operator
        let result = engine.transpile_sigma_condition("sel1 and sel2", &keys);
        assert_eq!(result, "sel1 && sel2");

        // Test OR operator
        let result = engine.transpile_sigma_condition("sel1 or sel2", &keys);
        assert_eq!(result, "sel1 || sel2");

        // Test NOT operator
        let result = engine.transpile_sigma_condition("not sel1", &keys);
        assert_eq!(result, "! sel1");

        // Test uppercase variants
        let result = engine.transpile_sigma_condition(
            "sel1 AND sel2 OR sel3",
            &["sel1".to_string(), "sel2".to_string(), "sel3".to_string()],
        );
        assert_eq!(result, "sel1 && sel2 || sel3");
    }

    #[test]
    fn test_transpile_1_of_them() {
        let engine = Engine::new();
        let keys = vec![
            "selection1".to_string(),
            "selection2".to_string(),
            "selection3".to_string(),
        ];

        let result = engine.transpile_sigma_condition("1 of them", &keys);
        assert!(result.contains("selection1"));
        assert!(result.contains("selection2"));
        assert!(result.contains("selection3"));
        assert!(result.contains("||"));
    }

    #[test]
    fn test_transpile_all_of_them() {
        let engine = Engine::new();
        let keys = vec!["sel1".to_string(), "sel2".to_string()];

        let result = engine.transpile_sigma_condition("all of them", &keys);
        assert!(result.contains("sel1"));
        assert!(result.contains("sel2"));
        assert!(result.contains("&&"));
    }

    #[test]
    fn test_transpile_pattern_aggregation() {
        let engine = Engine::new();
        let keys = vec![
            "selection_img".to_string(),
            "selection_cmd".to_string(),
            "other".to_string(),
        ];

        let result = engine.transpile_sigma_condition("all of selection*", &keys);
        // Should only include keys starting with "selection"
        assert!(result.contains("selection_img"));
        assert!(result.contains("selection_cmd"));
        assert!(!result.contains("other"));
        assert!(result.contains("&&"));
    }

    #[test]
    fn test_transpile_complex_expression() {
        let engine = Engine::new();
        let keys = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        let result = engine.transpile_sigma_condition("(a or b) and not c", &keys);
        assert_eq!(result, "(a || b) && ! c");
    }

    #[test]
    fn test_check_condition_simple_and() {
        let engine = Engine::new();
        let mut results = HashMap::new();
        results.insert("selection1".to_string(), true);
        results.insert("selection2".to_string(), false);

        // selection1 AND selection2 -> true AND false -> false
        let is_match = engine.check_condition("selection1 and selection2", &results);
        assert!(!is_match);

        // Both true
        results.insert("selection2".to_string(), true);
        let is_match = engine.check_condition("selection1 and selection2", &results);
        assert!(is_match);
    }

    #[test]
    fn test_check_condition_and_not() {
        let engine = Engine::new();
        let mut results = HashMap::new();
        results.insert("selection1".to_string(), true);
        results.insert("selection2".to_string(), false);

        // selection1 AND NOT selection2 -> true AND NOT false -> true AND true -> true
        let is_match = engine.check_condition("selection1 and not selection2", &results);
        assert!(is_match);

        // Now make selection2 true
        results.insert("selection2".to_string(), true);
        // selection1 AND NOT selection2 -> true AND NOT true -> true AND false -> false
        let is_match = engine.check_condition("selection1 and not selection2", &results);
        assert!(!is_match);
    }

    #[test]
    fn test_check_condition_1_of_them() {
        let engine = Engine::new();
        let mut results = HashMap::new();
        results.insert("proc_creation".to_string(), false);
        results.insert("file_event".to_string(), true);

        // 1 of them -> proc_creation OR file_event -> false OR true -> true
        let is_match = engine.check_condition("1 of them", &results);
        assert!(is_match);

        // All false
        results.insert("file_event".to_string(), false);
        let is_match = engine.check_condition("1 of them", &results);
        assert!(!is_match);
    }

    #[test]
    fn test_check_condition_parentheses() {
        let engine = Engine::new();
        let mut results = HashMap::new();
        results.insert("a".to_string(), true);
        results.insert("b".to_string(), false);
        results.insert("c".to_string(), true);

        // (a OR b) AND c -> (true OR false) AND true -> true AND true -> true
        let is_match = engine.check_condition("(a or b) and c", &results);
        assert!(is_match);

        // a OR (b AND c) -> true OR (false AND true) -> true OR false -> true
        let is_match = engine.check_condition("a or (b and c)", &results);
        assert!(is_match);
    }

    #[test]
    fn test_evaluate_selections() {
        let engine = Engine::new();

        // Create a test rule with multiple selections
        let rule_yaml = r#"
title: Test Rule
logsource:
  category: process_creation
detection:
  selection1:
    Image: "*whoami.exe"
  selection2:
    CommandLine: "*priv*"
  condition: selection1 and selection2
level: high
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();

        // Create event that matches selection1 but not selection2
        use crate::models::*;
        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "etw".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("C:\\Windows\\System32\\whoami.exe".to_string()),
                command_line: Some("whoami".to_string()),
                process_id: None,
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
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
        };

        let results = engine.evaluate_selections(&event, &compiled);

        assert_eq!(results.get("selection1"), Some(&true));
        assert_eq!(results.get("selection2"), Some(&false));
    }

    #[test]
    fn test_skip_non_windows_product_rule() {
        let rule_yaml = r#"
title: Linux Process Rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: "*bash"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        assert_eq!(
            windows_engine().classify_logsource(&rule.logsource).status,
            LogSourceStatus::ProductMismatch
        );
        assert_eq!(
            linux_engine().classify_logsource(&rule.logsource).status,
            LogSourceStatus::Supported
        );
    }

    #[test]
    fn test_skip_unsupported_service_rule() {
        let rule_yaml = r#"
title: Unsupported Service
logsource:
  product: windows
  service: cloudtrail
  category: process_creation
detection:
  selection:
    Image: "*cmd.exe"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        assert_eq!(
            windows_engine().classify_logsource(&rule.logsource).status,
            LogSourceStatus::Unknown
        );
        assert_eq!(
            linux_engine().classify_logsource(&rule.logsource).status,
            LogSourceStatus::ProductMismatch
        );
    }

    #[test]
    fn test_skip_unsupported_category_rule() {
        let rule_yaml = r#"
title: Unsupported Category
logsource:
  product: windows
  category: process_tampering
detection:
  selection:
    Image: "*cmd.exe"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        assert_eq!(
            windows_engine().classify_logsource(&rule.logsource).status,
            LogSourceStatus::Unknown
        );
    }

    #[test]
    fn test_linux_sysmon_process_rule_matches_full_logsource() {
        let rule_yaml = r#"
title: Linux Sysmon Process
logsource:
  product: linux
  service: sysmon
  category: process_creation
detection:
  selection:
    Image: "*bash"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let mut engine = linux_engine();
        let compiled = engine.compile_rule(rule).unwrap();
        engine
            .rules_by_logsource
            .entry(compiled.logsource.clone())
            .or_default()
            .push(compiled);

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "ebpf".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some("/usr/bin/bash".to_string()),
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                command_line: Some("/usr/bin/bash -c id".to_string()),
                process_id: Some("42".to_string()),
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: Some("alice".to_string()),
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        };

        assert!(engine.check_event(&event).is_some());
    }

    #[test]
    fn test_linux_sysmon_service_only_rule_loads_without_category() {
        let rule_yaml = r#"
title: Linux Sysmon Any Category
logsource:
  product: linux
  service: sysmon
detection:
  selection:
    Image: "*bash"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let classification = linux_engine().classify_logsource(&rule.logsource);
        assert_eq!(classification.status, LogSourceStatus::Supported);
        assert_eq!(classification.collector_active, Some(true));
    }

    #[test]
    fn test_generic_network_connection_rule_matches_linux_network_event() {
        let rule_yaml = r#"
title: Generic Network Connection
logsource:
  category: network
  service: connection
detection:
  selection:
    DestinationPort: "443"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let mut engine = linux_engine();
        let compiled = engine.compile_rule(rule).unwrap();
        engine
            .rules_by_logsource
            .entry(compiled.logsource.clone())
            .or_default()
            .push(compiled);

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "ebpf".to_string(),
            category: EventCategory::Network,
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
            }),
            process_context: None,
        };

        assert!(engine.check_event(&event).is_some());
    }

    #[test]
    fn test_linux_file_rename_rule_matches_source_and_target_fields() {
        let rule_yaml = r#"
title: Linux File Rename
logsource:
  product: linux
  category: file_rename
detection:
  selection:
    SourceFilename|endswith: "/old.txt"
    TargetFilename|endswith: "/new.txt"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let mut engine = linux_engine();
        let compiled = engine.compile_rule(rule).unwrap();
        engine
            .rules_by_logsource
            .entry(compiled.logsource.clone())
            .or_default()
            .push(compiled);

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "ebpf".to_string(),
            category: EventCategory::File,
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
            }),
            process_context: None,
        };

        assert!(engine.check_event(&event).is_some());
    }

    #[test]
    fn test_generic_dns_rule_matches_linux_dns_event_via_alias_fields() {
        let rule_yaml = r#"
title: Generic DNS Query
logsource:
  category: dns
detection:
  selection:
    query: "example.com"
    record_type: "A"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let mut engine = linux_engine();
        let compiled = engine.compile_rule(rule).unwrap();
        engine
            .rules_by_logsource
            .entry(compiled.logsource.clone())
            .or_default()
            .push(compiled);

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "ebpf".to_string(),
            category: EventCategory::Dns,
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

        assert!(engine.check_event(&event).is_some());
    }

    #[test]
    fn test_linux_deferred_logsource_is_reported() {
        let rule_yaml = r#"
title: Deferred Auditd Rule
logsource:
  product: linux
  service: auditd
  category: process_creation
detection:
  selection:
    exe: "/usr/bin/bash"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let classification = linux_engine().classify_logsource(&rule.logsource);
        assert_eq!(classification.status, LogSourceStatus::Deferred);
        assert_eq!(classification.collector_active, None);
    }

    #[test]
    fn test_unsupported_modifier_rejected_explicitly() {
        let rule_yaml = r#"
title: Unsupported Modifier
logsource:
  category: process_creation
detection:
  selection:
    Image|foobar: "*cmd.exe"
  condition: selection
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let error = windows_engine().compile_rule(rule).unwrap_err().to_string();
        assert!(error.contains("Unsupported Sigma modifier"));
    }

    #[test]
    fn test_compile_rule_builds_precompiled_condition_tree() {
        let engine = Engine::new();
        let rule_yaml = r#"
title: Condition AST
logsource:
  product: windows
  category: process_creation
detection:
  sel1:
    Image: "*cmd.exe"
  sel2:
    CommandLine: "* /c *"
  condition: sel1 and sel2
"#;

        let rule: SigmaRule = serde_yaml::from_str(rule_yaml).unwrap();
        let compiled = engine.compile_rule(rule).unwrap();
        assert!(compiled.transpiled_condition.is_some());
        assert!(compiled.condition_tree.is_some());
    }
}
