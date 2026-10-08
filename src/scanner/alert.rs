//! Alert construction for YARA file scans.

use crate::models::{
    Alert, DetectionEngine, EventCategory, EventFields, MatchDebugLevel, MatchDetails,
    NormalizedEvent, ProcessCreationFields, Provenance, YaraMatchDetails, YaraRuleMatch,
};
use crate::utils;
use crate::vocab::Platform;

pub fn build_yara_match_details(
    match_debug: MatchDebugLevel,
    rule_match: &YaraRuleMatch,
) -> Option<MatchDetails> {
    if matches!(match_debug, MatchDebugLevel::Off) {
        return None;
    }

    let summary = if matches!(match_debug, MatchDebugLevel::Full) {
        if let Some(first_string) = rule_match.strings.first() {
            if let Some(offset) = first_string.offset {
                format!(
                    "matched YARA rule {} via {} at 0x{:x}",
                    rule_match.rule, first_string.id, offset
                )
            } else {
                format!(
                    "matched YARA rule {} via {}",
                    rule_match.rule, first_string.id
                )
            }
        } else {
            format!("matched YARA rule {}", rule_match.rule)
        }
    } else {
        format!("matched YARA rule {}", rule_match.rule)
    };

    let mut rule = rule_match.clone();
    if !matches!(match_debug, MatchDebugLevel::Full) {
        rule.strings.clear();
    }

    Some(MatchDetails {
        summary,
        sigma: None,
        correlation: None,
        yara: Some(YaraMatchDetails { rules: vec![rule] }),
    })
}

pub fn build_yara_alert(
    rule_match: &YaraRuleMatch,
    path: &str,
    pid: u32,
    provenance: &Provenance,
    match_details: Option<MatchDetails>,
    platform: Platform,
    provider: &str,
) -> Alert {
    let rule_id = rule_match
        .metadata_id
        .as_ref()
        .map(|id| format!("yara::{}", id));
    let mut alert = Alert {
        severity: rule_match.severity,
        rule_name: rule_match.rule.clone(),
        rule_description: None,
        rule_id,
        sigma_metadata: None,
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: utils::now_timestamp_string(),
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
                container: Default::default(),
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
                parent_user: None,
                current_directory: None,
                integrity_level: None,
                user: None,
            }),
            process_name: None,
            provenance: Default::default(),
            process_context: None,
        },
        match_details,
    };
    alert.event.inherit_populated_provenance(provenance);
    alert
}
