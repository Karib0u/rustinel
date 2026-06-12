#[cfg(test)]
mod common;

use common::{
    assert_ecs_field_eq, ecs_json, provider_for, test_time, YaraFixture, TEST_PID, TEST_YARA_MARKER,
};
use rustinel::{
    models::{
        Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, MatchDebugLevel,
        MatchDetails, NormalizedEvent, ProcessCreationFields, YaraMatchDetails, YaraRuleMatch,
    },
    scanner::Scanner,
    sensor::Platform,
};

fn load_scanner(fixture: &YaraFixture) -> Scanner {
    fixture.write_default_rule();
    let scanner = Scanner::new(fixture.rules_dir()).expect("Scanner::new failed");
    assert_eq!(scanner.compiled_files(), 1, "expected one YARA rule file");
    scanner
}

fn build_yara_match_details(
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
        yara: Some(YaraMatchDetails { rules: vec![rule] }),
    })
}

fn build_yara_alert(
    platform: Platform,
    path: &str,
    rule_match: &YaraRuleMatch,
    match_debug: MatchDebugLevel,
) -> Alert {
    Alert {
        severity: AlertSeverity::Critical,
        rule_name: rule_match.rule.clone(),
        rule_description: None,
        rule_id: None,
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: chrono::DateTime::<chrono::Utc>::from(test_time()).to_rfc3339(),
            platform,
            provider: provider_for(platform).to_string(),
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
                command_line: Some(path.to_string()),
                process_id: Some(TEST_PID.to_string()),
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
        match_details: build_yara_match_details(match_debug, rule_match),
    }
}

#[test]
fn yara_disk_scanner_loads_rules_from_subdirectories() {
    let fixture = YaraFixture::new();
    fixture.write_rule("subdir/nested.yar", "NestedSubdirRule", TEST_YARA_MARKER);
    let scanner = Scanner::new(fixture.rules_dir()).expect("Scanner::new failed");
    assert_eq!(
        scanner.compiled_files(),
        1,
        "expected rule from subdirectory to be compiled"
    );

    let marker_sample = fixture.write_marker_sample();
    let matches = scanner
        .scan_file(&marker_sample.to_string_lossy(), MatchDebugLevel::Off)
        .expect("scan failed");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule, "NestedSubdirRule");
}

#[test]
fn yara_disk_scan_matches_marker_and_rejects_clean_temp_file() {
    let fixture = YaraFixture::new();
    let scanner = load_scanner(&fixture);
    let marker_sample = fixture.write_marker_sample();
    let clean_sample = fixture.write_clean_sample();

    let marker_path = marker_sample.to_string_lossy();
    let matches = scanner
        .scan_file(&marker_path, MatchDebugLevel::Off)
        .expect("marker sample scan failed");
    assert_eq!(matches.len(), 1, "expected exactly one YARA match");
    assert_eq!(matches[0].rule, "TestMarkerString");
    assert!(
        matches[0].strings.is_empty(),
        "Off debug mode should omit string matches"
    );

    let clean_matches = scanner
        .scan_file(&clean_sample.to_string_lossy(), MatchDebugLevel::Off)
        .expect("clean sample scan failed");
    assert!(
        clean_matches.is_empty(),
        "expected zero YARA matches for clean temp file"
    );
}

#[test]
fn yara_disk_scan_full_debug_includes_string_offsets_for_temp_file() {
    let fixture = YaraFixture::new();
    let scanner = load_scanner(&fixture);
    let marker_sample = fixture.write_sample(
        "marker-with-prefix.bin",
        format!("prefix:{TEST_YARA_MARKER}:suffix").as_bytes(),
    );

    let marker_path = marker_sample.to_string_lossy();
    let off_matches = scanner
        .scan_file(&marker_path, MatchDebugLevel::Off)
        .expect("Off debug scan failed");
    assert_eq!(off_matches.len(), 1);
    assert!(off_matches[0].strings.is_empty());

    let full_matches = scanner
        .scan_file(&marker_path, MatchDebugLevel::Full)
        .expect("Full debug scan failed");
    assert_eq!(full_matches.len(), 1);
    let first_string = full_matches[0]
        .strings
        .first()
        .expect("Full debug mode should include string match details");
    assert!(
        first_string.offset.is_some(),
        "Full debug string match should include an offset"
    );
    assert!(
        first_string
            .snippet
            .as_deref()
            .unwrap_or("")
            .contains(TEST_YARA_MARKER),
        "Full debug string match should include the marker snippet"
    );
}

#[test]
fn yara_disk_alert_maps_to_ecs_with_process_file_context() {
    for platform in [Platform::Windows, Platform::Linux] {
        let fixture = YaraFixture::new();
        let scanner = load_scanner(&fixture);
        let marker_sample = fixture.write_marker_sample();
        let marker_path = marker_sample.to_string_lossy();
        let matches = scanner
            .scan_file(&marker_path, MatchDebugLevel::Full)
            .expect("marker sample scan failed");
        let rule_match = matches.first().expect("expected marker rule match");

        let alert = build_yara_alert(platform, &marker_path, rule_match, MatchDebugLevel::Full);
        let ecs = ecs_json(&alert);

        assert_ecs_field_eq(&ecs, "edr.rule.engine", "Yara");
        assert_ecs_field_eq(&ecs, "rule.name", "TestMarkerString");
        assert_ecs_field_eq(&ecs, "event.dataset", "edr.process");
        assert_ecs_field_eq(&ecs, "event.provider", provider_for(platform));
        assert_ecs_field_eq(&ecs, "process.executable", marker_path.as_ref());
        assert_ecs_field_eq(&ecs, "process.pid", TEST_PID);
        assert!(
            ecs.get("edr.match")
                .and_then(|details| details.get("yara"))
                .and_then(|yara| yara.get("rules"))
                .and_then(|rules| rules.as_array())
                .is_some_and(|rules| !rules.is_empty()),
            "ECS output should include YARA match details in Full debug mode"
        );

        let off_alert = build_yara_alert(platform, &marker_path, rule_match, MatchDebugLevel::Off);
        let off_ecs = ecs_json(&off_alert);
        assert!(
            off_ecs.get("edr.match").is_none(),
            "Off debug mode should omit ECS match details"
        );
    }
}
