//! Collection loading, Sigma correlations, and Sigma filters.

use std::fs;

use rustinel::engine::{Engine, UnsupportedRuleKind};
use rustinel::models::MatchDebugLevel;
use rustinel::models::{
    EventCategory, EventFields, NetworkConnectionFields, NormalizedEvent, ProcessCreationFields,
};
use rustinel::sensor::Platform;
use tempfile::TempDir;

fn engine_for(path: &std::path::Path) -> Engine {
    let mut engine =
        Engine::new_for_platform_with_match_debug(Platform::Linux, MatchDebugLevel::Off);
    engine.load_rules(path).expect("Sigma rules should load");
    engine
}

fn process_event(timestamp: &str, user: &str) -> NormalizedEvent {
    NormalizedEvent {
        timestamp: timestamp.to_string(),
        platform: Platform::Linux,
        provider: "test".to_string(),
        category: EventCategory::Process,
        event_id: 1,
        event_id_string: "1".to_string(),
        opcode: 1,
        fields: EventFields::ProcessCreation(ProcessCreationFields {
            image: Some("/usr/bin/curl".to_string()),
            command_line: Some("curl https://example.test".to_string()),
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
            user: Some(user.to_string()),
        }),
        process_context: None,
    }
}

fn network_event(timestamp: &str, user: &str) -> NormalizedEvent {
    NormalizedEvent {
        timestamp: timestamp.to_string(),
        platform: Platform::Linux,
        provider: "test".to_string(),
        category: EventCategory::Network,
        event_id: 3,
        event_id_string: "3".to_string(),
        opcode: 12,
        fields: EventFields::NetworkConnection(NetworkConnectionFields {
            destination_ip: Some("198.51.100.10".to_string()),
            source_ip: Some("10.0.0.5".to_string()),
            destination_port: Some("443".to_string()),
            source_port: Some("51234".to_string()),
            process_id: Some("1234".to_string()),
            image: Some("/usr/bin/curl".to_string()),
            user: Some(user.to_string()),
            destination_hostname: None,
            protocol: Some("tcp".to_string()),
            initiated: Some(true),
        }),
        process_context: None,
    }
}

#[test]
fn loads_cross_file_correlation_and_applies_filter() {
    let fixture = TempDir::new().expect("temporary rule directory");
    let nested = fixture.path().join("nested");
    fs::create_dir_all(&nested).expect("create nested rule directory");

    fs::write(
        fixture.path().join("base.yml"),
        r#"title: Base Process Rule
id: base-process-rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
level: low
"#,
    )
    .expect("write detection rule");
    fs::write(
        nested.join("correlation.yml"),
        r#"title: Repeated Process Rule
id: repeated-process-rule
correlation:
  type: event_count
  rules:
    - base-process-rule
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 2
level: high
"#,
    )
    .expect("write correlation rule");
    fs::write(
        fixture.path().join("filter.yml"),
        r#"title: Suppress Admin Process
id: suppress-admin-process
logsource:
  product: linux
  category: process_creation
filter:
  rules:
    - base-process-rule
  selection:
    User: alice
  condition: not selection
"#,
    )
    .expect("write filter rule");

    let engine = engine_for(fixture.path());
    let stats = engine.stats();
    assert_eq!(stats.total_rules, 1);
    assert!(stats.failed_rules.is_empty());
    assert!(stats.unsupported_rules.is_empty());

    // The filter is active, so this otherwise matching event produces no
    // detection and does not advance the correlation window.
    assert!(engine
        .check_event(&process_event("2026-01-01T00:00:00Z", "alice"))
        .is_empty());

    let first = engine.check_event(&process_event("2026-01-01T00:00:01Z", "bob"));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].rule_name, "Base Process Rule");

    let second = engine.check_event(&process_event("2026-01-01T00:00:02Z", "bob"));
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].rule_name, "Base Process Rule");
    assert_eq!(second[1].rule_name, "Repeated Process Rule");
    assert_eq!(
        second[1].rule_id.as_deref(),
        Some("sigma::repeated-process-rule")
    );

    let details = second[1]
        .match_details
        .as_ref()
        .expect("correlation details are part of the alert");
    let correlation = details
        .correlation
        .as_ref()
        .expect("correlation match details");
    assert_eq!(correlation.correlation_type, "event_count");
    assert_eq!(correlation.aggregated_value, 2.0);
    assert_eq!(correlation.timespan_secs, 300);
    assert_eq!(
        correlation.group_key,
        vec![("Image".to_string(), "/usr/bin/curl".to_string())]
    );
}

#[test]
fn drops_correlation_and_filter_when_their_rule_was_filtered_out() {
    let fixture = TempDir::new().expect("temporary rule directory");
    fs::write(
        fixture.path().join("windows.yml"),
        r#"title: Windows Process Rule
id: windows-process-rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: cmd.exe
  condition: selection
---
title: Windows Correlation
id: windows-correlation
correlation:
  type: event_count
  rules:
    - windows-process-rule
  timespan: 5m
  condition:
    gte: 2
---
title: Windows Filter
id: windows-filter
filter:
  rules:
    - windows-process-rule
  selection:
    User: alice
  condition: selection
"#,
    )
    .expect("write Windows rules");

    let engine = engine_for(fixture.path());
    let stats = engine.stats();
    assert_eq!(stats.total_rules, 0);
    assert_eq!(stats.skipped_product_rules, 1);
    assert_eq!(stats.unsupported_rules.len(), 2);
    assert!(stats
        .unsupported_rules
        .iter()
        .all(|rule| rule.kind == UnsupportedRuleKind::UnresolvedReference));
    assert!(stats
        .unsupported_rules
        .iter()
        .all(|rule| rule.reason == "references a rule not loaded on this platform"));
    assert!(stats
        .unsupported_rules
        .iter()
        .any(|rule| rule.identity.contains("windows-correlation")));
    assert!(stats
        .unsupported_rules
        .iter()
        .any(|rule| rule.identity.contains("windows-filter")));
    assert!(engine
        .check_event(&process_event("2026-01-01T00:00:00Z", "alice"))
        .is_empty());
}

#[test]
fn correlation_uses_normalized_event_timestamps_for_window_expiry() {
    let fixture = TempDir::new().expect("temporary rule directory");
    fs::write(
        fixture.path().join("rules.yml"),
        r#"title: Curl Process
id: curl-process
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
---
title: Two Curl Processes
id: two-curl-processes
correlation:
  type: event_count
  rules:
    - curl-process
  group-by:
    - User
  timespan: 5m
  condition:
    gte: 2
"#,
    )
    .expect("write timestamp fixture");

    let engine = engine_for(fixture.path());
    assert_eq!(
        engine
            .check_event(&process_event("2026-01-01T00:00:00Z", "alice"))
            .len(),
        1
    );
    assert_eq!(
        engine
            .check_event(&process_event("2026-01-01T00:10:00Z", "alice"))
            .len(),
        1,
        "events ten minutes apart must not share a five-minute window"
    );

    let result = engine.check_event(&process_event("2026-01-01T00:10:01Z", "alice"));
    assert_eq!(result.len(), 2);
    assert_eq!(result[1].rule_name, "Two Curl Processes");
}

#[test]
fn correlation_can_reference_a_named_rule_without_an_id() {
    let fixture = TempDir::new().expect("temporary rule directory");
    fs::write(
        fixture.path().join("rules.yml"),
        r#"title: Named Curl Process
name: named-curl-process
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
---
title: Repeated Named Curl Process
id: repeated-named-curl-process
correlation:
  type: event_count
  rules:
    - named-curl-process
  group-by:
    - User
  timespan: 5m
  condition:
    gte: 2
"#,
    )
    .expect("write named-rule fixture");

    let engine = engine_for(fixture.path());
    assert_eq!(
        engine
            .check_event(&process_event("2026-01-01T00:00:00Z", "alice"))
            .len(),
        1
    );
    let result = engine.check_event(&process_event("2026-01-01T00:00:01Z", "alice"));
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].rule_id, None);
    assert_eq!(result[1].rule_name, "Repeated Named Curl Process");
}

#[test]
fn temporal_correlation_combines_different_logsource_buckets() {
    let fixture = TempDir::new().expect("temporary rule directory");
    fs::write(
        fixture.path().join("process.yml"),
        r#"title: Curl Process
id: curl-process
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
"#,
    )
    .expect("write process rule");
    fs::write(
        fixture.path().join("network.yml"),
        r#"title: HTTPS Connection
id: https-connection
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DestinationPort: '443'
  condition: selection
"#,
    )
    .expect("write network rule");
    fs::write(
        fixture.path().join("temporal.yml"),
        r#"title: Curl Then HTTPS
id: curl-then-https
correlation:
  type: temporal
  rules:
    - curl-process
    - https-connection
  group-by:
    - User
  timespan: 5m
  condition:
    gte: 2
level: high
"#,
    )
    .expect("write temporal rule");

    let engine = engine_for(fixture.path());
    let process = engine.check_event(&process_event("2026-01-01T00:00:00Z", "alice"));
    assert_eq!(process.len(), 1);
    assert_eq!(process[0].rule_name, "Curl Process");

    let network = engine.check_event(&network_event("2026-01-01T00:00:01Z", "alice"));
    assert_eq!(network.len(), 2);
    assert_eq!(network[0].rule_name, "HTTPS Connection");
    assert_eq!(network[1].rule_name, "Curl Then HTTPS");
    assert_eq!(
        network[1]
            .match_details
            .as_ref()
            .and_then(|details| details.correlation.as_ref())
            .map(|details| details.correlation_type.as_str()),
        Some("temporal")
    );
}

#[test]
fn invalid_compiled_rule_does_not_discard_valid_rule_files() {
    let fixture = TempDir::new().expect("temporary rule directory");
    fs::write(
        fixture.path().join("valid.yml"),
        r#"title: Valid Curl Rule
id: valid-curl-rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
"#,
    )
    .expect("write valid rule");
    fs::write(
        fixture.path().join("invalid.yml"),
        r#"title: Invalid CIDR Rule
id: invalid-cidr-rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|cidr: definitely-not-a-cidr
  condition: selection
---
title: Correlation For Invalid Rule
id: correlation-for-invalid-rule
correlation:
  type: event_count
  rules:
    - invalid-cidr-rule
  timespan: 5m
  condition:
    gte: 2
"#,
    )
    .expect("write invalid rule");

    let engine = engine_for(fixture.path());
    let stats = engine.stats();
    assert_eq!(stats.total_rules, 1);
    assert_eq!(stats.failed_rules.len(), 1);
    assert!(stats.failed_rules[0].0.ends_with("invalid.yml"));
    assert_eq!(stats.unsupported_rules.len(), 1);
    assert!(stats.unsupported_rules[0]
        .identity
        .contains("correlation-for-invalid-rule"));

    let alerts = engine.check_event(&process_event("2026-01-01T00:00:00Z", "alice"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_name, "Valid Curl Rule");
}

#[test]
fn filter_can_target_name_of_rule_that_also_has_an_id() {
    let fixture = TempDir::new().expect("temporary rule directory");
    fs::write(
        fixture.path().join("rules.yml"),
        r#"title: Named Curl Rule
id: named-curl-id
name: named-curl-rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
---
title: Suppress Alice By Name
filter:
  rules:
    - named-curl-rule
  selection:
    User: alice
  condition: not selection
"#,
    )
    .expect("write named filter fixture");

    let engine = engine_for(fixture.path());
    assert!(engine
        .check_event(&process_event("2026-01-01T00:00:00Z", "alice"))
        .is_empty());
    assert_eq!(
        engine
            .check_event(&process_event("2026-01-01T00:00:01Z", "bob"))
            .len(),
        1
    );
}

#[test]
fn temporal_without_condition_requires_every_referenced_rule() {
    let fixture = TempDir::new().expect("temporary rule directory");
    fs::write(
        fixture.path().join("rules.yml"),
        r#"title: Curl Process For Implicit Temporal
id: implicit-curl-process
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image: /usr/bin/curl
  condition: selection
---
title: HTTPS For Implicit Temporal
id: implicit-https-connection
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DestinationPort: '443'
  condition: selection
---
title: Implicit Curl Then HTTPS
id: implicit-curl-then-https
correlation:
  type: temporal
  rules:
    - implicit-curl-process
    - implicit-https-connection
  group-by:
    - User
  timespan: 5m
level: high
---
title: Explicit Any Curl Or HTTPS
id: explicit-any-curl-or-https
correlation:
  type: temporal
  rules:
    - implicit-curl-process
    - implicit-https-connection
  group-by:
    - User
  timespan: 5m
  condition:
    gte: 1
level: medium
"#,
    )
    .expect("write implicit temporal fixture");

    let engine = engine_for(fixture.path());
    let process = engine.check_event(&process_event("2026-01-01T00:00:00Z", "alice"));
    assert_eq!(process.len(), 2);
    assert_eq!(process[0].rule_name, "Curl Process For Implicit Temporal");
    assert_eq!(process[1].rule_name, "Explicit Any Curl Or HTTPS");

    let network = engine.check_event(&network_event("2026-01-01T00:00:01Z", "alice"));
    assert_eq!(network.len(), 3);
    assert_eq!(network[1].rule_name, "Implicit Curl Then HTTPS");
    assert_eq!(network[2].rule_name, "Explicit Any Curl Or HTTPS");
}
