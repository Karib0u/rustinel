//! End-to-end Sigma detection over normalized sensor events.
//!
//! Each test loads a small ruleset from a temporary directory, normalizes a
//! synthetic sensor payload, and asserts the verdict. The rules deliberately
//! exercise the modifiers most sensitive to how Rustinel exposes an event to
//! the evaluator: `cidr` (where the event adapter yields values as strings)
//! plus `re` and `contains|all`.

#[cfg(test)]
mod common;

use common::{
    network_connect_event, powershell_module_event, process_start_event,
    service_installation_event, SigmaFixture, TestNormalizer,
};
use rustinel::engine::Engine;
use rustinel::models::MatchDebugLevel;
use rustinel::sensor::{Platform, SensorPayload};

fn engine_with(fixture: &SigmaFixture, platform: Platform) -> Engine {
    let mut engine = Engine::new_for_platform_with_match_debug(platform, MatchDebugLevel::Off);
    engine
        .load_rules(fixture.rules_dir())
        .expect("sigma rules should load");
    assert_eq!(
        engine.stats().failed_rules,
        Vec::<(String, String)>::new(),
        "no rule should fail to load"
    );
    engine
}

#[test]
fn cidr_and_port_rule_matches_network_event() {
    let fixture = SigmaFixture::new();
    // TEST_DESTINATION_IP is 198.51.100.10 on port 443.
    fixture.write_rule(
        "net_cidr.yml",
        r#"title: Network CIDR
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: 198.51.100.0/24
    DestinationPort: '443'
  condition: selection
level: high
"#,
    );
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("network event should normalize");

    let engine = engine_with(&fixture, Platform::Linux);
    let alert = engine
        .check_event(&normalized)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("cidr + port rule should match"));
    assert_eq!(alert.rule_name, "Network CIDR");
}

#[test]
fn out_of_range_cidr_does_not_alert() {
    let fixture = SigmaFixture::new();
    // The destination (198.51.100.10) is outside 10.0.0.0/8; only the source
    // IP is in that range, and the rule matches on DestinationIp.
    fixture.write_rule(
        "net_miss.yml",
        r#"title: Network Miss
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: 10.0.0.0/8
  condition: selection
level: high
"#,
    );
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("network event should normalize");

    let engine = engine_with(&fixture, Platform::Linux);
    assert!(
        engine.check_event(&normalized).is_empty(),
        "destination outside the CIDR must not alert"
    );
}

#[test]
fn contains_all_and_regex_rule_matches_process_event() {
    let fixture = SigmaFixture::new();
    // The process command line is "<image> https://example.test" and the image
    // ends in /curl.
    fixture.write_rule(
        "proc_all_re.yml",
        r#"title: Process ContainsAll Regex
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - curl
      - example.test
    Image|re: '.*/curl$'
  condition: selection
level: high
"#,
    );
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .expect("process event should normalize");

    let engine = engine_with(&fixture, Platform::Linux);
    let alert = engine
        .check_event(&normalized)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("contains|all + re rule should match"));
    assert_eq!(alert.rule_name, "Process ContainsAll Regex",);
}

/// `Provider_Name` is carried on the event and `ImagePath` is an alias resolved
/// in `NormalizedEvent::get_field`. The RSigma adapter reads both through that
/// accessor, while its serde-based field enumeration sees only the stored
/// `ServiceFileName` field.
#[test]
fn service_provider_and_image_path_rule_matches() {
    let fixture = SigmaFixture::new();
    fixture.write_service_rule();
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&service_installation_event())
        .expect("service event should normalize");

    let engine = engine_with(&fixture, Platform::Windows);
    let alert = engine
        .check_event(&normalized)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("service rule should match"));
    assert_eq!(alert.rule_name, "Test Service Installation",);
}

#[test]
fn initiated_rules_separate_outbound_from_inbound_connections() {
    // Sysmon Event 3's `Initiated` is written as a string in rules even though
    // the model holds a boolean, so the event accessor exposes its string form.
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "net_inbound.yml",
        r#"title: Inbound Connection
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationPort: '443'
    Initiated: 'false'
  condition: selection
level: high
"#,
    );

    let harness = TestNormalizer::new(false);
    let outbound = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Windows))
        .expect("outbound event should normalize");

    let mut accepted = network_connect_event(Platform::Windows);
    if let SensorPayload::Network(fields) = &mut accepted.payload {
        fields.initiated = Some(false);
    }
    let inbound = harness
        .normalizer
        .normalize(&accepted)
        .expect("inbound event should normalize");

    let engine = engine_with(&fixture, Platform::Windows);
    assert!(
        engine.check_event(&outbound).is_empty(),
        "an outbound connection must not match Initiated: 'false'"
    );
    let alert = engine
        .check_event(&inbound)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("an accepted connection should match"));
    assert_eq!(alert.rule_name, "Inbound Connection",);
}

#[test]
fn an_unknown_direction_matches_neither_initiated_value() {
    // A sensor that cannot tell the direction leaves the field absent, and an
    // absent field matches no equality selection in either direction. Guessing
    // would silently answer a question the sensor never asked.
    let fixture = SigmaFixture::new();
    for (name, value) in [("net_true.yml", "true"), ("net_false.yml", "false")] {
        fixture.write_rule(
            name,
            &format!(
                r#"title: Initiated {value}
logsource:
  product: macos
  category: network_connection
detection:
  selection:
    Initiated: '{value}'
  condition: selection
level: high
"#
            ),
        );
    }

    let mut unknown = network_connect_event(Platform::MacOS);
    if let SensorPayload::Network(fields) = &mut unknown.payload {
        fields.initiated = None;
    }
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&unknown)
        .expect("network event should normalize");

    let engine = engine_with(&fixture, Platform::MacOS);
    assert!(
        engine.check_event(&normalized).is_empty(),
        "an unknown direction must not match either value"
    );
}

#[test]
fn powershell_module_rule_matches_a_module_event() {
    let fixture = SigmaFixture::new();
    fixture.write_ps_module_rule();
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&powershell_module_event())
        .expect("module logging event should normalize");

    let engine = engine_with(&fixture, Platform::Windows);
    let alert = engine
        .check_event(&normalized)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("ps_module rule should match"));
    assert_eq!(alert.rule_name, "Test PowerShell Module Download");
}

/// A rule whose logsource values carry stray whitespace or case must still
/// route. Load-time classification trims and lowercases the logsource, so a
/// rule that survives it is counted as loaded; if routing compared the raw
/// value the rule would be silently inert — loaded, reported, never firing.
#[test]
fn padded_and_uppercased_logsource_values_still_route() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "padded.yml",
        "title: Padded Logsource\nid: padded-logsource\nlogsource:\n  product: \" LINUX \"\n  category: \"  Process_Creation \"\ndetection:\n  selection:\n    Image|endswith: /curl\n  condition: selection\nlevel: high\n",
    );

    let engine = engine_with(&fixture, Platform::Linux);
    assert_eq!(
        engine.stats().total_rules,
        1,
        "the rule is accepted at load"
    );

    let event = TestNormalizer::new(false)
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .expect("process event should normalize");

    let alerts = engine.check_event(&event);
    assert_eq!(
        alerts.len(),
        1,
        "a rule counted as loaded must be able to fire"
    );
    assert_eq!(alerts[0].rule_name, "Padded Logsource");
}
