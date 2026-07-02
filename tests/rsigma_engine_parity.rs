//! Sigma detection parity checks that must hold for both the built-in engine
//! and the RSigma-backed engine.
//!
//! These tests use only the public `Engine` API, so CI runs them once with the
//! default backend and once with `--features rsigma-engine`; agreement across
//! both runs is the parity guarantee. They deliberately exercise the modifiers
//! most likely to diverge between the two matchers: `cidr` and numeric/string
//! comparisons (where the RSigma adapter yields every value as a string) plus
//! `re` and `contains|all`.

#[cfg(test)]
mod common;

use common::{network_connect_event, process_start_event, SigmaFixture, TestNormalizer};
use rustinel::{engine::Engine, sensor::Platform};

fn load_engine(fixture: &SigmaFixture, platform: Platform) -> Engine {
    let mut engine = Engine::new_for_platform(platform);
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
        r#"title: Parity Network CIDR
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
    let engine = load_engine(&fixture, Platform::Linux);
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("network event should normalize");

    let alert = engine
        .check_event(&normalized)
        .expect("cidr + port rule should match");
    assert_eq!(alert.rule_name, "Parity Network CIDR");
}

#[test]
fn out_of_range_cidr_does_not_alert() {
    let fixture = SigmaFixture::new();
    // The destination (198.51.100.10) is outside 10.0.0.0/8; only the source
    // IP is in that range, and the rule matches on DestinationIp.
    fixture.write_rule(
        "net_miss.yml",
        r#"title: Parity Network Miss
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
    let engine = load_engine(&fixture, Platform::Linux);
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("network event should normalize");

    assert!(
        engine.check_event(&normalized).is_none(),
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
        r#"title: Parity Process ContainsAll Regex
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
    let engine = load_engine(&fixture, Platform::Linux);
    let harness = TestNormalizer::new(false);
    let normalized = harness
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .expect("process event should normalize");

    let alert = engine
        .check_event(&normalized)
        .expect("contains|all + re rule should match");
    assert_eq!(alert.rule_name, "Parity Process ContainsAll Regex");
}
