//! Single-alert selection policy.
//!
//! Rustinel emits at most one Sigma alert per event. When several rules match,
//! the winner is the highest normalized severity, with equal severities broken
//! deterministically by rule id and then rule title. These tests pin that
//! policy and assert it does not depend on the order rules were loaded in.

#[cfg(test)]
mod common;

use std::time::Instant;

use common::{process_start_event, SigmaFixture, TestNormalizer};
use rustinel::engine::Engine;
use rustinel::models::{AlertSeverity, MatchDebugLevel, NormalizedEvent};
use rustinel::sensor::Platform;

fn engine_with(fixture: &SigmaFixture) -> Engine {
    let mut engine =
        Engine::new_for_platform_with_match_debug(Platform::Linux, MatchDebugLevel::Off);
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

fn linux_process_event() -> NormalizedEvent {
    TestNormalizer::new(false)
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .expect("process event should normalize")
}

/// A rule matching the Linux process fixture (`/usr/bin/curl`).
fn matching_rule(title: &str, id: &str, level: &str) -> String {
    format!(
        r#"title: {title}
id: {id}
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
  condition: selection
level: {level}
"#
    )
}

/// Load order is directory-traversal dependent, so both rules of a pair live in
/// one multi-document file where document order is the load order.
fn rules_file(first: &str, second: &str) -> String {
    format!("{first}---\n{second}")
}

#[test]
fn higher_severity_rule_wins_regardless_of_load_order() {
    let low = matching_rule(
        "Broad Low Rule",
        "11111111-1111-1111-1111-111111111111",
        "low",
    );
    let critical = matching_rule(
        "Specific Critical Rule",
        "22222222-2222-2222-2222-222222222222",
        "critical",
    );
    let normalized = linux_process_event();

    for (order, yaml) in [
        ("low first", rules_file(&low, &critical)),
        ("critical first", rules_file(&critical, &low)),
    ] {
        let fixture = SigmaFixture::new();
        fixture.write_rule("overlapping.yml", &yaml);

        let engine = engine_with(&fixture);
        let alert = engine
            .check_event(&normalized)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("an overlapping rule should match ({order})"));

        assert_eq!(
            alert.severity,
            AlertSeverity::Critical,
            "low severity must not shadow critical ({order})"
        );
        assert_eq!(alert.rule_name, "Specific Critical Rule", "{order}");
    }
}

#[test]
fn equal_severity_ties_break_on_rule_id() {
    let first_id = matching_rule(
        "Zulu Titled Rule",
        "11111111-1111-1111-1111-111111111111",
        "high",
    );
    let second_id = matching_rule(
        "Alpha Titled Rule",
        "99999999-9999-9999-9999-999999999999",
        "high",
    );
    let normalized = linux_process_event();

    for (order, yaml) in [
        ("ascending", rules_file(&first_id, &second_id)),
        ("descending", rules_file(&second_id, &first_id)),
    ] {
        let fixture = SigmaFixture::new();
        fixture.write_rule("tie.yml", &yaml);

        let engine = engine_with(&fixture);
        let alert = engine
            .check_event(&normalized)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("a tied rule should match ({order})"));

        // The smallest rule id wins, not the smallest title and not the
        // first rule loaded.
        assert_eq!(
            alert.rule_name, "Zulu Titled Rule",
            "equal severity must resolve on rule id ({order})"
        );
    }
}

#[test]
fn equal_severity_prefers_a_rule_carrying_an_id() {
    let with_id = matching_rule(
        "Identified Rule",
        "99999999-9999-9999-9999-999999999999",
        "high",
    );
    let without_id = r#"title: Anonymous Rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
  condition: selection
level: high
"#;
    let normalized = linux_process_event();

    for (order, yaml) in [
        ("identified first", rules_file(&with_id, without_id)),
        ("anonymous first", rules_file(without_id, &with_id)),
    ] {
        let fixture = SigmaFixture::new();
        fixture.write_rule("identity.yml", &yaml);

        let engine = engine_with(&fixture);
        let alert = engine
            .check_event(&normalized)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("a tied rule should match ({order})"));

        assert_eq!(
            alert.rule_name, "Identified Rule",
            "an identified rule must win an otherwise equal tie ({order})"
        );
    }
}

/// Selecting the best match means every candidate rule is evaluated instead of
/// returning on the first hit. This bounds that cost so a regression to
/// super-linear candidate evaluation fails the suite. The budget is loose
/// enough for an unoptimized test build on a loaded CI runner.
#[test]
fn candidate_evaluation_stays_within_a_per_event_budget() {
    const SHADOW_RULES: usize = 500;
    const EVENTS: usize = 500;
    const BUDGET_PER_EVENT: std::time::Duration = std::time::Duration::from_millis(5);

    let mut documents = vec![matching_rule(
        "Budget Critical Rule",
        "00000000-0000-0000-0000-000000000000",
        "critical",
    )];
    for index in 0..SHADOW_RULES {
        documents.push(format!(
            r#"title: Budget Shadow Rule {index}
id: 10000000-0000-0000-0000-{index:012}
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /no-such-binary-{index}
  condition: selection
level: low
"#
        ));
    }

    let fixture = SigmaFixture::new();
    fixture.write_rule("budget.yml", &documents.join("---\n"));
    let normalized = linux_process_event();

    let engine = engine_with(&fixture);
    assert_eq!(
        engine.stats().total_rules,
        SHADOW_RULES + 1,
        "every budget rule should load"
    );

    let start = Instant::now();
    for _ in 0..EVENTS {
        let alert = engine
            .check_event(&normalized)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("the critical rule should match"));
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed < BUDGET_PER_EVENT * EVENTS as u32,
        "evaluating {} candidate rules took {:?} for {EVENTS} events ), over the {:?} per-event budget",
        SHADOW_RULES + 1,
        elapsed,
        BUDGET_PER_EVENT
    );
}
