//! Throughput benchmark for `Engine::check_event`.
//!
//! The Sigma backend is selected at compile time, so this benchmark measures
//! whichever engine is built. Compare the two by running it once per backend:
//!
//! ```sh
//! cargo bench --bench sigma_backend                          # built-in
//! cargo bench --bench sigma_backend --features rsigma-engine # RSigma
//! ```
//!
//! Results are labelled with the active backend so the two runs do not clobber
//! each other's Criterion baselines.

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rustinel::engine::{Engine, SigmaEngineKind};
use rustinel::models::{EventCategory, EventFields, MatchDebugLevel, NormalizedEvent};
use rustinel::sensor::Platform;
use tempfile::TempDir;

#[cfg(feature = "rsigma-engine")]
const ENGINE_KIND: SigmaEngineKind = SigmaEngineKind::Rsigma;
#[cfg(not(feature = "rsigma-engine"))]
const ENGINE_KIND: SigmaEngineKind = SigmaEngineKind::Builtin;

#[cfg(feature = "rsigma-engine")]
const BACKEND: &str = "rsigma";
#[cfg(not(feature = "rsigma-engine"))]
const BACKEND: &str = "builtin";

fn engine() -> Engine {
    Engine::new_for_platform_with_logging_level_and_match_debug(
        Platform::Linux,
        "info",
        MatchDebugLevel::Off,
        ENGINE_KIND,
    )
}

/// A representative Linux ruleset covering the common logsource families and
/// the modifiers Rustinel rules lean on (`endswith`, `contains`, `cidr`).
fn write_rules(dir: &std::path::Path) {
    let rules = [
        (
            "process.yml",
            r#"title: Bench Process Curl
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
    CommandLine|contains: example.test
  condition: selection
level: high
"#,
        ),
        (
            "network.yml",
            r#"title: Bench Network CIDR
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: 198.51.100.0/24
  condition: selection
level: medium
"#,
        ),
        (
            "file.yml",
            r#"title: Bench File Script
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|endswith: .sh
  condition: selection
level: low
"#,
        ),
        (
            "dns.yml",
            r#"title: Bench DNS Domain
logsource:
  product: linux
  category: dns_query
detection:
  selection:
    QueryName|contains: example.test
  condition: selection
level: medium
"#,
        ),
    ];
    for (name, yaml) in rules {
        std::fs::write(dir.join(name), yaml).expect("write bench rule");
    }
}

/// Number of synthetic, non-matching rules written per logsource family for the
/// large-ruleset benchmark. With four families this yields ~4x this many rules,
/// so each candidate bucket holds a few hundred rules, the regime where an
/// inverted rule index matters.
const SYNTHETIC_RULES_PER_FAMILY: usize = 500;

/// Writes the matching ruleset plus a large set of synthetic rules that never
/// match the sample events, so `check_event` pays the cost of scanning a
/// realistically sized bucket before its one hit (or miss).
fn write_scaled_rules(dir: &std::path::Path, per_family: usize) {
    write_rules(dir);
    for i in 0..per_family {
        std::fs::write(
            dir.join(format!("synth_process_{i}.yml")),
            format!(
                "title: Synth Process {i}\n\
                 logsource:\n  product: linux\n  category: process_creation\n\
                 detection:\n  selection:\n    Image|endswith: /synthbin{i}\n\
                 \x20   CommandLine|contains: synthtoken{i}\n  condition: selection\nlevel: low\n"
            ),
        )
        .expect("write synthetic process rule");
        std::fs::write(
            dir.join(format!("synth_network_{i}.yml")),
            format!(
                "title: Synth Network {i}\n\
                 logsource:\n  product: linux\n  category: network_connection\n\
                 detection:\n  selection:\n    DestinationIp|cidr: 203.0.113.{octet}/32\n\
                 \x20 condition: selection\nlevel: low\n",
                octet = i % 256
            ),
        )
        .expect("write synthetic network rule");
        std::fs::write(
            dir.join(format!("synth_file_{i}.yml")),
            format!(
                "title: Synth File {i}\n\
                 logsource:\n  product: linux\n  category: file_event\n\
                 detection:\n  selection:\n    TargetFilename|endswith: .synth{i}\n\
                 \x20 condition: selection\nlevel: low\n"
            ),
        )
        .expect("write synthetic file rule");
        std::fs::write(
            dir.join(format!("synth_dns_{i}.yml")),
            format!(
                "title: Synth Dns {i}\n\
                 logsource:\n  product: linux\n  category: dns_query\n\
                 detection:\n  selection:\n    QueryName|contains: synth{i}.invalid\n\
                 \x20 condition: selection\nlevel: low\n"
            ),
        )
        .expect("write synthetic dns rule");
    }
}

fn event(category: EventCategory, event_id: u16, fields: &[(&str, &str)]) -> NormalizedEvent {
    let mut map = HashMap::new();
    for (key, value) in fields {
        map.insert((*key).to_string(), (*value).to_string());
    }
    NormalizedEvent {
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        platform: Platform::Linux,
        provider: "bench".to_string(),
        category,
        event_id,
        event_id_string: event_id.to_string(),
        opcode: 0,
        fields: EventFields::Generic(map),
        process_context: None,
    }
}

fn sample_events() -> Vec<NormalizedEvent> {
    vec![
        event(
            EventCategory::Process,
            1,
            &[
                ("Image", "/usr/bin/curl"),
                ("CommandLine", "/usr/bin/curl https://example.test"),
                ("User", "alice"),
            ],
        ),
        event(
            EventCategory::Network,
            3,
            &[
                ("DestinationIp", "198.51.100.10"),
                ("DestinationPort", "443"),
                ("SourceIp", "10.0.0.5"),
            ],
        ),
        event(
            EventCategory::File,
            11,
            &[
                ("TargetFilename", "/tmp/payload.sh"),
                ("Image", "/usr/bin/bash"),
            ],
        ),
        event(
            EventCategory::Dns,
            22,
            &[
                ("QueryName", "example.test"),
                ("QueryResults", "198.51.100.10"),
            ],
        ),
        // A process event that matches nothing, exercising the miss path.
        event(
            EventCategory::Process,
            1,
            &[("Image", "/usr/bin/ls"), ("CommandLine", "ls -la")],
        ),
    ]
}

fn bench_check_event(c: &mut Criterion) {
    let tempdir = TempDir::new().expect("bench tempdir");
    write_rules(tempdir.path());
    let mut engine = engine();
    engine
        .load_rules(tempdir.path())
        .expect("bench rules should load");
    let events = sample_events();

    c.bench_function(&format!("check_event/{BACKEND}/mixed"), |b| {
        b.iter(|| {
            for ev in &events {
                black_box(engine.check_event(black_box(ev)));
            }
        });
    });
}

fn bench_check_event_large(c: &mut Criterion) {
    let tempdir = TempDir::new().expect("bench tempdir");
    write_scaled_rules(tempdir.path(), SYNTHETIC_RULES_PER_FAMILY);
    let mut engine = engine();
    engine
        .load_rules(tempdir.path())
        .expect("bench rules should load");
    let events = sample_events();

    c.bench_function(&format!("check_event/{BACKEND}/large"), |b| {
        b.iter(|| {
            for ev in &events {
                black_box(engine.check_event(black_box(ev)));
            }
        });
    });
}

criterion_group!(benches, bench_check_event, bench_check_event_large);
criterion_main!(benches);
