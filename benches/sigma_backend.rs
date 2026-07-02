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
use rustinel::engine::Engine;
use rustinel::models::{EventCategory, EventFields, NormalizedEvent};
use rustinel::sensor::Platform;
use tempfile::TempDir;

#[cfg(feature = "rsigma-engine")]
const BACKEND: &str = "rsigma";
#[cfg(not(feature = "rsigma-engine"))]
const BACKEND: &str = "builtin";

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
    let mut engine = Engine::new_for_platform(Platform::Linux);
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

criterion_group!(benches, bench_check_event);
criterion_main!(benches);
