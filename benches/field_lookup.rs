//! Cost of one default-view field lookup, the path every Sigma field read uses.
//!
//! The view consults the field availability contract before answering, so
//! its cost tracks how far into `FIELD_AVAILABILITY` the event's contract sits.
//! The table is grouped by platform and searched one platform at a time;
//! without that, adding event families for one platform slows down every other
//! platform's detection hot path. These cases cover a contract found
//! immediately, one found deep in its platform's rows, and one that does not
//! exist.
//!
//! ```sh
//! cargo bench --bench field_lookup
//! ```

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rustinel::models::{EventCategory, EventFields, NormalizedEvent};
use rustinel::sensor::Platform;

fn event(
    platform: Platform,
    provider: &str,
    category: EventCategory,
    event_id: u16,
    opcode: u8,
    fields: &[(&str, &str)],
) -> NormalizedEvent {
    let mut map = HashMap::new();
    for (key, value) in fields {
        map.insert((*key).to_string(), (*value).to_string());
    }
    NormalizedEvent {
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        source_seq: None,
        ingest_seq: 0,
        platform,
        provider: provider.to_string(),
        category,
        event_id,
        event_id_string: event_id.to_string(),
        opcode,
        fields: EventFields::Generic(map),
        process_name: None,
        provenance: Default::default(),
        process_context: None,
    }
}

fn bench(c: &mut Criterion) {
    let fields = [
        ("Image", "/usr/bin/curl"),
        ("CommandLine", "/usr/bin/curl https://example.test"),
        ("User", "alice"),
    ];
    let keys = ["Image", "CommandLine", "User", "ParentImage"];

    // A real Linux ebpf process event. Its contract sits after every Windows
    // row, so this case is what regresses if the search stops being scoped to
    // one platform.
    let linux = event(
        Platform::Linux,
        "ebpf",
        EventCategory::Process,
        1,
        1,
        &fields,
    );
    // A real Windows process start: opcode 1 is what its contract is keyed on,
    // so it matches the first row of the table.
    let windows = event(
        Platform::Windows,
        "etw",
        EventCategory::Process,
        1,
        1,
        &fields,
    );
    // A Windows Security audit event. The Security channel carries many event
    // IDs, so its contracts sit deep in the Windows rows.
    let windows_security = event(
        Platform::Windows,
        "windows_event_log",
        EventCategory::Security,
        4624,
        0,
        &[("TargetUserName", "bob"), ("LogonType", "3")],
    );
    // No contract matches this provider, so the lookup scans every row of the
    // platform.
    let unmatched = event(
        Platform::Linux,
        "bench",
        EventCategory::Process,
        1,
        1,
        &fields,
    );

    for (name, sample) in [
        ("linux_ebpf_process", &linux),
        ("windows_etw_process", &windows),
        ("windows_security_4624", &windows_security),
        ("unmatched_provider", &unmatched),
    ] {
        c.bench_function(name, |b| {
            b.iter(|| {
                for key in keys {
                    black_box(black_box(sample).get_field(black_box(key)));
                }
            })
        });
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
