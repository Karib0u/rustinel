//! Feeds recorded ring buffer records through the real `drain_*_ring` functions.
//!
//! Fixtures live in `tests/fixtures/linux_ring`: a `provenance` block and a list
//! of `{"ring", "hex"}` records in arrival order, the same lines
//! `RUSTINEL_EBPF_RECORD` writes. See `docs/development.md`.

use std::collections::VecDeque;

use serde_json::Value;
use tokio::sync::mpsc;

use super::*;

struct Recorded(VecDeque<Vec<u8>>);

impl RingSource for Recorded {
    fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
        self.0.pop_front()
    }
}

fn load(name: &str, ring: &str) -> Recorded {
    let path = format!(
        "{}/tests/fixtures/linux_ring/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(
        doc["provenance"]["scenario"].is_string(),
        "{name}: provenance needs a scenario"
    );
    let records = doc["records"].as_array().unwrap();
    Recorded(
        records
            .iter()
            .map(|r| {
                assert_eq!(r["ring"], ring, "{name}: record from the wrong ring");
                hex::decode(r["hex"].as_str().unwrap()).unwrap()
            })
            .collect(),
    )
}

struct Counts {
    received: u64,
    decoded: u64,
    short_reads: u64,
    internal: u64,
    emitted: u64,
    dropped: u64,
    unresolved: u64,
}

fn counts(telemetry: &LinuxEbpfCounters, ring: &str) -> Counts {
    telemetry.activate();
    let snapshot = telemetry.snapshot().unwrap();
    let f = snapshot.families.iter().find(|f| f.ring == ring).unwrap();
    Counts {
        received: f.userspace_received,
        decoded: f.userspace_decoded,
        short_reads: f.short_reads,
        internal: f.userspace_internal,
        emitted: f.canonical_emitted,
        dropped: f.userspace_dropped,
        unresolved: f.unresolved_file_events,
    }
}

fn drained(rx: &mut mpsc::Receiver<RawEvent>) -> Vec<RawEvent> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

#[test]
fn process_ring_fixture_decodes_exec_and_exit() {
    let mut ring = load("process", "process");
    let (tx, mut rx) = mpsc::channel(16);
    let telemetry = LinuxEbpfCounters::new();
    drain_process_ring(&mut ring, &tx, &telemetry, BootTimeConverter::capture());

    let events = drained(&mut rx);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].action, SensorAction::Start);
    assert!(events[0].pid.is_some());
    match &events[0].payload {
        RawPayload::Process(p) => {
            assert_eq!(p.image.as_deref(), Some("/usr/bin/bash"));
            assert_eq!(
                p.command_line.as_deref(),
                Some("bash -c id; echo hi > /tmp/ringfx-payload.sh")
            );
        }
        other => panic!("expected process payload, got {other:?}"),
    }
    assert_eq!(events[1].action, SensorAction::Start);
    assert_eq!(events[2].action, SensorAction::Stop);
    assert_eq!(events[2].pid, events[0].pid);

    let c = counts(&telemetry, "process");
    assert_eq!((c.received, c.decoded, c.short_reads), (4, 3, 1));
    assert_eq!((c.emitted, c.dropped), (3, 0));
}

#[test]
fn network_ring_fixture_decodes_connect() {
    let mut ring = load("network", "network");
    let (tx, mut rx) = mpsc::channel(16);
    let telemetry = LinuxEbpfCounters::new();
    drain_network_ring(&mut ring, &tx, &telemetry, BootTimeConverter::capture());

    let events = drained(&mut rx);
    assert_eq!(events.len(), 1);
    match &events[0].payload {
        RawPayload::Network(n) => {
            assert_eq!(n.destination_port.as_deref(), Some("53"));
            assert_eq!(n.protocol.as_deref(), Some("udp"));
        }
        other => panic!("expected network payload, got {other:?}"),
    }

    let c = counts(&telemetry, "network");
    assert_eq!((c.received, c.decoded, c.short_reads), (2, 1, 1));
    assert_eq!((c.emitted, c.dropped), (1, 0));
}

#[test]
fn file_ring_fixture_decodes_creates_and_internal_records() {
    let mut ring = load("file", "file");
    let (tx, mut rx) = mpsc::channel(16);
    let telemetry = LinuxEbpfCounters::new();
    let host = crate::state::HostState::default();
    let mut dir_fds = DirFdIndex::new();
    let mut unresolved = 0;
    drain_file_ring(
        &mut ring,
        &tx,
        &telemetry,
        &mut dir_fds,
        &mut unresolved,
        &host,
        BootTimeConverter::capture(),
    );

    let paths: Vec<String> = drained(&mut rx)
        .into_iter()
        .map(|e| match e.payload {
            RawPayload::File(f) => f.target_filename.unwrap_or_default(),
            other => panic!("expected file payload, got {other:?}"),
        })
        .collect();
    assert_eq!(paths, ["/var/tmp/ringfx", "/tmp/ringfx-payload.sh"]);

    assert_eq!(unresolved, 0);
    let c = counts(&telemetry, "file");
    assert_eq!((c.received, c.decoded, c.short_reads), (7, 6, 1));
    assert_eq!((c.internal, c.emitted, c.unresolved), (4, 2, 0));
}

#[test]
fn dns_ring_fixture_decodes_query_and_response() {
    let mut ring = load("dns", "dns");
    let (tx, mut rx) = mpsc::channel(16);
    let telemetry = LinuxEbpfCounters::new();
    drain_dns_ring(&mut ring, &tx, &telemetry, BootTimeConverter::capture());

    let events = drained(&mut rx);
    assert_eq!(events.len(), 2);
    match &events[0].payload {
        RawPayload::Dns(d) => assert_eq!(d.query_name.as_deref(), Some("example.com")),
        other => panic!("expected dns payload, got {other:?}"),
    }

    let c = counts(&telemetry, "dns");
    assert_eq!((c.received, c.decoded, c.short_reads), (3, 2, 1));
    assert_eq!(c.emitted, 2);
}

#[test]
fn recorded_lines_round_trip_through_the_fixture_format() {
    // `RUSTINEL_EBPF_RECORD` writes `{"ring":..,"hex":..}`; the fixtures hold the
    // same objects, so a recording can be pasted into `records` unchanged.
    let line = format!(
        "{{\"ring\":\"dns\",\"hex\":\"{}\"}}",
        hex::encode([1u8, 2, 3])
    );
    let v: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(hex::decode(v["hex"].as_str().unwrap()).unwrap(), [1, 2, 3]);
}
