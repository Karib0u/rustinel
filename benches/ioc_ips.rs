//! Throughput benchmark for CIDR IOC matching.
//!
//! CIDR indicators are indexed by address family and prefix length, so lookup
//! cost is bounded by the number of possible prefix lengths rather than feed
//! size.
//!
//! ```sh
//! cargo bench --bench ioc_ips
//! ```

use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rustinel::config::IocConfig;
use rustinel::ioc::IocEngine;
use rustinel::models::{
    CanonicalEvent, EventCategory, EventFields, NetworkConnectionFields, NormalizedEvent,
};
use rustinel::sensor::Platform;
use tempfile::TempDir;

fn write_feed(dir: &Path, count: usize) -> PathBuf {
    let mut feed = String::new();
    for i in 0..count {
        let second = (i / (256 * 256)) % 256;
        let third = (i / 256) % 256;
        let fourth = i % 256;
        feed.push_str(&format!("10.{second}.{third}.{fourth}/32;bench\n"));
    }
    feed.push_str("198.51.100.0/24;bench hit\n");

    let path = dir.join("ips.txt");
    std::fs::write(&path, feed).expect("write IP feed");
    path
}

fn engine_with_feed(dir: &Path, count: usize) -> IocEngine {
    IocEngine::load(&IocConfig {
        enabled: true,
        hashes_path: dir.join("hashes.txt"),
        ips_path: write_feed(dir, count),
        domains_path: dir.join("domains.txt"),
        paths_regex_path: dir.join("paths.txt"),
        default_severity: "high".to_string(),
        max_file_size_mb: 0,
        hash_allowlist_paths: Vec::new(),
    })
}

fn network_event(destination_ip: &str) -> CanonicalEvent {
    CanonicalEvent::from_normalized(NormalizedEvent {
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        source_seq: None,
        ingest_seq: 0,
        platform: Platform::Linux,
        provider: "bench".to_string(),
        category: EventCategory::Network,
        event_id: 1,
        event_id_string: "1".to_string(),
        opcode: 0,
        fields: EventFields::NetworkConnection(NetworkConnectionFields {
            destination_ip: Some(destination_ip.to_string()),
            source_ip: None,
            destination_port: Some("443".to_string()),
            source_port: None,
            process_id: None,
            image: None,
            user: None,
            destination_hostname: None,
            protocol: None,
            initiated: None,
        }),
        process_name: None,
        provenance: Default::default(),
        process_context: None,
    })
}

fn bench_ip_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("ioc_cidr_match");

    for count in [100, 10_000, 100_000] {
        let dir = TempDir::new().expect("temp dir");
        let engine = engine_with_feed(dir.path(), count);

        let miss = network_event("203.0.113.10");
        group.bench_with_input(BenchmarkId::new("miss", count), &count, |b, _| {
            b.iter(|| black_box(engine.check_event(black_box(&miss))));
        });

        let hit = network_event("198.51.100.10");
        group.bench_with_input(BenchmarkId::new("hit", count), &count, |b, _| {
            b.iter(|| black_box(engine.check_event(black_box(&hit))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_ip_matching);
criterion_main!(benches);
