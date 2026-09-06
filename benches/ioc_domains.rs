//! Throughput benchmark for wildcard-domain IOC matching.
//!
//! Wildcard indicators (`*.example.com`) are indexed by suffix, so lookup cost
//! should track hostname depth, not feed size. The small and 100,000-entry
//! feeds below are the two ends of that comparison: threat feeds of the latter
//! size are common, and the previous linear scan made every eligible event pay
//! for the whole feed.
//!
//! ```sh
//! cargo bench --bench ioc_domains
//! ```

use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rustinel::config::IocConfig;
use rustinel::ioc::IocEngine;
use rustinel::models::{DnsQueryFields, EventCategory, EventFields, NormalizedEvent};
use rustinel::sensor::Platform;
use tempfile::TempDir;

const SMALL_FEED: usize = 100;
const LARGE_FEED: usize = 100_000;

/// A wildcard feed of `count` distinct suffixes, none of which match the
/// hostnames benchmarked below, plus one indicator that does.
fn write_feed(dir: &Path, count: usize) -> PathBuf {
    let mut feed = String::from("# IOC Type: Domains\n");
    for i in 0..count {
        feed.push_str(&format!("*.feed{i}.invalid;bench\n"));
    }
    feed.push_str("*.malware.test;bench hit\n");

    let path = dir.join("domains.txt");
    std::fs::write(&path, feed).expect("write domain feed");
    path
}

fn engine_with_feed(dir: &Path, count: usize) -> IocEngine {
    let domains_path = write_feed(dir, count);
    IocEngine::load(&IocConfig {
        enabled: true,
        hashes_path: dir.join("hashes.txt"),
        ips_path: dir.join("ips.txt"),
        domains_path,
        paths_regex_path: dir.join("paths.txt"),
        default_severity: "high".to_string(),
        max_file_size_mb: 0,
        hash_allowlist_paths: Vec::new(),
    })
}

fn dns_event(query_name: &str) -> NormalizedEvent {
    NormalizedEvent {
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        platform: Platform::Linux,
        provider: "bench".to_string(),
        category: EventCategory::Dns,
        event_id: 22,
        event_id_string: "22".to_string(),
        opcode: 0,
        fields: EventFields::DnsQuery(DnsQueryFields {
            query_name: Some(query_name.to_string()),
            query_results: None,
            record_type: None,
            query_status: None,
            process_id: None,
            image: None,
        }),
        process_context: None,
    }
}

fn bench_domain_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("ioc_domain_match");

    for count in [SMALL_FEED, LARGE_FEED] {
        let dir = TempDir::new().expect("temp dir");
        let engine = engine_with_feed(dir.path(), count);

        // The common case: an ordinary hostname no indicator covers, which
        // used to walk the entire feed before concluding nothing matched.
        let miss = dns_event("cdn.assets.example.org");
        group.bench_with_input(BenchmarkId::new("miss", count), &count, |b, _| {
            b.iter(|| black_box(engine.check_event(black_box(&miss))));
        });

        let hit = dns_event("beacon.c2.malware.test");
        group.bench_with_input(BenchmarkId::new("hit", count), &count, |b, _| {
            b.iter(|| black_box(engine.check_event(black_box(&hit))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_domain_matching);
criterion_main!(benches);
