//! Eviction cost for the bounded, timestamp-ordered caches.
//!
//! Cache timestamps have second precision, so a burst of inserts usually shares
//! one timestamp. This benchmark contrasts inserting into a cache that is at its
//! cap (every insert may trigger a trim) with inserting into one that has spare
//! capacity, using `DnsCache` as the representative implementation.
//! It also measures the stable-identity lookup and metadata copy for a burst of
//! 1,000 process-fork lineage updates.
//!
//! ```sh
//! cargo bench --bench cache_eviction
//! ```

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustinel::sensor::{
    Platform, ProcessStartKey, RawLinuxProcess, RawPayload, RawProcessEvent, RawProcessPlatform,
    SensorAction, SensorNormalization,
};
use rustinel::state::{DnsCache, HostState};

const CAPACITY: usize = 10_000;
const INSERTS: u32 = 1_000;

fn ip_for(index: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(index))
}

/// A cache holding `entries` mappings, all stamped within the same second.
fn filled_cache(entries: u32) -> DnsCache {
    let cache = DnsCache::with_limits(CAPACITY, 15 * 60);
    for index in 0..entries {
        cache.update(ip_for(index), "bench.example".to_string());
    }
    cache
}

fn bench_dns_inserts(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_cache_insert");
    group.throughput(criterion::Throughput::Elements(u64::from(INSERTS)));

    // At capacity: each insert overflows the cap and may trigger eviction.
    group.bench_function("at_capacity_same_second", |b| {
        b.iter_batched(
            || filled_cache(CAPACITY as u32),
            |cache| {
                for index in 0..INSERTS {
                    cache.update(
                        ip_for(CAPACITY as u32 + index),
                        black_box("bench.example").to_string(),
                    );
                }
                cache
            },
            BatchSize::LargeInput,
        );
    });

    // Spare capacity: the same inserts with no eviction at all, as a baseline.
    group.bench_function("with_spare_capacity", |b| {
        b.iter_batched(
            || filled_cache(CAPACITY as u32 - INSERTS),
            |cache| {
                for index in 0..INSERTS {
                    cache.update(
                        ip_for(CAPACITY as u32 + index),
                        black_box("bench.example").to_string(),
                    );
                }
                cache
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn fork_event(pid: u32) -> rustinel::sensor::RawEvent {
    rustinel::sensor::RawEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::Linux,
        provider: "ebpf",
        action: SensorAction::Fork,
        normalization: SensorNormalization {
            event_id: 0,
            action_code: 3,
        },
        pid: Some(pid),
        timestamp: SystemTime::UNIX_EPOCH,
        source_seq: None,
        process_start_key: Some(ProcessStartKey {
            pid,
            start_time: u64::from(pid),
        }),
        parent_process_start_key: Some(ProcessStartKey {
            pid: 1,
            start_time: 1,
        }),
        payload: RawPayload::Process(RawProcessEvent {
            process_id: pid,
            parent_process_id: Some(1),
            process_start_time: None,
            image: None,
            command_line: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            platform: Box::new(RawProcessPlatform::Linux(RawLinuxProcess {
                real_user_id: None,
                identity: Default::default(),
                cgroup_id: None,
                parent_process_id_derived: false,
                image_source: None,
                image_truncated: None,
            })),
        }),
    }
}

/// Measures the userspace cost added to each process fork by executable
/// inheritance, including stable-identity lookup and bounded-cache insertion.
fn bench_process_fork_inheritance(c: &mut Criterion) {
    c.bench_function("process_fork_inheritance", |b| {
        b.iter_batched(
            || {
                let host = HostState::default();
                host.processes.add(
                    1,
                    1,
                    "/usr/bin/server".into(),
                    Some("server --prefork".into()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                );
                let events = (2..=INSERTS + 1).map(fork_event).collect::<Vec<_>>();
                (host, events)
            },
            |(host, events)| {
                for event in events {
                    black_box(host.canonicalize(event));
                }
                host
            },
            BatchSize::LargeInput,
        );
    });
}

criterion_group!(benches, bench_dns_inserts, bench_process_fork_inheritance);
criterion_main!(benches);
