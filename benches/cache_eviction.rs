//! Eviction cost for the bounded, timestamp-ordered caches.
//!
//! Cache timestamps have second precision, so a burst of inserts usually shares
//! one timestamp. This benchmark contrasts inserting into a cache that is at its
//! cap (every insert may trigger a trim) with inserting into one that has spare
//! capacity, using `DnsCache` as the representative implementation.
//!
//! ```sh
//! cargo bench --bench cache_eviction
//! ```

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustinel::state::DnsCache;

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

criterion_group!(benches, bench_dns_inserts);
criterion_main!(benches);
