//! Cost of IOC matching for every indicator kind.
//!
//! Every event reaching detection is walked once for observables, then matched
//! against loaded domain, IP, and path indicators; computed file hashes are
//! matched through the same code. The feeds below hold 100,000 wildcard
//! domains, 1,000 exact domains, 1,000 exact IPs, 100 CIDRs, 100 path regexes,
//! and 10,000 hashes of each algorithm.
//!
//! - `ioc_event_miss`: no indicator matches, the case paid on every event. The
//!   DNS, network, and file events carry only fields matched before observable
//!   extraction; the process and script events also carry text fields it added.
//! - `ioc_event_hit`: one indicator of each event-matched kind fires.
//! - `ioc_hash`: computed MD5, SHA1, and SHA256 all miss, or all hit.
//! - `ioc_hash_only_feed`: an event checked by an engine loaded with hashes only.
//!
//! ```sh
//! cargo bench --bench ioc_observables
//! ```

use std::hint::black_box;
use std::path::Path;

use criterion::{criterion_group, criterion_main, Criterion};
use rustinel::config::IocConfig;
use rustinel::ioc::{ComputedHashes, IocEngine};
use rustinel::models::{
    CanonicalEvent, DnsQueryFields, EventCategory, EventFields, FileEventFields,
    NetworkConnectionFields, NormalizedEvent, PowerShellScriptFields, ProcessCreationFields,
};
use rustinel::sensor::Platform;
use tempfile::TempDir;

const HIT_MD5: &str = "0c2674c3a97c53082187d930efb645c2";
const HIT_SHA1: &str = "3f786850e387550fdab836ed7e6dc881de23001b";
const HIT_SHA256: &str = "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef";

fn hash_feed() -> String {
    let mut hashes = String::new();
    for i in 0..10_000u64 {
        hashes.push_str(&format!("{i:032x};bench\n{i:040x};bench\n{i:064x};bench\n"));
    }
    hashes.push_str(&format!(
        "{HIT_MD5};hit\n{HIT_SHA1};hit\n{HIT_SHA256};hit\n"
    ));
    hashes
}

fn engine(dir: &Path) -> IocEngine {
    let mut domains = String::from("# IOC Type: Domains\n");
    for i in 0..100_000 {
        domains.push_str(&format!("*.feed{i}.invalid;bench\n"));
    }
    for i in 0..1_000 {
        domains.push_str(&format!("host{i}.exact.invalid;bench\n"));
    }
    domains.push_str("*.malware.test;hit\nc2.exact.test;hit\n");
    let mut ips = String::new();
    for i in 0..1_000u32 {
        ips.push_str(&format!("10.{}.{}.1;bench\n", i / 256, i % 256));
    }
    for i in 0..100u32 {
        ips.push_str(&format!("172.16.{i}.0/24;bench\n"));
    }
    ips.push_str("203.0.113.7;hit\n100.64.0.0/16;hit\n");
    let mut paths = String::new();
    for i in 0..100 {
        paths.push_str(&format!(r"(?i)\\feed{i}\\payload\.exe$;bench"));
        paths.push('\n');
    }
    paths.push_str("(?i)\\\\staging\\\\dropper\\.exe$;hit\n");

    let write = |name: &str, body: &str| {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write feed");
        path
    };
    IocEngine::load(&IocConfig {
        enabled: true,
        hashes_path: write("hashes.txt", &hash_feed()),
        ips_path: write("ips.txt", &ips),
        domains_path: write("domains.txt", &domains),
        paths_regex_path: write("paths.txt", &paths),
        default_severity: "high".to_string(),
        max_file_size_mb: 0,
        hash_allowlist_paths: Vec::new(),
    })
}

fn hash_only_engine(dir: &Path) -> IocEngine {
    let write = |name: &str, body: &str| {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write feed");
        path
    };
    IocEngine::load(&IocConfig {
        enabled: true,
        hashes_path: write("hashes-only.txt", &hash_feed()),
        ips_path: write("ips-empty.txt", ""),
        domains_path: write("domains-empty.txt", ""),
        paths_regex_path: write("paths-empty.txt", ""),
        default_severity: "high".to_string(),
        max_file_size_mb: 0,
        hash_allowlist_paths: Vec::new(),
    })
}

fn event(platform: Platform, category: EventCategory, fields: EventFields) -> CanonicalEvent {
    CanonicalEvent::from_normalized(NormalizedEvent {
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        source_seq: None,
        ingest_seq: 0,
        platform,
        provider: "bench".to_string(),
        category,
        event_id: 1,
        event_id_string: "1".to_string(),
        opcode: 0,
        fields,
        process_name: None,
        provenance: Default::default(),
        process_context: None,
    })
}

fn dns() -> CanonicalEvent {
    dns_query("cdn.assets.example.org")
}

fn dns_query(query_name: &str) -> CanonicalEvent {
    event(
        Platform::Windows,
        EventCategory::Dns,
        EventFields::DnsQuery(DnsQueryFields {
            user: None,
            query_name: Some(query_name.to_string()),
            query_results: Some(
                "type: 5 cdn.example.net;::ffff:192.0.2.10;192.0.2.11;".to_string(),
            ),
            record_type: None,
            query_status: None,
            process_id: None,
            image: None,
        }),
    )
}

fn network() -> CanonicalEvent {
    connection("192.0.2.80")
}

fn connection(destination_ip: &str) -> CanonicalEvent {
    event(
        Platform::Linux,
        EventCategory::Network,
        EventFields::NetworkConnection(NetworkConnectionFields {
            destination_ip: Some(destination_ip.to_string()),
            source_ip: Some("198.51.100.4".to_string()),
            destination_port: Some("443".to_string()),
            source_port: Some("51234".to_string()),
            process_id: None,
            image: None,
            user: None,
            destination_hostname: Some("api.example.org".to_string()),
            protocol: None,
            initiated: None,
        }),
    )
}

fn file() -> CanonicalEvent {
    file_at(r"C:\Users\alice\AppData\Local\Temp\setup.tmp")
}

fn file_at(target: &str) -> CanonicalEvent {
    event(
        Platform::Windows,
        EventCategory::File,
        EventFields::FileEvent(FileEventFields {
            source_filename: None,
            target_filename: Some(target.to_string()),
            process_id: None,
            image: None,
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: None,
            file_identity: None,
            path_truncated: None,
        }),
    )
}

fn process() -> CanonicalEvent {
    event(
        Platform::Windows,
        EventCategory::Process,
        EventFields::ProcessCreation(ProcessCreationFields {
            linux_identity: Default::default(),
            cgroup_id: None,
            exec: Default::default(),
            parent_process_id_derived: false,
            windows: Default::default(),
            image: Some(r"C:\Program Files\Git\mingw64\bin\git.exe".to_string()),
            image_source: None,
            image_truncated: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: Some(
                r#""C:\Program Files\Git\mingw64\bin\git.exe" -c credential.helper= fetch --prune origin https://github.com/example/repo.git src\main.rs"#
                    .to_string(),
            ),
            process_id: Some("4242".to_string()),
            process_start_time: None,
            parent_process_id: Some("4000".to_string()),
            parent_image: Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string()),
            parent_command_line: None,
            current_directory: Some(r"C:\Users\alice\source\repo\".to_string()),
            integrity_level: None,
            user: None,
        }),
    )
}

fn script() -> CanonicalEvent {
    let block = r#"$ErrorActionPreference = 'Stop'
$client = New-Object System.Net.WebClient
$target = Join-Path $env:TEMP "update.zip"
$client.DownloadFile("https://updates.example.org/agent/latest.zip", $target)
Expand-Archive -Path $target -DestinationPath "C:\ProgramData\Agent" -Force
Start-Process -FilePath "C:\ProgramData\Agent\agent.exe" -ArgumentList '--server', '192.0.2.44:8443'
"#
    .repeat(4);
    event(
        Platform::Windows,
        EventCategory::Scripting,
        EventFields::PowerShellScript(PowerShellScriptFields {
            script_block_text: Some(block),
            script_block_id: None,
            path: Some(r"C:\ProgramData\Agent\install.ps1".to_string()),
            process_id: None,
            image: None,
            user: None,
        }),
    )
}

fn bench_event_shapes(c: &mut Criterion) {
    let dir = TempDir::new().expect("temp dir");
    let engine = engine(dir.path());
    let mut group = c.benchmark_group("ioc_event_miss");

    for (name, event) in [
        ("dns", dns()),
        ("network", network()),
        ("file", file()),
        ("process", process()),
        ("powershell_script", script()),
    ] {
        assert!(engine.check_event(&event).is_empty(), "{name} should miss");
        group.bench_function(name, |b| {
            b.iter(|| black_box(engine.check_event(black_box(&event))));
        });
    }

    group.finish();
}

/// Extraction alone, without matching, to separate the cost of reading an
/// event from the cost of the indicator lookups it feeds.
fn bench_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("observable_extract");

    for (name, event) in [
        ("dns", dns()),
        ("network", network()),
        ("file", file()),
        ("process", process()),
        ("powershell_script", script()),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| black_box(black_box(&event).observables().len()));
        });
    }

    group.finish();
}

fn bench_event_hits(c: &mut Criterion) {
    let dir = TempDir::new().expect("temp dir");
    let engine = engine(dir.path());
    let mut group = c.benchmark_group("ioc_event_hit");

    for (name, event, expected) in [
        ("domain_exact", dns_query("c2.exact.test"), 1),
        ("domain_suffix", dns_query("beacon.malware.test"), 1),
        ("ip_exact", connection("203.0.113.7"), 1),
        ("ip_cidr", connection("100.64.3.9"), 1),
        (
            "path_regex",
            file_at(r"C:\Users\alice\staging\dropper.exe"),
            1,
        ),
    ] {
        assert_eq!(engine.check_event(&event).len(), expected, "{name}");
        group.bench_function(name, |b| {
            b.iter(|| black_box(engine.check_event(black_box(&event))));
        });
    }

    group.finish();
}

fn bench_hashes(c: &mut Criterion) {
    let dir = TempDir::new().expect("temp dir");
    let engine = engine(dir.path());
    let hash_only = hash_only_engine(dir.path());
    let mut group = c.benchmark_group("ioc_hash");

    let miss = ComputedHashes {
        md5: Some("ffffffffffffffffffffffffffffffff".to_string()),
        sha1: Some("ffffffffffffffffffffffffffffffffffffffff".to_string()),
        sha256: Some("f".repeat(64)),
    };
    let hit = ComputedHashes {
        md5: Some(HIT_MD5.to_string()),
        sha1: Some(HIT_SHA1.to_string()),
        sha256: Some(HIT_SHA256.to_string()),
    };
    assert!(engine.match_hashes(&miss).is_empty());
    assert_eq!(engine.match_hashes(&hit).len(), 3);

    group.bench_function("miss", |b| {
        b.iter(|| black_box(engine.match_hashes(black_box(&miss))));
    });
    group.bench_function("hit", |b| {
        b.iter(|| black_box(engine.match_hashes(black_box(&hit))));
    });
    group.finish();

    let mut group = c.benchmark_group("ioc_hash_only_feed");
    for (name, event) in [("process", process()), ("dns", dns())] {
        assert!(hash_only.check_event(&event).is_empty());
        group.bench_function(name, |b| {
            b.iter(|| black_box(hash_only.check_event(black_box(&event))));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_event_shapes,
    bench_event_hits,
    bench_hashes,
    bench_extraction
);
criterion_main!(benches);
