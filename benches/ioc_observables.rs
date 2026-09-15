//! Per-event cost of inline IOC matching across event shapes.
//!
//! Every event reaching detection is walked once for observables, then matched
//! against loaded domain, IP, and path indicators. The feeds below hold 100,000
//! wildcard domains, 1,000 exact IPs, 100 CIDRs, and 100 path regexes, and no
//! event matches, which is the common case and the one paid on every event.
//!
//! The DNS, network, and file events carry only fields matched before
//! observable extraction, so they measure its overhead directly. The process
//! and script events also carry the text fields extraction added.
//!
//! ```sh
//! cargo bench --bench ioc_observables
//! ```

use std::hint::black_box;
use std::path::Path;

use criterion::{criterion_group, criterion_main, Criterion};
use rustinel::config::IocConfig;
use rustinel::ioc::IocEngine;
use rustinel::models::{
    CanonicalEvent, DnsQueryFields, EventCategory, EventFields, FileEventFields,
    NetworkConnectionFields, NormalizedEvent, PowerShellScriptFields, ProcessCreationFields,
};
use rustinel::sensor::Platform;
use tempfile::TempDir;

fn engine(dir: &Path) -> IocEngine {
    let mut domains = String::from("# IOC Type: Domains\n");
    for i in 0..100_000 {
        domains.push_str(&format!("*.feed{i}.invalid;bench\n"));
    }
    let mut ips = String::new();
    for i in 0..1_000u32 {
        ips.push_str(&format!("10.{}.{}.1;bench\n", i / 256, i % 256));
    }
    for i in 0..100u32 {
        ips.push_str(&format!("172.16.{i}.0/24;bench\n"));
    }
    let mut paths = String::new();
    for i in 0..100 {
        paths.push_str(&format!(r"(?i)\\feed{i}\\payload\.exe$;bench"));
        paths.push('\n');
    }

    let write = |name: &str, body: &str| {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write feed");
        path
    };
    IocEngine::load(&IocConfig {
        enabled: true,
        hashes_path: write("hashes.txt", ""),
        ips_path: write("ips.txt", &ips),
        domains_path: write("domains.txt", &domains),
        paths_regex_path: write("paths.txt", &paths),
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
    event(
        Platform::Windows,
        EventCategory::Dns,
        EventFields::DnsQuery(DnsQueryFields {
            user: None,
            query_name: Some("cdn.assets.example.org".to_string()),
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
    event(
        Platform::Linux,
        EventCategory::Network,
        EventFields::NetworkConnection(NetworkConnectionFields {
            destination_ip: Some("192.0.2.80".to_string()),
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
    event(
        Platform::Windows,
        EventCategory::File,
        EventFields::FileEvent(FileEventFields {
            source_filename: None,
            target_filename: Some(r"C:\Users\alice\AppData\Local\Temp\setup.tmp".to_string()),
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
            hashes: None,
            imphash: None,
            container: Default::default(),
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

criterion_group!(benches, bench_event_shapes, bench_extraction);
criterion_main!(benches);
