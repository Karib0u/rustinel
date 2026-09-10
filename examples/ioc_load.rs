//! Measure IOC load time and retain the engine for external RSS measurement.
//! Run `cargo run --release --example ioc_load -- /path/to/domains.txt`.
//! The process exits when a line is read from stdin.

use rustinel::config::IocConfig;
use rustinel::ioc::IocEngine;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let domains_path = PathBuf::from(std::env::args_os().nth(1).expect("domain feed path"));
    let empty = tempfile::tempdir().expect("empty IOC directory");
    let config = IocConfig {
        enabled: true,
        hashes_path: empty.path().join("hashes.txt"),
        ips_path: empty.path().join("ips.txt"),
        domains_path,
        paths_regex_path: empty.path().join("paths.txt"),
        default_severity: "high".to_string(),
        max_file_size_mb: 0,
        hash_allowlist_paths: Vec::new(),
    };
    let start = Instant::now();
    let engine = IocEngine::load(&config);
    let elapsed = start.elapsed();
    println!(
        "pid={} exact={} suffix={} load_ms={:.3}",
        std::process::id(),
        engine.stats().domain_exact,
        engine.stats().domain_suffix,
        elapsed.as_secs_f64() * 1000.0
    );
    io::stdout().flush().expect("flush measurement");
    io::stdin()
        .read_line(&mut String::new())
        .expect("wait for input");
    std::hint::black_box(&engine);
}
