//! YARA byte and memory integration tests.
//!
//! Run CI-safe tests:
//! ```sh
//! cargo test --test yara_memory
//! ```
//!
//! Run ignored live memory tests manually after building the target binary:
//! ```sh
//! cargo build --example memory_target
//! cargo test --test yara_memory -- --include-ignored
//! ```

use rustinel::{
    memory::{read_process_memory_chunks, MemoryScanConfig},
    models::MatchDebugLevel,
    scanner::Scanner,
};
use std::{process::Stdio, time::Duration};

#[cfg(test)]
mod common;

use common::{YaraFixture, TEST_YARA_MARKER};

fn load_scanner(fixture: &YaraFixture) -> Scanner {
    fixture.write_default_rule();
    let scanner = Scanner::new(fixture.rules_dir()).expect("Scanner::new failed");
    assert_eq!(scanner.compiled_files(), 1, "expected one YARA rule file");
    scanner
}

fn memory_target_exe() -> &'static str {
    if cfg!(windows) {
        "target\\debug\\examples\\memory_target.exe"
    } else {
        "target/debug/examples/memory_target"
    }
}

fn default_mem_cfg() -> MemoryScanConfig {
    MemoryScanConfig {
        max_process_bytes: 64 * 1024 * 1024,
        max_region_bytes: 8 * 1024 * 1024,
        include_private: true,
        include_image: false,
        include_mapped: false,
        delay_ms: 0,
    }
}

#[test]
fn scan_bytes_detects_yara_marker() {
    let fixture = YaraFixture::new();
    let scanner = load_scanner(&fixture);
    let matches = scanner
        .scan_bytes(TEST_YARA_MARKER.as_bytes(), MatchDebugLevel::Off)
        .expect("scan_bytes failed");
    assert!(
        !matches.is_empty(),
        "expected a YARA match for the marker bytes"
    );
    assert_eq!(
        matches[0].rule, "TestMarkerString",
        "matched rule name should match the temp .yar fixture"
    );
}

#[test]
fn scan_bytes_no_false_positive() {
    let fixture = YaraFixture::new();
    let scanner = load_scanner(&fixture);
    let matches = scanner
        .scan_bytes(b"harmless bytes with no known marker", MatchDebugLevel::Off)
        .expect("scan_bytes failed");
    assert!(
        matches.is_empty(),
        "expected zero YARA matches for clean data"
    );
}

#[test]
fn scan_bytes_full_debug_includes_string_match() {
    let fixture = YaraFixture::new();
    let scanner = load_scanner(&fixture);
    let matches = scanner
        .scan_bytes(TEST_YARA_MARKER.as_bytes(), MatchDebugLevel::Full)
        .expect("scan_bytes failed");
    assert!(!matches.is_empty(), "expected a match in Full debug mode");
    let first = &matches[0];
    assert!(
        !first.strings.is_empty(),
        "Full debug mode should populate matched strings"
    );
    let s = &first.strings[0];
    assert!(s.offset.is_some(), "match offset should be present");
    assert!(
        s.snippet
            .as_deref()
            .unwrap_or("")
            .contains(TEST_YARA_MARKER),
        "snippet should contain the matched string"
    );
}

#[test]
fn scan_bytes_wide_string_variant() {
    let wide: Vec<u8> = TEST_YARA_MARKER
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let fixture = YaraFixture::new();
    let scanner = load_scanner(&fixture);
    let matches = scanner
        .scan_bytes(&wide, MatchDebugLevel::Off)
        .expect("scan_bytes failed");
    assert!(
        !matches.is_empty(),
        "expected YARA match for UTF-16LE encoded marker"
    );
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires admin on Windows (ReadProcessMemory needs PROCESS_VM_READ)"
)]
fn read_own_process_memory_returns_chunks() {
    let cfg = MemoryScanConfig {
        max_process_bytes: 16 * 1024 * 1024,
        max_region_bytes: 4 * 1024 * 1024,
        include_private: true,
        include_image: false,
        include_mapped: false,
        delay_ms: 0,
    };
    let chunks = read_process_memory_chunks(std::process::id(), &cfg).expect("memory read failed");
    assert!(
        !chunks.is_empty(),
        "own process should have at least one readable private region"
    );
    let total: usize = chunks.iter().map(|c| c.bytes.len()).sum();
    assert!(total > 0, "should have read at least one byte");
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires admin on Windows (ReadProcessMemory needs PROCESS_VM_READ)"
)]
fn memory_scan_finds_marker_in_own_process() {
    let marker: Vec<u8> = TEST_YARA_MARKER.as_bytes().to_vec();
    std::hint::black_box(&marker);

    let cfg = default_mem_cfg();
    let chunks = read_process_memory_chunks(std::process::id(), &cfg).expect("memory read failed");
    assert!(
        !chunks.is_empty(),
        "own process should have readable private memory"
    );

    let fixture = YaraFixture::new();
    let scanner = load_scanner(&fixture);
    let found = chunks.iter().any(|chunk| {
        scanner
            .scan_bytes(&chunk.bytes, MatchDebugLevel::Off)
            .map(|m| !m.is_empty())
            .unwrap_or(false)
    });
    assert!(
        found,
        "YARA should find {TEST_YARA_MARKER} in own process private memory"
    );
}

#[test]
#[ignore = "requires admin on Windows; build memory_target first: cargo build --example memory_target"]
fn memory_scan_finds_marker_in_child_process() {
    let exe = memory_target_exe();
    if !std::path::Path::new(exe).exists() {
        panic!("binary not found at {exe}. Run: cargo build --example memory_target");
    }

    let mut child = std::process::Command::new(exe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn memory_target");
    let pid = child.id();

    std::thread::sleep(Duration::from_millis(400));

    let cfg = default_mem_cfg();
    let chunks = read_process_memory_chunks(pid, &cfg).expect("memory read failed");

    child.kill().ok();
    let _ = child.wait();

    assert!(
        !chunks.is_empty(),
        "child process should have readable private memory"
    );

    let fixture = YaraFixture::new();
    let scanner = load_scanner(&fixture);
    let found = chunks.iter().any(|chunk| {
        scanner
            .scan_bytes(&chunk.bytes, MatchDebugLevel::Off)
            .map(|m| !m.is_empty())
            .unwrap_or(false)
    });
    assert!(
        found,
        "YARA should find {TEST_YARA_MARKER} in child process private memory"
    );
}
