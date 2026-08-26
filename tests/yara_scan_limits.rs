//! Guards that keep a single pathological scan from pinning a worker thread.

use rustinel::{
    models::MatchDebugLevel,
    scanner::{ScanError, ScanLimits, Scanner},
};
use std::time::{Duration, Instant};

/// A rule whose condition runs long enough to cross YARA-X's one-second
/// timeout check interval, even in optimized builds.
const SLOW_RULE: &str = r#"
rule SlowRule {
    condition:
        for all i in (0..2000000000) : ( uint8(i % 64) != 0xff )
}
"#;

fn slow_scanner(timeout: Duration) -> (tempfile::TempDir, Scanner) {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let rules_dir = tempdir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).expect("create rules dir");
    std::fs::write(rules_dir.join("slow.yar"), SLOW_RULE).expect("write slow rule");
    let scanner = Scanner::new(&rules_dir)
        .expect("compile slow rule")
        .with_limits(ScanLimits {
            timeout,
            max_file_bytes: 64 * 1024 * 1024,
        });
    (tempdir, scanner)
}

const MARKER_RULE: &str = r#"rule MarkerRule { strings: $marker = "evil!!" condition: $marker }"#;

fn marker_scanner(limits: ScanLimits) -> (tempfile::TempDir, Scanner) {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let rules_dir = tempdir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).expect("create rules dir");
    std::fs::write(rules_dir.join("marker.yar"), MARKER_RULE).expect("write marker rule");
    let scanner = Scanner::new(&rules_dir)
        .expect("compile marker rule")
        .with_limits(limits);
    (tempdir, scanner)
}

#[test]
fn file_scan_outcomes_stay_distinct() {
    let (tempdir, scanner) = marker_scanner(ScanLimits {
        timeout: Duration::from_secs(5),
        max_file_bytes: 8,
    });

    let matching = tempdir.path().join("matching.bin");
    std::fs::write(&matching, b"evil!!").expect("write matching sample");
    let matches = scanner
        .scan_file(&matching.to_string_lossy(), MatchDebugLevel::Off)
        .expect("matching scan");
    assert_eq!(matches[0].rule, "MarkerRule");

    let clean = tempdir.path().join("clean.bin");
    std::fs::write(&clean, b"clean!").expect("write clean sample");
    assert!(scanner
        .scan_file(&clean.to_string_lossy(), MatchDebugLevel::Off)
        .expect("clean scan")
        .is_empty());

    let oversized = tempdir.path().join("oversized.bin");
    std::fs::write(&oversized, b"evil!! and then some more").expect("write oversized sample");
    let error = scanner
        .scan_file(&oversized.to_string_lossy(), MatchDebugLevel::Off)
        .expect_err("an oversized target must not be reported as clean");
    assert!(
        matches!(error, ScanError::TooLarge { .. }),
        "expected an oversized outcome, got {error}"
    );

    let missing = tempdir.path().join("missing.bin");
    let error = scanner
        .scan_file(&missing.to_string_lossy(), MatchDebugLevel::Off)
        .expect_err("a failed scan must not be reported as clean");
    assert!(
        matches!(error, ScanError::Failed(_)),
        "expected a failure outcome, got {error}"
    );
}

#[test]
fn memory_scan_times_out_instead_of_running_unbounded() {
    let timeout = Duration::from_millis(100);
    let (_tempdir, scanner) = slow_scanner(timeout);

    let started = Instant::now();
    let error = scanner
        .scan_bytes(&vec![0x41u8; 4096], MatchDebugLevel::Off)
        .expect_err("a timed-out scan must not be reported as clean");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, ScanError::TimedOut { .. }),
        "expected a timeout outcome, got {error}"
    );
    // YARA-X checks timeouts on a roughly one-second heartbeat, so the
    // configured timeout is a floor on abort latency rather than a deadline.
    assert!(
        elapsed < Duration::from_secs(10),
        "timeout should bound the scan, took {elapsed:?}"
    );
}

#[test]
fn file_scan_times_out_instead_of_running_unbounded() {
    let timeout = Duration::from_millis(100);
    let (tempdir, scanner) = slow_scanner(timeout);
    let sample = tempdir.path().join("sample.bin");
    std::fs::write(&sample, vec![0x41u8; 4096]).expect("write sample");

    let started = Instant::now();
    let error = scanner
        .scan_file(&sample.to_string_lossy(), MatchDebugLevel::Off)
        .expect_err("a timed-out scan must not be reported as clean");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, ScanError::TimedOut { .. }),
        "expected a timeout outcome, got {error}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "timeout should bound the scan, took {elapsed:?}"
    );
}
