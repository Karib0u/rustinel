use crate::alerts::AlertSink;
use crate::engine::DetectorStore;
use crate::memory::{self, MemoryChunk, MemoryScanConfig};
use crate::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, MatchDebugLevel,
    MatchDetails, NormalizedEvent, ProcessCreationFields, YaraMatchDetails, YaraRuleMatch,
};
use crate::response::ResponseEngine;
use crate::scanner::{self, ScanError, ScanResult, YaraMemoryJob};
use crate::sensor::Platform;
use crate::utils::{self, validate_process_identity, LogRateLimiter};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const WORKER_LOG_WINDOW_SECS: u64 = 30;

#[derive(Debug, Default, PartialEq, Eq)]
struct YaraScanCounters {
    failed: u64,
    skipped: u64,
    clean: u64,
    matched: u64,
    timed_out: u64,
    oversized: u64,
}

impl YaraScanCounters {
    fn record_result(&mut self, result: &ScanResult) {
        match result {
            Ok(matches) if matches.is_empty() => self.clean += 1,
            Ok(_) => self.matched += 1,
            Err(ScanError::TimedOut { .. } | ScanError::ProcessDeadline { .. }) => {
                self.timed_out += 1
            }
            Err(ScanError::TooLarge { .. }) => self.oversized += 1,
            Err(ScanError::Failed(_)) => self.failed += 1,
        }
    }

    fn record_skip(&mut self) {
        self.skipped += 1;
    }
}

pub fn build_yara_match_details(
    match_debug: MatchDebugLevel,
    rule_match: &YaraRuleMatch,
) -> Option<MatchDetails> {
    if matches!(match_debug, MatchDebugLevel::Off) {
        return None;
    }

    let summary = if matches!(match_debug, MatchDebugLevel::Full) {
        if let Some(first_string) = rule_match.strings.first() {
            if let Some(offset) = first_string.offset {
                format!(
                    "matched YARA rule {} via {} at 0x{:x}",
                    rule_match.rule, first_string.id, offset
                )
            } else {
                format!(
                    "matched YARA rule {} via {}",
                    rule_match.rule, first_string.id
                )
            }
        } else {
            format!("matched YARA rule {}", rule_match.rule)
        }
    } else {
        format!("matched YARA rule {}", rule_match.rule)
    };

    let mut rule = rule_match.clone();
    if !matches!(match_debug, MatchDebugLevel::Full) {
        rule.strings.clear();
    }

    Some(MatchDetails {
        summary,
        sigma: None,
        correlation: None,
        yara: Some(YaraMatchDetails { rules: vec![rule] }),
    })
}

pub fn build_yara_alert(
    rule_name: &str,
    metadata_id: Option<String>,
    path: &str,
    pid: u32,
    match_details: Option<MatchDetails>,
    platform: Platform,
    provider: &str,
) -> Alert {
    let rule_id = metadata_id.map(|id| format!("yara::{}", id));
    Alert {
        severity: AlertSeverity::Critical,
        rule_name: rule_name.to_string(),
        rule_description: None,
        rule_id,
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: utils::now_timestamp_string(),
            source_seq: None,
            ingest_seq: 0,
            platform,
            provider: provider.to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                linux_identity: Default::default(),
                cgroup_id: None,
                exec: Default::default(),
                parent_process_id_derived: false,
                windows: Default::default(),
                image: Some(path.to_string()),
                image_source: None,
                image_truncated: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                command_line: None,
                process_id: Some(pid.to_string()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
            }),
            provenance: Default::default(),
            process_context: None,
        },
        match_details,
    }
}

pub fn build_yara_memory_match_details(
    match_debug: MatchDebugLevel,
    rule_match: &YaraRuleMatch,
    chunk: &MemoryChunk,
) -> Option<MatchDetails> {
    if matches!(match_debug, MatchDebugLevel::Off) {
        return None;
    }

    let summary = format!(
        "matched YARA rule {} in process memory at 0x{:x} {:?} {}{}{}",
        rule_match.rule,
        chunk.base,
        chunk.region.kind,
        if chunk.region.readable { 'r' } else { '-' },
        if chunk.region.writable { 'w' } else { '-' },
        if chunk.region.executable { 'x' } else { '-' },
    );

    let mut rule = rule_match.clone();
    if !matches!(match_debug, MatchDebugLevel::Full) {
        rule.strings.clear();
    }

    Some(MatchDetails {
        summary,
        sigma: None,
        correlation: None,
        yara: Some(YaraMatchDetails { rules: vec![rule] }),
    })
}

pub fn build_yara_memory_alert(
    rule_name: &str,
    metadata_id: Option<String>,
    image: &str,
    pid: u32,
    match_details: Option<MatchDetails>,
    platform: Platform,
    provider: &str,
) -> Alert {
    let rule_id = metadata_id.map(|id| format!("yara::{}", id));
    Alert {
        severity: AlertSeverity::Critical,
        rule_name: rule_name.to_string(),
        rule_description: None,
        rule_id,
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: utils::now_timestamp_string(),
            source_seq: None,
            ingest_seq: 0,
            platform,
            provider: provider.to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                linux_identity: Default::default(),
                cgroup_id: None,
                exec: Default::default(),
                parent_process_id_derived: false,
                windows: Default::default(),
                image: Some(image.to_string()),
                image_source: None,
                image_truncated: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                command_line: None,
                process_id: Some(pid.to_string()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
            }),
            provenance: Default::default(),
            process_context: None,
        },
        match_details,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_yara_file_worker(
    detectors: Arc<DetectorStore>,
    alert_sink: AlertSink,
    response_engine: ResponseEngine,
    match_debug: MatchDebugLevel,
    mut rx: mpsc::Receiver<crate::scanner::FileScanTarget>,
    allowlist_paths: Vec<String>,
    platform: Platform,
    provider: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        info!(
            target: "scanner",
            "YARA worker thread started and waiting for files to scan"
        );
        let mut scan_error_limiter =
            LogRateLimiter::new(Duration::from_secs(WORKER_LOG_WINDOW_SECS));
        let mut counters = YaraScanCounters::default();

        while let Some(target) = rx.blocking_recv() {
            let path = target.path.clone();
            let pid = target.pid;
            if scanner::is_path_allowlisted(&path, &allowlist_paths) {
                counters.record_skip();
                tracing::trace!(
                    target: "scanner",
                    pid = pid,
                    file = %path,
                    "YARA worker skipping allowlisted path"
                );
                continue;
            }

            tracing::trace!(
                target: "scanner",
                pid = pid,
                file = %path,
                "YARA worker received file for scan"
            );

            let scanner = detectors.yara();
            let scan_result = scanner.scan_target(&target, match_debug);
            counters.record_result(&scan_result);
            match scan_result {
                Ok(matches) => {
                    if !matches.is_empty() {
                        for rule_match in &matches {
                            let match_details = build_yara_match_details(match_debug, rule_match);
                            let alert = build_yara_alert(
                                &rule_match.rule,
                                rule_match.metadata_id.clone(),
                                &path,
                                pid,
                                match_details,
                                platform,
                                provider,
                            );
                            alert_sink.write_alert(&alert);
                            response_engine.handle_alert(&alert);
                        }
                    } else {
                        tracing::trace!(
                            target: "scanner",
                            pid = pid,
                            file = %path,
                            "YARA worker no matches"
                        );
                    }
                }
                Err(err) => {
                    let decision = scan_error_limiter.should_emit(err.kind());
                    if decision.should_emit {
                        warn!(
                            target: "scanner",
                            pid = pid,
                            file = %path,
                            outcome = err.kind(),
                            error = %err,
                            suppressed = decision.suppressed_since_last_emit,
                            failed_scans_total = counters.failed,
                            timed_out_scans_total = counters.timed_out,
                            oversized_scans_total = counters.oversized,
                            "YARA worker scan not completed"
                        );
                    }
                }
            }
        }

        info!(
            target: "scanner",
            failed_scans_total = counters.failed,
            skipped_scans_total = counters.skipped,
            clean_scans_total = counters.clean,
            matched_scans_total = counters.matched,
            timed_out_scans_total = counters.timed_out,
            oversized_scans_total = counters.oversized,
            "YARA worker thread shutting down"
        );
    })
}

fn wait_for_memory_scan(
    enqueued_at: Instant,
    delay: Duration,
    now: Instant,
    sleep: impl FnOnce(Duration),
) {
    let remaining = delay.saturating_sub(now.saturating_duration_since(enqueued_at));
    if !remaining.is_zero() {
        sleep(remaining);
    }
}

/// Share one budget across streaming reads and scans. Successful detections
/// are emitted before the reader reuses the region buffer.
fn scan_memory_regions<T>(
    timeout: Duration,
    mut now: impl FnMut() -> Instant,
    read: impl FnOnce(Option<Instant>, &mut dyn FnMut(&T) -> ControlFlow<()>) -> anyhow::Result<()>,
    mut scan: impl FnMut(&T, Duration) -> ScanResult,
    mut on_matches: impl FnMut(&T, &[YaraRuleMatch]),
) -> ScanResult {
    let started = now();
    let deadline = if timeout.is_zero() {
        None
    } else {
        started.checked_add(timeout)
    };
    let mut matches = Vec::new();
    let mut failure = None;
    let read_result = read(deadline, &mut |region| {
        let remaining = if timeout.is_zero() {
            Duration::ZERO
        } else {
            let remaining = timeout.saturating_sub(now().duration_since(started));
            if remaining.is_zero() {
                failure = Some(ScanError::ProcessDeadline { timeout });
                return ControlFlow::Break(());
            }
            remaining
        };
        match scan(region, remaining) {
            Ok(mut found) => {
                on_matches(region, &found);
                matches.append(&mut found);
            }
            Err(ScanError::TimedOut { .. }) if !timeout.is_zero() => {
                failure = Some(ScanError::ProcessDeadline { timeout });
                return ControlFlow::Break(());
            }
            Err(err) => {
                failure.get_or_insert(err);
            }
        }
        if !timeout.is_zero() && now().duration_since(started) >= timeout {
            failure = Some(ScanError::ProcessDeadline { timeout });
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    });
    // The reader may stop at the deadline before yielding a region.
    if !timeout.is_zero() && now().duration_since(started) >= timeout {
        return Err(ScanError::ProcessDeadline { timeout });
    }
    if let Err(err) = read_result {
        failure.get_or_insert(ScanError::Failed(err));
    }
    failure.map_or(Ok(matches), Err)
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_yara_memory_worker(
    detectors: Arc<DetectorStore>,
    alert_sink: AlertSink,
    response_engine: ResponseEngine,
    cfg: MemoryScanConfig,
    match_debug: MatchDebugLevel,
    mut rx: mpsc::Receiver<YaraMemoryJob>,
    platform: Platform,
    provider: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        info!(target: "scanner", "YARA memory worker started");
        let mut scan_error_limiter =
            LogRateLimiter::new(Duration::from_secs(WORKER_LOG_WINDOW_SECS));
        let mut counters = YaraScanCounters::default();
        while let Some(job) = rx.blocking_recv() {
            wait_for_memory_scan(
                job.enqueued_at,
                Duration::from_millis(cfg.delay_ms),
                Instant::now(),
                std::thread::sleep,
            );
            if let Err(reason) = validate_process_identity(&job.expected_identity) {
                counters.record_skip();
                debug!(
                    target: "scanner",
                    pid = job.expected_identity.pid,
                    image = %job.expected_identity.image,
                    reason = %reason,
                    "YARA memory scan skipped after process identity validation"
                );
                continue;
            }

            let scanner = detectors.yara();
            let scan_result = scan_memory_regions(
                scanner.limits().timeout,
                Instant::now,
                |deadline, visitor| {
                    memory::visit_process_memory_chunks(
                        job.expected_identity.pid,
                        &cfg,
                        deadline,
                        visitor,
                    )
                },
                |chunk, timeout| {
                    scanner.scan_bytes_with_timeout(&chunk.bytes, match_debug, timeout)
                },
                |chunk, matches| {
                    if !matches.is_empty() {
                        for rule_match in matches {
                            let details =
                                build_yara_memory_match_details(match_debug, rule_match, chunk);
                            let alert = build_yara_memory_alert(
                                &rule_match.rule,
                                rule_match.metadata_id.clone(),
                                &job.expected_identity.image,
                                job.expected_identity.pid,
                                details,
                                platform,
                                provider,
                            );
                            alert_sink.write_alert(&alert);
                            response_engine.handle_alert(&alert);
                        }
                    }
                },
            );
            counters.record_result(&scan_result);
            if let Err(err) = scan_result {
                let decision = scan_error_limiter.should_emit(err.kind());
                if decision.should_emit {
                    warn!(
                        target: "scanner",
                        pid = job.expected_identity.pid,
                        outcome = err.kind(),
                        error = %err,
                        suppressed = decision.suppressed_since_last_emit,
                        failed_scans_total = counters.failed,
                        timed_out_scans_total = counters.timed_out,
                        "YARA memory process scan not completed"
                    );
                }
            }
        }

        info!(
            target: "scanner",
            failed_scans_total = counters.failed,
            skipped_scans_total = counters.skipped,
            clean_scans_total = counters.clean,
            matched_scans_total = counters.matched,
            timed_out_scans_total = counters.timed_out,
            "YARA memory worker shutting down"
        );
    })
}

#[cfg(test)]
mod tests {
    use super::YaraScanCounters;
    use crate::models::YaraRuleMatch;
    use crate::scanner::ScanError;
    use std::time::Duration;

    fn rule_match() -> YaraRuleMatch {
        YaraRuleMatch {
            rule: "TestRule".to_string(),
            metadata_id: None,
            tags: Vec::new(),
            namespace: None,
            strings: Vec::new(),
        }
    }

    fn read_test_regions(
        _deadline: Option<std::time::Instant>,
        visitor: &mut dyn FnMut(&i32) -> std::ops::ControlFlow<()>,
    ) -> anyhow::Result<()> {
        for region in 0..3 {
            if visitor(&region).is_break() {
                break;
            }
        }
        Ok(())
    }

    #[test]
    fn memory_read_time_counts_toward_process_deadline() {
        use std::cell::Cell;
        let started = std::time::Instant::now();
        for yield_region in [false, true] {
            let elapsed = Cell::new(Duration::ZERO);
            let result = super::scan_memory_regions(
                Duration::from_secs(10),
                || started + elapsed.get(),
                |deadline, visitor| {
                    assert_eq!(deadline, Some(started + Duration::from_secs(10)));
                    elapsed.set(Duration::from_secs(10));
                    if yield_region {
                        assert!(visitor(&0).is_break());
                    }
                    Ok(())
                },
                |_: &i32, _| panic!("read exhausted the budget before scanning"),
                |_, _| panic!("no matches"),
            );
            assert!(matches!(result, Err(ScanError::ProcessDeadline { .. })));
        }
    }

    #[test]
    fn streaming_matches_keep_region_metadata_after_later_read_failure() {
        use crate::memory::{MemoryChunk, MemoryRegion, MemoryRegionKind};
        use crate::models::MatchDebugLevel;
        let mut summaries = Vec::new();
        let result = super::scan_memory_regions(
            Duration::ZERO,
            std::time::Instant::now,
            |deadline, visitor| {
                assert!(deadline.is_none());
                for base in [0x1000, 0x2000] {
                    let chunk = MemoryChunk {
                        base,
                        bytes: vec![1; 4],
                        region: MemoryRegion {
                            base,
                            size: 20,
                            readable: true,
                            writable: true,
                            executable: false,
                            kind: MemoryRegionKind::Private,
                        },
                    };
                    assert!(visitor(&chunk).is_continue());
                }
                Err(anyhow::anyhow!("reader failure"))
            },
            |_: &MemoryChunk, _| Ok(vec![rule_match()]),
            |chunk, matches| {
                summaries.push(
                    super::build_yara_memory_match_details(
                        MatchDebugLevel::Full,
                        &matches[0],
                        chunk,
                    )
                    .unwrap()
                    .summary,
                );
            },
        );
        assert!(matches!(result, Err(ScanError::Failed(_))));
        assert_eq!(
            summaries,
            [
                "matched YARA rule TestRule in process memory at 0x1000 Private rw-",
                "matched YARA rule TestRule in process memory at 0x2000 Private rw-",
            ]
        );
    }

    #[test]
    fn memory_scan_burst_shares_enqueue_delay() {
        let enqueued_at = std::time::Instant::now();
        let delay = Duration::from_millis(750);
        let mut now = enqueued_at;
        let mut sleeps = Vec::new();
        for _ in 0..64 {
            super::wait_for_memory_scan(enqueued_at, delay, now, |remaining| {
                sleeps.push(remaining);
                now += remaining;
            });
        }
        assert_eq!(sleeps, [delay]);
        assert_eq!(now.duration_since(enqueued_at), delay);
    }

    #[test]
    fn memory_scan_waits_only_for_remaining_delay() {
        let enqueued_at = std::time::Instant::now();
        super::wait_for_memory_scan(
            enqueued_at,
            Duration::from_millis(750),
            enqueued_at + Duration::from_millis(500),
            |remaining| assert_eq!(remaining, Duration::from_millis(250)),
        );
        for (delay, elapsed) in [(750, 750), (750, 1000), (0, 0)] {
            super::wait_for_memory_scan(
                enqueued_at,
                Duration::from_millis(delay),
                enqueued_at + Duration::from_millis(elapsed),
                |_| panic!("due jobs must not sleep"),
            );
        }
    }

    #[test]
    fn memory_regions_share_deadline_and_preserve_earlier_matches() {
        use std::cell::Cell;
        use std::time::Instant;

        for engine_timeout in [false, true] {
            let elapsed = Cell::new(Duration::ZERO);
            let start = Instant::now();
            let mut budgets = Vec::new();
            let mut detected = Vec::new();
            let result = super::scan_memory_regions(
                Duration::from_secs(10),
                || start + elapsed.get(),
                read_test_regions,
                |region, remaining| {
                    budgets.push(remaining);
                    if *region == 0 {
                        elapsed.set(Duration::from_secs(4));
                        Ok(vec![rule_match()])
                    } else if engine_timeout {
                        Err(ScanError::TimedOut { timeout: remaining })
                    } else {
                        elapsed.set(Duration::from_secs(10));
                        Ok(Vec::new())
                    }
                },
                |region, matches| {
                    detected.extend(matches.iter().map(|m| (*region, m.rule.clone())));
                },
            );
            assert_eq!(budgets, [Duration::from_secs(10), Duration::from_secs(6)]);
            assert_eq!(detected, [(0, "TestRule".to_string())]);
            assert!(matches!(result, Err(ScanError::ProcessDeadline { .. })));
            assert_eq!(result.as_ref().unwrap_err().kind(), "process_deadline");
            let mut counters = YaraScanCounters::default();
            counters.record_result(&result);
            assert_eq!(counters.timed_out, 1);
            assert_eq!(counters.clean + counters.matched + counters.failed, 0);
        }
    }

    #[test]
    fn memory_regions_do_not_start_after_deadline() {
        let start = std::time::Instant::now();
        let mut calls = 0;
        let result = super::scan_memory_regions(
            Duration::from_secs(1),
            || {
                calls += 1;
                start + Duration::from_secs(calls - 1)
            },
            read_test_regions,
            |_, _| panic!("expired region must not start"),
            |_, _| {},
        );
        assert!(matches!(result, Err(ScanError::ProcessDeadline { .. })));
    }

    #[test]
    fn memory_regions_without_timeout_continue_after_failure() {
        let mut scanned = Vec::new();
        let mut detected = Vec::new();
        let result = super::scan_memory_regions(
            Duration::ZERO,
            std::time::Instant::now,
            read_test_regions,
            |region, remaining| {
                assert!(remaining.is_zero());
                scanned.push(*region);
                if *region == 1 {
                    Err(ScanError::Failed(anyhow::anyhow!("engine failure")))
                } else {
                    Ok(vec![rule_match()])
                }
            },
            |region, _| detected.push(*region),
        );
        assert_eq!(scanned, [0, 1, 2]);
        assert_eq!(detected, [0, 2]);
        assert!(matches!(result, Err(ScanError::Failed(_))));
    }

    #[test]
    fn memory_regions_report_one_successful_process_outcome() {
        for matched in [false, true] {
            let result = super::scan_memory_regions(
                Duration::from_secs(10),
                std::time::Instant::now,
                read_test_regions,
                |_, _| {
                    Ok(if matched {
                        vec![rule_match()]
                    } else {
                        Vec::new()
                    })
                },
                |_, _| {},
            );
            let mut counters = YaraScanCounters::default();
            counters.record_result(&result);
            assert_eq!(counters.matched, u64::from(matched));
            assert_eq!(counters.clean, u64::from(!matched));
        }
    }

    #[test]
    fn yara_scan_counters_distinguish_every_outcome() {
        let mut counters = YaraScanCounters::default();
        counters.record_skip();
        counters.record_result(&Ok(Vec::new()));
        counters.record_result(&Ok(vec![rule_match()]));
        counters.record_result(&Err(ScanError::Failed(anyhow::anyhow!("scan failed"))));
        counters.record_result(&Err(ScanError::TimedOut {
            timeout: Duration::from_millis(10),
        }));
        counters.record_result(&Err(ScanError::TooLarge { size: 2, limit: 1 }));

        assert_eq!(
            counters,
            YaraScanCounters {
                failed: 1,
                skipped: 1,
                clean: 1,
                matched: 1,
                timed_out: 1,
                oversized: 1,
            }
        );
    }
}
