use crate::alerts::AlertSink;
use crate::memory::{self, MemoryChunk, MemoryScanConfig};
use crate::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, MatchDebugLevel,
    MatchDetails, NormalizedEvent, ProcessCreationFields, YaraMatchDetails, YaraRuleMatch,
};
use crate::reload::DetectorStore;
use crate::response::ResponseEngine;
use crate::scanner::{self, ScanError, ScanResult, YaraMemoryJob};
use crate::sensor::Platform;
use crate::utils::{self, validate_process_identity, LogRateLimiter};
use std::sync::Arc;
use std::time::Duration;
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
            Err(ScanError::TimedOut { .. }) => self.timed_out += 1,
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
            platform,
            provider: provider.to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(path.to_string()),
                original_file_name: None,
                product: None,
                description: None,
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
            platform,
            provider: provider.to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(image.to_string()),
                original_file_name: None,
                product: None,
                description: None,
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
    mut rx: mpsc::Receiver<(String, u32)>,
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

        while let Some((path, pid)) = rx.blocking_recv() {
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
            let scan_result = scanner.scan_file(&path, match_debug);
            counters.record_result(&scan_result);
            match scan_result {
                Ok(matches) => {
                    if !matches.is_empty() {
                        let rule_names: Vec<String> =
                            matches.iter().map(|rule| rule.rule.clone()).collect();
                        warn!(
                            pid = pid,
                            file = %path,
                            rules = ?rule_names,
                            "YARA detection triggered"
                        );

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
            std::thread::sleep(Duration::from_millis(cfg.delay_ms));
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

            let chunks = match memory::read_process_memory_chunks(job.expected_identity.pid, &cfg) {
                Ok(chunks) => chunks,
                Err(err) => {
                    counters.failed += 1;
                    let decision = scan_error_limiter.should_emit("memory_read_error");
                    if decision.should_emit {
                        warn!(
                            target: "scanner",
                            pid = job.expected_identity.pid,
                            image = %job.expected_identity.image,
                            error = %err,
                            suppressed = decision.suppressed_since_last_emit,
                            failed_scans_total = counters.failed,
                            "YARA memory read failure"
                        );
                    }
                    continue;
                }
            };

            let scanner = detectors.yara();
            for chunk in &chunks {
                let scan_result = scanner.scan_bytes(&chunk.bytes, match_debug);
                counters.record_result(&scan_result);
                let matches = match scan_result {
                    Ok(matches) => matches,
                    Err(err) => {
                        let decision =
                            scan_error_limiter.should_emit(&format!("memory_{}", err.kind()));
                        if decision.should_emit {
                            warn!(
                                target: "scanner",
                                pid = job.expected_identity.pid,
                                outcome = err.kind(),
                                error = %err,
                                suppressed = decision.suppressed_since_last_emit,
                                failed_scans_total = counters.failed,
                                timed_out_scans_total = counters.timed_out,
                                "YARA memory chunk scan not completed"
                            );
                        }
                        continue;
                    }
                };

                if !matches.is_empty() {
                    let rule_names: Vec<String> =
                        matches.iter().map(|rule| rule.rule.clone()).collect();
                    warn!(
                        pid = job.expected_identity.pid,
                        image = %job.expected_identity.image,
                        rules = ?rule_names,
                        "YARA memory detection triggered"
                    );

                    for rule_match in &matches {
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
