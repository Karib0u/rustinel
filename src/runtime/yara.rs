use crate::alerts::AlertSink;
use crate::memory::{self, MemoryChunk, MemoryScanConfig};
use crate::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, MatchDebugLevel,
    MatchDetails, NormalizedEvent, ProcessCreationFields, YaraMatchDetails, YaraRuleMatch,
};
use crate::reload::DetectorStore;
use crate::response::ResponseEngine;
use crate::scanner::{self, YaraMemoryJob};
use crate::sensor::Platform;
use crate::utils::{self, validate_process_identity, LogRateLimiter};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const WORKER_DEBUG_LOG_WINDOW_SECS: u64 = 30;

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
                logon_id: None,
                logon_guid: None,
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
                logon_id: None,
                logon_guid: None,
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
            LogRateLimiter::new(Duration::from_secs(WORKER_DEBUG_LOG_WINDOW_SECS));

        while let Some((path, pid)) = rx.blocking_recv() {
            if scanner::is_path_allowlisted(&path, &allowlist_paths) {
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
            match scanner.scan_file(&path, match_debug) {
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
                    let decision = scan_error_limiter.should_emit("scan_error");
                    if decision.should_emit {
                        debug!(
                            target: "scanner",
                            pid = pid,
                            file = %path,
                            error = %err,
                            suppressed = decision.suppressed_since_last_emit,
                            "YARA worker scan failure"
                        );
                    }
                }
            }
        }

        info!(target: "scanner", "YARA worker thread shutting down");
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
        while let Some(job) = rx.blocking_recv() {
            std::thread::sleep(Duration::from_millis(cfg.delay_ms));
            if let Err(reason) = validate_process_identity(&job.expected_identity) {
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
                    tracing::trace!(
                        target: "scanner",
                        pid = job.expected_identity.pid,
                        image = %job.expected_identity.image,
                        error = %err,
                        "YARA memory scan skipped"
                    );
                    continue;
                }
            };

            let scanner = detectors.yara();
            for chunk in &chunks {
                let matches = match scanner.scan_bytes(&chunk.bytes, match_debug) {
                    Ok(matches) => matches,
                    Err(err) => {
                        tracing::trace!(
                            target: "scanner",
                            pid = job.expected_identity.pid,
                            error = %err,
                            "YARA memory chunk scan failed"
                        );
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

        info!(target: "scanner", "YARA memory worker shutting down");
    })
}
