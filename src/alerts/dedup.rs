//! Sliding-window alert deduplication.
//!
//! The deduplicator groups repeated identical alerts within a configurable time window
//! and emits a single rollup alert with `event.count` at window close.  The first
//! occurrence always emits immediately, so there is zero added latency for novel alerts.
//!
//! # Identity
//! Every key contains the detection engine, rule ID (or rule name fallback), event
//! dataset/action/code, and a canonical subject fingerprint. The fingerprint includes
//! process instance and command-line fields plus the fields that identify the subject
//! for each supported category:
//! - network endpoints, domain, and protocol
//! - file or loaded-image path
//! - registry path, data, event type, and rename target
//! - DNS query, answers, and response status
//! - script, WMI, remote-thread, service, and task targets
//!
//! Timestamps and rollup counts are deliberately excluded. Missing fields remain
//! `None`, which is distinct from a present value but stable across repeated alerts.
//!
//! # Window semantics
//! Each key starts a *tumbling* window anchored to the first emission.  Once
//! `now - first_seen >= window` the entry is expired during the next flush tick,
//! at which point a rollup alert is written (if count > 1) and the slot is freed.

use crate::models::ecs::EcsAlert;
use crate::models::Alert;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::info;

/// Compound key used to identify "same alert" across repeats.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DedupKey {
    engine: String,
    rule_id_or_name: String,
    subject: SubjectIdentity,
}

/// Canonical security-relevant subject fields. Keeping these as typed values avoids
/// delimiter ambiguity and makes the identity semantics explicit for every category.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SubjectIdentity {
    event_dataset: String,
    event_action: Option<String>,
    event_code: Option<String>,
    process_executable: Option<String>,
    process_command_line: Option<String>,
    process_pid: Option<u64>,
    process_parent_executable: Option<String>,
    process_parent_command_line: Option<String>,
    process_parent_pid: Option<u64>,
    user_name: Option<String>,
    user_id: Option<String>,
    user_domain: Option<String>,
    destination_ip: Option<String>,
    destination_port: Option<u16>,
    source_ip: Option<String>,
    source_port: Option<u16>,
    destination_domain: Option<String>,
    network_transport: Option<String>,
    network_protocol: Option<String>,
    network_direction: Option<String>,
    file_path: Option<String>,
    registry_path: Option<String>,
    registry_data_strings: Option<Vec<String>>,
    registry_event_type: Option<String>,
    registry_new_name: Option<String>,
    dns_query: Option<String>,
    dns_answers: Option<Vec<String>>,
    dns_response_code: Option<String>,
    service_name: Option<String>,
    service_executable: Option<String>,
    service_type: Option<String>,
    service_start_type: Option<String>,
    service_account_name: Option<String>,
    task_name: Option<String>,
    task_content: Option<String>,
    task_user_name: Option<String>,
    powershell_script_block_text: Option<String>,
    powershell_script_block_id: Option<String>,
    wmi_operation: Option<String>,
    wmi_query: Option<String>,
    wmi_namespace: Option<String>,
    wmi_event_type: Option<String>,
    remote_thread_target_pid: Option<u64>,
    remote_thread_target_image: Option<String>,
    remote_thread_start_address: Option<String>,
    remote_thread_start_module: Option<String>,
    remote_thread_start_function: Option<String>,
    process_target_image: Option<String>,
}

impl DedupKey {
    fn from_ecs(ecs: &EcsAlert) -> Self {
        Self {
            engine: ecs.edr_rule_engine.clone(),
            rule_id_or_name: ecs
                .rule_id
                .clone()
                .unwrap_or_else(|| format!("name::{}", ecs.rule_name)),
            subject: SubjectIdentity {
                event_dataset: ecs.event_dataset.clone(),
                event_action: ecs.event_action.clone(),
                event_code: ecs.event_code.clone(),
                process_executable: ecs.process_executable.clone(),
                process_command_line: ecs.process_command_line.clone(),
                process_pid: ecs.process_pid,
                process_parent_executable: ecs.process_parent_executable.clone(),
                process_parent_command_line: ecs.process_parent_command_line.clone(),
                process_parent_pid: ecs.process_parent_pid,
                user_name: ecs.user_name.clone(),
                user_id: ecs.user_id.clone(),
                user_domain: ecs.user_domain.clone(),
                destination_ip: ecs.destination_ip.clone(),
                destination_port: ecs.destination_port,
                source_ip: ecs.source_ip.clone(),
                source_port: ecs.source_port,
                destination_domain: ecs.destination_domain.clone(),
                network_transport: ecs.network_transport.clone(),
                network_protocol: ecs.network_protocol.clone(),
                network_direction: ecs.network_direction.clone(),
                file_path: ecs.file_path.clone(),
                registry_path: ecs.registry_path.clone(),
                registry_data_strings: ecs.registry_data_strings.clone(),
                registry_event_type: ecs.edr_registry_event_type.clone(),
                registry_new_name: ecs.edr_registry_new_name.clone(),
                dns_query: ecs.dns_query.clone(),
                dns_answers: ecs
                    .dns_answers
                    .as_ref()
                    .map(|answers| answers.iter().map(|answer| answer.data.clone()).collect()),
                dns_response_code: ecs.dns_response_code.clone(),
                service_name: ecs.service_name.clone(),
                service_executable: ecs.edr_service_executable.clone(),
                service_type: ecs.edr_service_type.clone(),
                service_start_type: ecs.edr_service_start_type.clone(),
                service_account_name: ecs.edr_service_account_name.clone(),
                task_name: ecs.edr_task_name.clone(),
                task_content: ecs.edr_task_content.clone(),
                task_user_name: ecs.edr_task_user_name.clone(),
                powershell_script_block_text: ecs.edr_powershell_script_block_text.clone(),
                powershell_script_block_id: ecs.edr_powershell_script_block_id.clone(),
                wmi_operation: ecs.edr_wmi_operation.clone(),
                wmi_query: ecs.edr_wmi_query.clone(),
                wmi_namespace: ecs.edr_wmi_namespace.clone(),
                wmi_event_type: ecs.edr_wmi_event_type.clone(),
                remote_thread_target_pid: ecs.edr_remote_thread_target_pid,
                remote_thread_target_image: ecs.edr_remote_thread_target_image.clone(),
                remote_thread_start_address: ecs.edr_remote_thread_start_address.clone(),
                remote_thread_start_module: ecs.edr_remote_thread_start_module.clone(),
                remote_thread_start_function: ecs.edr_remote_thread_start_function.clone(),
                process_target_image: ecs.edr_process_target_image.clone(),
            },
        }
    }
}

/// State tracked per unique alert key.
struct DedupEntry {
    first_seen: Instant,
    count: u64,
    /// A clone of the original internal `Alert` so we can rebuild a complete ECS
    /// rollup (with all enriched fields) at flush time.
    sample: Alert,
}

/// Global counters visible to operational logs.
struct Counters {
    /// Total alerts suppressed (not written to the sink).
    suppressed_total: AtomicU64,
    /// Total aggregate rollup alerts written at window close.
    aggregated_total: AtomicU64,
}

pub struct Deduplicator {
    window: Duration,
    max_entries: usize,
    table: Mutex<HashMap<DedupKey, DedupEntry>>,
    counters: Counters,
}

impl Deduplicator {
    pub fn new(window_secs: u64, max_entries: usize) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            max_entries,
            table: Mutex::new(HashMap::new()),
            counters: Counters {
                suppressed_total: AtomicU64::new(0),
                aggregated_total: AtomicU64::new(0),
            },
        }
    }

    /// Record an alert.  Returns `true` if the caller should emit the alert now
    /// (first occurrence), `false` if it was suppressed.
    pub fn record(&self, ecs: &EcsAlert, alert: &Alert) -> bool {
        let key = DedupKey::from_ecs(ecs);
        let mut table = self.table.lock().unwrap();

        if let Some(entry) = table.get_mut(&key) {
            entry.count += 1;
            self.counters
                .suppressed_total
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Over capacity: emit untracked rather than drop or evict blindly.
        if table.len() >= self.max_entries {
            return true;
        }

        table.insert(
            key,
            DedupEntry {
                first_seen: Instant::now(),
                count: 1,
                sample: alert.clone(),
            },
        );
        true
    }

    /// Flush entries whose window has expired.  Emits a rollup alert with
    /// `event.count` for any entry that had more than one occurrence.
    pub fn flush_expired(&self, sink: &super::AlertSink) {
        let now = Instant::now();
        let expired = self.drain_expired(now);
        self.emit_rollups(expired, sink);
    }

    fn drain_expired(&self, now: Instant) -> Vec<DedupEntry> {
        let mut expired = Vec::new();
        let mut table = self.table.lock().unwrap();
        // Collect keys to remove first (can't take owned values from retain).
        let expired_keys: Vec<DedupKey> = table
            .iter()
            .filter(|(_, e)| now.duration_since(e.first_seen) >= self.window)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired_keys {
            if let Some(entry) = table.remove(&key) {
                expired.push(entry);
            }
        }
        expired
    }

    /// Flush all remaining entries regardless of window age (called on shutdown).
    pub fn flush_all(&self, sink: &super::AlertSink) {
        let entries: Vec<DedupEntry> = {
            let mut table = self.table.lock().unwrap();
            table.drain().map(|(_, v)| v).collect()
        };
        self.emit_rollups(entries, sink);
    }

    fn emit_rollups(&self, entries: Vec<DedupEntry>, sink: &super::AlertSink) {
        for entry in entries {
            if entry.count <= 1 {
                // Already emitted on first occurrence, so nothing more to do.
                continue;
            }
            let mut ecs = EcsAlert::from(&entry.sample);
            ecs.event_count = Some(entry.count);
            self.counters
                .aggregated_total
                .fetch_add(1, Ordering::Relaxed);
            sink.write_ecs(&ecs);
        }
    }

    /// Log current metrics to the operational log.
    pub fn log_metrics(&self) {
        let suppressed = self.counters.suppressed_total.load(Ordering::Relaxed);
        let aggregated = self.counters.aggregated_total.load(Ordering::Relaxed);
        let pending = self.table.lock().unwrap().len();
        info!(
            target: "dedup",
            suppressed_total = suppressed,
            aggregated_rollup_alerts = aggregated,
            pending_keys = pending,
            "Alert dedup metrics"
        );
    }
}

/// Spawn a background task that ticks every `tick_interval` and flushes expired
/// dedup entries.  The returned handle should be aborted on shutdown, after which
/// the caller should call `flush_all` directly.
pub fn spawn_flush_worker(
    dedup: std::sync::Arc<Deduplicator>,
    sink: super::AlertSink,
    tick_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick_interval);
        // The first tick fires immediately; skip it to avoid an early no-op flush.
        interval.tick().await;
        loop {
            interval.tick().await;
            dedup.flush_expired(&sink);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::AlertSink;
    use crate::models::{
        Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
        ProcessCreationFields,
    };
    use crate::sensor::Platform;

    fn make_alert(rule: &str, image: &str) -> Alert {
        Alert {
            severity: AlertSeverity::High,
            rule_name: rule.to_string(),
            rule_description: None,
            rule_id: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-06-09T00:00:00Z".to_string(),
                platform: Platform::Linux,
                provider: "ebpf".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some(image.to_string()),
                    command_line: None,
                    process_id: Some("42".to_string()),
                    process_start_time: None,
                    parent_image: None,
                    parent_process_id: None,
                    parent_command_line: None,
                    current_directory: None,
                    integrity_level: None,
                    user: Some("alice".to_string()),
                    original_file_name: None,
                    product: None,
                    description: None,
                    target_image: None,
                    logon_id: None,
                    logon_guid: None,
                }),
                process_context: None,
            },
            match_details: None,
        }
    }

    fn null_sink() -> AlertSink {
        let (writer, _guard) = tracing_appender::non_blocking(std::io::sink());
        // Keep guard alive for the duration of this helper's use.
        // The guard is intentionally dropped here. The sink writer is non-blocking,
        // so the underlying channel still processes in the background. For tests that
        // don't inspect the output this is fine.
        AlertSink::new(writer)
    }

    fn assert_distinct_subjects(change_subject: impl FnOnce(&mut EcsAlert)) {
        let dedup = Deduplicator::new(60, 1000);
        let alert = make_alert("Rule A", "/usr/bin/curl");
        let ecs_a = EcsAlert::from(&alert);
        let mut ecs_b = EcsAlert::from(&alert);
        change_subject(&mut ecs_b);

        assert!(dedup.record(&ecs_a, &alert));
        assert!(
            dedup.record(&ecs_b, &alert),
            "different event subjects must use separate dedup keys"
        );
    }

    #[test]
    fn first_occurrence_is_emitted() {
        let dedup = Deduplicator::new(60, 1000);
        let alert = make_alert("Rule A", "/usr/bin/curl");
        let ecs = EcsAlert::from(&alert);
        assert!(
            dedup.record(&ecs, &alert),
            "first hit must return true (emit)"
        );
    }

    #[test]
    fn repeat_is_suppressed() {
        let dedup = Deduplicator::new(60, 1000);
        let alert = make_alert("Rule A", "/usr/bin/curl");
        let ecs = EcsAlert::from(&alert);
        dedup.record(&ecs, &alert);
        assert!(
            !dedup.record(&ecs, &alert),
            "second hit must return false (suppress)"
        );
        assert!(
            !dedup.record(&ecs, &alert),
            "third hit must return false (suppress)"
        );
        assert_eq!(dedup.counters.suppressed_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn network_destinations_are_tracked_separately() {
        assert_distinct_subjects(|ecs| {
            ecs.destination_ip = Some("203.0.113.7".to_string());
            ecs.destination_port = Some(443);
        });
        assert_distinct_subjects(|ecs| {
            ecs.destination_port = Some(8443);
        });
    }

    #[test]
    fn file_targets_are_tracked_separately() {
        assert_distinct_subjects(|ecs| {
            ecs.file_path = Some("/tmp/second-payload".to_string());
        });
    }

    #[test]
    fn registry_targets_are_tracked_separately() {
        assert_distinct_subjects(|ecs| {
            ecs.registry_path = Some(r"HKLM\Software\Example\Second".to_string());
        });
    }

    #[test]
    fn dns_queries_are_tracked_separately() {
        assert_distinct_subjects(|ecs| {
            ecs.dns_query = Some("second.example".to_string());
        });
    }

    #[test]
    fn process_instances_and_command_lines_are_tracked_separately() {
        assert_distinct_subjects(|ecs| {
            ecs.process_pid = Some(43);
        });
        assert_distinct_subjects(|ecs| {
            ecs.process_command_line = Some("curl https://second.example".to_string());
        });
    }

    #[test]
    fn service_and_task_names_are_tracked_separately() {
        assert_distinct_subjects(|ecs| {
            ecs.service_name = Some("second-service".to_string());
        });
        assert_distinct_subjects(|ecs| {
            ecs.edr_task_name = Some("second-task".to_string());
        });
    }

    #[test]
    fn distinct_rules_tracked_separately() {
        let dedup = Deduplicator::new(60, 1000);
        let a = make_alert("Rule A", "/usr/bin/curl");
        let b = make_alert("Rule B", "/usr/bin/curl");
        let ecs_a = EcsAlert::from(&a);
        let ecs_b = EcsAlert::from(&b);
        assert!(dedup.record(&ecs_a, &a));
        assert!(
            dedup.record(&ecs_b, &b),
            "different rule must be a separate key"
        );
    }

    #[test]
    fn flush_expired_emits_rollup_with_count() {
        let dedup = std::sync::Arc::new(Deduplicator::new(0, 1000)); // 0-second window
        let alert = make_alert("Rule A", "/usr/bin/curl");
        let ecs = EcsAlert::from(&alert);

        // First hit emitted by caller; two more suppressed.
        dedup.record(&ecs, &alert);
        dedup.record(&ecs, &alert);
        dedup.record(&ecs, &alert);
        assert_eq!(dedup.counters.suppressed_total.load(Ordering::Relaxed), 2);

        // With a 0-second window the entry is already expired.
        let sink = null_sink();
        std::thread::sleep(Duration::from_millis(10)); // ensure duration_since > 0
        dedup.flush_expired(&sink);

        assert_eq!(
            dedup.counters.aggregated_total.load(Ordering::Relaxed),
            1,
            "one rollup alert should have been emitted"
        );
    }

    #[test]
    fn flush_all_drains_all_entries() {
        let dedup = Deduplicator::new(3600, 1000); // long window so nothing expires
        let a = make_alert("Rule A", "/usr/bin/curl");
        let b = make_alert("Rule B", "/usr/bin/ssh");
        dedup.record(&EcsAlert::from(&a), &a);
        dedup.record(&EcsAlert::from(&a), &a); // one repeat
        dedup.record(&EcsAlert::from(&b), &b);

        assert_eq!(dedup.table.lock().unwrap().len(), 2);

        let sink = null_sink();
        dedup.flush_all(&sink);

        assert_eq!(
            dedup.table.lock().unwrap().len(),
            0,
            "table must be empty after flush_all"
        );
        // Rule A had count=2 → rollup emitted; Rule B had count=1 → no rollup
        assert_eq!(dedup.counters.aggregated_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn over_capacity_emits_untracked() {
        let dedup = Deduplicator::new(60, 1); // capacity of 1
        let a = make_alert("Rule A", "/usr/bin/curl");
        let b = make_alert("Rule B", "/usr/bin/curl");
        let ecs_a = EcsAlert::from(&a);
        let ecs_b = EcsAlert::from(&b);

        assert!(dedup.record(&ecs_a, &a)); // fills the one slot
        assert!(
            dedup.record(&ecs_b, &b),
            "over-capacity new key must still emit (untracked)"
        );
        // But the table is still full of only the original key
        assert_eq!(dedup.table.lock().unwrap().len(), 1);
    }

    #[test]
    fn no_rollup_emitted_when_count_is_one() {
        let dedup = Deduplicator::new(0, 1000);
        let alert = make_alert("Rule A", "/usr/bin/curl");
        dedup.record(&EcsAlert::from(&alert), &alert);

        let sink = null_sink();
        std::thread::sleep(Duration::from_millis(10));
        dedup.flush_expired(&sink);

        assert_eq!(dedup.counters.aggregated_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn equal_names_with_different_ids_tracked_separately() {
        let dedup = Deduplicator::new(60, 1000);

        let mut alert_a = make_alert("Rule A", "/usr/bin/curl");
        alert_a.rule_id = Some("id-123".to_string());

        let mut alert_b = make_alert("Rule A", "/usr/bin/curl");
        alert_b.rule_id = Some("id-456".to_string());

        let mut alert_c = make_alert("Rule A", "/usr/bin/curl");
        alert_c.rule_id = None;

        // An alert where the ID matches the raw name of alert_c.
        // The prefixing of fallback names prevents collision with this alert's ID.
        let mut alert_d = make_alert("Other Name", "/usr/bin/curl");
        alert_d.rule_id = Some("Rule A".to_string());

        let ecs_a = EcsAlert::from(&alert_a);
        let ecs_b = EcsAlert::from(&alert_b);
        let ecs_c = EcsAlert::from(&alert_c);
        let ecs_d = EcsAlert::from(&alert_d);

        assert!(
            dedup.record(&ecs_a, &alert_a),
            "first alert with id-123 must emit"
        );
        assert!(
            dedup.record(&ecs_b, &alert_b),
            "different alert with same name but id-456 must also emit"
        );
        assert!(
            dedup.record(&ecs_c, &alert_c),
            "alert with same name but no id must also emit"
        );
        assert!(
            dedup.record(&ecs_d, &alert_d),
            "alert with id matching another rule's name must not collide and must emit"
        );
    }
}
