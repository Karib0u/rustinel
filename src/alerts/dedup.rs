//! Sliding-window alert deduplication.
//!
//! The deduplicator groups repeated identical alerts within a configurable time window
//! and emits a single rollup alert with `event.count` at window close.  The first
//! occurrence always emits immediately — there is zero added latency for novel alerts.
//!
//! # Key
//! `(engine, rule_name, process_executable, process_parent_executable, user_name)`
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
    rule_name: String,
    executable: String,
    parent_executable: String,
    user_name: String,
}

impl DedupKey {
    fn from_ecs(ecs: &EcsAlert) -> Self {
        Self {
            engine: ecs.edr_rule_engine.clone(),
            rule_name: ecs.rule_name.clone(),
            executable: ecs.process_executable.clone().unwrap_or_default(),
            parent_executable: ecs.process_parent_executable.clone().unwrap_or_default(),
            user_name: ecs.user_name.clone().unwrap_or_default(),
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

/// Global counters — visible to operational logs.
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

        // Over capacity — emit untracked rather than drop or evict blindly.
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
                // Already emitted on first occurrence — nothing more to do.
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
        // The guard is intentionally dropped here — the sink writer is non-blocking
        // so the underlying channel still processes in the background. For tests that
        // don't inspect the output this is fine.
        AlertSink::new(writer)
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
}
