//! Pipeline drop-counter diagnostics.
//!
//! Answers "did this endpoint lose telemetry, and how much?" from the snapshot
//! the running agent writes, so an operator does not have to grep rotated logs
//! to size a detection gap.

use crate::config::AppConfig;
use crate::doctor::inspect::DiagnosticResult;
use crate::telemetry::{snapshot_path, TelemetrySnapshot};
use std::path::Path;

/// Inspect the persisted pipeline counters for `logs_dir`.
///
/// Returns the snapshot alongside the diagnostic so `--json` can carry the
/// full per-channel numbers rather than only the summary line.
pub(crate) fn telemetry_results(
    cfg: &AppConfig,
    logs_dir: &Path,
) -> (Vec<DiagnosticResult>, Option<TelemetrySnapshot>) {
    if !cfg.telemetry.enabled {
        return (
            vec![DiagnosticResult::warn(
                "pipeline_telemetry",
                "Pipeline drop counters are not being persisted",
                "telemetry.enabled is false, so dropped-event totals are only visible in the agent log",
            )
            .with_fix("Set telemetry.enabled = true to make drop counters readable here")],
            None,
        );
    }

    let path = snapshot_path(logs_dir);
    let Some(snapshot) = TelemetrySnapshot::read_from(&path) else {
        return (
            vec![DiagnosticResult::pass(
                "pipeline_telemetry",
                format!(
                    "No pipeline telemetry snapshot yet at {} (written once the agent has run)",
                    path.display()
                ),
            )],
            None,
        );
    };

    let mut results = registry_results(&snapshot);
    results.extend(file_attribution_results(&snapshot));
    results.extend(etw_decode_results(&snapshot));

    let dropping = snapshot.dropping_channels();
    if dropping.is_empty() {
        results.insert(
            0,
            DiagnosticResult::pass(
                "pipeline_telemetry",
                format!(
                    "No telemetry dropped across {} events (snapshot from {})",
                    snapshot.total_accepted(),
                    snapshot.captured_at
                ),
            ),
        );
        return (results, Some(snapshot));
    }

    let detail = dropping
        .iter()
        .map(|channel| channel.describe())
        .collect::<Vec<_>>()
        .join("; ");

    let result = DiagnosticResult::warn(
        "pipeline_telemetry",
        format!(
            "{} events were dropped under load (snapshot from {})",
            snapshot.total_dropped(),
            snapshot.captured_at
        ),
        detail,
    )
    .with_fix(
        "Detection gaps are proportional to these counts. Reduce event volume - narrow broad \
         rules, widen trusted-path allowlists - and re-run to confirm the totals stop growing; \
         see docs/troubleshooting.md",
    );

    results.insert(0, result);
    (results, Some(snapshot))
}

/// Registry key-path resolution, the one gap a channel counter cannot show.
///
/// A registry write whose key path cannot be recovered is discarded inside the
/// sensor, before any channel sees it, so it appears in no drop count (#341).
/// Empty on platforms without the ETW registry sensor.
fn registry_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let Some(registry) = snapshot.registry.as_ref() else {
        return Vec::new();
    };

    if registry.rundown_attempted && registry.snapshot_keys == 0 {
        return vec![DiagnosticResult::warn(
            "registry_path_resolution",
            "Registry startup rundown found no open keys",
            registry.describe(),
        )
        .with_fix(
            "The sensor could not seed paths for handles older than the trace session. Check the \
             agent log for the registry rundown failure and confirm the service has SYSTEM rights",
        )];
    }

    // The threshold the #341 follow-up hangs on: below it, the classic kernel
    // provider's KCB rundown is the next thing to try.
    const TARGET_RATE_PCT: f64 = 99.9;

    let rate = registry.resolution_rate_pct();
    if registry.events_unresolved == 0 || rate >= TARGET_RATE_PCT {
        return vec![DiagnosticResult::pass(
            "registry_path_resolution",
            registry.describe(),
        )];
    }

    vec![DiagnosticResult::warn(
        "registry_path_resolution",
        format!(
            "{} registry writes had no recoverable key path ({:.2}% resolved)",
            registry.events_unresolved, rate,
        ),
        registry.describe(),
    )
    .with_fix(
        "Those writes reached no rule. Writes by protected processes are expected here; a \
         sustained rate below 99.9% otherwise means the key rundown missed keys - see \
         docs/troubleshooting.md",
    )]
}

/// Kernel-File path attribution, the file-side twin of [`registry_results`].
///
/// A file event whose `FileObject`/`FileKey` resolves to no path is discarded
/// inside the ETW callback, so like the registry gap it appears in no channel
/// drop count. Empty on platforms without the ETW file sensor.
fn file_attribution_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let Some(files) = snapshot.file_attribution.as_ref() else {
        return Vec::new();
    };

    // Writes through handles opened before the sensor started are unresolvable
    // by construction, so a small residue is expected on any agent that has
    // not been running long. The threshold is the registry one: below it, the
    // gap is large enough to cost detections.
    const TARGET_RATE_PCT: f64 = 99.0;

    let rate = files.resolution_rate_pct();
    if files.unresolved == 0 || rate >= TARGET_RATE_PCT {
        return vec![DiagnosticResult::pass(
            "file_path_attribution",
            files.describe(),
        )];
    }

    let fix = if files.index_capacity_evictions > 0 {
        "Those events reached no rule. The handle index also evicted entries at its capacity, \
         which is what a process holding many handles open looks like - see \
         docs/troubleshooting.md"
    } else {
        "Those events reached no rule. Writes through handles opened before the agent started \
         are expected here; a rate that stays low after a restart means naming events are being \
         lost - see docs/troubleshooting.md"
    };

    vec![DiagnosticResult::warn(
        "file_path_attribution",
        format!(
            "{} file events had no recoverable path ({:.2}% resolved)",
            files.unresolved, rate,
        ),
        files.describe(),
    )
    .with_fix(fix)]
}

/// ETW decoder degradation.
///
/// A schema lookup that fails, a payload template that no longer matches, or a
/// payload with nothing a rule can select on all produce a healthy-looking
/// pipeline with fewer detections in it (#394). Empty on platforms without the
/// ETW sensor.
fn etw_decode_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let Some(decode) = snapshot.etw_decode.as_ref() else {
        return Vec::new();
    };

    let mut results = Vec::new();

    if decode.failed() > 0 {
        let detail = decode
            .failures
            .iter()
            .take(5)
            .map(|failure| {
                format!(
                    "{} event {} v{}: {} x{}",
                    failure.provider,
                    failure.event_id,
                    failure.version,
                    failure.failure,
                    failure.count
                )
            })
            .collect::<Vec<_>>()
            .join("; ");

        results.push(
            DiagnosticResult::warn(
                "etw_decode",
                format!(
                    "{} ETW records failed to decode ({:.4}% of {} received)",
                    decode.failed(),
                    decode.failure_rate_pct(),
                    decode.records_received,
                ),
                if detail.is_empty() {
                    decode.describe()
                } else {
                    detail
                },
            )
            .with_fix(
                "Those records produced no event, so their rules could not fire. A provider and \
                 event version that appear here changed under this build - report them with the \
                 Windows build number; see docs/troubleshooting.md",
            ),
        );
    } else {
        results.push(DiagnosticResult::pass("etw_decode", decode.describe()));
    }

    // Only meaningful as a persistent mismatch: the counters are incremented
    // independently on the callback's hot path, so a snapshot taken mid-record
    // is legitimately off by a few.
    if !decode.is_reconciled() {
        results.push(
            DiagnosticResult::warn(
                "etw_decode_reconciliation",
                format!(
                    "{} of {} ETW records are unaccounted for",
                    decode.records_received.saturating_sub(decode.classified()),
                    decode.records_received,
                ),
                decode.describe(),
            )
            .with_fix(
                "A small, non-growing difference is the snapshot catching a record mid-decode. A \
                 growing one is a decoder path that reports no outcome - please report it",
            ),
        );
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::inspect::DiagnosticStatus;
    use crate::telemetry::{
        ChannelSnapshot, EtwDecodeFailureSnapshot, EtwDecodeSnapshot, FileAttributionSnapshot,
        RegistrySnapshot,
    };

    fn snapshot(channels: Vec<ChannelSnapshot>) -> TelemetrySnapshot {
        TelemetrySnapshot {
            version: "1.3.0".to_string(),
            pid: 7,
            captured_at: "2026-08-24T12:00:00Z".to_string(),
            uptime_secs: 3600,
            channels,
            sensor_events_by_category: Vec::new(),
            windows_process_command_line: None,
            registry: None,
            file_attribution: None,
            etw_decode: None,
        }
    }

    fn channel(name: &str, accepted: u64, dropped: u64) -> ChannelSnapshot {
        ChannelSnapshot {
            channel: name.to_string(),
            capacity: 8192,
            accepted,
            dropped,
            dropped_channel_closed: 0,
            high_water_mark: 8192,
        }
    }

    #[test]
    fn a_missing_snapshot_is_not_a_finding() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cfg = AppConfig::default();

        let (results, read) = telemetry_results(&cfg, temp.path());

        assert!(read.is_none());
        assert_eq!(results[0].status, DiagnosticStatus::Pass);
        assert!(results[0]
            .message
            .contains("No pipeline telemetry snapshot"));
    }

    #[test]
    fn a_clean_snapshot_passes_and_reports_the_volume() {
        let temp = tempfile::tempdir().expect("tempdir");
        snapshot(vec![channel("sensor_events", 5_000, 0)])
            .write_to(&snapshot_path(temp.path()))
            .expect("write snapshot");

        let (results, read) = telemetry_results(&AppConfig::default(), temp.path());

        assert_eq!(results[0].status, DiagnosticStatus::Pass);
        assert!(results[0].message.contains("5000 events"));
        assert_eq!(read.expect("snapshot").pid, 7);
    }

    /// The whole point of the check: an operator sees the size of the gap and
    /// which channel produced it without opening a log file.
    #[test]
    fn dropped_telemetry_warns_with_per_channel_counts() {
        let temp = tempfile::tempdir().expect("tempdir");
        snapshot(vec![
            channel("sensor_events", 9_000, 1_000),
            channel("yara_file_scan", 100, 25),
        ])
        .write_to(&snapshot_path(temp.path()))
        .expect("write snapshot");

        let (results, _) = telemetry_results(&AppConfig::default(), temp.path());

        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].message.contains("1025 events were dropped"));

        let detail = results[0].detail.as_deref().expect("detail");
        // Worst channel first, so the summary leads with the real gap.
        assert!(detail.starts_with("sensor_events: 1000 dropped of 10000 offered (10.00%)"));
        assert!(detail.contains("yara_file_scan: 25 dropped of 125 offered"));
        assert!(results[0].fix.is_some());
    }

    #[test]
    fn disabling_persistence_is_reported_as_a_visibility_gap() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut cfg = AppConfig::default();
        cfg.telemetry.enabled = false;

        let (results, read) = telemetry_results(&cfg, temp.path());

        assert!(read.is_none());
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
    }
    fn registry(resolved: u64, unresolved: u64, from_snapshot: u64) -> RegistrySnapshot {
        RegistrySnapshot {
            rundown_attempted: true,
            events_received: resolved + unresolved,
            events_resolved: resolved,
            events_unresolved: unresolved,
            resolved_from_snapshot: from_snapshot,
            resolved_after_close: 7,
            naming_create: 10,
            naming_open: 100,
            naming_failed: 40,
            snapshot_keys: 5_879,
        }
    }

    fn file_attribution(resolved: u64, unresolved: u64, evictions: u64) -> FileAttributionSnapshot {
        FileAttributionSnapshot {
            attempted: resolved + unresolved,
            resolved_from_event: resolved,
            resolved_from_index: 0,
            unresolved,
            index_capacity_evictions: evictions,
        }
    }

    fn etw_decode(received: u64, schema_errors: u64) -> EtwDecodeSnapshot {
        EtwDecodeSnapshot {
            records_received: received,
            records_filtered: received.saturating_sub(schema_errors),
            records_indexed: 0,
            records_decoded: 0,
            records_unattributed: 0,
            schema_errors,
            unsupported_layouts: 0,
            fieldless_payloads: 0,
            events_emitted: 0,
            failures: vec![EtwDecodeFailureSnapshot {
                provider: "Microsoft-Windows-Kernel-Registry".to_string(),
                event_id: 5,
                version: 2,
                failure: "schema".to_string(),
                count: schema_errors,
            }],
            unkeyed_failures: 0,
        }
    }

    /// The file-side twin of the registry gap: these events are discarded
    /// inside the ETW callback, so no channel counter can show them (#394).
    #[test]
    fn unattributed_file_events_are_reported_as_their_own_gap() {
        let mut snap = snapshot(vec![channel("sensor_events", 10_000, 0)]);
        snap.file_attribution = Some(file_attribution(900, 100, 0));

        let results = file_attribution_results(&snap);

        assert_eq!(results[0].id, "file_path_attribution");
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].message.contains("100 file events"));
        assert!(results[0].message.contains("90.00% resolved"));
        assert!(results[0]
            .fix
            .as_deref()
            .expect("fix")
            .contains("opened before the agent started"));
    }

    /// Evictions and unresolved events have different fixes, so the advice has
    /// to name the one that is actually happening.
    #[test]
    fn index_evictions_change_the_suggested_fix() {
        let mut snap = snapshot(vec![channel("sensor_events", 10, 0)]);
        snap.file_attribution = Some(file_attribution(900, 100, 4_096));

        let results = file_attribution_results(&snap);

        assert!(results[0]
            .fix
            .as_deref()
            .expect("fix")
            .contains("evicted entries at its capacity"));
    }

    #[test]
    fn a_file_resolution_rate_at_target_passes() {
        let mut snap = snapshot(vec![channel("sensor_events", 10, 0)]);
        snap.file_attribution = Some(file_attribution(10_000, 1, 0));

        let results = file_attribution_results(&snap);

        assert_eq!(results[0].status, DiagnosticStatus::Pass);
    }

    #[test]
    fn a_snapshot_without_windows_counters_adds_no_diagnostic() {
        // Linux and macOS have no ETW sensor, and snapshots written before
        // #394 carry neither section.
        let snap = snapshot(vec![channel("sensor_events", 10, 0)]);

        assert!(file_attribution_results(&snap).is_empty());
        assert!(etw_decode_results(&snap).is_empty());
    }

    /// The whole point of #394: records that fail to decode leave the channel
    /// counters looking healthy, so the failure needs a check of its own that
    /// names the provider and event version to report.
    #[test]
    fn decode_failures_are_reported_with_their_bounded_key() {
        let mut snap = snapshot(vec![channel("sensor_events", 10_000, 0)]);
        snap.etw_decode = Some(etw_decode(10_000, 25));

        let results = etw_decode_results(&snap);

        assert_eq!(results[0].id, "etw_decode");
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0]
            .message
            .contains("25 ETW records failed to decode"));
        assert_eq!(
            results[0].detail.as_deref(),
            Some("Microsoft-Windows-Kernel-Registry event 5 v2: schema x25")
        );
        // Reconciles, so the second check must not fire.
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn a_decoder_with_no_failures_passes() {
        let mut snap = snapshot(vec![channel("sensor_events", 10, 0)]);
        snap.etw_decode = Some(etw_decode(10_000, 0));

        let results = etw_decode_results(&snap);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, DiagnosticStatus::Pass);
        assert!(results[0].message.contains("10000 records received"));
    }

    #[test]
    fn records_that_reach_no_outcome_are_reported_separately() {
        let mut snap = snapshot(vec![channel("sensor_events", 10, 0)]);
        let mut decode = etw_decode(10_000, 0);
        decode.records_filtered = 9_000;
        snap.etw_decode = Some(decode);

        let results = etw_decode_results(&snap);

        assert_eq!(results[1].id, "etw_decode_reconciliation");
        assert_eq!(results[1].status, DiagnosticStatus::Warn);
        assert!(results[1].message.contains("1000 of 10000"));
    }

    #[test]
    fn unresolved_registry_writes_are_reported_as_their_own_gap() {
        // These never reach a channel, so no drop counter can show them: the
        // sensor discards a registry write it cannot name (#341).
        let mut snap = snapshot(vec![channel("sensor_events", 10_000, 0)]);
        snap.registry = Some(registry(900, 100, 40));

        let results = registry_results(&snap);

        assert_eq!(results[0].id, "registry_path_resolution");
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].message.contains("100 registry writes"));
        assert!(results[0].message.contains("90.00% resolved"));
        assert!(results[0]
            .detail
            .as_deref()
            .expect("detail")
            .contains("40 rescued by the startup snapshot of 5879 keys"));
    }

    #[test]
    fn a_registry_resolution_rate_at_target_passes() {
        let mut snap = snapshot(vec![channel("sensor_events", 10_000, 0)]);
        snap.registry = Some(registry(10_000, 1, 12));

        let results = registry_results(&snap);

        assert_eq!(results[0].status, DiagnosticStatus::Pass);
    }

    #[test]
    fn a_snapshot_without_registry_counters_adds_no_diagnostic() {
        // Linux and macOS have no ETW registry sensor, and snapshots written
        // before #341 carry no registry section.
        let snap = snapshot(vec![channel("sensor_events", 10, 0)]);

        assert!(registry_results(&snap).is_empty());
    }

    #[test]
    fn an_empty_attempted_rundown_is_reported() {
        let mut snap = snapshot(vec![channel("sensor_events", 0, 0)]);
        let mut registry = registry(0, 0, 0);
        registry.snapshot_keys = 0;
        snap.registry = Some(registry);

        let results = registry_results(&snap);

        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].message.contains("rundown found no open keys"));
    }
}
