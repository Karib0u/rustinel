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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::inspect::DiagnosticStatus;
    use crate::telemetry::{ChannelSnapshot, RegistrySnapshot};

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
