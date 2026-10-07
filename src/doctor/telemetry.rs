//! Pipeline drop-counter diagnostics.
//!
//! Answers "did this endpoint lose telemetry, and how much?" from the snapshot
//! the running agent writes, so an operator does not have to grep rotated logs
//! to size a detection gap.

use crate::config::AppConfig;
use crate::doctor::inspect::{DiagnosticResult, InstallMode};
use crate::telemetry::{snapshot_path, SnapshotRead, TelemetrySnapshot};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Whether the agent is believed to be running, from the service manager.
///
/// Portable runs and unreadable service state are `Unknown`: the absence of a
/// running service there says nothing about whether an agent is alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeState {
    Running,
    Starting,
    Stopped,
    Unknown,
}

impl RuntimeState {
    pub(crate) fn from_service(mode: InstallMode, service_status: &str) -> Self {
        if mode == InstallMode::Portable {
            return Self::Unknown;
        }
        match service_status {
            "running" => Self::Running,
            "starting" => Self::Starting,
            "stopped" | "failed" | "not-installed" => Self::Stopped,
            _ => Self::Unknown,
        }
    }
}

/// Grace added to twice the publication interval before a snapshot is stale.
///
/// Twice the interval absorbs one missed write under load, and the fixed
/// allowance covers scheduler delay and the first write after a restart.
pub(crate) const STALE_GRACE_SECS: i64 = 30;
/// How far ahead of this host's clock a timestamp may be before it is reported.
pub(crate) const FUTURE_TOLERANCE_SECS: i64 = 60;

/// Availability and age of the snapshot, carried in the `--json` report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TelemetrySnapshotStatus {
    /// `disabled`, `missing`, `unreadable`, `malformed`, `invalid_timestamp`,
    /// `future`, `fresh`, `stale`, or `historical`.
    pub state: &'static str,
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<i64>,
    pub interval_secs: u64,
    pub stale_after_secs: u64,
}

pub(crate) struct TelemetryAssessment {
    pub(crate) results: Vec<DiagnosticResult>,
    pub(crate) snapshot: Option<TelemetrySnapshot>,
    pub(crate) status: TelemetrySnapshotStatus,
}

fn stale_after_secs(interval_secs: u64) -> u64 {
    interval_secs
        .max(1)
        .saturating_mul(2)
        .saturating_add(STALE_GRACE_SECS as u64)
}

/// Inspect the persisted pipeline counters for `logs_dir`.
///
/// Snapshot availability and freshness are judged separately from the counters
/// inside it: an unreadable or stale snapshot is not evidence of a healthy
/// pipeline, and a running service makes that gap a warning.
pub(crate) fn telemetry_results(
    cfg: &AppConfig,
    logs_dir: &Path,
    runtime: RuntimeState,
) -> TelemetryAssessment {
    assess(cfg, logs_dir, runtime, Utc::now())
}

fn assess(
    cfg: &AppConfig,
    logs_dir: &Path,
    runtime: RuntimeState,
    now: DateTime<Utc>,
) -> TelemetryAssessment {
    let path = snapshot_path(logs_dir);
    let interval_secs = cfg.telemetry.snapshot_interval_secs;
    let stale_after = stale_after_secs(interval_secs);
    let status = |state, age_secs| TelemetrySnapshotStatus {
        state,
        path: path.clone(),
        age_secs,
        interval_secs,
        stale_after_secs: stale_after,
    };

    if !cfg.telemetry.enabled {
        return TelemetryAssessment {
            results: vec![DiagnosticResult::warn(
                "pipeline_telemetry",
                "Pipeline drop counters are not being persisted",
                "telemetry.enabled is false, so dropped-event totals are only visible in the agent log",
            )
            .with_fix("Set telemetry.enabled = true to make drop counters readable here")],
            snapshot: None,
            status: status("disabled", None),
        };
    }

    let running = runtime == RuntimeState::Running;
    let unavailable = |state, message: String, detail: String, fix: &str| {
        // A snapshot that cannot be used is a warning whenever it could be the
        // only evidence of a live agent, and a passing note only when no agent
        // is expected to have written it.
        let result = if running || state != "missing" {
            DiagnosticResult::warn("pipeline_telemetry", message, detail).with_fix(fix)
        } else {
            DiagnosticResult::pass("pipeline_telemetry", message)
        };
        TelemetryAssessment {
            results: vec![result],
            snapshot: None,
            status: status(state, None),
        }
    };

    let snapshot = match TelemetrySnapshot::load(&path) {
        SnapshotRead::Missing => {
            let prefix = format!("No pipeline telemetry snapshot at {}", path.display());
            let message = if running {
                format!("{prefix} although the service is running; runtime health is unknown")
            } else if runtime == RuntimeState::Starting {
                format!("{prefix} yet (the service is starting; the first is written after one interval)")
            } else {
                format!("{prefix} (the agent has not written one yet)")
            };
            return unavailable(
                "missing",
                message,
                "A running service writes the snapshot within telemetry.snapshot_interval_secs of starting. Collection and detection cannot be assessed without it".to_string(),
                "Check that this config's log directory is the one the service uses, then inspect the service log",
            );
        }
        SnapshotRead::Unreadable(err) => {
            return unavailable(
                "unreadable",
                format!("Pipeline telemetry snapshot at {} could not be read; runtime health is unknown", path.display()),
                err,
                "Run doctor as a user that can read the log directory, or fix the file permissions",
            );
        }
        SnapshotRead::Malformed(err) => {
            return unavailable(
                "malformed",
                format!("Pipeline telemetry snapshot at {} is not valid; runtime health is unknown", path.display()),
                err,
                "Inspect the file and the agent log; the agent rewrites it every interval, so a persistent failure means it cannot write",
            );
        }
        SnapshotRead::Valid(snapshot) => *snapshot,
    };

    let (state, age) = match DateTime::parse_from_rfc3339(&snapshot.captured_at) {
        Err(_) => ("invalid_timestamp", None),
        Ok(captured) => {
            let age = (now - captured.with_timezone(&Utc)).num_seconds();
            let state = if age < -FUTURE_TOLERANCE_SECS {
                "future"
            } else if age <= stale_after as i64 {
                "fresh"
            } else if runtime == RuntimeState::Stopped {
                "historical"
            } else {
                "stale"
            };
            (state, Some(age))
        }
    };

    let freshness = match state {
        "fresh" => DiagnosticResult::pass(
            "telemetry_snapshot",
            format!(
                "Telemetry snapshot is current ({}s old, stale after {}s)",
                age.unwrap_or(0).max(0),
                stale_after
            ),
        ),
        "historical" => DiagnosticResult::pass(
            "telemetry_snapshot",
            format!(
                "Telemetry snapshot from {} is historical: the agent is not running, so these counters describe its last run",
                snapshot.captured_at
            ),
        ),
        "stale" if running => DiagnosticResult::warn(
            "telemetry_snapshot",
            format!(
                "Telemetry snapshot is {}s old but the service is running; runtime health is degraded or unknown",
                age.unwrap_or(0)
            ),
            format!(
                "Written {}, expected every {}s and stale after {}s. The agent may be hung or unable to write its log directory",
                snapshot.captured_at, interval_secs, stale_after
            ),
        )
        .with_fix("Inspect the service log; restart the service if it is not making progress"),
        "stale" if runtime == RuntimeState::Starting => DiagnosticResult::pass(
            "telemetry_snapshot",
            format!(
                "Telemetry snapshot from {} predates this start; a new one is written after one interval",
                snapshot.captured_at
            ),
        ),
        "stale" => DiagnosticResult::pass(
            "telemetry_snapshot",
            format!(
                "Telemetry snapshot is {}s old; service state is unknown, so it is not evidence of current health",
                age.unwrap_or(0)
            ),
        ),
        "future" => DiagnosticResult::warn(
            "telemetry_snapshot",
            format!(
                "Telemetry snapshot timestamp {} is {}s in the future; freshness cannot be assessed",
                snapshot.captured_at,
                -age.unwrap_or(0)
            ),
            "The clock moved backwards, or the snapshot was written on a host with a different clock",
        )
        .with_fix("Check system time on this host"),
        _ => DiagnosticResult::warn(
            "telemetry_snapshot",
            format!(
                "Telemetry snapshot timestamp {:?} is not RFC 3339; freshness cannot be assessed",
                snapshot.captured_at
            ),
            "Runtime health cannot be confirmed from this snapshot",
        )
        .with_fix("Inspect the file and the agent log"),
    };

    let mut results = pipeline_results(snapshot.clone());
    results.insert(1, freshness);
    TelemetryAssessment {
        results,
        snapshot: Some(snapshot),
        status: status(state, age),
    }
}

fn pipeline_results(snapshot: TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let mut results = linux_ebpf_results(&snapshot);
    results.extend(host_state_results(&snapshot));
    results.extend(artifact_resolver_results(&snapshot));
    results.extend(macos_collector_results(&snapshot));
    results.extend(registry_results(&snapshot));
    results.extend(file_attribution_results(&snapshot));
    results.extend(etw_decode_results(&snapshot));
    results.extend(event_log_results(&snapshot));

    results.extend(process_correlation_results(&snapshot));
    results.extend(field_contract_results(&snapshot));
    results.extend(field_fidelity_results(&snapshot));
    results.extend(alert_webhook_results(&snapshot));
    let dropping = snapshot.dropping_channels();
    let alert_writer_drops = snapshot
        .channels
        .iter()
        .find(|channel| channel.channel == "alert_writer")
        .map_or(0, |channel| channel.dropped);
    if dropping.is_empty() {
        results.insert(
            0,
            DiagnosticResult::pass(
                "pipeline_telemetry",
                format!(
                    "No channel drops across {} items (snapshot from {})",
                    snapshot.total_accepted(),
                    snapshot.captured_at
                ),
            ),
        );
        return results;
    }

    let detail = dropping
        .iter()
        .map(|channel| channel.describe())
        .collect::<Vec<_>>()
        .join("; ");

    let result = if alert_writer_drops > 0 {
        let message = format!(
            "{} alerts were dropped by the alert writer ({} total channel drops; snapshot from {})",
            alert_writer_drops,
            snapshot.total_dropped(),
            snapshot.captured_at
        );
        DiagnosticResult::fail("pipeline_telemetry", message, detail).with_fix(
            "Alert file output lost records. Check disk health and alert volume, then re-run to confirm the count stops growing",
        )
    } else {
        let message = format!(
            "{} events were shed by pipeline channels (snapshot from {})",
            snapshot.total_dropped(),
            snapshot.captured_at
        );
        DiagnosticResult::warn("pipeline_telemetry", message, detail).with_fix(
            "Detection gaps are proportional to these counts. Reduce event volume - narrow broad \
             rules, widen trusted-path allowlists - and re-run to confirm the totals stop growing; \
             see https://docs.rustinel.io/telemetry-loss/",
        )
    };

    results.insert(0, result);
    results
}

fn field_contract_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    if snapshot.field_contract_violations == 0 {
        return Vec::new();
    }

    vec![DiagnosticResult::warn(
        "field_contract_violations",
        format!(
            "{} populated fields contradicted the field availability contract",
            snapshot.field_contract_violations
        ),
        "The detector read path filtered fields declared Never. Correct the decoder or update the contract before relying on those fields.",
    )]
}

fn artifact_resolver_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let Some(resolver) = &snapshot.artifact_resolver else {
        return Vec::new();
    };
    let failures = resolver
        .queue_saturated
        .saturating_add(resolver.worker_saturated)
        .saturating_add(resolver.deadline_exceeded)
        .saturating_add(resolver.admission_budget_exceeded)
        .saturating_add(resolver.open_failed)
        .saturating_add(resolver.identity_mismatch)
        .saturating_add(resolver.identity_unavailable)
        .saturating_add(resolver.read_failed)
        .saturating_add(resolver.consumer_failed)
        .saturating_add(resolver.oversized)
        .saturating_add(resolver.deferred_budget_exceeded)
        .saturating_add(resolver.deferred_queue_saturated);
    let detail = format!(
        "{} queued, {} resolved, {} cache hits/{} misses; stores: PE {}, hashes {}, imphashes {}, signatures {}, YARA {} (generation {}), {} evicted; admission: {} past the {} ms budget, {} backpressured sends; deferred pass: {} queued, {} with artifact fields, {} without ({} past the {} ms budget), {} queue saturated, correlation lateness bounded at {} ms; outcomes: {} queue saturated, {} workers saturated, {} deadline, {} open, {} identity, {} identity unavailable, {} read, {} consumer, {} oversized",
        resolver.queued,
        resolver.resolved,
        resolver.cache_hits,
        resolver.cache_misses,
        resolver.pe_entries,
        resolver.hash_entries,
        resolver.imphash_entries,
        resolver.signature_entries,
        resolver.yara_entries,
        resolver.yara_generation,
        resolver.evicted,
        resolver.admission_budget_exceeded,
        resolver.admission_budget_ms,
        resolver.admission_backpressure,
        resolver.deferred_queued,
        resolver.deferred_enriched,
        resolver.deferred_unenriched,
        resolver.deferred_budget_exceeded,
        resolver.deferred_budget_ms,
        resolver.deferred_queue_saturated,
        resolver.correlation_lateness_ms,
        resolver.queue_saturated,
        resolver.worker_saturated,
        resolver.deadline_exceeded,
        resolver.open_failed,
        resolver.identity_mismatch,
        resolver.identity_unavailable,
        resolver.read_failed,
        resolver.consumer_failed,
        resolver.oversized,
    );
    let detail = format!(
        "{detail}; dropped jobs: process images {}, loaded images {}, written files {}; written-file selection: {} rejected, {} coalesced",
        resolver.process_image_dropped,
        resolver.loaded_image_dropped,
        resolver.written_file_dropped,
        resolver.written_file_rejected,
        resolver.written_file_coalesced,
    );
    let dropped = resolver
        .process_image_dropped
        .saturating_add(resolver.loaded_image_dropped)
        .saturating_add(resolver.written_file_dropped);
    let message = format!(
        "{} artifact-resolution failure outcomes were recorded",
        failures.max(dropped)
    );
    let message = if resolver.written_file_dropped > 0 {
        format!(
            "{message}; {} written-file jobs dropped, leaving a YARA and hash IOC detection gap",
            resolver.written_file_dropped
        )
    } else {
        message
    };
    vec![if failures == 0 && dropped == 0 {
        DiagnosticResult::pass("artifact_resolver", detail)
    } else {
        DiagnosticResult::warn(
            "artifact_resolver",
            message,
            detail,
        )
        .with_fix(
            "Inspect artifact resolver pressure and file-access failures; increase throughput or narrow artifact consumers before relying on enriched detections",
        )
    }]
}

/// Webhook delivery is additive to the alert file, so undelivered alerts are a
/// gap at the receiver, not a detection gap.
fn alert_webhook_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    if snapshot.alert_webhooks.is_empty() {
        return Vec::new();
    }
    let detail = snapshot
        .alert_webhooks
        .iter()
        .map(|webhook| webhook.describe())
        .collect::<Vec<_>>()
        .join("; ");
    let undelivered = snapshot
        .alert_webhooks
        .iter()
        .map(|webhook| webhook.undelivered())
        .fold(0u64, u64::saturating_add);
    if undelivered == 0 {
        let delivered = snapshot
            .alert_webhooks
            .iter()
            .map(|webhook| webhook.delivered)
            .fold(0u64, u64::saturating_add);
        return vec![DiagnosticResult::pass(
            "alert_webhooks",
            format!(
                "{delivered} alerts delivered to {} webhook destinations",
                snapshot.alert_webhooks.len()
            ),
        )
        .with_detail(detail)];
    }
    vec![DiagnosticResult::warn(
        "alert_webhooks",
        format!("{undelivered} alerts did not reach a webhook destination"),
        detail,
    )
    .with_fix(
        "The alert file still holds every alert. Check the endpoint's availability and the operational log for the failure reason; raise queue_capacity or max_attempts if the endpoint is only slow",
    )]
}

fn host_state_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let Some(state) = &snapshot.host_state else {
        return Vec::new();
    };
    let detail = format!("{} active and {} retired processes (limit {} each), {} users (limit {}), {} DNS entries (limit {}), {} path entries (limit {} per index); {} attribution losses",
        state.processes, state.retired_processes, state.limits.processes,
        state.users, state.limits.users, state.dns, state.limits.dns, state.paths, state.limits.paths, state.attribution_loss);
    let mut results = vec![if state.attribution_loss > 0 {
        DiagnosticResult::warn(
            "host_state",
            "Host attribution state updates were lost",
            detail,
        )
    } else {
        DiagnosticResult::pass("host_state", detail)
    }];
    if let Some(inventory) = &state.inventory {
        let detail = format!(
            "{} of {} processes seeded, {} skipped in {} ms",
            inventory.seeded, inventory.scanned, inventory.skipped, inventory.duration_ms
        );
        results.push(if let Some(error) = &inventory.error {
            DiagnosticResult::warn("process_inventory", detail, error)
        } else if inventory.seeded == 0 && inventory.scanned > 0 {
            DiagnosticResult::warn(
                "process_inventory",
                "No existing processes could be attributed",
                detail,
            )
        } else {
            DiagnosticResult::pass("process_inventory", detail)
        });
    }
    results
}

fn field_fidelity_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();
    if !snapshot.field_fidelity.is_empty() {
        results.push(
            DiagnosticResult::pass("field_fidelity", "Field fidelity limitations recorded")
                .with_detail(
                    snapshot
                        .field_fidelity
                        .iter()
                        .map(|entry| {
                            format!("{}: {:?} ({})", entry.field, entry.fidelity, entry.count)
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                ),
        );
    }
    results
}

/// Keep kernel loss distinct from ingress and detector queue shedding.
fn macos_collector_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let Some(macos) = &snapshot.macos_collectors else {
        return Vec::new();
    };
    let mut results = Vec::new();
    if let Some(esf) = &macos.esf {
        let detail = format!(
            "ESF: {} received; per-event-type kernel gaps: {:?}",
            esf.received, esf.kernel_dropped_by_event_type
        );
        if esf.kernel_dropped > 0 || esf.kernel_dropped_by_event_type.values().any(|n| *n > 0) {
            results.push(DiagnosticResult::warn(
                "macos_esf_kernel_loss",
                format!(
                    "ESF kernel loss: {} global sequence gaps",
                    esf.kernel_dropped
                ),
                detail,
            ));
        } else {
            results.push(DiagnosticResult::pass("macos_esf_kernel_loss", detail));
        }
    }
    if let Some(bpf) = &macos.bpf {
        let detail = format!(
            "BPF: {} kernel packets received, {} kernel drops, {} stats polls, {} stats errors",
            bpf.kernel_received, bpf.kernel_dropped, bpf.stats_polls, bpf.stats_errors
        );
        if bpf.kernel_dropped > 0 || bpf.stats_errors > 0 || bpf.stats_polls == 0 {
            results.push(DiagnosticResult::warn(
                "macos_bpf_kernel_loss",
                "BPF kernel loss or unavailable capture statistics",
                detail,
            ));
        } else {
            results.push(DiagnosticResult::pass("macos_bpf_kernel_loss", detail));
        }
        for (name, interface) in &bpf.interfaces {
            let detail =
                format!(
                "{}: active={}, DLT={:?}, {} kernel packets, {} kernel drops, {} stats errors{}",
                name, interface.active, interface.link_type,
                interface.kernel_received, interface.kernel_dropped, interface.stats_errors,
                interface.error.as_ref().map_or(String::new(), |error| format!(", {error}"))
            );
            let id = format!("macos_bpf_interface_{name}");
            if !interface.active
                || interface.stats_polls == 0
                || interface.error.is_some()
                || interface.kernel_dropped > 0
                || interface.stats_errors > 0
            {
                results.push(DiagnosticResult::warn(
                    id,
                    format!("BPF interface {name} is degraded"),
                    detail,
                ));
            } else {
                results.push(DiagnosticResult::pass(id, detail));
            }
        }
    }
    results
}

fn event_log_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();
    for channel in &snapshot.windows_event_log {
        let id = format!("windows_event_log_{}", channel.channel);
        let detail =
            format!(
            "active={}, delivered={}, subscription_errors={}, live_stale={}, resume_failures={}, \
             checkpoint_errors={}, decode_errors={}, last_error={}",
            channel.active, channel.delivered, channel.subscription_errors, channel.live_stale,
            channel.resume_failures, channel.checkpoint_errors, channel.decode_errors,
            channel.last_error.as_deref().unwrap_or("none"),
        );
        let degraded = !channel.active
            || channel.subscription_errors > 0
            || channel.resume_failures > 0
            || channel.checkpoint_errors > 0
            || channel.decode_errors > 0;
        results.push(if degraded {
            DiagnosticResult::warn(
                &id,
                format!(
                    "{} Event Log subscription is stopped or degraded",
                    channel.channel
                ),
                detail,
            )
        } else {
            DiagnosticResult::pass(&id, detail)
        });
        let retention_id = format!("{id}_retention");
        results.push(if channel.retention_wraps > 0 {
            DiagnosticResult::warn(
                retention_id,
                format!(
                    "{} Event Log retention passed the saved bookmark",
                    channel.channel
                ),
                format!(
                    "{} downtime retention incidents; matching records lost is unknown",
                    channel.retention_wraps
                ),
            )
        } else {
            DiagnosticResult::pass(retention_id, "No downtime retention wrap detected")
        });
    }
    results
}

fn process_correlation_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();
    let correlation = &snapshot.windows_process_correlation;
    if correlation.classic_records + correlation.unmatched + correlation.session_failures > 0 {
        let detail = format!("matched={}, unmatched={}, conflicting={}, classic_unmatched={}, classic_command_line={}, rundown={}, decode_failed={}, session_failures={}",
            correlation.matched, correlation.unmatched, correlation.conflicting,
            correlation.classic_unmatched, correlation.classic_command_line, correlation.rundown,
            correlation.decode_failed, correlation.session_failures);
        results.push(
            if correlation.conflicting
                + correlation.unmatched
                + correlation.session_failures
                + correlation.classic_unmatched
                + correlation.decode_failed
                > 0
            {
                DiagnosticResult::warn(
                    "windows_process_correlation",
                    "Process metadata correlation has gaps or conflicts",
                    detail,
                )
            } else {
                DiagnosticResult::pass("windows_process_correlation", detail)
            },
        );
    }
    results
}

/// Linux eBPF loss and reconciliation across every ring family.
fn linux_ebpf_results(snapshot: &TelemetrySnapshot) -> Vec<DiagnosticResult> {
    let Some(ebpf) = snapshot.linux_ebpf.as_ref() else {
        return Vec::new();
    };

    let mut results = ebpf
        .features
        .iter()
        .map(|feature| {
            let id = format!("linux_ebpf_{}_capability", feature.feature);
            if feature.unavailable_hooks.is_empty() {
                return DiagnosticResult::pass(
                    id,
                    format!(
                        "Linux eBPF {} telemetry is active ({} hooks)",
                        feature.feature,
                        feature.attached_hooks.len()
                    ),
                );
            }

            let state = if feature.active { "degraded" } else { "unavailable" };
            DiagnosticResult::warn(
                id,
                format!("Linux eBPF {} telemetry is {state}", feature.feature),
                feature.unavailable_hooks.join("; "),
            )
            .with_fix(
                "The named hooks are not available on this kernel. Upgrade the kernel or disable rules that require this telemetry category",
            )
        })
        .collect::<Vec<_>>();

    let mut findings = Vec::new();
    for family in &ebpf.families {
        if family.kernel_ring_full > 0 {
            findings.push(format!(
                "{} ring was full {} times",
                family.ring, family.kernel_ring_full
            ));
        }
        if family.kernel_oversized > 0 {
            findings.push(format!(
                "{} ring rejected {} oversized events",
                family.ring, family.kernel_oversized
            ));
        }
        if family.kernel_map_full > 0 {
            findings.push(format!(
                "{} pending maps rejected {} inserts",
                family.ring, family.kernel_map_full
            ));
        }
        if family.short_reads > 0 {
            findings.push(format!(
                "{} ring produced {} short reads",
                family.ring, family.short_reads
            ));
        }
        if family.unresolved_file_events > 0 {
            findings.push(format!(
                "{} file events had no resolvable path",
                family.unresolved_file_events
            ));
        }
        let other_userspace_drops = family
            .userspace_dropped
            .saturating_sub(family.unresolved_file_events);
        if other_userspace_drops > 0 {
            findings.push(format!(
                "{} ring dropped {} decoded events in userspace",
                family.ring, other_userspace_drops
            ));
        }
        if !family.kernel_is_reconciled() {
            findings.push(format!("{} kernel counters do not reconcile", family.ring));
        }
        if !family.receive_is_reconciled() {
            findings.push(format!("{} receive counters do not reconcile", family.ring));
        }
        if !family.decode_is_reconciled() {
            findings.push(format!("{} decode counters do not reconcile", family.ring));
        }
    }

    let submitted = ebpf
        .families
        .iter()
        .map(|family| family.kernel_submitted)
        .fold(0u64, u64::saturating_add);
    let in_flight = ebpf
        .families
        .iter()
        .map(|family| family.queue_occupancy())
        .fold(0u64, u64::saturating_add);
    let detail = ebpf
        .families
        .iter()
        .map(|family| family.describe())
        .collect::<Vec<_>>()
        .join("; ");
    if let Some(sensor_channel) = snapshot
        .channels
        .iter()
        .find(|channel| channel.channel == "sensor_events")
    {
        let channel_offered = sensor_channel
            .accepted
            .saturating_add(sensor_channel.dropped);
        if ebpf.canonical_emitted() != channel_offered {
            findings.push(format!(
                "{} canonical events were emitted but the sensor channel accounted for {}",
                ebpf.canonical_emitted(),
                channel_offered
            ));
        }
    }

    if findings.is_empty() {
        results.push(DiagnosticResult::pass(
            "linux_ebpf",
            format!(
                "Linux eBPF pipeline reconciles across {} submitted events ({} in flight)",
                submitted, in_flight
            ),
        ));
        return results;
    }

    results.push(
        DiagnosticResult::warn("linux_ebpf", findings.join("; "), detail).with_fix(
            "Kernel ring or map failures are detection gaps. Reduce event volume or investigate a \
         stalled ring drain. A small non-growing reconciliation mismatch may be a snapshot taken \
         during an update; a growing mismatch should be reported",
        ),
    );
    results
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
         https://docs.rustinel.io/telemetry-loss/",
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

    if let Some(rundown) = files.rundown.as_ref().filter(|r| r.rejected) {
        return vec![DiagnosticResult::warn(
            "file_path_attribution",
            "File startup rundown was rejected; using live names only",
            format!("{} records, {} events lost, {} buffers lost, {} decode failures, {} ms. {}",
                rundown.records, rundown.events_lost, rundown.buffers_lost, rundown.decode_failed,
                rundown.duration_ms, files.describe()),
        ).with_fix("Check the agent log for the rundown failure and confirm administrator or SYSTEM rights")];
    }

    // A sustained gap below this target costs detections.
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
         https://docs.rustinel.io/telemetry-loss/"
    } else {
        "Those events reached no rule. Check the startup file rundown and ETW loss counters; \
         a sustained gap can mean missing naming events - see https://docs.rustinel.io/telemetry-loss/"
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
                 Windows build number; see https://docs.rustinel.io/telemetry-loss/",
            ),
        );
    } else {
        results.push(DiagnosticResult::pass("etw_decode", decode.describe()));
    }

    // Only meaningful as a persistent mismatch: the counters are incremented
    // independently on the callback's hot path, so a snapshot taken mid-record
    // is legitimately off by a few.
    if !decode.is_reconciled() {
        let classified = decode.classified();
        let (message, fix) = if classified < decode.records_received {
            (
                format!(
                    "{} of {} ETW records are unaccounted for",
                    decode.records_received - classified,
                    decode.records_received,
                ),
                "A small, non-growing difference is the snapshot catching a record mid-decode. A \
                 growing one is a decoder path that reports no outcome - please report it",
            )
        } else {
            (
                format!(
                    "ETW outcome count exceeds records received by {}",
                    classified - decode.records_received,
                ),
                "A small, non-growing excess is a snapshot sampled across concurrent ETW updates. \
                 A growing one means a decoder path reports more than one outcome - please report it",
            )
        };
        results.push(
            DiagnosticResult::warn("etw_decode_reconciliation", message, decode.describe())
                .with_fix(fix),
        );
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::inspect::DiagnosticStatus;
    use std::fs;

    /// Ten seconds after the fixture snapshot's `captured_at`.
    fn fixture_now() -> DateTime<Utc> {
        "2026-08-24T12:00:10Z".parse().unwrap()
    }

    fn telemetry_results(
        cfg: &AppConfig,
        dir: &Path,
    ) -> (Vec<DiagnosticResult>, Option<TelemetrySnapshot>) {
        let a = assess(cfg, dir, RuntimeState::Unknown, fixture_now());
        (a.results, a.snapshot)
    }
    use crate::telemetry::{
        ChannelSnapshot, EtwDecodeFailureSnapshot, EtwDecodeSnapshot, FileAttributionSnapshot,
        LinuxEbpfFamilySnapshot, LinuxEbpfFeatureSnapshot, LinuxEbpfSnapshot, RegistrySnapshot,
    };

    #[test]
    fn event_log_health_and_retention_are_separate_from_shedding() {
        let mut report = snapshot(Vec::new());
        assert!(event_log_results(&report).is_empty());
        report
            .windows_event_log
            .push(crate::telemetry::event_log::EventLogSnapshot {
                channel: "Security".into(),
                active: true,
                delivered: 2,
                last_record_id: Some(100_000),
                ..Default::default()
            });
        assert!(event_log_results(&report)
            .iter()
            .all(|r| r.status == DiagnosticStatus::Pass));
        report.windows_event_log[0].subscription_errors = 1;
        report.windows_event_log[0].live_stale = 1;
        report.windows_event_log[0].last_error = Some("ERROR_EVT_QUERY_RESULT_STALE".into());
        let results = event_log_results(&report);
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].id.contains("Security"));
        assert!(results[0]
            .detail
            .as_ref()
            .unwrap()
            .contains("ERROR_EVT_QUERY_RESULT_STALE"));
        assert_eq!(results[1].status, DiagnosticStatus::Pass);
        report.windows_event_log[0].retention_wraps = 1;
        assert_eq!(event_log_results(&report)[1].status, DiagnosticStatus::Warn);
        assert_eq!(report.total_dropped(), 0);
        assert!(report.dropping_channels().is_empty());
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serde_json::from_str::<TelemetrySnapshot>(&json).unwrap(),
            report
        );
    }

    #[test]
    fn doctor_warns_when_webhook_alerts_go_undelivered() {
        let mut report = snapshot(Vec::new());
        assert!(alert_webhook_results(&report).is_empty());
        report
            .alert_webhooks
            .push(crate::telemetry::WebhookSnapshot {
                name: "collector".to_string(),
                target: "https://collector.example".to_string(),
                capacity: 8,
                queued: 3,
                delivered: 3,
                failed: 0,
                retries: 1,
                dropped_queue_full: 0,
                dropped_oversized: 0,
                abandoned_at_shutdown: 0,
                high_water_mark: 2,
            });
        let results = alert_webhook_results(&report);
        assert_eq!(results[0].id, "alert_webhooks");
        assert_eq!(results[0].status, DiagnosticStatus::Pass);

        report.alert_webhooks[0].dropped_queue_full = 2;
        report.alert_webhooks[0].failed = 1;
        let results = alert_webhook_results(&report);
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].message.starts_with("3 alerts"));
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serde_json::from_str::<TelemetrySnapshot>(&json).unwrap(),
            report
        );
    }

    #[test]
    fn doctor_reports_process_join_outcomes_separately() {
        let mut report = snapshot(Vec::new());
        assert!(process_correlation_results(&report).is_empty());
        report.windows_process_correlation.classic_records = 10;
        report.windows_process_correlation.matched = 10;
        assert_eq!(
            process_correlation_results(&report)[0].status,
            DiagnosticStatus::Pass
        );
        report.windows_process_correlation.conflicting = 1;
        assert_eq!(
            process_correlation_results(&report)[0].status,
            DiagnosticStatus::Warn
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["windows_process_correlation"]["matched"], 10);
        assert_eq!(json["windows_process_correlation"]["conflicting"], 1);
        assert_eq!(json["windows_process_correlation"]["unmatched"], 0);
    }

    #[test]
    fn field_fidelity_survives_snapshots_and_reaches_doctor() {
        let mut report = snapshot(Vec::new());
        assert!(field_fidelity_results(&report).is_empty());
        report
            .field_fidelity
            .push(crate::telemetry::FieldFidelitySnapshot {
                field: "Image".into(),
                fidelity: crate::models::Fidelity::Truncated,
                count: 3,
            });
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["field_fidelity"][0]["fidelity"], "truncated");
        let decoded: TelemetrySnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.field_fidelity, report.field_fidelity);
        let results = field_fidelity_results(&decoded);
        assert_eq!(results[0].id, "field_fidelity");
        assert!(results[0]
            .detail
            .as_ref()
            .unwrap()
            .contains("Image: Truncated (3)"));
    }

    fn snapshot(channels: Vec<ChannelSnapshot>) -> TelemetrySnapshot {
        TelemetrySnapshot {
            host_state: None,
            artifact_resolver: None,
            version: "1.3.0".to_string(),
            pid: 7,
            captured_at: "2026-08-24T12:00:00Z".to_string(),
            uptime_secs: 3600,
            field_contract_violations: 0,
            field_fidelity: Vec::new(),
            channels,
            sensor_events_by_category: Vec::new(),
            linux_ebpf: None,
            macos_collectors: None,
            windows_event_log: Vec::new(),
            windows_process_correlation: Default::default(),
            windows_process_command_line: None,
            registry: None,
            file_attribution: None,
            etw_decode: None,
            alert_webhooks: Vec::new(),
        }
    }

    #[test]
    fn doctor_warns_about_populated_never_fields() {
        let mut snap = snapshot(Vec::new());
        assert!(field_contract_results(&snap).is_empty());

        snap.field_contract_violations = 3;
        let results = field_contract_results(&snap);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "field_contract_violations");
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].message.contains("3 populated fields"));
    }

    #[test]
    fn artifact_resolver_check_reports_every_store_and_failure() {
        let mut snap = snapshot(Vec::new());
        snap.artifact_resolver = Some(crate::artifact::ArtifactResolverSnapshot {
            queue_capacity: 256,
            written_file_queue_capacity: 8192,
            deadline_ms: 10_000,
            admission_budget_ms: 100,
            queued: 12,
            resolved: 11,
            cache_hits: 5,
            cache_misses: 6,
            queue_saturated: 1,
            process_image_dropped: 0,
            loaded_image_dropped: 0,
            written_file_dropped: 1,
            written_file_rejected: 3,
            written_file_coalesced: 8,
            worker_saturated: 0,
            deadline_exceeded: 0,
            admission_budget_exceeded: 2,
            admission_backpressure: 9,
            open_failed: 0,
            identity_mismatch: 0,
            identity_unavailable: 4,
            read_failed: 0,
            consumer_failed: 0,
            oversized: 0,
            evicted: 3,
            deferred_queued: 20,
            deferred_enriched: 17,
            deferred_unenriched: 3,
            deferred_budget_exceeded: 1,
            deferred_queue_saturated: 2,
            deferred_budget_ms: 2_000,
            correlation_lateness_ms: 2_000,
            pe_entries: 4,
            hash_entries: 5,
            imphash_entries: 6,
            signature_entries: 7,
            yara_entries: 8,
            yara_generation: 2,
        });

        let results = artifact_resolver_results(&snap);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0]
            .message
            .contains("10 artifact-resolution failure"));
        assert!(results[0].message.contains("1 written-file jobs dropped"));
        assert!(results[0]
            .message
            .contains("YARA and hash IOC detection gap"));
        let detail = results[0].detail.as_deref().expect("resolver detail");
        assert!(detail.contains("PE 4, hashes 5, imphashes 6, signatures 7, YARA 8"));
        assert!(detail.contains("1 queue saturated"));
        assert!(detail.contains("dropped jobs: process images 0, loaded images 0, written files 1"));
        assert!(detail.contains("written-file selection: 3 rejected, 8 coalesced"));
        assert!(detail.contains("0 identity, 4 identity unavailable"));
        assert!(detail.contains("2 past the 100 ms budget, 9 backpressured sends"));
        assert!(detail.contains(
            "deferred pass: 20 queued, 17 with artifact fields, 3 without (1 past the 2000 ms budget), 2 queue saturated"
        ));
    }

    #[test]
    fn written_file_drops_are_a_detection_gap_even_without_other_failures() {
        let mut snap = snapshot(Vec::new());
        snap.artifact_resolver = Some(crate::artifact::ArtifactResolverSnapshot {
            written_file_dropped: 7,
            ..Default::default()
        });
        let results = artifact_resolver_results(&snap);
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].message.contains("7 written-file jobs dropped"));
        assert!(results[0]
            .message
            .contains("YARA and hash IOC detection gap"));

        snap.artifact_resolver
            .as_mut()
            .unwrap()
            .written_file_dropped = 0;
        let results = artifact_resolver_results(&snap);
        assert_eq!(results[0].status, DiagnosticStatus::Pass);
        assert!(!results[0].message.contains("detection gap"));
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

    fn linux_ring(ring: &str) -> LinuxEbpfFamilySnapshot {
        LinuxEbpfFamilySnapshot {
            ring: ring.to_string(),
            kernel_seen: 10,
            kernel_submitted: 10,
            kernel_ring_full: 0,
            kernel_oversized: 0,
            kernel_map_full: 0,
            userspace_received: 10,
            userspace_decoded: 10,
            short_reads: 0,
            userspace_internal: 0,
            canonical_emitted: 10,
            userspace_dropped: 0,
            unresolved_file_events: 0,
            in_flight: 0,
        }
    }

    #[test]
    fn linux_ring_overflow_warns_and_names_the_ring() {
        let mut snap = snapshot(vec![channel("sensor_events", 8, 0)]);
        let mut process = linux_ring("process");
        process.kernel_seen = 12;
        process.kernel_ring_full = 2;
        snap.linux_ebpf = Some(LinuxEbpfSnapshot {
            abi_version: 1,
            features: Vec::new(),
            families: vec![process],
        });

        let results = linux_ebpf_results(&snap);

        assert_eq!(results[0].id, "linux_ebpf");
        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0].message.contains("process ring was full 2 times"));
    }

    #[test]
    fn clean_quiesced_linux_pipeline_passes() {
        let mut snap = snapshot(vec![channel("sensor_events", 10, 0)]);
        snap.linux_ebpf = Some(LinuxEbpfSnapshot {
            abi_version: 1,
            features: Vec::new(),
            families: vec![linux_ring("process")],
        });

        let results = linux_ebpf_results(&snap);

        assert_eq!(results[0].status, DiagnosticStatus::Pass);
        assert!(results[0].message.contains("10 submitted events"));
        assert!(results[0].message.contains("0 in flight"));
    }

    #[test]
    fn degraded_linux_feature_gets_a_named_warning() {
        let mut snap = snapshot(vec![]);
        snap.linux_ebpf = Some(LinuxEbpfSnapshot {
            abi_version: 1,
            features: vec![LinuxEbpfFeatureSnapshot {
                feature: "dns".to_string(),
                active: true,
                attached_hooks: vec!["handle_sendto".to_string()],
                unavailable_hooks: vec![
                    "handle_sendmmsg: syscalls/sys_enter_sendmmsg is unavailable".to_string(),
                ],
            }],
            families: vec![linux_ring("dns")],
        });

        let results = linux_ebpf_results(&snap);
        let capability = results
            .iter()
            .find(|result| result.id == "linux_ebpf_dns_capability")
            .expect("named DNS capability result");
        assert_eq!(capability.status, DiagnosticStatus::Warn);
        assert!(capability.message.contains("degraded"));
        assert!(capability.detail.as_deref().unwrap().contains("sendmmsg"));
    }

    fn assess_at(dir: &Path, runtime: RuntimeState, now: &str) -> TelemetryAssessment {
        assess(&AppConfig::default(), dir, runtime, now.parse().unwrap())
    }

    fn write_fixture(dir: &Path) {
        snapshot(vec![channel("sensor_events", 5_000, 0)])
            .write_to(&snapshot_path(dir))
            .expect("write snapshot");
    }

    fn freshness(a: &TelemetryAssessment) -> &DiagnosticResult {
        a.results
            .iter()
            .find(|r| r.id == "telemetry_snapshot")
            .expect("freshness result")
    }

    #[test]
    fn a_fresh_snapshot_passes_for_a_running_service() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path());
        // Default interval 30s: stale after 90s.
        let a = assess_at(temp.path(), RuntimeState::Running, "2026-08-24T12:01:29Z");
        assert_eq!(a.status.state, "fresh");
        assert_eq!(a.status.stale_after_secs, 90);
        assert_eq!(freshness(&a).status, DiagnosticStatus::Pass);
    }

    #[test]
    fn a_stale_snapshot_warns_for_a_running_service() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path());
        let a = assess_at(temp.path(), RuntimeState::Running, "2026-08-24T12:01:31Z");
        assert_eq!(a.status.state, "stale");
        assert_eq!(a.status.age_secs, Some(91));
        assert_eq!(freshness(&a).status, DiagnosticStatus::Warn);
        assert!(freshness(&a).fix.is_some());
    }

    #[test]
    fn a_stopped_agents_old_snapshot_is_historical() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path());
        let a = assess_at(temp.path(), RuntimeState::Stopped, "2026-08-25T12:00:00Z");
        assert_eq!(a.status.state, "historical");
        assert_eq!(freshness(&a).status, DiagnosticStatus::Pass);
        assert!(freshness(&a).message.contains("historical"));
    }

    #[test]
    fn unknown_service_state_makes_no_claim_of_current_health() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path());
        let a = assess_at(temp.path(), RuntimeState::Unknown, "2026-08-25T12:00:00Z");
        assert_eq!(a.status.state, "stale");
        assert!(freshness(&a)
            .message
            .contains("not evidence of current health"));
    }

    #[test]
    fn future_and_invalid_timestamps_warn() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path());
        let a = assess_at(temp.path(), RuntimeState::Unknown, "2026-08-24T11:58:00Z");
        assert_eq!(a.status.state, "future");
        assert_eq!(freshness(&a).status, DiagnosticStatus::Warn);

        let mut bad = snapshot(vec![]);
        bad.captured_at = "yesterday".to_string();
        bad.write_to(&snapshot_path(temp.path())).unwrap();
        let a = assess_at(temp.path(), RuntimeState::Running, "2026-08-24T12:00:10Z");
        assert_eq!(a.status.state, "invalid_timestamp");
        assert_eq!(freshness(&a).status, DiagnosticStatus::Warn);
    }

    #[test]
    fn a_missing_snapshot_depends_on_whether_the_service_runs() {
        let temp = tempfile::tempdir().unwrap();
        let a = assess_at(temp.path(), RuntimeState::Running, "2026-08-24T12:00:10Z");
        assert_eq!(a.status.state, "missing");
        assert_eq!(a.results[0].status, DiagnosticStatus::Warn);
        assert!(a.results[0].message.contains("runtime health is unknown"));

        let a = assess_at(temp.path(), RuntimeState::Stopped, "2026-08-24T12:00:10Z");
        assert_eq!(a.results[0].status, DiagnosticStatus::Pass);
        assert!(a.results[0].message.contains("has not written one yet"));
    }

    #[test]
    fn a_malformed_snapshot_warns_even_when_the_service_is_stopped() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(snapshot_path(temp.path()), b"{ not json").unwrap();
        let a = assess_at(temp.path(), RuntimeState::Stopped, "2026-08-24T12:00:10Z");
        assert_eq!(a.status.state, "malformed");
        assert_eq!(a.results[0].status, DiagnosticStatus::Warn);
        assert!(a.snapshot.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_snapshot_is_distinct_from_a_missing_one() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path());
        let path = snapshot_path(temp.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&path).is_ok() {
            return; // running as root: permissions do not apply
        }
        let a = assess_at(temp.path(), RuntimeState::Unknown, "2026-08-24T12:00:10Z");
        assert_eq!(a.status.state, "unreadable");
        assert_eq!(a.results[0].status, DiagnosticStatus::Warn);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn service_status_maps_to_runtime_state() {
        use InstallMode::*;
        assert_eq!(
            RuntimeState::from_service(Portable, "running"),
            RuntimeState::Unknown
        );
        assert_eq!(
            RuntimeState::from_service(Managed, "running"),
            RuntimeState::Running
        );
        assert_eq!(
            RuntimeState::from_service(Managed, "not-installed"),
            RuntimeState::Stopped
        );
        assert_eq!(
            RuntimeState::from_service(Managed, "unknown"),
            RuntimeState::Unknown
        );
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
        assert!(results[0].message.contains("5000 items"));
        assert_eq!(read.expect("snapshot").pid, 7);
    }

    /// The whole point of the check: an operator sees the size of the gap and
    /// which channel produced it without opening a log file.
    #[test]
    fn dropped_telemetry_warns_with_per_channel_counts() {
        let temp = tempfile::tempdir().expect("tempdir");
        snapshot(vec![
            channel("sensor_events", 9_000, 1_000),
            channel("artifact_resolution", 100, 25),
        ])
        .write_to(&snapshot_path(temp.path()))
        .expect("write snapshot");

        let (results, _) = telemetry_results(&AppConfig::default(), temp.path());

        assert_eq!(results[0].status, DiagnosticStatus::Warn);
        assert!(results[0]
            .message
            .contains("1025 events were shed by pipeline channels"));

        let detail = results[0].detail.as_deref().expect("detail");
        // Worst channel first, so the summary leads with the real gap.
        assert!(detail.starts_with("sensor_events: 1000 dropped of 10000 offered (10.00%)"));
        assert!(detail.contains("artifact_resolution: 25 dropped of 125 offered"));
        assert!(results[0].fix.is_some());
    }

    #[test]
    fn alert_writer_drops_fail_doctor() {
        let temp = tempfile::tempdir().unwrap();
        snapshot(vec![channel("alert_writer", 2, 8)])
            .write_to(&snapshot_path(temp.path()))
            .unwrap();

        let (results, read) = telemetry_results(&AppConfig::default(), temp.path());
        assert_eq!(results[0].status, DiagnosticStatus::Fail);
        assert!(results[0].message.contains("8 alerts were dropped"));
        assert!(results[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("alert_writer: 8 dropped"));
        assert_eq!(read.unwrap().channels[0].dropped, 8);
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
            rundown: None,
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
            .contains("startup file rundown"));
    }

    #[test]
    fn rejected_rundown_warns_even_without_live_file_events() {
        let mut snap = snapshot(vec![]);
        let mut files = file_attribution(0, 0, 0);
        files.rundown = Some(
            serde_json::from_value(serde_json::json!({
                "seeded":0, "records":0, "events_lost":100, "buffers_lost":0,
                "decode_failed":0, "duration_ms":30, "path_bytes":0,
                "index_capacity":0, "rejected":true,
            }))
            .unwrap(),
        );
        snap.file_attribution = Some(files);
        assert_eq!(
            file_attribution_results(&snap)[0].status,
            DiagnosticStatus::Warn
        );
    }

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
    fn excess_outcomes_are_reported_without_masking_the_difference() {
        let mut snap = snapshot(vec![channel("sensor_events", 10, 0)]);
        let mut decode = etw_decode(10_000, 0);
        decode.records_filtered = 10_001;
        snap.etw_decode = Some(decode);

        let results = etw_decode_results(&snap);

        assert_eq!(results[1].id, "etw_decode_reconciliation");
        assert_eq!(results[1].status, DiagnosticStatus::Warn);
        assert!(results[1].message.contains("exceeds records received by 1"));
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
    #[test]
    fn macos_kernel_loss_does_not_inflate_channel_shedding() {
        let mut snap = snapshot(vec![channel("sensor_events", 10, 0)]);
        snap.macos_collectors = Some(crate::telemetry::MacosCollectorSnapshot {
            esf: Some(crate::telemetry::EsfSnapshot {
                kernel_dropped: 3,
                ..Default::default()
            }),
            bpf: Some(crate::telemetry::BpfSnapshot {
                kernel_dropped: 7,
                stats_polls: 1,
                ..Default::default()
            }),
        });
        let results = macos_collector_results(&snap);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.status == DiagnosticStatus::Warn));
        assert_eq!(snap.total_dropped(), 0);
        let encoded = serde_json::to_string(&snap).unwrap();
        assert_eq!(
            serde_json::from_str::<TelemetrySnapshot>(&encoded).unwrap(),
            snap
        );
    }

    #[test]
    fn macos_stats_errors_are_visible_and_old_snapshots_remain_readable() {
        let mut snap = snapshot(vec![]);
        assert!(macos_collector_results(&snap).is_empty());
        let encoded = serde_json::to_string(&snap).unwrap();
        assert!(!encoded.contains("macos_collectors"));
        assert_eq!(
            serde_json::from_str::<TelemetrySnapshot>(&encoded).unwrap(),
            snap
        );
        snap.macos_collectors = Some(crate::telemetry::MacosCollectorSnapshot {
            bpf: Some(crate::telemetry::BpfSnapshot {
                stats_errors: 1,
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(
            macos_collector_results(&snap)[0].status,
            DiagnosticStatus::Warn
        );
    }
    #[test]
    fn failed_bpf_interface_does_not_hide_a_healthy_interface() {
        let mut snap = snapshot(vec![]);
        let mut bpf = crate::telemetry::BpfSnapshot {
            stats_polls: 1,
            ..Default::default()
        };
        bpf.interfaces.insert(
            "en0".into(),
            crate::telemetry::macos::BpfInterfaceSnapshot {
                active: true,
                stats_polls: 1,
                link_type: Some(1),
                ..Default::default()
            },
        );
        bpf.interfaces.insert(
            "utun0".into(),
            crate::telemetry::macos::BpfInterfaceSnapshot {
                error: Some("device unavailable".into()),
                ..Default::default()
            },
        );
        snap.macos_collectors = Some(crate::telemetry::MacosCollectorSnapshot {
            bpf: Some(bpf),
            ..Default::default()
        });
        let results = macos_collector_results(&snap);
        let wifi = results
            .iter()
            .find(|r| r.id == "macos_bpf_interface_en0")
            .unwrap();
        let vpn = results
            .iter()
            .find(|r| r.id == "macos_bpf_interface_utun0")
            .unwrap();
        assert_eq!(wifi.status, DiagnosticStatus::Pass);
        assert_eq!(vpn.status, DiagnosticStatus::Warn);
        assert!(vpn.detail.as_ref().unwrap().contains("device unavailable"));
    }
    #[test]
    fn host_state_diagnostics_report_loss_and_inventory_failure() {
        let mut snapshot = snapshot(Vec::new());
        assert!(host_state_results(&snapshot).is_empty());
        let host = crate::state::HostState::default();
        host.record_attribution_loss();
        host.record_inventory(crate::state::InventorySnapshot {
            error: Some("inventory denied".into()),
            ..Default::default()
        });
        snapshot.host_state = Some(host.snapshot());
        let results = host_state_results(&snapshot);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].id, "host_state");
        assert_eq!(results[1].id, "process_inventory");
    }
}
