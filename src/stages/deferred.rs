//! Deferred detection: Sigma rules that need `Hashes` or `Imphash`.
//!
//! # Ordering invariant
//!
//! Each deferred event is evaluated exactly once, in the order ingress
//! deferred them, which is ingest order. The deferred stage owns the
//! correlation flush timer, so a window closes on time even when no later
//! event arrives. Correlation updates wait for an earlier event's deferred
//! pass, which is why [`DEFERRED_DETECTION_BUDGET`] equals the engine's
//! correlation reorder budget.
//!
//! # Budget
//!
//! An event waits at most [`DEFERRED_DETECTION_BUDGET`], measured from its
//! arrival, for resolution to supply the fields. Past it the deferred rules
//! evaluate the event without them. Computing digests costs far more than the
//! admission budget allows, which is why these rules are not evaluated at
//! admission.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::apply_pe_metadata;
use crate::alerts::AlertSink;
use crate::engine::{ArtifactFieldNeeds, DetectionPass, DetectorStore, EventDetectors};
use crate::ioc::ComputedHashes;
use crate::models::{CanonicalEvent, EventFields};
use crate::response::ResponseEngine;
use crate::state::HostState;
use crate::vocab::PeMetadata;

/// Longest a deferred-pass event waits for `Hashes` and `Imphash`, measured
/// from its arrival. Past it the deferred rules evaluate it without them, so
/// their detections reach correlation at most this late.
pub(crate) const DEFERRED_DETECTION_BUDGET: Duration = crate::engine::CORRELATION_REORDER_BUDGET;
/// Deferred entries wait at most their budget, so the queue only absorbs the
/// artifact events of one budget window. When it is full, the event keeps
/// every rule at admission instead.
const DEFERRED_QUEUE_CAPACITY: usize = 1024;
const CORRELATION_FLUSH_TICK: Duration = Duration::from_millis(100);

pub(crate) type DeferredReceiver = Receiver<DeferredFields>;
pub(crate) type DeferredSender = SyncSender<DeferredFields>;

/// What the deferred stage counts, read into the resolver telemetry snapshot.
#[derive(Default)]
pub(crate) struct DeferredCounters {
    /// Events whose deferred-pass rules waited for `Hashes`/`Imphash`.
    pub queued: AtomicU64,
    /// Deferred passes evaluated with at least one artifact field.
    pub enriched: AtomicU64,
    /// Deferred passes evaluated without artifact fields, because resolution
    /// failed, was shed, or produced nothing for the file.
    pub unenriched: AtomicU64,
    /// Deferred passes evaluated without artifact fields because the budget
    /// expired first. Counted in `unenriched` too.
    pub budget_exceeded: AtomicU64,
    /// Events whose deferred-pass rules ran at admission, without artifact
    /// fields, because the deferred queue was full.
    pub queue_saturated: AtomicU64,
}

/// What resolution learned for a deferred pass: the artifact fields, and PE
/// metadata so the deferred event is no poorer than the admitted one.
#[derive(Debug, Default)]
pub(crate) struct DeferredFields {
    pub hashes: Option<ComputedHashes>,
    pub imphash: Option<String>,
    pub pe_metadata: Option<PeMetadata>,
}

struct DeferredEntry {
    /// The event as ingress accepted it, before admission-time enrichment.
    event: CanonicalEvent,
    needs: ArtifactFieldNeeds,
    /// A dropped sender means resolution ended without artifact fields.
    fields: DeferredReceiver,
    evaluate_by: Instant,
}

/// The producing half, owned by ingress.
pub(crate) struct DeferredIngress {
    tx: SyncSender<DeferredEntry>,
    counters: Arc<DeferredCounters>,
}

/// Evaluates deferred-pass rules exactly once per deferred event, in the
/// order ingress deferred them, each no later than its own budget.
pub(crate) struct DeferredDetection {
    rx: Receiver<DeferredEntry>,
    detectors: Arc<DetectorStore>,
    host_state: Arc<HostState>,
    alert_sink: Option<AlertSink>,
    response_engine: Option<ResponseEngine>,
    counters: Arc<DeferredCounters>,
}

/// Connect an ingress half to the stage that evaluates for it.
pub(crate) fn channel(
    detectors: Arc<DetectorStore>,
    host_state: Arc<HostState>,
    alert_sink: Option<AlertSink>,
    response_engine: Option<ResponseEngine>,
    counters: Arc<DeferredCounters>,
) -> (DeferredIngress, DeferredDetection) {
    let (tx, rx) = std::sync::mpsc::sync_channel(DEFERRED_QUEUE_CAPACITY);
    (
        DeferredIngress {
            tx,
            counters: Arc::clone(&counters),
        },
        DeferredDetection {
            rx,
            detectors,
            host_state,
            alert_sink,
            response_engine,
            counters,
        },
    )
}

impl DeferredIngress {
    /// Hand the event's deferred-pass rules to the deferred stage. Returns
    /// false when that stage cannot take it, so admission keeps every rule.
    pub(crate) fn defer(
        &self,
        event: &CanonicalEvent,
        needs: ArtifactFieldNeeds,
        fields: DeferredReceiver,
    ) -> bool {
        let entry = DeferredEntry {
            event: event.clone(),
            needs,
            fields,
            evaluate_by: Instant::now()
                .checked_add(DEFERRED_DETECTION_BUDGET)
                .unwrap_or_else(Instant::now),
        };
        match self.tx.try_send(entry) {
            Ok(()) => {
                self.counters.queued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.counters
                    .queue_saturated
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

impl DeferredDetection {
    pub(crate) fn run(self) {
        loop {
            let mut entry = match self.rx.recv_timeout(CORRELATION_FLUSH_TICK) {
                Ok(entry) => entry,
                Err(RecvTimeoutError::Timeout) => {
                    self.flush_due();
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            };
            let fields = match entry.fields.try_recv() {
                Ok(fields) => Some(fields),
                Err(TryRecvError::Disconnected) => None,
                Err(TryRecvError::Empty) => loop {
                    let remaining = entry.evaluate_by.saturating_duration_since(Instant::now());
                    match entry
                        .fields
                        .recv_timeout(remaining.min(CORRELATION_FLUSH_TICK))
                    {
                        Ok(fields) => break Some(fields),
                        Err(RecvTimeoutError::Disconnected) => break None,
                        Err(RecvTimeoutError::Timeout) => {
                            self.flush_due();
                            if Instant::now() >= entry.evaluate_by {
                                self.counters
                                    .budget_exceeded
                                    .fetch_add(1, Ordering::Relaxed);
                                break None;
                            }
                        }
                    }
                },
            };
            let enriched = fields.is_some_and(|fields| {
                if let Some(metadata) = &fields.pe_metadata {
                    apply_pe_metadata(&mut entry.event, metadata);
                }
                apply_artifact_fields(
                    &mut entry.event,
                    entry.needs,
                    fields.hashes.as_ref(),
                    fields.imphash.as_deref(),
                )
            });
            let counter = if enriched {
                &self.counters.enriched
            } else {
                &self.counters.unenriched
            };
            counter.fetch_add(1, Ordering::Relaxed);
            self.evaluate(&entry.event);
            self.flush_due();
        }
        self.emit_sigma_alerts(self.detectors.sigma().flush_pending_with_origins());
    }

    fn flush_due(&self) {
        self.emit_sigma_alerts(
            self.detectors
                .sigma()
                .flush_due_with_origins(Instant::now()),
        );
    }

    fn emit_sigma_alerts(&self, alerts: Vec<crate::engine::SigmaAlert>) {
        for result in alerts {
            let mut alert = result.alert;
            self.host_state
                .enrich_process_context(&mut alert.event, result.process_start_key);
            if let Some(sink) = &self.alert_sink {
                sink.write_alert(&alert);
            }
            if let Some(response) = &self.response_engine {
                response.handle_alert(&alert);
            }
        }
    }

    fn evaluate(&self, event: &CanonicalEvent) {
        let detectors = EventDetectors::snapshot(&self.detectors);
        for result in detectors.evaluate_pass_with_origins(event, DetectionPass::Deferred) {
            let mut alert = result.alert;
            self.host_state
                .enrich_process_context(&mut alert.event, result.process_start_key);
            if let Some(sink) = &self.alert_sink {
                sink.write_alert(&alert);
            }
            if let Some(response) = &self.response_engine {
                response.handle_alert(&alert);
            }
        }
    }
}

/// Fill `Hashes` and `Imphash` on a process-start or image-load event from
/// resolved values, limited to what the deferred rules asked for. Returns
/// whether either field was set.
fn apply_artifact_fields(
    event: &mut CanonicalEvent,
    needs: ArtifactFieldNeeds,
    hashes: Option<&ComputedHashes>,
    imphash: Option<&str>,
) -> bool {
    let imphash = imphash.filter(|_| needs.imphash);
    let formatted = sysmon_hashes(needs, hashes, imphash);
    let (hashes_field, imphash_field) = match &mut event.normalized_mut().fields {
        EventFields::ProcessCreation(fields) => (&mut fields.hashes, &mut fields.imphash),
        EventFields::ImageLoad(fields) => (&mut fields.hashes, &mut fields.imphash),
        _ => return false,
    };
    let has_hashes = formatted.is_some();
    let has_imphash = imphash.is_some();
    *hashes_field = formatted;
    *imphash_field = imphash.map(str::to_string);
    // Read from the file after the event, so not a kernel measurement.
    if has_hashes {
        event
            .normalized_mut()
            .provenance
            .mark_derived(crate::engine::HASHES_FIELD);
    }
    if has_imphash {
        event
            .normalized_mut()
            .provenance
            .mark_derived(crate::engine::IMPHASH_FIELD);
    }
    has_hashes || has_imphash
}

/// Sysmon's `Hashes` value: `SHA1=`, `MD5=`, `SHA256=`, `IMPHASH=` in that
/// order, uppercase hex, comma separated, listing only requested values that
/// resolved. `None` when none did, so absence is never an empty string.
fn sysmon_hashes(
    needs: ArtifactFieldNeeds,
    hashes: Option<&ComputedHashes>,
    imphash: Option<&str>,
) -> Option<String> {
    fn digest(wanted: bool, value: Option<&String>) -> Option<&str> {
        value.filter(|_| wanted).map(String::as_str)
    }
    let parts: Vec<String> = [
        (
            "SHA1",
            hashes.and_then(|h| digest(needs.sha1, h.sha1.as_ref())),
        ),
        (
            "MD5",
            hashes.and_then(|h| digest(needs.md5, h.md5.as_ref())),
        ),
        (
            "SHA256",
            hashes.and_then(|h| digest(needs.sha256, h.sha256.as_ref())),
        ),
        ("IMPHASH", imphash.filter(|_| needs.imphash)),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| format!("{name}={}", value.to_ascii_uppercase())))
    .collect();
    (!parts.is_empty()).then(|| parts.join(","))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::artifact::test_support::{
        detecting_runtime, process_event, read_alerts, rule_names,
    };
    use crate::sensor::Platform;

    #[test]
    fn deferred_stage_flushes_correlation_without_another_event() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("sample.exe");
        std::fs::write(&image, b"sample").unwrap();
        let (runtime, detectors, alerts_path, guard) = detecting_runtime(
            temp.path(),
            &[
                r#"title: Image
id: image
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: sample.exe
  condition: selection
"#
                .to_string(),
                r#"title: Image Count
id: image-count
correlation:
  type: event_count
  rules:
    - image
  timespan: 1m
  condition:
    gte: 1
"#
                .to_string(),
            ],
        );
        let event = process_event(&image, Platform::Windows);
        detectors
            .sigma()
            .evaluate_event_pass(event.normalized(), DetectionPass::Admission);

        let (ingress, stage) = channel(
            detectors,
            Arc::new(HostState::default()),
            runtime.alert_sink,
            None,
            Arc::new(DeferredCounters::default()),
        );
        let worker = std::thread::spawn(move || stage.run());
        let deadline = Instant::now() + DEFERRED_DETECTION_BUDGET + Duration::from_secs(1);
        while Instant::now() < deadline
            && !std::fs::read_to_string(&alerts_path)
                .unwrap()
                .contains("Image Count")
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            std::fs::read_to_string(&alerts_path)
                .unwrap()
                .contains("Image Count"),
            "the timer must emit the alert while the deferred queue is still open"
        );
        drop(ingress);
        worker.join().unwrap();
        drop(guard);
        assert_eq!(rule_names(&read_alerts(&alerts_path)), vec!["Image Count"]);
    }

    #[test]
    fn sysmon_hashes_lists_requested_values_in_sysmon_order() {
        let hashes = ComputedHashes {
            md5: Some("aa".into()),
            sha1: Some("bb".into()),
            sha256: Some("cc".into()),
        };
        assert_eq!(
            sysmon_hashes(ArtifactFieldNeeds::ALL, Some(&hashes), Some("dd")).as_deref(),
            Some("SHA1=BB,MD5=AA,SHA256=CC,IMPHASH=DD")
        );
        let md5_and_imphash = ArtifactFieldNeeds {
            md5: true,
            imphash: true,
            ..ArtifactFieldNeeds::default()
        };
        assert_eq!(
            sysmon_hashes(md5_and_imphash, Some(&hashes), None).as_deref(),
            Some("MD5=AA"),
            "an image without imports leaves IMPHASH out rather than inventing one"
        );
        assert_eq!(sysmon_hashes(md5_and_imphash, None, None), None);
    }
}
