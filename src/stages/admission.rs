//! Admission: the stage that routes events downstream in ingest order.
//!
//! # Ordering invariant
//!
//! Detection and capture see events in exactly the order ingress accepted
//! them, which is `ingest_seq` order. Replay rejects a recording whose
//! `ingest_seq` goes backwards, so an event held here holds every event behind
//! it. An event is routed inline only when no earlier entry is still queued;
//! otherwise it queues behind them.
//!
//! # Budget
//!
//! Only enrichment that Sigma can match may hold an event, which today means
//! PE metadata. It holds the event for at most [`ADMISSION_BUDGET`], measured
//! from the moment ingress accepted it. Past the budget the event is admitted,
//! still in order, without those fields, and the resolver keeps working so the
//! next start of the same image is served from its store. Hash and YARA
//! consumers never hold admission because they raise their own alerts.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SendError, SyncSender, TryRecvError, TrySendError,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::apply_pe_metadata;
use crate::models::CanonicalEvent;
use crate::sensor::SensorEventRouter;
use crate::vocab::PeMetadata;

/// Longest Sigma-visible enrichment may hold an event at admission. Past it
/// the event is admitted, still in ingest order, without those fields.
pub(crate) const ADMISSION_BUDGET: Duration = Duration::from_millis(100);
/// Admission entries only have to absorb the events that arrive while the
/// head of the queue waits out its budget.
const ADMISSION_QUEUE_CAPACITY: usize = 4096;

pub(crate) type PeReceiver = Receiver<Option<PeMetadata>>;
pub(crate) type PeSender = SyncSender<Option<PeMetadata>>;

/// What admission counts, read into the resolver telemetry snapshot.
#[derive(Default)]
pub(crate) struct AdmissionCounters {
    /// Events admitted without PE metadata because it missed the budget.
    pub budget_exceeded: AtomicU64,
    /// Ingress sends that waited for room in the admission queue.
    pub backpressure: AtomicU64,
}

struct AdmissionEntry {
    event: CanonicalEvent,
    /// Resolved PE metadata, or `None` when the artifact has none. A dropped
    /// sender means resolution ended without it.
    pe: Option<PeReceiver>,
    admit_by: Instant,
}

/// The producing half, owned by ingress.
pub(crate) struct AdmissionIngress {
    tx: SyncSender<AdmissionEntry>,
    /// Admission entries not yet routed. Ingress is the only producer, so a
    /// zero here means every earlier event has already reached downstream.
    pending: Arc<AtomicUsize>,
    downstream: Arc<SensorEventRouter>,
    counters: Arc<AdmissionCounters>,
}

/// The routing half, run on its own thread until ingress closes.
pub(crate) struct Admission {
    rx: Receiver<AdmissionEntry>,
    pending: Arc<AtomicUsize>,
    downstream: Arc<SensorEventRouter>,
    counters: Arc<AdmissionCounters>,
}

/// Connect an ingress half to the stage that routes for it.
pub(crate) fn channel(
    downstream: Arc<SensorEventRouter>,
    counters: Arc<AdmissionCounters>,
) -> (AdmissionIngress, Admission) {
    let (tx, rx) = std::sync::mpsc::sync_channel(ADMISSION_QUEUE_CAPACITY);
    let pending = Arc::new(AtomicUsize::new(0));
    (
        AdmissionIngress {
            tx,
            pending: Arc::clone(&pending),
            downstream: Arc::clone(&downstream),
            counters: Arc::clone(&counters),
        },
        Admission {
            rx,
            pending,
            downstream,
            counters,
        },
    )
}

impl AdmissionIngress {
    /// Admit `event` in ingest order. Without an outstanding admission it is
    /// routed inline; otherwise it queues behind the events already waiting.
    /// A `deferred` event reaches admission marked so its deferred-pass rules
    /// are left to the deferred stage.
    pub(crate) fn admit(&self, event: &CanonicalEvent, pe: Option<PeReceiver>, deferred: bool) {
        let marked;
        let event = if deferred {
            let mut copy = event.clone();
            copy.set_deferred_pass_pending(true);
            marked = copy;
            &marked
        } else {
            event
        };
        if pe.is_none() && self.pending.load(Ordering::Acquire) == 0 {
            self.downstream.route_event(event);
            return;
        }
        let entry = AdmissionEntry {
            event: event.clone(),
            pe,
            admit_by: Instant::now()
                .checked_add(ADMISSION_BUDGET)
                .unwrap_or_else(Instant::now),
        };
        self.pending.fetch_add(1, Ordering::AcqRel);
        let entry = match self.tx.try_send(entry) {
            Ok(()) => return,
            Err(TrySendError::Full(entry)) => {
                // Every queued entry is released within its budget, so this
                // wait is bounded; the sensor channel absorbs it meanwhile.
                self.counters.backpressure.fetch_add(1, Ordering::Relaxed);
                entry
            }
            Err(TrySendError::Disconnected(entry)) => entry,
        };
        if let Err(SendError(entry)) = self.tx.send(entry) {
            self.pending.fetch_sub(1, Ordering::AcqRel);
            self.downstream.route_event(&entry.event);
        }
    }
}

impl Admission {
    pub(crate) fn run(self) {
        while let Ok(mut entry) = self.rx.recv() {
            if let Some(pe) = entry.pe.take() {
                let metadata = match pe.try_recv() {
                    Ok(metadata) => metadata,
                    Err(TryRecvError::Disconnected) => None,
                    Err(TryRecvError::Empty) => {
                        let remaining = entry.admit_by.saturating_duration_since(Instant::now());
                        match pe.recv_timeout(remaining) {
                            Ok(metadata) => metadata,
                            Err(RecvTimeoutError::Disconnected) => None,
                            Err(RecvTimeoutError::Timeout) => {
                                self.counters
                                    .budget_exceeded
                                    .fetch_add(1, Ordering::Relaxed);
                                None
                            }
                        }
                    }
                };
                if let Some(metadata) = metadata {
                    apply_pe_metadata(&mut entry.event, &metadata);
                }
            }
            self.downstream.route_event(&entry.event);
            self.pending.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
