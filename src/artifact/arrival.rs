//! Off-thread arrival identity measurement for written files.
//!
//! The receive loop of the written-file queue must never touch the file
//! system: one slow open (an antivirus filter, a network share, a stuck
//! handle) would stall receiving, settling and dispatch for every pending
//! file. Opens run on a few dedicated threads and report back over a channel.
//! The loop owns the deadline: an open still outstanding when it passes is
//! counted as failed and its late result is ignored, while a thread blocked in
//! the OS only ever occupies itself.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use super::job::ArtifactJob;
use super::target::ArrivalIdentity;
use super::written_file::WRITTEN_FILE_QUEUE_CAPACITY;

pub(super) type ArrivalMeasure = Arc<dyn Fn(&Path) -> ArrivalIdentity + Send + Sync>;

const ARRIVAL_WORKERS: usize = 4;

struct Request {
    id: u64,
    job: ArtifactJob,
    deadline_at: Instant,
}

pub(super) struct Measured {
    pub(super) job: ArtifactJob,
    pub(super) identity: ArrivalIdentity,
}

pub(super) enum Submit {
    Queued,
    /// Every worker is busy and the queue is full.
    Saturated(Box<ArtifactJob>),
}

pub(super) struct ArrivalMeasurer {
    requests: SyncSender<Request>,
    results: UnboundedReceiver<(u64, Measured)>,
    outstanding: HashMap<u64, Instant>,
    deadlines: BTreeSet<(Instant, u64)>,
    next_id: u64,
}

impl ArrivalMeasurer {
    pub(super) fn new(measure: ArrivalMeasure) -> Self {
        let (requests, queue) = sync_channel::<Request>(WRITTEN_FILE_QUEUE_CAPACITY);
        let (done, results) = unbounded_channel();
        let queue = Arc::new(Mutex::new(queue));
        for _ in 0..ARRIVAL_WORKERS {
            let (queue, done, measure) = (Arc::clone(&queue), done.clone(), Arc::clone(&measure));
            let spawned = std::thread::Builder::new()
                .name("artifact-arrival".to_string())
                .spawn(move || worker(&queue, &done, &*measure));
            if let Err(error) = spawned {
                tracing::debug!(target: "artifact", %error, "Could not start arrival worker");
            }
        }
        Self {
            requests,
            results,
            outstanding: HashMap::new(),
            deadlines: BTreeSet::new(),
            next_id: 0,
        }
    }

    pub(super) fn is_idle(&self) -> bool {
        self.outstanding.is_empty()
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.first().map(|(deadline, _)| *deadline)
    }

    pub(super) fn submit(&mut self, job: ArtifactJob, deadline_at: Instant) -> Submit {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        match self.requests.try_send(Request {
            id,
            job,
            deadline_at,
        }) {
            Ok(()) => {
                self.outstanding.insert(id, deadline_at);
                self.deadlines.insert((deadline_at, id));
                Submit::Queued
            }
            Err(TrySendError::Full(request) | TrySendError::Disconnected(request)) => {
                Submit::Saturated(Box::new(request.job))
            }
        }
    }

    /// Forget every request whose deadline has passed and return how many.
    /// A late result for one is ignored by [`Self::accept`].
    pub(super) fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        while let Some(&(deadline, id)) = self.deadlines.first() {
            if deadline > now {
                break;
            }
            self.deadlines.pop_first();
            if self.outstanding.remove(&id).is_some() {
                expired += 1;
            }
        }
        expired
    }

    /// Wait for the next result. Pends forever when nothing is outstanding.
    pub(super) async fn recv(&mut self) -> Option<(u64, Measured)> {
        if self.outstanding.is_empty() {
            return std::future::pending().await;
        }
        self.results.recv().await
    }

    pub(super) fn try_recv(&mut self) -> Option<(u64, Measured)> {
        self.results.try_recv().ok()
    }

    /// The result of a request that has not expired, or `None` for a late one.
    pub(super) fn accept(&mut self, id: u64, measured: Measured) -> Option<Measured> {
        let deadline_at = self.outstanding.remove(&id)?;
        self.deadlines.remove(&(deadline_at, id));
        Some(measured)
    }
}

fn worker(
    queue: &Mutex<Receiver<Request>>,
    done: &tokio::sync::mpsc::UnboundedSender<(u64, Measured)>,
    measure: &(dyn Fn(&Path) -> ArrivalIdentity + Send + Sync),
) {
    loop {
        let request = match queue.lock() {
            Ok(queue) => queue.recv(),
            Err(_) => return,
        };
        let Ok(Request {
            id,
            job,
            deadline_at,
        }) = request
        else {
            return;
        };
        // The loop already counted a request that waited past its deadline.
        if Instant::now() >= deadline_at {
            continue;
        }
        let identity = measure(&job.target.path);
        if done.send((id, Measured { job, identity })).is_err() {
            return;
        }
    }
}
