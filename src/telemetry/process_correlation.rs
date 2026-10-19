//! Classic/manifest process correlation outcomes.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

use super::ProcessCommandLineSnapshot;

#[derive(Debug, Default)]
pub struct ProcessCorrelationCounters {
    pub classic_records: AtomicU64,
    pub decode_failed: AtomicU64,
    pub rundown: AtomicU64,
    pub matched: AtomicU64,
    pub unmatched: AtomicU64,
    pub conflicting: AtomicU64,
    pub classic_unmatched: AtomicU64,
    pub classic_command_line: AtomicU64,
    pub session_failures: AtomicU64,
    pub logon_id_captured: AtomicU64,
    pub logon_id_missed: AtomicU64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessCorrelationSnapshot {
    pub classic_records: u64,
    pub decode_failed: u64,
    pub rundown: u64,
    pub matched: u64,
    pub unmatched: u64,
    pub conflicting: u64,
    pub classic_unmatched: u64,
    pub classic_command_line: u64,
    pub session_failures: u64,
    pub logon_id_captured: u64,
    pub logon_id_missed: u64,
}

impl ProcessCorrelationCounters {
    pub fn snapshot(&self) -> ProcessCorrelationSnapshot {
        ProcessCorrelationSnapshot {
            classic_records: self.classic_records.load(Ordering::Relaxed),
            decode_failed: self.decode_failed.load(Ordering::Relaxed),
            rundown: self.rundown.load(Ordering::Relaxed),
            matched: self.matched.load(Ordering::Relaxed),
            unmatched: self.unmatched.load(Ordering::Relaxed),
            conflicting: self.conflicting.load(Ordering::Relaxed),
            classic_unmatched: self.classic_unmatched.load(Ordering::Relaxed),
            classic_command_line: self.classic_command_line.load(Ordering::Relaxed),
            session_failures: self.session_failures.load(Ordering::Relaxed),
            logon_id_captured: self.logon_id_captured.load(Ordering::Relaxed),
            logon_id_missed: self.logon_id_missed.load(Ordering::Relaxed),
        }
    }
}

/// Windows process command-line collection after every available fallback.
#[derive(Debug, Default)]
pub struct ProcessCommandLineCounters {
    attempted: AtomicU64,
    captured: AtomicU64,
    missed: AtomicU64,
    current_directory_captured: AtomicU64,
    current_directory_missed: AtomicU64,
    backfill_queries: AtomicU64,
    backfill_micros: AtomicU64,
    backfill_max_micros: AtomicU64,
}

impl ProcessCommandLineCounters {
    pub(crate) const fn new() -> Self {
        Self {
            attempted: AtomicU64::new(0),
            captured: AtomicU64::new(0),
            missed: AtomicU64::new(0),
            current_directory_captured: AtomicU64::new(0),
            current_directory_missed: AtomicU64::new(0),
            backfill_queries: AtomicU64::new(0),
            backfill_micros: AtomicU64::new(0),
            backfill_max_micros: AtomicU64::new(0),
        }
    }

    /// Count whether a Windows process start ended with a working directory.
    pub fn record_current_directory(&self, captured: bool) {
        let counter = if captured {
            &self.current_directory_captured
        } else {
            &self.current_directory_missed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Time one live back-fill of the command line and working directory.
    pub fn record_latency(&self, elapsed: std::time::Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.backfill_queries.fetch_add(1, Ordering::Relaxed);
        self.backfill_micros.fetch_add(micros, Ordering::Relaxed);
        self.backfill_max_micros
            .fetch_max(micros, Ordering::Relaxed);
    }

    pub fn record(&self, captured: bool) {
        self.attempted.fetch_add(1, Ordering::Relaxed);
        if captured {
            self.captured.fetch_add(1, Ordering::Relaxed);
        } else {
            self.missed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> Option<ProcessCommandLineSnapshot> {
        let attempted = self.attempted.load(Ordering::Relaxed);
        if attempted == 0 {
            return None;
        }
        Some(ProcessCommandLineSnapshot {
            attempted,
            captured: self.captured.load(Ordering::Relaxed),
            missed: self.missed.load(Ordering::Relaxed),
            current_directory_captured: self.current_directory_captured.load(Ordering::Relaxed),
            current_directory_missed: self.current_directory_missed.load(Ordering::Relaxed),
            backfill_queries: self.backfill_queries.load(Ordering::Relaxed),
            backfill_micros: self.backfill_micros.load(Ordering::Relaxed),
            backfill_max_micros: self.backfill_max_micros.load(Ordering::Relaxed),
        })
    }
}
