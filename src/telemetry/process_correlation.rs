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
        }
    }
}

/// Windows process command-line collection after every available fallback.
#[derive(Debug, Default)]
pub struct ProcessCommandLineCounters {
    attempted: AtomicU64,
    captured: AtomicU64,
    missed: AtomicU64,
}

impl ProcessCommandLineCounters {
    pub(crate) const fn new() -> Self {
        Self {
            attempted: AtomicU64::new(0),
            captured: AtomicU64::new(0),
            missed: AtomicU64::new(0),
        }
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
        })
    }
}
