//! Classic/manifest process correlation outcomes.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

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

pub static WINDOWS_PROCESS_CORRELATION: LazyLock<ProcessCorrelationCounters> =
    LazyLock::new(ProcessCorrelationCounters::default);

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
