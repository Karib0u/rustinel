//! Linux auth journal reader health.
//!
//! The snapshot type is shared by every platform because `rustinel doctor`
//! reads it on any host. Like the Event Log counters, loss here is a counted
//! incident, never a gap between journal sequence numbers: the reader asks
//! journald for two syslog facilities, so the numbers it skips belong to
//! other records.
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::sync::Mutex;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxJournalSnapshot {
    /// What the reader follows: `auth` for the auth and authpriv facilities.
    pub source: String,
    /// Whether a journalctl reader is running now.
    pub active: bool,
    /// Records journalctl printed.
    pub read: u64,
    /// Events handed to the sensor channel.
    pub delivered: u64,
    /// Events the full sensor channel refused.
    pub dropped: u64,
    /// Records from a sender journald did not attest as privileged, such as
    /// `logger -t sshd` run by an ordinary user. Expected, not loss.
    pub untrusted: u64,
    /// sudo and su records accepted because the invoker they name is the
    /// sender's own UID, when the sender exited before journald could read
    /// its capabilities. Included in `delivered`.
    #[serde(default)]
    pub same_user: u64,
    /// Lines that were not a journal record.
    pub decode_errors: u64,
    /// journalctl exits the reader recovered from by restarting it.
    pub reader_restarts: u64,
    /// Starts whose saved cursor belonged to another journal sequence, after
    /// a reboot with a volatile journal or a journal reset. What was written
    /// in between cannot be known.
    pub resume_failures: u64,
    /// Starts at which journal retention had already removed records after
    /// the saved cursor. How many of them were auth records is unknown.
    pub retention_wraps: u64,
    /// Cursor files that could not be read or written.
    pub checkpoint_errors: u64,
    /// journald sequence number of the last record read.
    pub last_seqnum: Option<u64>,
    pub last_error: Option<String>,
}

impl LinuxJournalSnapshot {
    /// Whether the reader is stopped or has hit anything worth a warning.
    pub fn degraded(&self) -> bool {
        !self.active
            || self.dropped > 0
            || self.decode_errors > 0
            || self.reader_restarts > 0
            || self.resume_failures > 0
            || self.checkpoint_errors > 0
    }
}

/// Live journal reader health for one runtime.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct JournalHealth {
    state: Mutex<Option<LinuxJournalSnapshot>>,
}

#[cfg(target_os = "linux")]
impl JournalHealth {
    pub(crate) fn update(&self, change: impl FnOnce(&mut LinuxJournalSnapshot)) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot = state.get_or_insert_with(|| LinuxJournalSnapshot {
            source: "auth".into(),
            ..Default::default()
        });
        change(snapshot);
    }

    /// `None` until a reader has been started on this runtime.
    pub(crate) fn snapshot(&self) -> Option<LinuxJournalSnapshot> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
