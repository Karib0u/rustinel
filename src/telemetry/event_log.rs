//! Event Log loss signals are incidents, never gaps between filtered record IDs.
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::sync::Mutex;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventLogSnapshot {
    pub channel: String,
    pub active: bool,
    pub delivered: u64,
    pub last_record_id: Option<u64>,
    pub subscription_errors: u64,
    pub live_stale: u64,
    pub resume_failures: u64,
    pub retention_wraps: u64,
    pub checkpoint_errors: u64,
    pub decode_errors: u64,
    pub last_error: Option<String>,
}

/// Per-channel Event Log health for one runtime.
#[cfg(windows)]
#[derive(Debug, Default)]
pub struct EventLogHealth {
    channels: Mutex<Vec<EventLogSnapshot>>,
}

#[cfg(windows)]
impl EventLogHealth {
    pub(crate) fn update(&self, channel: &str, change: impl FnOnce(&mut EventLogSnapshot)) {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        let index = channels
            .iter()
            .position(|entry| entry.channel == channel)
            .unwrap_or_else(|| {
                channels.push(EventLogSnapshot {
                    channel: channel.to_owned(),
                    ..Default::default()
                });
                channels.len() - 1
            });
        change(&mut channels[index]);
    }

    pub(crate) fn snapshot(&self) -> Vec<EventLogSnapshot> {
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}
