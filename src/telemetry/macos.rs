//! Kernel loss accounting, independent of pipeline channel shedding.
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosCollectorSnapshot {
    pub esf: Option<EsfSnapshot>,
    pub bpf: Option<BpfSnapshot>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsfSnapshot {
    pub received: u64,
    /// Global sequence gaps. Do not add per-type gaps to this total.
    pub kernel_dropped: u64,
    pub kernel_dropped_by_event_type: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfSnapshot {
    #[serde(default)]
    pub interfaces: BTreeMap<String, BpfInterfaceSnapshot>,
    /// BIOCGSTATS bs_recv counts packets before the capture filter.
    pub kernel_received: u64,
    pub kernel_dropped: u64,
    pub stats_polls: u64,
    pub stats_errors: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfInterfaceSnapshot {
    pub active: bool,
    pub link_type: Option<u32>,
    pub error: Option<String>,
    pub kernel_received: u64,
    pub kernel_dropped: u64,
    pub stats_polls: u64,
    pub stats_errors: u64,
}

pub(crate) static MACOS_COLLECTORS: LazyLock<Mutex<MacosCollectorSnapshot>> =
    LazyLock::new(|| Mutex::new(MacosCollectorSnapshot::default()));

pub(super) fn snapshot() -> Option<MacosCollectorSnapshot> {
    let counters = MACOS_COLLECTORS.lock().unwrap();
    (counters.esf.is_some() || counters.bpf.is_some()).then(|| counters.clone())
}

/// First observations establish a baseline. Missing version-gated fields do
/// not change it. Duplicate or older values cannot move the high-water mark.
#[cfg(any(target_os = "macos", test))]
#[derive(Default)]
pub(crate) struct EsfSequences {
    global: Option<u64>,
    event_types: BTreeMap<String, Option<u64>>,
}

#[cfg(any(target_os = "macos", test))]
impl EsfSequences {
    pub(crate) fn observe(
        &mut self,
        counters: &mut EsfSnapshot,
        event_type: String,
        sequence: Option<u64>,
        global: Option<u64>,
    ) {
        counters.received += 1;
        counters.kernel_dropped += sequence_gap(&mut self.global, global);
        let previous = self.event_types.entry(event_type.clone()).or_default();
        *counters
            .kernel_dropped_by_event_type
            .entry(event_type)
            .or_default() += sequence_gap(previous, sequence);
    }
}

#[cfg(any(target_os = "macos", test))]
fn sequence_gap(previous: &mut Option<u64>, current: Option<u64>) -> u64 {
    let Some(current) = current else { return 0 };
    match *previous {
        Some(last) if current <= last => 0,
        last => {
            *previous = Some(current);
            last.map_or(0, |last| current - last - 1)
        }
    }
}

/// One tracker per newly configured device. No filter changes or resets occur
/// during capture, so decreases are 32-bit kernel counter wraparound.
#[cfg(any(target_os = "macos", test))]
#[derive(Default)]
pub(crate) struct BpfStatsTracker {
    received: u32,
    dropped: u32,
}

#[cfg(any(target_os = "macos", test))]
impl BpfStatsTracker {
    pub(crate) fn observe_interface(
        &mut self,
        counters: &mut BpfSnapshot,
        interface: &str,
        received: u32,
        dropped: u32,
    ) {
        let received_delta = u64::from(received.wrapping_sub(self.received));
        let dropped_delta = u64::from(dropped.wrapping_sub(self.dropped));
        self.observe(counters, received, dropped);
        let entry = counters
            .interfaces
            .entry(interface.to_string())
            .or_default();
        entry.kernel_received += received_delta;
        entry.kernel_dropped += dropped_delta;
        entry.stats_polls += 1;
    }

    pub(crate) fn observe(&mut self, counters: &mut BpfSnapshot, received: u32, dropped: u32) {
        counters.kernel_received += u64::from(received.wrapping_sub(self.received));
        counters.kernel_dropped += u64::from(dropped.wrapping_sub(self.dropped));
        counters.stats_polls += 1;
        self.received = received;
        self.dropped = dropped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_gaps_are_separate_and_ignore_missing_or_old_values() {
        let mut tracker = EsfSequences::default();
        let mut counters = EsfSnapshot::default();
        for (kind, seq, global) in [
            ("exec", Some(10), Some(20)),
            ("exit", Some(4), Some(21)),
            ("exec", Some(14), Some(27)),
            ("exec", None, None),
            ("exec", Some(12), Some(23)),
            ("exec", Some(15), Some(28)),
        ] {
            tracker.observe(&mut counters, kind.into(), seq, global);
        }
        assert_eq!(counters.kernel_dropped, 5);
        assert_eq!(counters.kernel_dropped_by_event_type["exec"], 3);
        assert_eq!(counters.kernel_dropped_by_event_type["exit"], 0);
        assert_eq!(counters.received, 6);
    }

    #[test]
    fn bpf_polls_accumulate_deltas_and_wrap() {
        let mut tracker = BpfStatsTracker::default();
        let mut counters = BpfSnapshot::default();
        tracker.observe(&mut counters, u32::MAX, u32::MAX);
        tracker.observe(&mut counters, 2, 1);
        tracker.observe(&mut counters, 2, 1);
        assert_eq!(counters.kernel_received, u64::from(u32::MAX) + 3);
        assert_eq!(counters.kernel_dropped, u64::from(u32::MAX) + 2);
        assert_eq!(counters.stats_polls, 3);
    }
    #[test]
    fn interface_samples_reconcile_with_totals_and_wrap_independently() {
        let mut counters = BpfSnapshot::default();
        let mut wifi = BpfStatsTracker::default();
        let mut vpn = BpfStatsTracker::default();
        wifi.observe_interface(&mut counters, "en0", 100, 3);
        vpn.observe_interface(&mut counters, "utun0", u32::MAX, 7);
        vpn.observe_interface(&mut counters, "utun0", 2, 8);
        wifi.observe_interface(&mut counters, "en0", 120, 4);
        assert_eq!(
            counters.kernel_received,
            counters
                .interfaces
                .values()
                .map(|i| i.kernel_received)
                .sum::<u64>()
        );
        assert_eq!(counters.kernel_dropped, 12);
        assert_eq!(counters.interfaces["en0"].kernel_dropped, 4);
        assert_eq!(counters.interfaces["utun0"].kernel_dropped, 8);
        assert_eq!(counters.stats_polls, 4);
    }
}
