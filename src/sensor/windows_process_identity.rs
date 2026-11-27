//! Bounded Windows process-lifetime attribution.

use super::{ProcessStartKey, RawEvent, RawPayload, SensorAction};
use std::collections::{BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

const PROCESS_IDENTITY_HISTORY_100NS: u64 = 5 * 10_000_000;
const PROCESS_IDENTITY_CLEANUP_100NS: u64 = 10 * 10_000_000;
const WINDOWS_EPOCH_DELTA_100NS: u64 = 116_444_736_000_000_000;

#[derive(Debug, Clone, Copy)]
struct ProcessLifetime {
    key: ProcessStartKey,
    stopped_at: Option<u64>,
}

impl ProcessLifetime {
    fn close_at(&mut self, at: u64) {
        self.stopped_at = Some(self.stopped_at.map_or(at, |previous| previous.min(at)));
    }
}

pub(crate) struct ProcessIdentityIndex {
    by_pid: HashMap<u32, Vec<ProcessLifetime>>,
    last_cleanup_at: u64,
    order: BTreeSet<(u64, u32)>,
    max_entries: usize,
}

impl ProcessIdentityIndex {
    pub(crate) fn with_max_entries(max_entries: usize) -> Self {
        Self {
            by_pid: HashMap::new(),
            last_cleanup_at: 0,
            order: BTreeSet::new(),
            max_entries,
        }
    }
    pub(crate) fn count(&self) -> usize {
        self.order.len()
    }

    pub(crate) fn observe_start(&mut self, key: ProcessStartKey) {
        let lifetimes = self.by_pid.entry(key.pid).or_default();
        let Err(index) =
            lifetimes.binary_search_by_key(&key.start_time, |life| life.key.start_time)
        else {
            return;
        };
        let stopped_at = lifetimes.get(index).map(|life| life.key.start_time - 1);
        if let Some(previous) = index.checked_sub(1).and_then(|i| lifetimes.get_mut(i)) {
            previous.close_at(key.start_time - 1);
        }
        lifetimes.insert(index, ProcessLifetime { key, stopped_at });
        self.order.insert((key.start_time, key.pid));
        while self.order.len() > self.max_entries {
            if let Some((start_time, pid)) = self.order.pop_first() {
                if let Some(lifetimes) = self.by_pid.get_mut(&pid) {
                    lifetimes.retain(|lifetime| lifetime.key.start_time != start_time);
                    if lifetimes.is_empty() {
                        self.by_pid.remove(&pid);
                    }
                }
            }
        }
    }

    fn observe_stop(&mut self, key: ProcessStartKey, stopped_at: u64) {
        if let Some(lifetime) = self
            .by_pid
            .get_mut(&key.pid)
            .and_then(|lifetimes| lifetimes.iter_mut().find(|lifetime| lifetime.key == key))
        {
            if stopped_at >= key.start_time {
                lifetime.close_at(stopped_at);
            }
        }
    }

    pub(crate) fn resolve(&self, pid: u32, event_at: u64) -> Option<ProcessStartKey> {
        let lifetimes = self.by_pid.get(&pid)?;
        let index = lifetimes.partition_point(|lifetime| lifetime.key.start_time <= event_at);
        let lifetime = lifetimes.get(index.checked_sub(1)?)?;
        lifetime
            .stopped_at
            .is_none_or(|stopped_at| event_at <= stopped_at)
            .then_some(lifetime.key)
    }

    pub(crate) fn attribute(&mut self, event: &mut RawEvent) {
        let event_at = system_time_to_filetime(event.timestamp);
        self.cleanup(event_at);

        if let RawPayload::Process(fields) = &event.payload {
            if event.action == SensorAction::Start {
                event.parent_process_start_key = fields
                    .parent_process_id
                    .and_then(|pid| self.resolve(pid, event_at));

                if let Some(key) = event.process_start_key {
                    self.observe_start(key);
                }
                return;
            }

            if event.action == SensorAction::Stop {
                if event.process_start_key.is_none() {
                    event.process_start_key = event.pid.and_then(|pid| self.resolve(pid, event_at));
                }
                if let Some(key) = event.process_start_key {
                    self.observe_stop(key, event_at);
                }
                return;
            }
        }

        if event.process_start_key.is_none() {
            event.process_start_key = event.pid.and_then(|pid| self.resolve(pid, event_at));
        }
        if let RawPayload::ProcessAccess(access) = &mut event.payload {
            access.target_start_key = access
                .fields
                .target_process_id
                .as_deref()
                .and_then(|value| value.parse().ok())
                .and_then(|pid| self.resolve(pid, event_at));
        }
    }

    fn cleanup(&mut self, now: u64) {
        if now.saturating_sub(self.last_cleanup_at) < PROCESS_IDENTITY_CLEANUP_100NS {
            return;
        }
        self.last_cleanup_at = now;
        self.by_pid.retain(|_, lifetimes| {
            lifetimes.retain(|lifetime| {
                lifetime.stopped_at.is_none_or(|stopped_at| {
                    now.saturating_sub(stopped_at) <= PROCESS_IDENTITY_HISTORY_100NS
                })
            });
            !lifetimes.is_empty()
        });
        self.order.retain(|(start, pid)| {
            self.by_pid.get(pid).is_some_and(|lifetimes| {
                lifetimes
                    .iter()
                    .any(|lifetime| lifetime.key.start_time == *start)
            })
        });
    }
}

#[cfg(test)]
impl Default for ProcessIdentityIndex {
    fn default() -> Self {
        Self::with_max_entries(crate::state::StateLimits::default().processes)
    }
}

pub(crate) fn system_time_to_filetime(timestamp: SystemTime) -> u64 {
    let since_unix = timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
    WINDOWS_EPOCH_DELTA_100NS
        .saturating_add(since_unix.as_secs().saturating_mul(10_000_000))
        .saturating_add(u64::from(since_unix.subsec_nanos()) / 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity_history_is_bounded_under_pid_reuse() {
        let mut index = ProcessIdentityIndex::with_max_entries(2);
        for start_time in 1..100 {
            index.observe_start(ProcessStartKey {
                pid: 42,
                start_time,
            });
            assert!(index.count() <= 2);
        }
        assert!(index.resolve(42, 1).is_none());
        assert_eq!(index.resolve(42, 99).unwrap().start_time, 99);
    }

    #[test]
    fn process_identity_index_resolves_the_generation_active_at_event_time() {
        let pid = 42;
        let old = ProcessStartKey {
            pid,
            start_time: 100,
        };
        let new = ProcessStartKey {
            pid,
            start_time: 300,
        };
        let mut index = ProcessIdentityIndex::default();

        index.observe_start(old);
        index.observe_stop(old, 200);
        index.observe_start(new);

        assert_eq!(index.resolve(pid, 150), Some(old));
        assert_eq!(index.resolve(pid, 250), None);
        assert_eq!(index.resolve(pid, 350), Some(new));
    }

    #[test]
    fn missing_old_exit_cannot_resurrect_an_older_pid_after_the_new_one_exits() {
        let older = ProcessStartKey {
            pid: 42,
            start_time: 100,
        };
        let newer = ProcessStartKey {
            pid: 42,
            start_time: 200,
        };
        let mut index = ProcessIdentityIndex::default();
        index.observe_start(newer);
        index.observe_start(older);
        index.observe_stop(newer, 300);

        assert_eq!(index.resolve(42, 199), Some(older));
        assert_eq!(index.resolve(42, 200), Some(newer));
        assert_eq!(index.resolve(42, 301), None);
        index.cleanup(300 + PROCESS_IDENTITY_CLEANUP_100NS);
        assert_eq!(index.count(), 0);
        assert_eq!(index.resolve(42, 301), None);
    }
}
