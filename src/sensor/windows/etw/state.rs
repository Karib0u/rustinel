//! Pending registry events and shared ETW path state.

use super::super::file_paths::FilePathCache;
use super::super::registry_paths::RegistryPathCache;
use super::routing::EtwRouting;
use crate::models::RegistryEventFields;
use crate::sensor::{
    Platform, ProcessStartKey, RawEvent, RawPayload, SensorAction, SensorNormalization,
};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use crate::sensor::windows_process_identity::{system_time_to_filetime, ProcessIdentityIndex};
use crate::sensor::windows_thread::{self, ModuleIndex};

const MODULE_INDEX_CAPACITY: usize = 8192;

/// Registry writes held briefly while their `OpenKey` or `CreateKey` naming
/// event catches up in the ETW stream.
pub(super) const PENDING_REGISTRY_EVENT_CAPACITY: usize = 4096;

pub(super) const PENDING_REGISTRY_EVENTS_PER_KEY: usize = 8;

pub(super) const REGISTRY_NAME_REORDER_WINDOW_100NS: u64 = 2 * 10_000_000;

pub(super) struct PendingRegistryEvent {
    pub(super) action: SensorAction,
    pub(super) value_name: Option<String>,
    pub(super) fields: RegistryEventFields,
    pub(super) pid: Option<u32>,
    pub(super) normalization: SensorNormalization,
    pub(super) timestamp: SystemTime,
    pub(super) event_at: i64,
}

impl PendingRegistryEvent {
    pub(super) fn into_sensor_event(mut self, key_path: &str) -> RawEvent {
        let target_object = match self.value_name.as_deref() {
            Some(value) if !value.is_empty() => format!("{key_path}\\{value}"),
            _ => key_path.to_string(),
        };
        self.fields.target_object = Some(target_object);

        RawEvent {
            process_name: None,
            provenance: {
                let mut provenance = crate::models::Provenance::default();
                provenance.mark_derived("TargetObject");
                provenance
            },
            platform: Platform::Windows,
            provider: "etw",
            action: self.action,
            normalization: self.normalization,
            pid: self.pid,
            timestamp: self.timestamp,
            source_seq: None,
            process_start_key: None,
            parent_process_start_key: None,
            payload: RawPayload::Registry(self.fields),
        }
    }
}

/// Bounded writes that arrived before the naming event for their key object.
///
/// The kernel provider normally emits `OpenKey` before `SetValueKey`, but ETW
/// buffers can deliver the adjacent records in the opposite order. Keeping a
/// short pending window closes that race without retaining stale kernel
/// pointers long enough for address reuse to misattribute a write.
pub(super) struct PendingRegistryEvents {
    pub(super) by_key_object: HashMap<u64, Vec<PendingRegistryEvent>>,
    pub(super) insertion_order: VecDeque<u64>,
    pub(super) event_count: usize,
}

impl PendingRegistryEvents {
    pub(super) fn new() -> Self {
        Self {
            by_key_object: HashMap::new(),
            insertion_order: VecDeque::new(),
            event_count: 0,
        }
    }

    /// Queue one unresolved write and return how many older writes had to be
    /// discarded because they expired or the bounded queue was full.
    pub(super) fn insert(&mut self, key_object: u64, event: PendingRegistryEvent) -> usize {
        let mut dropped = self.expire(event.event_at);

        if let Some(events) = self.by_key_object.get_mut(&key_object) {
            if events.len() == PENDING_REGISTRY_EVENTS_PER_KEY {
                events.remove(0);
                self.event_count -= 1;
                dropped += 1;
            }
            events.push(event);
            self.event_count += 1;
            if self.event_count > PENDING_REGISTRY_EVENT_CAPACITY {
                dropped += self.evict_oldest_key();
            }
            return dropped;
        }

        while self.event_count >= PENDING_REGISTRY_EVENT_CAPACITY {
            dropped += self.evict_oldest_key();
        }

        self.by_key_object.insert(key_object, vec![event]);
        self.insertion_order.push_back(key_object);
        self.event_count += 1;
        dropped
    }

    /// Resolve all recent writes for a key and return the events plus the
    /// number of stale writes that were discarded.
    pub(super) fn resolve(
        &mut self,
        key_object: u64,
        key_path: &str,
        named_at: i64,
    ) -> (Vec<RawEvent>, usize) {
        let mut dropped = self.expire(named_at);
        let Some(events) = self.by_key_object.remove(&key_object) else {
            return (Vec::new(), dropped);
        };
        self.insertion_order.retain(|object| *object != key_object);
        self.event_count = self.event_count.saturating_sub(events.len());

        let mut resolved = Vec::with_capacity(events.len());
        for event in events {
            if event.event_at.abs_diff(named_at) <= REGISTRY_NAME_REORDER_WINDOW_100NS {
                resolved.push(event.into_sensor_event(key_path));
            } else {
                dropped += 1;
            }
        }
        (resolved, dropped)
    }

    pub(super) fn expire(&mut self, now: i64) -> usize {
        let mut dropped = 0;
        while let Some(key_object) = self.insertion_order.front().copied() {
            let Some(events) = self.by_key_object.get_mut(&key_object) else {
                self.insertion_order.pop_front();
                continue;
            };

            let before = events.len();
            events.retain(|event| {
                now.checked_sub(event.event_at)
                    .is_none_or(|age| age < 0 || age as u64 <= REGISTRY_NAME_REORDER_WINDOW_100NS)
            });
            let expired = before - events.len();
            dropped += expired;
            self.event_count = self.event_count.saturating_sub(expired);

            if events.is_empty() {
                self.by_key_object.remove(&key_object);
                self.insertion_order.pop_front();
            } else {
                break;
            }
        }
        dropped
    }

    pub(super) fn evict_oldest_key(&mut self) -> usize {
        while let Some(key_object) = self.insertion_order.pop_front() {
            if let Some(events) = self.by_key_object.remove(&key_object) {
                self.event_count = self.event_count.saturating_sub(events.len());
                return events.len();
            }
        }
        0
    }
}

/// Shared state the ETW callback carries across events.
///
/// The path index has to outlive a single event: the naming event and the
/// write it explains are different records, often seconds apart.
pub(super) struct EtwState {
    pub(super) routing: EtwRouting,
    pub(super) process_correlation: Mutex<super::process::ProcessCorrelation>,
    host: std::sync::Arc<crate::state::HostState>,
    modules: Mutex<ModuleIndex>,
    pub(super) pending_registry_events: Mutex<PendingRegistryEvents>,
}

impl EtwState {
    pub(super) fn with_process_identities(
        keys: impl IntoIterator<Item = ProcessStartKey>,
        host: std::sync::Arc<crate::state::HostState>,
    ) -> Self {
        {
            let mut identities = host
                .extension::<crate::sensor::windows::WindowsHostExtension>()
                .process_identities
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for key in keys {
                identities.observe_start(key);
            }
        }
        Self {
            routing: EtwRouting::new(),
            process_correlation: Mutex::new(super::process::ProcessCorrelation::with_metrics(
                std::sync::Arc::clone(&host.process_correlation),
            )),
            host,
            modules: Mutex::new(ModuleIndex::new(MODULE_INDEX_CAPACITY)),
            pending_registry_events: Mutex::new(PendingRegistryEvents::new()),
        }
    }

    pub(super) fn process_correlation_metrics(
        &self,
    ) -> &crate::telemetry::ProcessCorrelationCounters {
        &self.host.process_correlation
    }

    /// Counters for this runtime's registry, file and decoder accounting.
    pub(super) fn counters(&self) -> &crate::sensor::windows::telemetry::WindowsCounters {
        &self
            .host
            .extension::<crate::sensor::windows::WindowsHostExtension>()
            .counters
    }

    pub(super) fn attribute_process_identity(&self, event: &mut RawEvent) {
        let mut identities = self.process_identities();
        let RawPayload::RemoteThread(fields) = &event.payload else {
            identities.attribute(event);
            return;
        };
        let at = system_time_to_filetime(event.timestamp);
        let source = identities.resolve(fields.source_process_id, at);
        let target = identities.resolve(fields.target_process_id, at);
        drop(identities);

        let module = target
            .zip(
                fields
                    .start_address
                    .as_deref()
                    .and_then(|address| u64::from_str_radix(address.strip_prefix("0x")?, 16).ok()),
            )
            .and_then(|(target, address)| {
                self.modules()
                    .resolve(target, at, address)
                    .map(str::to_owned)
            });
        windows_thread::enrich(event, source, target, module, &self.host.processes);
    }

    pub(super) fn process_identities(&self) -> MutexGuard<'_, ProcessIdentityIndex> {
        self.host
            .extension::<crate::sensor::windows::WindowsHostExtension>()
            .process_identities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn modules(&self) -> MutexGuard<'_, ModuleIndex> {
        self.modules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The path index is derived state, so a poisoned lock is recoverable and
    /// recovering is the only safe option: this runs inside an ETW callback
    /// invoked by the OS, and unwinding across that boundary would take the
    /// sensor down. Losing path resolution for the life of the process because
    /// one callback panicked is a worse failure than a stale cache entry.
    pub(super) fn paths(&self) -> MutexGuard<'_, FilePathCache> {
        self.host
            .extension::<crate::sensor::windows::WindowsHostExtension>()
            .file_paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Recovered for the same reason as [`Self::paths`]: unwinding out of an
    /// OS-invoked ETW callback would take the sensor down.
    pub(super) fn registry_paths(&self) -> MutexGuard<'_, RegistryPathCache> {
        self.host
            .extension::<crate::sensor::windows::WindowsHostExtension>()
            .registry_paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn pending_registry_events(&self) -> MutexGuard<'_, PendingRegistryEvents> {
        self.pending_registry_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::RegistryEventFields;
    use crate::sensor::RawPayload;
    use crate::sensor::SensorAction;
    use crate::sensor::SensorNormalization;
    use std::time::UNIX_EPOCH;

    fn pending_registry_set(event_at: i64, value_name: &str) -> PendingRegistryEvent {
        PendingRegistryEvent {
            action: SensorAction::Set,
            value_name: Some(value_name.to_string()),
            fields: RegistryEventFields {
                target_object: None,
                details: Some("notepad.exe".to_string()),
                process_id: Some("42".to_string()),
                image: None,
                event_type: None,
                user: None,
                new_name: None,
            },
            pid: Some(42),
            normalization: SensorNormalization {
                event_id: 13,
                action_code: 39,
            },
            timestamp: UNIX_EPOCH,
            event_at,
        }
    }

    #[test]
    fn registry_write_is_replayed_when_name_arrives_late() {
        let mut pending = PendingRegistryEvents::new();
        assert_eq!(pending.insert(7, pending_registry_set(100, "Startup")), 0);

        let (events, dropped) = pending.resolve(7, r"\REGISTRY\USER\S-1-5-21\Run", 110);

        assert_eq!(dropped, 0);
        assert_eq!(events.len(), 1);
        assert_eq!(pending.event_count, 0);
        let RawPayload::Registry(fields) = &events[0].payload else {
            panic!("replayed event must keep its registry payload");
        };
        assert_eq!(
            fields.target_object.as_deref(),
            Some(r"\REGISTRY\USER\S-1-5-21\Run\Startup")
        );
        assert_eq!(events[0].action, SensorAction::Set);
    }

    #[test]
    fn stale_registry_write_is_not_replayed_for_reused_pointer() {
        let mut pending = PendingRegistryEvents::new();
        assert_eq!(pending.insert(7, pending_registry_set(100, "Old")), 0);

        let named_at = 100 + REGISTRY_NAME_REORDER_WINDOW_100NS as i64 + 1;
        let (events, dropped) = pending.resolve(7, r"\REGISTRY\MACHINE\NewKey", named_at);

        assert!(events.is_empty());
        assert_eq!(dropped, 1);
        assert_eq!(pending.event_count, 0);
    }

    #[test]
    fn registry_pending_queue_is_bounded_per_key() {
        let mut pending = PendingRegistryEvents::new();
        let mut dropped = 0;
        for index in 0..=PENDING_REGISTRY_EVENTS_PER_KEY {
            dropped += pending.insert(7, pending_registry_set(100, &format!("Value{index}")));
        }

        let (events, resolved_drops) = pending.resolve(7, r"\REGISTRY\MACHINE\Run", 110);

        assert_eq!(dropped, 1);
        assert_eq!(resolved_drops, 0);
        assert_eq!(events.len(), PENDING_REGISTRY_EVENTS_PER_KEY);
    }

    #[test]
    fn registry_pending_queue_is_globally_bounded() {
        let mut pending = PendingRegistryEvents::new();
        for key_object in 1..=PENDING_REGISTRY_EVENT_CAPACITY as u64 {
            assert_eq!(
                pending.insert(key_object, pending_registry_set(100, "Value")),
                0
            );
        }

        let dropped = pending.insert(1, pending_registry_set(100, "SecondValue"));

        assert!(dropped >= 1);
        assert!(pending.event_count <= PENDING_REGISTRY_EVENT_CAPACITY);
    }
}
