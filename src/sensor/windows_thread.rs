//! Decode facts and enrich cross-process ETW thread starts.

use super::{ProcessStartKey, RawEvent, RawPayload};
use crate::models::RemoteThreadFields;
use crate::state::{ProcessCache, ProcessMetadata};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ThreadStart {
    MissingProcess,
    SameProcess,
    Remote { source: u32, target: u32 },
}

impl ThreadStart {
    pub(super) fn classify(source: u32, target: Option<u32>) -> Self {
        let Some(target) = target else {
            return Self::MissingProcess;
        };
        match (source, target) {
            (0 | u32::MAX, _) | (_, 0 | u32::MAX) => Self::MissingProcess,
            _ if source == target => Self::SameProcess,
            _ => Self::Remote { source, target },
        }
    }
}

impl RemoteThreadFields {
    pub(super) fn from_thread_start(
        source: u32,
        target: u32,
        thread: Option<u32>,
        win32_start: Option<u64>,
    ) -> Self {
        Self {
            source_process_id: source,
            target_process_id: target,
            new_thread_id: thread,
            start_address: win32_start.map(|address| format!("0x{address:016X}")),
            start_module: None,
            source_image: None,
            source_command_line: None,
            source_parent_process_id: None,
            source_parent_image: None,
            source_parent_command_line: None,
            target_image: None,
            target_command_line: None,
            target_parent_process_id: None,
            target_parent_image: None,
            target_parent_command_line: None,
        }
    }
}

/// Copy only state tied to the lifetime active at the ETW timestamp.
pub(super) fn enrich(
    event: &mut RawEvent,
    source: Option<ProcessStartKey>,
    target: Option<ProcessStartKey>,
    module: Option<String>,
    processes: &ProcessCache,
) {
    let RawPayload::RemoteThread(fields) = &mut event.payload else {
        return;
    };
    event.process_start_key = source;
    if let Some(source) = metadata(processes, source) {
        fields.source_image = nonempty(source.image_name);
        fields.source_command_line = source.command_line;
        fields.source_parent_process_id = source.parent_pid;
        fields.source_parent_image = source.parent_image;
        fields.source_parent_command_line = source.parent_command_line;
    }
    if let Some(target) = metadata(processes, target) {
        fields.target_image = nonempty(target.image_name);
        fields.target_command_line = target.command_line;
        fields.target_parent_process_id = target.parent_pid;
        fields.target_parent_image = target.parent_image;
        fields.target_parent_command_line = target.parent_command_line;
    }
    fields.start_module = module;
    for (field, present) in [
        ("SourceImage", fields.source_image.is_some()),
        ("SourceCommandLine", fields.source_command_line.is_some()),
        (
            "SourceParentProcessId",
            fields.source_parent_process_id.is_some(),
        ),
        ("SourceParentImage", fields.source_parent_image.is_some()),
        (
            "SourceParentCommandLine",
            fields.source_parent_command_line.is_some(),
        ),
        ("TargetImage", fields.target_image.is_some()),
        ("TargetCommandLine", fields.target_command_line.is_some()),
        (
            "TargetParentProcessId",
            fields.target_parent_process_id.is_some(),
        ),
        ("TargetParentImage", fields.target_parent_image.is_some()),
        (
            "TargetParentCommandLine",
            fields.target_parent_command_line.is_some(),
        ),
        ("StartModule", fields.start_module.is_some()),
    ] {
        if present {
            event.provenance.mark_derived(field);
        }
    }
}

fn metadata(processes: &ProcessCache, key: Option<ProcessStartKey>) -> Option<ProcessMetadata> {
    let key = key?;
    processes.get_metadata_by_key(key.pid, key.start_time)
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

type ModuleKey = (u32, u64, u64); // PID, process start, image base

struct ModuleRange {
    end: u64,
    path: String,
}

struct ModuleMapping {
    updated_at: u64,
    range: Option<ModuleRange>,
}

/// Address ranges from image records, capped across all processes. The
/// predecessor search is constrained to one process lifetime. Unloads
/// retain their timestamps to keep delayed loads from reviving a mapping.
pub(super) struct ModuleIndex {
    by_base: BTreeMap<ModuleKey, ModuleMapping>,
    order: BTreeSet<(u64, ModuleKey)>,
    capacity: usize,
}

impl ModuleIndex {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            by_base: BTreeMap::new(),
            order: BTreeSet::new(),
            capacity,
        }
    }

    pub(super) fn load(
        &mut self,
        process: ProcessStartKey,
        at: u64,
        base: u64,
        size: Option<u64>,
        path: Option<String>,
    ) {
        let range = size
            .and_then(|size| base.checked_add(size))
            .filter(|end| *end > base)
            .zip(path.filter(|path| !path.is_empty()))
            .map(|(end, path)| ModuleRange { end, path });
        let key = (process.pid, process.start_time, base);
        self.update(key, at, range);
    }

    pub(super) fn unload(&mut self, process: ProcessStartKey, at: u64, base: u64) {
        let key = (process.pid, process.start_time, base);
        self.update(key, at, None);
    }

    fn update(&mut self, key: ModuleKey, at: u64, range: Option<ModuleRange>) {
        if let Some(previous) = self.by_base.get(&key) {
            if previous.updated_at > at || (previous.updated_at == at && previous.range.is_none()) {
                return;
            }
            self.order.remove(&(previous.updated_at, key));
        }
        self.by_base.insert(
            key,
            ModuleMapping {
                updated_at: at,
                range,
            },
        );
        self.order.insert((at, key));
        if self.by_base.len() > self.capacity {
            if let Some((_, oldest)) = self.order.pop_first() {
                self.by_base.remove(&oldest);
            }
        }
    }

    pub(super) fn resolve(&self, process: ProcessStartKey, at: u64, address: u64) -> Option<&str> {
        let (_, mapping) = self
            .by_base
            .range(
                (process.pid, process.start_time, 0)..=(process.pid, process.start_time, address),
            )
            .next_back()?;
        let range = mapping.range.as_ref()?;
        (mapping.updated_at <= at && address < range.end).then_some(range.path.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CanonicalValue, Fidelity, FieldViewName, NormalizedEvent};
    use crate::sensor::windows_process_identity::{system_time_to_filetime, ProcessIdentityIndex};
    use crate::sensor::{Platform, RawProcessEvent, SensorAction, SensorNormalization};
    use crate::state::HostState;
    use std::time::{Duration, UNIX_EPOCH};

    fn raw_thread(fields: RemoteThreadFields) -> RawEvent {
        RawEvent {
            process_name: None,
            provenance: Default::default(),
            platform: Platform::Windows,
            provider: "etw",
            action: SensorAction::Start,
            normalization: SensorNormalization {
                event_id: 8,
                action_code: 1,
            },
            pid: Some(fields.source_process_id),
            timestamp: UNIX_EPOCH + Duration::from_secs(1),
            source_seq: None,
            process_start_key: None,
            parent_process_start_key: None,
            payload: RawPayload::RemoteThread(fields),
        }
    }

    #[test]
    fn same_process_and_missing_pids_are_distinguished_from_cross_process_starts() {
        assert_eq!(
            ThreadStart::classify(10, Some(10)),
            ThreadStart::SameProcess
        );
        assert_eq!(ThreadStart::classify(10, None), ThreadStart::MissingProcess);
        assert_eq!(
            ThreadStart::classify(0, Some(10)),
            ThreadStart::MissingProcess
        );
        assert_eq!(
            ThreadStart::classify(10, Some(u32::MAX)),
            ThreadStart::MissingProcess
        );
        assert_eq!(
            ThreadStart::classify(10, Some(20)),
            ThreadStart::Remote {
                source: 10,
                target: 20
            }
        );
    }

    #[test]
    fn thread_ids_and_raw_address_survive_normalization_and_replay() {
        let host = HostState::default();
        let event = host
            .canonicalize(raw_thread(RemoteThreadFields::from_thread_start(
                10,
                20,
                Some(42),
                Some(0x7ffc_9b11_0b80),
            )))
            .unwrap();
        let event = serde_json::to_value(event.normalized()).unwrap();
        assert_eq!(event["fields"]["SourceProcessId"], 10);
        assert_eq!(event["fields"]["TargetProcessId"], 20);
        assert_eq!(event["fields"]["NewThreadId"], 42);
        assert_eq!(event["fields"]["StartAddress"], "0x00007FFC9B110B80");
        for field in ["SourceImage", "TargetImage", "StartModule", "StartFunction"] {
            assert!(event["fields"].get(field).is_none(), "{field}");
        }

        let replayed: NormalizedEvent = serde_json::from_value(event).unwrap();
        let view = replayed.field_view(FieldViewName::SYSMON);
        assert_eq!(view.get("EventID"), Some(CanonicalValue::String("8")));
        assert_eq!(view.get("SourceProcessId"), Some(CanonicalValue::U64(10)));
        assert_eq!(view.get("TargetProcessId"), Some(CanonicalValue::U64(20)));
        assert_eq!(view.get("NewThreadId"), Some(CanonicalValue::U64(42)));
        assert_eq!(
            view.get("StartAddress"),
            Some(CanonicalValue::String("0x00007FFC9B110B80"))
        );
        assert_eq!(
            view.get("Channel"),
            Some(CanonicalValue::String(
                "Microsoft-Windows-Kernel-Process/Analytic"
            ))
        );

        let unknown_address = RemoteThreadFields::from_thread_start(10, 20, None, None);
        assert_eq!(unknown_address.new_thread_id, None);
        assert_eq!(unknown_address.start_address, None);
        let zero = RemoteThreadFields::from_thread_start(10, 20, None, Some(0));
        assert_eq!(zero.start_address.as_deref(), Some("0x0000000000000000"));
    }

    fn seed_process(host: &HostState, key: ProcessStartKey, image: &str) {
        host.processes.add(
            key.pid,
            key.start_time,
            image.to_owned(),
            Some(format!("{image} /test")),
            None,
            Some(4),
            Some("System".into()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
    }

    #[test]
    fn enrichment_uses_exact_source_and_target_generations_across_exit_and_reuse() {
        let host = HostState::default();
        let mut event = raw_thread(RemoteThreadFields::from_thread_start(
            10,
            20,
            Some(30),
            None,
        ));
        let now = system_time_to_filetime(event.timestamp);
        let source = ProcessStartKey {
            pid: 10,
            start_time: now - 20,
        };
        let target = ProcessStartKey {
            pid: 20,
            start_time: now - 10,
        };
        let reused = ProcessStartKey {
            pid: 20,
            start_time: now + 2,
        };
        let mut identities = ProcessIdentityIndex::default();
        for (key, image) in [
            (source, "source.exe"),
            (target, "target.exe"),
            (reused, "reused.exe"),
        ] {
            seed_process(&host, key, image);
            identities.observe_start(key);
        }
        // A stop for the old PID can arrive after the next generation's start.
        let mut stop = event.clone();
        let stop_fields = serde_json::from_value(serde_json::json!({})).unwrap();
        stop.action = SensorAction::Stop;
        stop.pid = Some(20);
        stop.timestamp += Duration::from_nanos(100);
        stop.process_start_key = Some(target);
        stop.payload = RawPayload::Process(RawProcessEvent::from_compatibility(
            stop_fields,
            Platform::Windows,
            Some(20),
        ));
        identities.attribute(&mut stop);

        enrich(
            &mut event,
            identities.resolve(10, now),
            identities.resolve(20, now),
            None,
            &host.processes,
        );
        assert_eq!(event.process_start_key, Some(source));
        let RawPayload::RemoteThread(fields) = &event.payload else {
            panic!("thread event")
        };
        assert_eq!(fields.source_image.as_deref(), Some("source.exe"));
        assert_eq!(
            fields.source_command_line.as_deref(),
            Some("source.exe /test")
        );
        assert_eq!(fields.target_image.as_deref(), Some("target.exe"));
        assert_eq!(fields.target_parent_process_id, Some(4));
        assert_eq!(fields.target_parent_image.as_deref(), Some("System"));
        assert!(event.provenance.has("SourceImage", Fidelity::Derived));
        assert!(event.provenance.has("TargetParentImage", Fidelity::Derived));
        assert!(fields.start_module.is_none());

        assert_eq!(identities.resolve(20, now - 11), None);
        assert_eq!(identities.resolve(20, now + 3), Some(reused));
        let mut gap = raw_thread(RemoteThreadFields::from_thread_start(10, 20, None, None));
        enrich(&mut gap, None, None, None, &host.processes);
        let RawPayload::RemoteThread(fields) = &gap.payload else {
            panic!("thread event")
        };
        assert!(fields.source_image.is_none());
        assert!(fields.target_image.is_none());
    }

    #[test]
    fn module_lookup_respects_address_boundaries_lifetime_and_unload_time() {
        let mut index = ModuleIndex::new(10);
        let process = ProcessStartKey {
            pid: 10,
            start_time: 100,
        };
        index.load(process, 110, 0x1000, Some(0x200), Some("first.dll".into()));
        assert_eq!(index.resolve(process, 109, 0x1000), None);
        assert_eq!(index.resolve(process, 110, 0x1000), Some("first.dll"));
        assert_eq!(index.resolve(process, 110, 0x11ff), Some("first.dll"));
        assert_eq!(index.resolve(process, 110, 0x1200), None);
        assert_eq!(index.resolve(process, 110, 0x0fff), None);

        let reused = ProcessStartKey {
            pid: 10,
            start_time: 200,
        };
        assert_eq!(index.resolve(reused, 210, 0x1000), None);

        index.unload(process, 150, 0x1000);
        index.load(process, 140, 0x1000, Some(0x200), Some("late.dll".into()));
        assert_eq!(index.resolve(process, 149, 0x1000), None);
        assert_eq!(index.resolve(process, 150, 0x1000), None);
        index.load(process, 160, 0x1000, Some(0x100), Some("second.dll".into()));
        index.unload(process, 155, 0x1000);
        assert_eq!(index.resolve(process, 170, 0x1000), Some("second.dll"));
        assert_eq!(index.resolve(process, 170, 0x1100), None);
    }

    #[test]
    fn module_index_limits_memory_and_leaves_invalid_or_unknown_ranges_unmapped() {
        let mut index = ModuleIndex::new(2);
        let process = ProcessStartKey {
            pid: 10,
            start_time: 100,
        };
        for (at, base) in [(110, 0x1000), (120, 0x2000), (130, 0x3000)] {
            index.load(process, at, base, Some(0x100), Some("known.dll".into()));
        }
        assert_eq!(index.by_base.len(), 2);
        assert_eq!(index.order.len(), 2);
        assert_eq!(index.resolve(process, 130, 0x1000), None);
        assert_eq!(index.resolve(process, 130, 0x2000), Some("known.dll"));

        index.load(
            process,
            140,
            0x3000,
            Some(0),
            Some("empty-range.dll".into()),
        );
        assert_eq!(index.resolve(process, 140, 0x3000), None);
        index.load(process, 145, 0x3000, Some(0x200), None);
        assert_eq!(index.resolve(process, 145, 0x3000), None);
        index.load(
            process,
            150,
            u64::MAX - 1,
            Some(2),
            Some("overflow.dll".into()),
        );
        assert_eq!(index.resolve(process, 150, u64::MAX), None);
    }
}
