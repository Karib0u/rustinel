//! Semantic event boundary shared by live detection, capture, and replay.
//!
//! Host-dependent work is complete before a `CanonicalEvent` is created.  The
//! `NormalizedEvent` is retained as the stable capture-schema-v2 payload.
//! Detectors render its Rustinel-named data through an explicit field view.

use super::{NormalizedEvent, Provenance};
use crate::sensor::{ProcessStartKey, SensorAction};

/// Cross-platform event after host-state enrichment.
#[derive(Debug, Clone)]
pub struct CanonicalEvent {
    normalized: NormalizedEvent,
    pub action: SensorAction,
    pub pid: Option<u32>,
    pub process_start_key: Option<ProcessStartKey>,
    pub parent_process_start_key: Option<ProcessStartKey>,
    /// Deferred-pass rules will evaluate this event after artifact resolution,
    /// so admission must leave them out. Never recorded: a recording replays
    /// every rule against the event it holds.
    deferred_pass_pending: bool,
}

impl CanonicalEvent {
    pub(crate) fn new(
        normalized: NormalizedEvent,
        action: SensorAction,
        pid: Option<u32>,
        process_start_key: Option<ProcessStartKey>,
        parent_process_start_key: Option<ProcessStartKey>,
    ) -> Self {
        Self {
            normalized,
            action,
            pid,
            process_start_key,
            parent_process_start_key,
            deferred_pass_pending: false,
        }
    }

    /// Build the canonical replay boundary from the stable recorded view.
    pub fn from_normalized(normalized: NormalizedEvent) -> Self {
        let action = action_from_view(&normalized);
        let pid = process_id_from_view(&normalized);
        Self::new(normalized, action, pid, None, None)
    }

    /// Stable event payload used by capture, replay, and output rendering.
    pub fn normalized(&self) -> &NormalizedEvent {
        &self.normalized
    }

    /// Mutable access for bounded host enrichment before detector admission.
    pub(crate) fn normalized_mut(&mut self) -> &mut NormalizedEvent {
        &mut self.normalized
    }

    /// Whether a deferred detection pass owns this event's deferred-pass rules.
    pub fn deferred_pass_pending(&self) -> bool {
        self.deferred_pass_pending
    }

    pub(crate) fn set_deferred_pass_pending(&mut self, pending: bool) {
        self.deferred_pass_pending = pending;
    }

    pub fn into_normalized(self) -> NormalizedEvent {
        self.normalized
    }

    pub fn provenance(&self) -> &Provenance {
        &self.normalized.provenance
    }

    /// Every indicator-shaped value this event carries, extracted in one pass.
    ///
    /// Relative command-line operands are resolved against the process
    /// working directory here, without rewriting any field of the event.
    pub fn observables(&self) -> crate::observable::Observables<'_> {
        crate::observable::extract(&self.normalized)
    }
}

fn process_id_from_view(event: &NormalizedEvent) -> Option<u32> {
    event
        .get_field("ProcessId")
        .and_then(|value| value.parse().ok())
}

fn action_from_view(event: &NormalizedEvent) -> SensorAction {
    use crate::models::EventCategory;

    match event.category {
        EventCategory::Process if event.opcode == 2 || event.event_id == 5 => SensorAction::Stop,
        EventCategory::Process => SensorAction::Start,
        EventCategory::Network => SensorAction::Connect,
        EventCategory::File => match event.opcode {
            70 => SensorAction::Delete,
            71 => SensorAction::Rename,
            65 => SensorAction::Modify,
            2 => SensorAction::Set,
            _ => SensorAction::Create,
        },
        EventCategory::Dns => SensorAction::Query,
        EventCategory::Registry => match event.opcode {
            38 => SensorAction::Delete,
            39 => SensorAction::Set,
            _ => SensorAction::Create,
        },
        EventCategory::ImageLoad => SensorAction::Load,
        EventCategory::Scripting => SensorAction::Execute,
        EventCategory::PowerShellModule => SensorAction::Load,
        EventCategory::PowerShellClassicStart => SensorAction::Start,
        EventCategory::Wmi | EventCategory::Service | EventCategory::Task => SensorAction::Register,
        EventCategory::Security => SensorAction::Access,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventCategory, EventFields, ProcessCreationFields};
    use crate::sensor::Platform;

    #[test]
    fn recorded_process_view_recovers_routing_metadata() {
        let event = NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            source_seq: None,
            ingest_seq: 1,
            platform: Platform::Linux,
            provider: "ebpf".into(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".into(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                hashes: None,
                imphash: None,
                container: Default::default(),
                linux_identity: Default::default(),
                cgroup_id: None,
                exec: Default::default(),
                parent_process_id_derived: false,
                windows: Default::default(),
                image: Some("/usr/bin/true".into()),
                image_source: Some("execve".into()),
                image_truncated: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                command_line: Some("/usr/bin/true".into()),
                process_id: Some("42".into()),
                process_start_time: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                parent_user: None,
                current_directory: None,
                integrity_level: None,
                user: None,
            }),
            process_name: None,
            provenance: Default::default(),
            process_context: None,
        };

        let canonical = CanonicalEvent::from_normalized(event);
        assert_eq!(canonical.action, SensorAction::Start);
        assert_eq!(canonical.pid, Some(42));
        assert_eq!(
            canonical.normalized().get_field("Image"),
            Some("/usr/bin/true")
        );
    }
}
