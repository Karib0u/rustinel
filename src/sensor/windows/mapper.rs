//! Windows ETW compatibility mapping.
//!
//! Keeps the ETW-to-Sysmon compatibility layer on the Windows side of the
//! sensor boundary so shared normalization stays platform-agnostic.

use ferrisetw::EventRecord;

use crate::models::EventCategory;
use crate::sensor::{SensorAction, SensorNormalization};

pub fn normalization_for_record(
    category: EventCategory,
    action: SensorAction,
    record: &EventRecord,
) -> SensorNormalization {
    let action_code = action_code_for_record(category, action, record);
    let raw_event_id = raw_event_id_for_record(category, action_code, record);

    SensorNormalization {
        event_id: map_to_sysmon_id(category, action_code, raw_event_id),
        action_code,
    }
}

fn action_code_for_record(
    category: EventCategory,
    action: SensorAction,
    record: &EventRecord,
) -> u8 {
    match category {
        EventCategory::Process | EventCategory::ImageLoad => record.opcode(),
        EventCategory::Network => match action {
            SensorAction::Connect => 12,
            SensorAction::Disconnect => 13,
            SensorAction::Accept => 15,
            _ => 0,
        },
        // The manifest-based Kernel-File provider emits events with opcode 0,
        // so the action code comes from the routed action, not the opcode.
        EventCategory::File => file_action_code(action),
        EventCategory::Registry => match record.opcode() {
            36 | 38 | 39 | 41 => record.opcode(),
            _ => match action {
                SensorAction::Create => 36,
                SensorAction::Delete => 38,
                SensorAction::Set => 39,
                _ => 0,
            },
        },
        EventCategory::Dns => 0,
        EventCategory::Scripting => 0,
        EventCategory::Wmi => 0,
        EventCategory::Service => 0,
        EventCategory::Task => 0,
    }
}

/// Maps a routed file action to the platform-shared action code scheme
/// (64 = create, 65 = modify, 70 = delete, 71 = rename), read from the same
/// [`crate::sensor::FILE_EVENT_NORMALIZATION`] table the Linux and macOS
/// sensors use.
fn file_action_code(action: SensorAction) -> u8 {
    SensorNormalization::for_file_action(action)
        .map_or(0, |normalization| normalization.action_code)
}

fn raw_event_id_for_record(category: EventCategory, action_code: u8, record: &EventRecord) -> u16 {
    match category {
        EventCategory::Process | EventCategory::ImageLoad => record.event_id(),
        EventCategory::Network => record.event_id(),
        EventCategory::File => u16::from(action_code),
        EventCategory::Registry => u16::from(action_code),
        EventCategory::Dns => record.event_id(),
        EventCategory::Scripting => record.event_id(),
        EventCategory::Wmi => record.event_id(),
        EventCategory::Service => 7045,
        EventCategory::Task => 106,
    }
}

/// Maps Windows ETW opcodes/event IDs to the existing Sysmon-compatible IDs.
pub fn map_to_sysmon_id(category: EventCategory, action_code: u8, raw_event_id: u16) -> u16 {
    match category {
        EventCategory::Process => match action_code {
            1 => 1,
            2 => 5,
            10 => 7,
            _ => raw_event_id,
        },
        EventCategory::ImageLoad => match action_code {
            10 => 7,
            _ => raw_event_id,
        },
        // 72 has no entry in the shared table: no sensor emits it, but it is
        // accepted here as an alias for delete because the engine's opcode
        // fallback treats it as one.
        EventCategory::File => match action_code {
            72 => 23,
            code => SensorNormalization::for_file_action_code(code)
                .map_or(raw_event_id, |normalization| normalization.event_id),
        },
        EventCategory::Registry => match action_code {
            36 | 38 | 41 => 12,
            39 => 13,
            _ => raw_event_id,
        },
        EventCategory::Network => match action_code {
            12 | 15 => 3,
            _ => raw_event_id,
        },
        EventCategory::Dns => 22,
        EventCategory::Wmi => 19,
        EventCategory::Scripting => 4104,
        EventCategory::Service => 7045,
        EventCategory::Task => 106,
    }
}

#[cfg(test)]
mod tests {
    use super::{file_action_code, map_to_sysmon_id};
    use crate::models::EventCategory;
    use crate::sensor::{SensorAction, FILE_EVENT_NORMALIZATION};

    #[test]
    fn process_start_maps_to_sysmon_1() {
        assert_eq!(map_to_sysmon_id(EventCategory::Process, 1, 999), 1);
    }

    #[test]
    fn file_create_maps_to_sysmon_11() {
        assert_eq!(map_to_sysmon_id(EventCategory::File, 64, 999), 11);
    }

    #[test]
    fn file_actions_map_to_shared_action_codes() {
        for (action, expected) in FILE_EVENT_NORMALIZATION {
            let code = file_action_code(*action);
            assert_eq!(code, expected.action_code, "action code for {action:?}");
            assert_eq!(
                map_to_sysmon_id(EventCategory::File, code, u16::from(code)),
                expected.event_id,
                "event id for {action:?}"
            );
        }
    }

    #[test]
    fn file_delete_action_maps_to_sysmon_23() {
        let code = file_action_code(SensorAction::Delete);
        assert_eq!(
            map_to_sysmon_id(EventCategory::File, code, u16::from(code)),
            23
        );
    }

    #[test]
    fn file_rename_action_keeps_event_id_71() {
        let code = file_action_code(SensorAction::Rename);
        assert_eq!(
            map_to_sysmon_id(EventCategory::File, code, u16::from(code)),
            71
        );
    }

    #[test]
    fn registry_setvalue_maps_to_sysmon_13() {
        assert_eq!(map_to_sysmon_id(EventCategory::Registry, 39, 999), 13);
    }

    #[test]
    fn network_udp_connect_maps_to_sysmon_3() {
        assert_eq!(map_to_sysmon_id(EventCategory::Network, 15, 999), 3);
    }

    #[test]
    fn file_modify_does_not_map_to_sysmon_11() {
        let code = file_action_code(SensorAction::Modify);
        assert_eq!(code, 65);
        // Modify must NOT map to Sysmon ID 11 (FileCreate); the shared table
        // gives a write its own event ID 65, which routes to the base
        // `file_event` family. Reporting it under 11 was the macOS bug from
        // issue #239; routing it to `file_change` was the mis-categorisation
        // settled in #238.
        assert_eq!(
            map_to_sysmon_id(EventCategory::File, code, u16::from(code)),
            65
        );
    }
}
