//! The single table that gives file and registry actions their meaning.
//!
//! A file or registry event carries `(category, opcode, event_id)`, and five
//! consumers used to decode that triple by hand: the sensors (which number
//! their events), the Windows ETW mapper, replay's `action_from_view`, the ECS
//! action and type, and the Sigma logsource categories. They disagreed about
//! action codes 41 and 72 and about the code 80. Each row here declares one
//! action once, and every consumer derives its answer from it.

use super::EventCategory;
use crate::vocab::SensorAction;
use serde::{Deserialize, Serialize};

/// Sensor-supplied compatibility metadata for the normalized event model.
///
/// Shared normalization copies this through without understanding any
/// platform-specific event numbering scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorNormalization {
    pub event_id: u16,
    pub action_code: u8,
}

impl SensorNormalization {
    /// Return the shared file-event numbering for `action`.
    ///
    /// `None` for actions that are not file actions, which lets a caller drop
    /// the event rather than invent a number for it.
    pub fn for_file_action(action: SensorAction) -> Option<Self> {
        row_for_action(EventCategory::File, action).map(|row| row.normalization())
    }

    /// Reverse lookup of [`Self::for_file_action`], for sensors that recover
    /// the action from an already-computed action code.
    pub fn for_file_action_code(action_code: u8) -> Option<Self> {
        row_for_code(EventCategory::File, action_code).map(|row| row.normalization())
    }
}

/// Everything downstream consumers need to know about one file or registry action.
#[derive(Debug, Clone, Copy)]
pub struct EventActionRow {
    pub category: EventCategory,
    pub action: SensorAction,
    /// Sysmon-compatible event ID sensors report for this action.
    pub event_id: u16,
    /// Canonical action code sensors report for this action.
    pub action_code: u8,
    /// Other action codes that older or foreign producers use for the same
    /// action. No sensor emits them, but every consumer must still agree on
    /// what they mean.
    pub alias_codes: &'static [u8],
    /// `event.action` in the ECS alert output.
    pub ecs_action: &'static str,
    /// `event.type` in the ECS alert output.
    pub ecs_type: &'static str,
    /// Sigma logsource categories the event is evaluated against.
    pub sigma_categories: &'static [&'static str],
}

impl EventActionRow {
    fn has_code(&self, code: u8) -> bool {
        self.action_code == code || self.alias_codes.contains(&code)
    }

    pub fn normalization(&self) -> SensorNormalization {
        SensorNormalization {
            event_id: self.event_id,
            action_code: self.action_code,
        }
    }
}

/// What a file or registry event means when its code matches no row.
///
/// Replay recovers `Create` for these, which is what it always did.
#[derive(Debug, Clone, Copy)]
pub struct UnknownActionRow {
    pub category: EventCategory,
    pub action: SensorAction,
    pub ecs_action: &'static str,
    pub ecs_type: &'static str,
    pub sigma_categories: &'static [&'static str],
}

const FILE: EventCategory = EventCategory::File;
const REGISTRY: EventCategory = EventCategory::Registry;

/// File events.
///
/// The identifiers are Sysmon-compatible where Sysmon has an equivalent event
/// (2 = FileCreateTime, 11 = FileCreate, 23 = FileDelete). Sysmon has no
/// file-modify or file-rename event, so those reuse the action code as the
/// `event_id`.
///
/// [`SensorAction::Set`] means the file's metadata was set, its timestamps or
/// attributes, which is what Sigma's `file_change` category denotes. A plain
/// write is [`SensorAction::Modify`] and is deliberately *not* `file_change`.
///
/// Registry rows come from the routed action alone, because Kernel-Registry
/// records carry opcode 0 (#279). `Modify` is not a registry action.
pub const EVENT_ACTIONS: &[EventActionRow] = &[
    EventActionRow {
        category: FILE,
        action: SensorAction::Create,
        event_id: 11,
        action_code: 64,
        alias_codes: &[],
        ecs_action: "file-create",
        ecs_type: "creation",
        sigma_categories: &["file_event", "file_create"],
    },
    EventActionRow {
        category: FILE,
        action: SensorAction::Set,
        event_id: 2,
        action_code: 2,
        alias_codes: &[],
        ecs_action: "file-change",
        ecs_type: "change",
        sigma_categories: &["file_event", "file_change"],
    },
    EventActionRow {
        category: FILE,
        action: SensorAction::Modify,
        event_id: 65,
        action_code: 65,
        alias_codes: &[80],
        ecs_action: "file-change",
        ecs_type: "change",
        sigma_categories: &["file_event"],
    },
    EventActionRow {
        category: FILE,
        action: SensorAction::Delete,
        event_id: 23,
        action_code: 70,
        alias_codes: &[72],
        ecs_action: "file-delete",
        ecs_type: "deletion",
        sigma_categories: &["file_delete"],
    },
    EventActionRow {
        category: FILE,
        action: SensorAction::Rename,
        event_id: 71,
        action_code: 71,
        alias_codes: &[],
        ecs_action: "file-rename",
        ecs_type: "change",
        sigma_categories: &["file_event", "file_rename"],
    },
    EventActionRow {
        category: REGISTRY,
        action: SensorAction::Create,
        event_id: 12,
        action_code: 36,
        alias_codes: &[],
        ecs_action: "registry-create",
        ecs_type: "creation",
        sigma_categories: &["registry_event", "registry_add"],
    },
    EventActionRow {
        category: REGISTRY,
        action: SensorAction::Delete,
        event_id: 12,
        action_code: 38,
        alias_codes: &[41],
        ecs_action: "registry-delete",
        ecs_type: "deletion",
        sigma_categories: &["registry_event", "registry_delete"],
    },
    EventActionRow {
        category: REGISTRY,
        action: SensorAction::Set,
        event_id: 13,
        action_code: 39,
        alias_codes: &[],
        ecs_action: "registry-set",
        ecs_type: "change",
        sigma_categories: &["registry_event", "registry_set"],
    },
];

const UNKNOWN_FILE: UnknownActionRow = UnknownActionRow {
    category: FILE,
    action: SensorAction::Create,
    ecs_action: "file-change",
    ecs_type: "change",
    sigma_categories: &["file_event"],
};

const UNKNOWN_REGISTRY: UnknownActionRow = UnknownActionRow {
    category: REGISTRY,
    action: SensorAction::Create,
    ecs_action: "registry-change",
    ecs_type: "change",
    sigma_categories: &["registry_event"],
};

/// Fallback for a code that no row claims; `None` outside file and registry.
pub fn unknown_action(category: EventCategory) -> Option<UnknownActionRow> {
    match category {
        EventCategory::File => Some(UNKNOWN_FILE),
        EventCategory::Registry => Some(UNKNOWN_REGISTRY),
        _ => None,
    }
}

/// The rows for one category.
pub fn rows_for(category: EventCategory) -> impl Iterator<Item = &'static EventActionRow> {
    EVENT_ACTIONS
        .iter()
        .filter(move |row| row.category == category)
}

/// The row a sensor uses for a routed action.
pub fn row_for_action(
    category: EventCategory,
    action: SensorAction,
) -> Option<&'static EventActionRow> {
    rows_for(category).find(|row| row.action == action)
}

/// The row that claims an action code, canonical or alias.
pub fn row_for_code(category: EventCategory, code: u8) -> Option<&'static EventActionRow> {
    rows_for(category).find(|row| row.has_code(code))
}

/// The row that claims a Sysmon-compatible event ID.
pub fn row_for_event_id(category: EventCategory, event_id: u16) -> Option<&'static EventActionRow> {
    rows_for(category).find(|row| row.event_id == event_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_do_not_claim_the_same_action_or_code_twice() {
        for (index, row) in EVENT_ACTIONS.iter().enumerate() {
            for other in &EVENT_ACTIONS[index + 1..] {
                if row.category != other.category {
                    continue;
                }
                assert_ne!(row.action, other.action, "{:?} declared twice", row.action);
                let codes = |r: &EventActionRow| {
                    let mut codes = vec![r.action_code];
                    codes.extend_from_slice(r.alias_codes);
                    codes
                };
                for code in codes(row) {
                    assert!(
                        !codes(other).contains(&code),
                        "code {code} is claimed by {:?} and {:?}",
                        row.action,
                        other.action
                    );
                }
            }
        }
    }
}
