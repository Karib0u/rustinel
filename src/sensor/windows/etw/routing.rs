//! ETW event routing and action refinement.

use super::parser::try_get_uint_as_u64;
use super::providers::EtwProviders;
use crate::models::EventCategory;
use crate::sensor::network_events::classify_kernel_network_event;
use crate::sensor::SensorAction;
use ferrisetw::parser::Parser;
use ferrisetw::{EventRecord, GUID};
use std::collections::HashMap;

/// The event IDs [`kernel_file_route`] accepts, pushed down to the provider as a
/// scope filter so the rest are never written into the session at all.
///
/// This does not measurably reduce sensor CPU - the unrouted events were already
/// rejected on an integer match before the schema lookup - but it roughly halves
/// the ETW buffer volume the kernel moves on our behalf, which is worth having
/// for free. Kept in sync with `kernel_file_route` by
/// `filter_matches_routing_allowlist`; a drift would silently delete detections.
pub(super) const KERNEL_FILE_ROUTED_EVENT_IDS: [u16; 9] = [10, 11, 12, 14, 16, 17, 26, 27, 28];

/// Microsoft-Windows-PowerShell manifest event IDs.
///
/// The two carry different Sigma logsources - 4104 is `ps_script`, 4103 is
/// `ps_module` - and different templates, so they are routed apart before
/// decoding rather than sharing one PowerShell payload.
pub(super) const POWERSHELL_EVENT_MODULE_LOGGING: u16 = 4103;

pub(super) const POWERSHELL_EVENT_SCRIPT_BLOCK: u16 = 4104;

/// One provider, two Sigma logsources: the event ID is the only thing that
/// separates script block logging from module logging, so the PowerShell
/// provider cannot be routed on its GUID like the others. Kept in sync with
/// [`EtwProviders::POWERSHELL_EVENT_IDS`] by
/// `powershell_filter_matches_routing_allowlist`.
pub(super) fn powershell_route(event_id: u16) -> Option<(EventCategory, SensorAction)> {
    match event_id {
        POWERSHELL_EVENT_SCRIPT_BLOCK => Some((EventCategory::Scripting, SensorAction::Execute)),
        POWERSHELL_EVENT_MODULE_LOGGING => {
            Some((EventCategory::PowerShellModule, SensorAction::Execute))
        }
        _ => None,
    }
}

/// Microsoft-Windows-Kernel-File manifest event IDs.
pub(super) const KERNEL_FILE_EVENT_NAME_CREATE: u16 = 10;

pub(super) const KERNEL_FILE_EVENT_NAME_DELETE: u16 = 11;

pub(super) const KERNEL_FILE_EVENT_CREATE: u16 = 12;

pub(super) const KERNEL_FILE_EVENT_CLOSE: u16 = 14;

pub(super) const KERNEL_FILE_EVENT_WRITE: u16 = 16;

pub(super) const KERNEL_FILE_EVENT_SET_INFORMATION: u16 = 17;

pub(super) const KERNEL_FILE_EVENT_DELETE_PATH: u16 = 26;

pub(super) const KERNEL_FILE_EVENT_RENAME_PATH: u16 = 27;

pub(super) const KERNEL_FILE_EVENT_SET_LINK_PATH: u16 = 28;

/// Microsoft-Windows-Kernel-Registry manifest event IDs.
///
/// The manifest declares opcodes 32-46 for event IDs 1-15, but the records the
/// session actually receives carry opcode 0, exactly as Kernel-File does. The
/// old classifier read `record.opcode()` and compared it against 36/38/39/41,
/// which is doubly wrong: opcode is always 0 at runtime, and even the manifest
/// values do not line up - 36 is `SetValueKey`, 38 `QueryValueKey`, 39
/// `EnumerateKey` and 41 `QueryMultipleValueKey`. Route on the event ID (#279).
pub(super) const KERNEL_REGISTRY_EVENT_CREATE_KEY: u16 = 1;

pub(super) const KERNEL_REGISTRY_EVENT_OPEN_KEY: u16 = 2;

pub(super) const KERNEL_REGISTRY_EVENT_DELETE_KEY: u16 = 3;

pub(super) const KERNEL_REGISTRY_EVENT_SET_VALUE_KEY: u16 = 5;

pub(super) const KERNEL_REGISTRY_EVENT_DELETE_VALUE_KEY: u16 = 6;

pub(super) const KERNEL_REGISTRY_EVENT_CLOSE_KEY: u16 = 13;

/// The event IDs [`kernel_registry_route`] accepts, pushed down to the provider
/// as a scope filter. Kept in sync with the router by
/// `registry_filter_matches_routing_allowlist`.
pub(super) const KERNEL_REGISTRY_ROUTED_EVENT_IDS: [u16; 6] = [
    KERNEL_REGISTRY_EVENT_CREATE_KEY,
    KERNEL_REGISTRY_EVENT_OPEN_KEY,
    KERNEL_REGISTRY_EVENT_DELETE_KEY,
    KERNEL_REGISTRY_EVENT_SET_VALUE_KEY,
    KERNEL_REGISTRY_EVENT_DELETE_VALUE_KEY,
    KERNEL_REGISTRY_EVENT_CLOSE_KEY,
];

/// What a Microsoft-Windows-Kernel-Registry event is good for.
///
/// An allowlist, like [`kernel_file_route`]: an unrecognised event is dropped
/// rather than labelled a modification. The `_ => SensorAction::Modify`
/// catch-all this replaces collapsed the whole action taxonomy onto a single
/// value that maps to no Sysmon event ID, so `registry_add`, `registry_set` and
/// `registry_delete` rules were evaluated against every registry event and
/// could never match one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KernelRegistryRoute {
    /// Carries `BaseName`/`RelativeName`; record the key's path.
    ///
    /// `creates` distinguishes `CreateKey`, which also reports a creation when
    /// its `Disposition` says a new key was made, from `OpenKey`, which is
    /// index maintenance only.
    Name { creates: bool },
    /// Emit telemetry under this action, resolving the path from the index.
    Emit(SensorAction),
    /// A closed key: drop its `KeyObject` from the index.
    Evict,
}

pub(super) fn kernel_registry_route(event_id: u16) -> Option<KernelRegistryRoute> {
    match event_id {
        KERNEL_REGISTRY_EVENT_CREATE_KEY => Some(KernelRegistryRoute::Name { creates: true }),
        KERNEL_REGISTRY_EVENT_OPEN_KEY => Some(KernelRegistryRoute::Name { creates: false }),
        // A deleted key and a deleted value are both Sysmon 12 and both
        // `registry_delete`; the value name survives in `Details`.
        KERNEL_REGISTRY_EVENT_DELETE_KEY | KERNEL_REGISTRY_EVENT_DELETE_VALUE_KEY => {
            Some(KernelRegistryRoute::Emit(SensorAction::Delete))
        }
        KERNEL_REGISTRY_EVENT_SET_VALUE_KEY => Some(KernelRegistryRoute::Emit(SensorAction::Set)),
        KERNEL_REGISTRY_EVENT_CLOSE_KEY => Some(KernelRegistryRoute::Evict),
        // 4 QueryKey, 7 QueryValueKey, 8 EnumerateKey, 9 EnumerateValueKey,
        // 10 QueryMultipleValueKey, 12 FlushKey, 14 QuerySecurityKey - reads
        // and bookkeeping, no state change. 11 SetInformationKey and
        // 15 SetSecurityKey do change state but have no Sysmon or Sigma
        // counterpart to carry them.
        _ => None,
    }
}

/// `FILE_INFORMATION_CLASS` values seen on `SetInformation` (event ID 17).
///
/// The event reports only which class was set, never the values written, so
/// these tell us *that* a timestamp or a file size changed but not to what.
pub(super) const FILE_BASIC_INFORMATION: u64 = 4;

pub(super) const FILE_ALLOCATION_INFORMATION: u64 = 19;

pub(super) const FILE_END_OF_FILE_INFORMATION: u64 = 20;

/// What a Microsoft-Windows-Kernel-File event is good for.
///
/// Previously every unrecognised event ID fell into a `_ => Modify` catch-all,
/// which quietly turned the provider's name-cache bookkeeping into telemetry:
/// one `CreateNew` produced a create *and* a spurious change event. Routing is
/// now an allowlist, so an event nobody has looked at is dropped rather than
/// labelled a modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KernelFileRoute {
    /// Emit telemetry under this action.
    Emit(SensorAction),
    /// Carries a name; record it and emit nothing. These are the index the
    /// provider publishes so consumers can resolve the pathless events.
    Index,
    /// A closed handle: drop its `FileObject` from the index.
    EvictObject,
    /// A name leaving the kernel's name cache: drop its `FileKey`.
    EvictKey,
    /// Action depends on the `InfoClass`, which needs the parsed event.
    SetInformation,
}

/// The manifest provider emits file events with opcode 0, so routing must use
/// manifest event IDs rather than MOF FileIo opcodes.
///
/// `None` means "not interesting" - checked before the schema lookup, so the
/// high-volume `Read` (15), `QueryInformation` (22), and `FSCTL` (23) events
/// that the `FILEIO` keyword also enables cost only a match on an integer.
pub(super) fn kernel_file_route(event_id: u16) -> Option<KernelFileRoute> {
    match event_id {
        KERNEL_FILE_EVENT_CREATE => Some(KernelFileRoute::Emit(SensorAction::Create)),
        KERNEL_FILE_EVENT_WRITE => Some(KernelFileRoute::Emit(SensorAction::Modify)),
        KERNEL_FILE_EVENT_DELETE_PATH => Some(KernelFileRoute::Emit(SensorAction::Delete)),
        KERNEL_FILE_EVENT_RENAME_PATH | KERNEL_FILE_EVENT_SET_LINK_PATH => {
            Some(KernelFileRoute::Emit(SensorAction::Rename))
        }
        KERNEL_FILE_EVENT_SET_INFORMATION => Some(KernelFileRoute::SetInformation),
        KERNEL_FILE_EVENT_NAME_CREATE => Some(KernelFileRoute::Index),
        KERNEL_FILE_EVENT_NAME_DELETE => Some(KernelFileRoute::EvictKey),
        KERNEL_FILE_EVENT_CLOSE => Some(KernelFileRoute::EvictObject),
        // Deliberately unrouted, with the reason recorded so a future reader
        // does not have to re-derive it:
        //   13 Cleanup     - precedes Close; Close is the eviction point
        //   15 Read        - not a modification
        //   18 SetDelete   - duplicate of 26 DeletePath, which carries the path
        //   19 Rename      - duplicate of 27 RenamePath, which carries the path
        //   22/23/32/34    - query and control paths, no state change
        _ => None,
    }
}

/// Resolve `SetInformation` (event ID 17) to an action via its `InfoClass`.
///
/// This is the event that makes truncation and timestamp manipulation visible
/// at all; both were previously uncollected because the keyword was not
/// enabled. Returns `None` for the many other information classes, which are
/// ordinary metadata updates.
pub(super) fn set_information_action(parser: &Parser) -> Option<SensorAction> {
    match try_get_uint_as_u64(parser, "InfoClass")? {
        // Timestamps and attributes. This is the closest analogue to Sysmon
        // Event ID 2 (file creation time changed), i.e. timestomping, which is
        // what Sigma's `file_change` category actually denotes.
        FILE_BASIC_INFORMATION => Some(SensorAction::Set),
        // Setting the allocation size or end-of-file position: truncation.
        // Truncate-to-zero of an existing file is a common wiper and
        // ransomware pattern and produced no event at all before this.
        FILE_ALLOCATION_INFORMATION | FILE_END_OF_FILE_INFORMATION => Some(SensorAction::Modify),
        _ => None,
    }
}

/// IRP_MJ_CREATE disposition values (top byte of CreateOptions).
///
/// The disposition controls whether the I/O manager creates a new file,
/// opens an existing one, or some combination of both.
pub(super) const FILE_DISPOSITION_SUPERSEDE: u32 = 0;

pub(super) const FILE_DISPOSITION_OPEN: u32 = 1;

pub(super) const FILE_DISPOSITION_CREATE: u32 = 2;

pub(super) const FILE_DISPOSITION_OPEN_IF: u32 = 3;

pub(super) const FILE_DISPOSITION_OVERWRITE: u32 = 4;

pub(super) const FILE_DISPOSITION_OVERWRITE_IF: u32 = 5;

/// Refine a [`SensorAction::Create`] for Kernel-File Event ID 12 based on
/// the `CreateOptions` disposition.
///
/// Event ID 12 corresponds to `IRP_MJ_CREATE`, which fires for **every** file
/// handle request - including plain opens and attribute queries.  Without
/// inspecting the disposition we would misclassify reads as file creations.
///
/// Returns:
/// * `Some(action)` - the (possibly adjusted) action for this event.
/// * `None` - the event should be dropped (pure open / read).
pub(super) fn refine_file_create_action(
    parser: &Parser,
    action: SensorAction,
) -> Option<SensorAction> {
    if action != SensorAction::Create {
        return Some(action);
    }

    let create_options = parser.try_parse::<u32>("CreateOptions").ok()?;
    let disposition = (create_options >> 24) & 0xFF;

    match disposition {
        // Pure open of an existing file - never creates.  Drop the event
        // to match Sysmon behaviour (Sysmon does not emit FileCreate for
        // plain opens).
        FILE_DISPOSITION_OPEN => None,

        // Overwrite of an existing file - the file already exists so this
        // is a modification, not a creation.
        FILE_DISPOSITION_OVERWRITE => Some(SensorAction::Modify),

        // SUPERSEDE, CREATE, OPEN_IF, OVERWRITE_IF can all result in a
        // new file being created.
        FILE_DISPOSITION_SUPERSEDE
        | FILE_DISPOSITION_CREATE
        | FILE_DISPOSITION_OPEN_IF
        | FILE_DISPOSITION_OVERWRITE_IF => Some(SensorAction::Create),

        // Unknown disposition - keep as Create to be safe.
        _ => Some(SensorAction::Create),
    }
}

/// `REG_DISPOSITION` values reported by Kernel-Registry event ID 1.
pub(super) const REG_CREATED_NEW_KEY: u32 = 1;

pub(super) const REG_OPENED_EXISTING_KEY: u32 = 2;

/// Whether a Kernel-Registry `CreateKey` (event ID 1) actually created a key.
///
/// `CreateKey` is `NtCreateKey`, which opens an existing key just as readily as
/// it makes a new one - the same trap as `IRP_MJ_CREATE` on the file side (see
/// [`refine_file_create_action`]). Without this check every key open on the
/// machine would surface as a `registry_add`, trading a category that never
/// fires for one that fires constantly.
///
/// Returns `None` when the event should be dropped.
pub(super) fn refine_registry_create_action(parser: &Parser) -> Option<()> {
    match parser.try_parse::<u32>("Disposition") {
        Ok(REG_CREATED_NEW_KEY) => Some(()),
        Ok(REG_OPENED_EXISTING_KEY) => None,
        // An unreadable or unknown disposition keeps the event: a missed
        // detection is worse than an extra one.
        Ok(_) | Err(_) => Some(()),
    }
}

pub(super) struct EtwRouting {
    pub(super) kernel_process_guid: GUID,
    pub(super) kernel_file_guid: GUID,
    pub(super) kernel_registry_guid: GUID,
    pub(super) powershell_guid: GUID,
    pub(super) guid_to_category: HashMap<GUID, EventCategory>,
    /// Subscribed provider GUIDs to their manifest names. Decode failures are
    /// labelled from this table rather than from a rendered GUID, so the label
    /// space cannot grow past the providers this build enables.
    guid_to_name: HashMap<GUID, &'static str>,
}

impl EtwRouting {
    pub(super) fn new() -> Self {
        let mut guid_to_category = HashMap::new();
        guid_to_category.insert(EtwProviders::kernel_network().guid, EventCategory::Network);
        guid_to_category.insert(EtwProviders::kernel_file().guid, EventCategory::File);
        guid_to_category.insert(
            EtwProviders::kernel_registry().guid,
            EventCategory::Registry,
        );
        guid_to_category.insert(EtwProviders::dns_client().guid, EventCategory::Dns);
        guid_to_category.insert(EtwProviders::wmi_activity().guid, EventCategory::Wmi);
        guid_to_category.insert(EtwProviders::task_scheduler().guid, EventCategory::Task);

        let guid_to_name = EtwProviders::all()
            .into_iter()
            .map(|provider| (provider.guid, provider.name))
            .collect();

        Self {
            kernel_process_guid: EtwProviders::kernel_process().guid,
            kernel_file_guid: EtwProviders::kernel_file().guid,
            kernel_registry_guid: EtwProviders::kernel_registry().guid,
            powershell_guid: EtwProviders::powershell().guid,
            guid_to_category,
            guid_to_name,
        }
    }

    /// The manifest name of a subscribed provider.
    ///
    /// A GUID that is not subscribed collapses to one shared label. Rendering
    /// it instead would make the failure label space unbounded, which is the
    /// thing this table exists to prevent; an unsubscribed provider reaching
    /// the callback is a session-configuration bug, not a decode statistic.
    pub(super) fn provider_name(&self, guid: GUID) -> &'static str {
        self.guid_to_name
            .get(&guid)
            .copied()
            .unwrap_or("unsubscribed")
    }

    pub(super) fn route(&self, record: &EventRecord) -> Option<(EventCategory, SensorAction)> {
        let provider_guid = record.provider_id();

        if provider_guid == self.kernel_process_guid {
            return match record.opcode() {
                1 => Some((EventCategory::Process, SensorAction::Start)),
                2 => Some((EventCategory::Process, SensorAction::Stop)),
                10 => Some((EventCategory::ImageLoad, SensorAction::Load)),
                _ => None,
            };
        }

        if provider_guid == self.powershell_guid {
            return powershell_route(record.event_id());
        }

        let category = *self.guid_to_category.get(&provider_guid)?;
        let action = match category {
            EventCategory::Network => {
                classify_kernel_network_event(record.event_id())?.connection_action()?
            }
            // Kernel-File needs the path index and so has its own pipeline;
            // `decode_record` diverts it before reaching here.
            EventCategory::File => return None,
            // Kernel-Registry needs the key-path index and so has its own
            // pipeline; `decode_record` diverts it before reaching here.
            EventCategory::Registry => return None,
            EventCategory::Dns => SensorAction::Query,
            EventCategory::Wmi => SensorAction::Execute,
            EventCategory::Task => SensorAction::Register,
            EventCategory::Service | EventCategory::Security => {
                unreachable!("event log categories use the event log sources")
            }
            EventCategory::Process
            | EventCategory::ImageLoad
            | EventCategory::Scripting
            | EventCategory::PowerShellModule => unreachable!(),
        };

        Some((category, action))
    }
}

#[cfg(test)]
mod tests {
    use super::super::providers::EtwProviders;
    use super::*;
    use crate::models::EventCategory;
    use crate::sensor::SensorAction;

    #[test]
    fn filter_matches_routing_allowlist() {
        // The provider-side filter is an allowlist: an ID that routes but is
        // missing here never reaches the callback at all, which would delete a
        // detection with no error, no dropped-event counter, and nothing in the
        // log. Derive the expected set from the router so the two cannot drift.
        let routed: Vec<u16> = (0u16..=64)
            .filter(|id| kernel_file_route(*id).is_some())
            .collect();
        assert_eq!(
            routed,
            KERNEL_FILE_ROUTED_EVENT_IDS.to_vec(),
            "provider filter and kernel_file_route disagree"
        );
    }

    #[test]
    fn kernel_file_event_ids_route_to_actions() {
        use KernelFileRoute::Emit;
        assert_eq!(kernel_file_route(12), Some(Emit(SensorAction::Create)));
        assert_eq!(kernel_file_route(16), Some(Emit(SensorAction::Modify)));
        assert_eq!(kernel_file_route(26), Some(Emit(SensorAction::Delete)));
        assert_eq!(kernel_file_route(27), Some(Emit(SensorAction::Rename)));
        assert_eq!(kernel_file_route(28), Some(Emit(SensorAction::Rename)));
    }

    #[test]
    fn name_cache_events_are_index_maintenance_not_telemetry() {
        // Measured on Windows 11: one CreateNew emits both a Create (12) and a
        // NameCreate (10). Treating 10 as telemetry produced a spurious change
        // event per file creation, and a rename produced three events.
        assert_eq!(kernel_file_route(10), Some(KernelFileRoute::Index));
        assert_eq!(kernel_file_route(11), Some(KernelFileRoute::EvictKey));
        assert_eq!(kernel_file_route(14), Some(KernelFileRoute::EvictObject));
    }

    #[test]
    fn unexamined_kernel_file_events_are_dropped_not_called_modifications() {
        // The old `_ => Modify` catch-all labelled every one of these a file
        // modification. 18 and 19 are the pathless duplicates of DeletePath
        // (26) and RenamePath (27); the rest are reads and queries.
        for event_id in [13, 15, 18, 19, 20, 21, 22, 23, 30, 32, 34, 99] {
            assert_eq!(
                kernel_file_route(event_id),
                None,
                "event {event_id} must not be routed"
            );
        }
    }

    #[test]
    fn set_information_needs_its_info_class() {
        assert_eq!(
            kernel_file_route(17),
            Some(KernelFileRoute::SetInformation),
            "the action depends on InfoClass, which needs the parsed event"
        );
    }

    #[test]
    fn registry_filter_matches_routing_allowlist() {
        // Same allowlist-drift guard as the Kernel-File filter: an ID that
        // routes but is missing from the filter never reaches the callback.
        let routed: Vec<u16> = (0u16..=64)
            .filter(|id| kernel_registry_route(*id).is_some())
            .collect();
        let mut expected = KERNEL_REGISTRY_ROUTED_EVENT_IDS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            routed, expected,
            "provider filter and kernel_registry_route disagree"
        );
    }

    #[test]
    fn registry_event_ids_route_to_write_actions() {
        use KernelRegistryRoute::Emit;
        assert_eq!(kernel_registry_route(3), Some(Emit(SensorAction::Delete)));
        assert_eq!(kernel_registry_route(5), Some(Emit(SensorAction::Set)));
        assert_eq!(kernel_registry_route(6), Some(Emit(SensorAction::Delete)));
    }

    #[test]
    fn naming_events_maintain_the_index_and_only_create_emits() {
        // SetValueKey delivers an empty KeyName, so CreateKey and OpenKey are
        // the only source of a key's path. OpenKey must never produce
        // telemetry of its own; CreateKey does, subject to its Disposition.
        assert_eq!(
            kernel_registry_route(1),
            Some(KernelRegistryRoute::Name { creates: true })
        );
        assert_eq!(
            kernel_registry_route(2),
            Some(KernelRegistryRoute::Name { creates: false })
        );
        assert_eq!(kernel_registry_route(13), Some(KernelRegistryRoute::Evict));
    }

    #[test]
    fn registry_reads_are_dropped_not_called_modifications() {
        // The `_ => Modify` catch-all this replaces put every one of these
        // through the full Sigma evaluation under an action code of 0.
        for event_id in [4, 7, 8, 9, 10, 11, 12, 14, 15, 16, 40, 99] {
            assert_eq!(
                kernel_registry_route(event_id),
                None,
                "registry event {event_id} must not be routed"
            );
        }
    }

    #[test]
    fn powershell_filter_matches_routing_allowlist() {
        // A provider filter and a router that disagree fail silently: an ID in
        // the filter but not the router is decoded work thrown away, and an ID
        // in the router but not the filter never reaches the session at all.
        for &event_id in EtwProviders::POWERSHELL_EVENT_IDS {
            assert!(
                powershell_route(event_id).is_some(),
                "event {event_id} is subscribed but not routed"
            );
        }

        assert_eq!(
            powershell_route(POWERSHELL_EVENT_SCRIPT_BLOCK),
            Some((EventCategory::Scripting, SensorAction::Execute)),
            "script block logging must stay on ps_script"
        );
        assert_eq!(
            powershell_route(POWERSHELL_EVENT_MODULE_LOGGING),
            Some((EventCategory::PowerShellModule, SensorAction::Execute)),
            "module logging must reach ps_module, not ps_script"
        );
        // 4105/4106 (script block start/stop) share the Runspace keyword and
        // carry no matchable text.
        assert_eq!(powershell_route(4105), None);
        assert_eq!(powershell_route(4106), None);
    }
}
