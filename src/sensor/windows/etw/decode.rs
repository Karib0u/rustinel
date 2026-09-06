//! ETW record decoding into sensor events.

use super::super::registry_paths::PathSource;
use super::super::{field_maps, mapper, registry_value_data};
use super::parser::{
    filetime_to_system_time, parse_optional_u32, try_get_ip, try_get_port, try_get_string,
    try_get_string_any, try_get_uint, try_get_uint_as_u64,
};
use super::routing::{
    kernel_file_route, kernel_registry_route, refine_file_create_action,
    refine_registry_create_action, set_information_action, KernelFileRoute, KernelRegistryRoute,
};
use super::state::{EtwState, PendingRegistryEvent};
use crate::models::{
    DnsQueryFields, EventCategory, FileEventFields, ImageLoadFields, NetworkConnectionFields,
    PowerShellModuleFields, PowerShellScriptFields, ProcessCreationFields, RegistryEventFields,
    TaskCreationFields, WmiEventFields,
};
use crate::sensor::integrity_level::integrity_level_from_sid;
use crate::sensor::network_events::classify_kernel_network_event;
use crate::sensor::{Platform, ProcessStartKey, SensorAction, SensorEvent, SensorPayload};
use crate::telemetry::{
    EtwDecodeFailure, EtwDecodeFailureKey, RegistryPathSource, ETW_DECODE, WINDOWS_FILE_ATTRIBUTION,
};
use crate::utils::{convert_nt_to_dos, query_process_command_line};
use ferrisetw::parser::Parser;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;
use std::sync::atomic::Ordering;
use tracing::{debug, trace};

/// Map the sensor's index tier onto the telemetry module's, which is platform
/// neutral and so cannot name a Windows-only type.
pub(super) fn registry_path_source(source: PathSource) -> RegistryPathSource {
    match source {
        PathSource::Session => RegistryPathSource::Session,
        PathSource::StartupSnapshot => RegistryPathSource::StartupSnapshot,
        PathSource::RecentlyClosed => RegistryPathSource::RecentlyClosed,
    }
}

/// How many unresolved registry writes are logged individually before the
/// line becomes a periodic volume report.
///
/// Enough PIDs to tell "the protected processes the key rundown cannot open",
/// which is expected, from "keys the rundown should have covered", which is a
/// bug, and few enough that a blind endpoint does not flood its own log.
pub(super) const UNRESOLVED_REGISTRY_SAMPLE: u64 = 20;

#[derive(Default)]
pub(super) struct DecodedEtwEvents {
    pub(super) primary: Option<SensorEvent>,
    pub(super) replayed: Vec<SensorEvent>,
}

impl DecodedEtwEvents {
    pub(super) fn single(primary: Option<SensorEvent>) -> Self {
        Self {
            primary,
            replayed: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(super) struct DecodedEtwEvent {
    pub(super) pid: Option<u32>,
    pub(super) process_start_key: Option<ProcessStartKey>,
    pub(super) payload: SensorPayload,
}

/// Attribute a decode failure to a bounded provider/event/version key.
///
/// The provider comes from the subscription table rather than the record's
/// GUID, so the key space is bounded by what this build enables; see
/// [`crate::telemetry::EtwDecodeFailureKey`].
fn record_failure(record: &EventRecord, state: &EtwState, failure: EtwDecodeFailure) {
    ETW_DECODE.record_failure(EtwDecodeFailureKey {
        provider: state.routing.provider_name(record.provider_id()),
        event_id: record.event_id(),
        version: record.version(),
        failure,
    });
}

/// Decode one ETW record, accounting for what became of it.
///
/// Every record is classified into exactly one outcome. The paths that produce
/// no event record their own reason - filtered, indexed, unattributed, or one
/// of the three failures - and this function records the ones that do, so the
/// totals reconcile against `records_received` and a decoder that quietly
/// stops producing events cannot hide behind healthy channel counters (#394).
pub(super) fn decode_record(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    state: &EtwState,
) -> DecodedEtwEvents {
    ETW_DECODE.record_received();

    let decoded = if record.provider_id() == state.routing.kernel_registry_guid {
        decode_kernel_registry_record(record, schema_locator, state)
    } else {
        DecodedEtwEvents::single(decode_single_record(record, schema_locator, state))
    };

    let produced = decoded.replayed.len() + usize::from(decoded.primary.is_some());
    if produced > 0 {
        ETW_DECODE.record_decoded(produced);
    }
    decoded
}

pub(super) fn decode_single_record(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    state: &EtwState,
) -> Option<SensorEvent> {
    if record.provider_id() == state.routing.kernel_file_guid {
        return decode_kernel_file_record(record, schema_locator, state);
    }

    let Some((category, action)) = state.routing.route(record) else {
        // Intentional: the router declined this record. Volume here is the
        // provider allowlist working, not a gap, so it is never a failure.
        ETW_DECODE.record_filtered();
        return None;
    };
    let schema = match schema_locator.event_schema(record) {
        Ok(schema) => schema,
        Err(err) => {
            record_failure(record, state, EtwDecodeFailure::Schema);
            trace!(
                "Failed to get ETW schema for provider {:?} event {}: {:?}",
                record.provider_id(),
                record.event_id(),
                err
            );
            return None;
        }
    };
    let parser = Parser::create(record, &schema);

    let decoded = match category {
        EventCategory::Process => decode_process(&parser, record, action),
        EventCategory::Network => decode_network(&parser, record),
        EventCategory::File => unreachable!("kernel-file records are diverted above"),
        EventCategory::Registry => unreachable!("kernel-registry records are diverted above"),
        EventCategory::Dns => decode_dns(&parser, record),
        EventCategory::ImageLoad => decode_image_load(&parser, record),
        EventCategory::Scripting => decode_powershell(&parser, record),
        EventCategory::PowerShellModule => decode_powershell_module(&parser, record),
        EventCategory::Wmi => decode_wmi(&parser, record),
        EventCategory::Service | EventCategory::Security => {
            unreachable!("event log categories use the event log sources")
        }
        EventCategory::Task => decode_task(&parser, record),
    };

    // A payload the template could not fill is a template this build does not
    // know, not an empty event: the record arrived, and its version says which
    // layout it used.
    let Some(decoded) = decoded else {
        record_failure(record, state, EtwDecodeFailure::UnsupportedLayout);
        return None;
    };

    // A payload without fields cannot satisfy a Sigma selection. Provider
    // allowlists should prevent these records, but keep this loss-free guard at
    // the decode boundary so manifest drift cannot reintroduce fieldless noise.
    if !has_matchable_fields(&decoded.payload) {
        record_failure(record, state, EtwDecodeFailure::Fieldless);
        return None;
    }

    let normalization = mapper::normalization_for_record(category, action, record);

    Some(SensorEvent {
        platform: Platform::Windows,
        provider: "etw",
        action,
        normalization,
        pid: decoded.pid,
        timestamp: filetime_to_system_time(record.raw_timestamp()),
        process_start_key: decoded.process_start_key,
        payload: decoded.payload,
    })
}

pub(super) fn has_matchable_fields(payload: &SensorPayload) -> bool {
    match payload {
        SensorPayload::Dns(fields) => {
            fields.query_name.is_some()
                || fields.query_results.is_some()
                || fields.record_type.is_some()
                || fields.query_status.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
        }
        SensorPayload::Scripting(fields) => {
            fields.script_block_text.is_some()
                || fields.script_block_id.is_some()
                || fields.path.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
                || fields.user.is_some()
        }
        SensorPayload::PowerShellModule(fields) => {
            fields.context_info.is_some()
                || fields.payload.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
                || fields.user.is_some()
        }
        SensorPayload::Wmi(fields) => {
            fields.operation.is_some()
                || fields.user.is_some()
                || fields.query.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
                || fields.event_namespace.is_some()
                || fields.event_type.is_some()
                || fields.destination_hostname.is_some()
        }
        SensorPayload::Service(fields) => {
            fields.service_name.is_some()
                || fields.service_file_name.is_some()
                || fields.service_type.is_some()
                || fields.start_type.is_some()
                || fields.account_name.is_some()
                || fields.user.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
        }
        SensorPayload::Task(fields) => {
            fields.task_name.is_some()
                || fields.task_content.is_some()
                || fields.user_name.is_some()
                || fields.user.is_some()
                || fields.process_id.is_some()
                || fields.image.is_some()
        }
        _ => true,
    }
}

pub(super) fn decode_process(
    parser: &Parser,
    record: &EventRecord,
    action: SensorAction,
) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::process_creation_mappings();

    // The PID and the command line come first, and nothing is allowed between
    // them and the back-fill below. Everything else this function does reads
    // data already carried by the event. PE metadata is added by the consumer
    // after the bounded channel. See `PROCESS_TRACE_SESSION_NAME`.
    let process_id = try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
        .or_else(|| Some(record.process_id().to_string()));
    let pid = process_id
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_else(|| record.process_id());

    // No Kernel-Process event version carries `CommandLine`, so this is a read
    // of the live process's PEB and only succeeds while it still exists.
    let mut command_line = try_get_string(parser, mappings.get_etw_field("CommandLine")?);
    if action == SensorAction::Start && command_line.is_none() {
        command_line = query_process_command_line(pid);
    }

    let creation_time_opt = try_get_uint_as_u64(parser, "CreateTime")
        .or_else(|| try_get_uint_as_u64(parser, "ProcessStartTime"));
    let creation_time_with_fallback =
        creation_time_opt.or_else(|| try_get_uint_as_u64(parser, "TimeStamp"));

    let raw_image = try_get_string_any(
        parser,
        &[
            mappings.get_etw_field("Image")?,
            "ImageFileName",
            "ProcessName",
        ],
    );
    let raw_parent_image = try_get_string_any(
        parser,
        &[mappings.get_etw_field("ParentImage")?, "ParentProcessName"],
    );
    let raw_current_directory = try_get_string(parser, mappings.get_etw_field("CurrentDirectory")?);

    let image = raw_image.map(|path| convert_nt_to_dos(&path));
    let parent_image = raw_parent_image.map(|path| convert_nt_to_dos(&path));
    let current_directory = raw_current_directory.map(|path| convert_nt_to_dos(&path));

    let fields = ProcessCreationFields {
        image: image.clone(),
        original_file_name: None,
        product: None,
        description: None,
        company: None,
        file_version: None,
        // Process creation describes one image and has no target process.
        target_image: None,
        command_line,
        process_id,
        process_start_time: creation_time_with_fallback,
        parent_process_id: try_get_uint(parser, mappings.get_etw_field("ParentProcessId")?),
        parent_image,
        parent_command_line: try_get_string(parser, mappings.get_etw_field("ParentCommandLine")?),
        current_directory,
        // `MandatoryLabel` is a SID; Sigma matches on Sysmon's level name.
        // It is only on the start template, so a stop event has none.
        integrity_level: try_get_string(parser, mappings.get_etw_field("IntegrityLevel")?)
            .and_then(|sid| integrity_level_from_sid(&sid)),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    let process_start_key = match action {
        SensorAction::Start => {
            creation_time_opt.map(|start_time| ProcessStartKey { pid, start_time })
        }
        SensorAction::Stop => {
            creation_time_opt.map(|start_time| ProcessStartKey { pid, start_time })
        }
        _ => None,
    };

    Some(DecodedEtwEvent {
        pid: Some(pid),
        process_start_key,
        payload: SensorPayload::Process(fields),
    })
}

/// Decode a Microsoft-Windows-Kernel-File record, resolving its path.
///
/// Kernel-File is handled apart from the other providers because it is the
/// only one whose events cannot be understood in isolation: the write events
/// name their target by kernel pointer and rely on an index the consumer
/// builds from earlier naming events.
pub(super) fn decode_kernel_file_record(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    state: &EtwState,
) -> Option<SensorEvent> {
    // Checked before the schema lookup: the FILEIO keyword needed for Close
    // and SetInformation also delivers every read and query on the machine,
    // and decoding those would be pure overhead.
    let Some(route) = kernel_file_route(record.event_id()) else {
        ETW_DECODE.record_filtered();
        return None;
    };

    let schema = match schema_locator.event_schema(record) {
        Ok(schema) => schema,
        Err(err) => {
            record_failure(record, state, EtwDecodeFailure::Schema);
            trace!(
                "Failed to get Kernel-File schema for event {}: {:?}",
                record.event_id(),
                err
            );
            return None;
        }
    };
    let parser = Parser::create(record, &schema);

    let file_object = try_get_uint_as_u64(&parser, "FileObject");
    let file_key = try_get_uint_as_u64(&parser, "FileKey");
    // DeletePath, RenamePath, and SetLinkPath carry `FilePath`; Create and the
    // name-cache events carry `FileName`.
    let named_path = try_get_string_any(&parser, &["FilePath", "FileName"]);

    // Any event carrying a name feeds the index, including the ones that also
    // produce telemetry - a Create both reports a creation and teaches us the
    // path for the writes that follow on that handle.
    if let Some(path) = named_path.as_deref() {
        let mut paths = state.paths();
        paths.learn(file_object, file_key, path);
        // Republished on the naming path only: evictions can only happen on an
        // insert, and this keeps the pathless hot path free of the extra load.
        WINDOWS_FILE_ATTRIBUTION.set_index_capacity_evictions(paths.capacity_evictions());
    }

    let action = match route {
        KernelFileRoute::Index => {
            ETW_DECODE.record_indexed();
            return None;
        }
        KernelFileRoute::EvictObject => {
            if let Some(object) = file_object {
                state.paths().forget_object(object);
            }
            ETW_DECODE.record_indexed();
            return None;
        }
        KernelFileRoute::EvictKey => {
            if let Some(key) = file_key {
                state.paths().forget_key(key);
            }
            ETW_DECODE.record_indexed();
            return None;
        }
        // Event ID 12 fires for every handle request, including plain opens;
        // the disposition says whether anything was actually created.
        KernelFileRoute::Emit(SensorAction::Create) => {
            // A disposition that reports an open rather than a creation is the
            // filter doing its job, not a decode failure.
            match refine_file_create_action(&parser, SensorAction::Create) {
                Some(action) => action,
                None => {
                    ETW_DECODE.record_filtered();
                    return None;
                }
            }
        }
        KernelFileRoute::Emit(action) => action,
        // An information class this build does not report on is filtered, not
        // an unsupported layout: the property was read, it just said "read" or
        // "rename target" rather than a state change worth an event.
        KernelFileRoute::SetInformation => match set_information_action(&parser) {
            Some(action) => action,
            None => {
                ETW_DECODE.record_filtered();
                return None;
            }
        },
    };

    // A file event with no path cannot match a rule - essentially every file
    // rule keys on TargetFilename - so an unresolvable event is dropped rather
    // than sent on to occupy space in a bounded channel.
    let raw_path = match named_path {
        Some(path) => {
            WINDOWS_FILE_ATTRIBUTION.record_resolved(false);
            path
        }
        None => match state.paths().resolve(file_object, file_key) {
            Some(path) => {
                WINDOWS_FILE_ATTRIBUTION.record_resolved(true);
                path.to_string()
            }
            None => {
                // Counted rather than silently discarded: this is the sensor's
                // blind spot, and its size is the only way to know whether an
                // endpoint is quiet or unobserved. The persistent count lives
                // in `telemetry.json`; the in-process one only spaces the log.
                ETW_DECODE.record_unattributed();
                WINDOWS_FILE_ATTRIBUTION.record_unresolved();
                let unresolved = state.unresolved_file_events.fetch_add(1, Ordering::Relaxed) + 1;
                if unresolved == 1 || unresolved.is_multiple_of(1000) {
                    debug!(
                        unresolved_file_events = unresolved,
                        "Dropping file event whose path could not be resolved"
                    );
                }
                return None;
            }
        },
    };

    let Some(fields) = file_event_fields(&parser, &raw_path) else {
        record_failure(record, state, EtwDecodeFailure::UnsupportedLayout);
        return None;
    };

    let pid = parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id()));
    let normalization = mapper::normalization_for_record(EventCategory::File, action, record);

    Some(SensorEvent {
        platform: Platform::Windows,
        provider: "etw",
        action,
        normalization,
        pid,
        timestamp: filetime_to_system_time(record.raw_timestamp()),
        process_start_key: None,
        payload: SensorPayload::File(fields),
    })
}

/// Build the file payload for an event whose path is already resolved.
///
/// Extracted so a missing field mapping is one `None` the caller can attribute
/// as an unsupported layout, rather than a `?` that returns from the middle of
/// the decode with no record of why.
fn file_event_fields(parser: &Parser, raw_path: &str) -> Option<FileEventFields> {
    let mappings = field_maps::file_event_mappings();
    Some(FileEventFields {
        source_filename: None,
        target_filename: Some(convert_nt_to_dos(raw_path)),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        // Kernel-File reports which information class was set, never the
        // values, so unlike Sysmon Event ID 2 these stay empty on Windows.
        creation_utc_time: try_get_string(parser, mappings.get_etw_field("CreationUtcTime")?),
        previous_creation_utc_time: try_get_string(
            parser,
            mappings.get_etw_field("PreviousCreationUtcTime")?,
        ),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        // ETW delivers whole paths or none at all; there is no capture buffer
        // to overflow on Windows.
        path_truncated: None,
    })
}

/// Decode a Microsoft-Windows-Kernel-Registry record, maintaining the key-path
/// index the pathless write events depend on.
///
/// Mirrors [`decode_kernel_file_record`]. `SetValueKey`, `DeleteValueKey` and
/// `DeleteKey` deliver an empty `KeyName` and identify their target only by
/// `KeyObject`, so the naming events (`CreateKey`, `OpenKey`) have to be joined
/// to them. Before #279 none of this existed: the action came from an opcode
/// that is always 0, and every registry event reached the detectors as an
/// unclassified `registry_event` with `event.code = 0`.
pub(super) fn decode_kernel_registry_record(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    state: &EtwState,
) -> DecodedEtwEvents {
    // Checked before the schema lookup so unrouted events cost only an
    // integer match.
    let Some(route) = kernel_registry_route(record.event_id()) else {
        ETW_DECODE.record_filtered();
        return DecodedEtwEvents::default();
    };

    let schema = match schema_locator.event_schema(record) {
        Ok(schema) => schema,
        Err(err) => {
            record_failure(record, state, EtwDecodeFailure::Schema);
            trace!(
                "Failed to get Kernel-Registry schema for event {}: {:?}",
                record.event_id(),
                err
            );
            return DecodedEtwEvents::default();
        }
    };
    let parser = Parser::create(record, &schema);

    let key_object = try_get_uint_as_u64(&parser, "KeyObject");
    let event_at = record.raw_timestamp();

    match route {
        KernelRegistryRoute::Name { creates } => {
            let base_object = try_get_uint_as_u64(&parser, "BaseObject");
            let base_name = try_get_string(&parser, "BaseName").unwrap_or_default();
            let relative_name = try_get_string(&parser, "RelativeName").unwrap_or_default();

            // Indexing happens for both CreateKey and OpenKey, including the
            // creates that also emit: a key that is created is then written
            // through, and those writes carry only its `KeyObject`.
            let path = state.registry_paths().learn_at(
                base_object,
                key_object,
                &base_name,
                &relative_name,
                event_at,
            );

            // A failed open names nothing. 39% of `OpenKey` events on a
            // measured idle desktop are failures carrying `KeyObject = 0`.
            match key_object {
                Some(object) if object != 0 && path.is_some() => {
                    crate::telemetry::REGISTRY.record_naming(creates)
                }
                _ => crate::telemetry::REGISTRY.record_naming_failed(),
            }

            let (replayed, dropped) = match (key_object, path.as_deref()) {
                (Some(object), Some(path)) if object != 0 => state
                    .pending_registry_events()
                    .resolve(object, path, event_at),
                _ => (Vec::new(), 0),
            };
            record_unresolved_registry_events(dropped, record.process_id());
            for _ in &replayed {
                crate::telemetry::REGISTRY.record_resolved(RegistryPathSource::Session);
            }

            // `NtCreateKey` opens existing keys just as readily as it makes new
            // ones - the same trap as `IRP_MJ_CREATE` on the file side. Without
            // the disposition check every key open would surface as a
            // `registry_add`.
            let primary = if creates && refine_registry_create_action(&parser).is_some() {
                path.and_then(|path| {
                    pending_registry_event(&parser, record, SensorAction::Create, None)
                        .map(|event| event.into_sensor_event(&path))
                })
            } else {
                None
            };

            // A naming event that emitted nothing did its real job: it taught
            // the index a path, and possibly replayed writes waiting on it.
            if primary.is_none() && replayed.is_empty() {
                ETW_DECODE.record_indexed();
            }

            DecodedEtwEvents { primary, replayed }
        }
        KernelRegistryRoute::Evict => {
            if let Some(object) = key_object {
                state.registry_paths().forget_at(object, event_at);
            }
            ETW_DECODE.record_indexed();
            DecodedEtwEvents::default()
        }
        KernelRegistryRoute::Emit(action) => {
            let value_name = try_get_string(&parser, "ValueName");
            // `KeyName` is declared on these events but measured empty on
            // Windows 11, so the index is the real source of the path.
            let mut source = RegistryPathSource::Session;
            let path = try_get_string(&parser, "KeyName")
                .filter(|name| !name.is_empty())
                .or_else(|| {
                    state
                        .registry_paths()
                        .resolve_at(key_object, event_at)
                        .map(|resolved| {
                            source = registry_path_source(resolved.source);
                            resolved.path.to_string()
                        })
                });

            let Some(event) = pending_registry_event(&parser, record, action, value_name) else {
                record_failure(record, state, EtwDecodeFailure::UnsupportedLayout);
                return DecodedEtwEvents::default();
            };

            match path.as_deref() {
                Some(path) => {
                    crate::telemetry::REGISTRY.record_resolved(source);
                    DecodedEtwEvents::single(Some(event.into_sensor_event(path)))
                }
                None => {
                    if let Some(object) = key_object.filter(|object| *object != 0) {
                        // Held for the naming event that has not arrived yet:
                        // deferred, not lost. Whatever the queue had to shed to
                        // make room is what the registry counters record.
                        let dropped = state.pending_registry_events().insert(object, event);
                        record_unresolved_registry_events(dropped, record.process_id());
                        ETW_DECODE.record_indexed();
                    } else {
                        // No key object at all, so nothing can ever name it.
                        record_unresolved_registry_events(1, record.process_id());
                        ETW_DECODE.record_unattributed();
                    }
                    DecodedEtwEvents::default()
                }
            }
        }
    }
}

pub(super) fn pending_registry_event(
    parser: &Parser,
    record: &EventRecord,
    action: SensorAction,
    value_name: Option<String>,
) -> Option<PendingRegistryEvent> {
    let mappings = field_maps::registry_event_mappings();
    let fields = RegistryEventFields {
        target_object: None,
        details: registry_details(parser),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        event_type: try_get_string(parser, "EventType"),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        new_name: try_get_string(parser, "NewName"),
    };

    let pid = parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id()));
    let normalization = mapper::normalization_for_record(EventCategory::Registry, action, record);

    Some(PendingRegistryEvent {
        action,
        value_name,
        fields,
        pid,
        normalization,
        timestamp: filetime_to_system_time(record.raw_timestamp()),
        event_at: record.raw_timestamp(),
    })
}

pub(super) fn record_unresolved_registry_events(count: usize, pid: u32) {
    for _ in 0..count {
        let unresolved = crate::telemetry::REGISTRY.record_unresolved();
        if unresolved <= UNRESOLVED_REGISTRY_SAMPLE || unresolved.is_multiple_of(10_000) {
            debug!(
                unresolved_registry_events = unresolved,
                pid, "Dropping registry event whose key path could not be resolved"
            );
        }
    }
}

/// `Details` for a registry event: the value *data*, as Sysmon Event ID 13
/// defines it. If captured data is unavailable or cannot be rendered, the
/// field stays absent rather than carrying the semantically different value
/// name.
pub(super) fn registry_details(parser: &Parser) -> Option<String> {
    let captured = parser
        .try_parse::<Vec<u8>>(field_maps::registry_event_mappings().get_etw_field("Details")?)
        .unwrap_or_default();
    let value_type =
        try_get_uint_as_u64(parser, registry_value_data::VALUE_TYPE_PROPERTY).unwrap_or(0);

    registry_value_data::format_value_data(value_type as u32, &captured)
}

pub(super) fn decode_network(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::network_connection_mappings();
    let route = classify_kernel_network_event(record.event_id())?;

    let fields = NetworkConnectionFields {
        destination_ip: try_get_ip(parser, "daddr", route.address_family)
            .or_else(|| try_get_ip(parser, "DestinationAddress", route.address_family))
            .or_else(|| try_get_ip(parser, "RemoteAddress", route.address_family))
            .or_else(|| try_get_ip(parser, "dstaddr", route.address_family)),
        source_ip: try_get_ip(parser, "saddr", route.address_family)
            .or_else(|| try_get_ip(parser, "SourceAddress", route.address_family))
            .or_else(|| try_get_ip(parser, "LocalAddress", route.address_family))
            .or_else(|| try_get_ip(parser, "srcaddr", route.address_family)),
        destination_port: try_get_port(parser, "dport")
            .or_else(|| try_get_port(parser, "DestinationPort"))
            .or_else(|| try_get_port(parser, "RemotePort"))
            .or_else(|| try_get_port(parser, "dstport")),
        source_port: try_get_port(parser, "sport")
            .or_else(|| try_get_port(parser, "SourcePort"))
            .or_else(|| try_get_port(parser, "LocalPort"))
            .or_else(|| try_get_port(parser, "srcport")),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
            .or_else(|| Some(record.process_id().to_string())),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        destination_hostname: try_get_string(
            parser,
            mappings.get_etw_field("DestinationHostname")?,
        ),
        protocol: Some(route.protocol.as_str().to_string()),
        // Direction comes from the operation the event ID encodes, not from a
        // payload property: Kernel-Network has no equivalent of Sysmon's
        // `Initiated`. Only Connect and Accept reach here, so this is `Some`
        // in practice, but the classifier stays the single source of truth.
        initiated: route.initiated(),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Network(fields),
    })
}

pub(super) fn decode_dns(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::dns_query_mappings();
    let fields = DnsQueryFields {
        query_name: try_get_string(parser, mappings.get_etw_field("QueryName")?),
        query_results: try_get_string(parser, mappings.get_etw_field("QueryResults")?),
        record_type: None,
        query_status: try_get_uint(parser, mappings.get_etw_field("QueryStatus")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Dns(fields),
    })
}

pub(super) fn decode_image_load(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::image_load_mappings();
    let image_loaded = try_get_string(parser, mappings.get_etw_field("ImageLoaded")?)
        .map(|path| convert_nt_to_dos(&path));

    let fields = ImageLoadFields {
        image_loaded,
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        original_file_name: None,
        product: None,
        description: None,
        company: None,
        file_version: None,
        signed: try_get_string(parser, mappings.get_etw_field("Signed")?),
        signature: try_get_string(parser, mappings.get_etw_field("Signature")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::ImageLoad(fields),
    })
}

pub(super) fn decode_powershell(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::powershell_script_mappings();
    let fields = PowerShellScriptFields {
        script_block_text: try_get_string(parser, mappings.get_etw_field("ScriptBlockText")?),
        script_block_id: try_get_string(parser, mappings.get_etw_field("ScriptBlockId")?),
        path: try_get_string(parser, mappings.get_etw_field("Path")?)
            .map(|path| convert_nt_to_dos(&path)),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Scripting(fields),
    })
}

pub(super) fn decode_powershell_module(
    parser: &Parser,
    record: &EventRecord,
) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::powershell_module_mappings();
    let fields = PowerShellModuleFields {
        context_info: try_get_string(parser, mappings.get_etw_field("ContextInfo")?),
        payload: try_get_string(parser, mappings.get_etw_field("Payload")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::PowerShellModule(fields),
    })
}

pub(super) fn decode_wmi(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::wmi_event_mappings();
    let fields = WmiEventFields {
        operation: try_get_string(parser, mappings.get_etw_field("Operation")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        query: try_get_string(parser, mappings.get_etw_field("Query")?)
            .or_else(|| try_get_string(parser, "Commandline")),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?)
            .or_else(|| try_get_uint(parser, "ClientProcessId")),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
        event_namespace: try_get_string(parser, mappings.get_etw_field("EventNamespace")?)
            .or_else(|| try_get_string(parser, "NamespaceName")),
        event_type: try_get_string(parser, mappings.get_etw_field("EventType")?),
        destination_hostname: try_get_string(
            parser,
            mappings.get_etw_field("DestinationHostname")?,
        )
        .or_else(|| try_get_string(parser, "ClientMachine")),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Wmi(fields),
    })
}

pub(super) fn decode_task(parser: &Parser, record: &EventRecord) -> Option<DecodedEtwEvent> {
    let mappings = field_maps::task_creation_mappings();
    let fields = TaskCreationFields {
        task_name: try_get_string(parser, mappings.get_etw_field("TaskName")?),
        task_content: try_get_string(parser, mappings.get_etw_field("TaskContent")?),
        user_name: try_get_string(parser, mappings.get_etw_field("UserName")?),
        user: try_get_string(parser, mappings.get_etw_field("User")?),
        process_id: try_get_uint(parser, mappings.get_etw_field("ProcessId")?),
        image: try_get_string(parser, mappings.get_etw_field("Image")?)
            .map(|path| convert_nt_to_dos(&path)),
    };

    Some(DecodedEtwEvent {
        pid: parse_optional_u32(fields.process_id.as_deref()).or(Some(record.process_id())),
        process_start_key: None,
        payload: SensorPayload::Task(fields),
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::field_maps;
    use super::*;
    use crate::models::PowerShellModuleFields;
    use crate::models::PowerShellScriptFields;
    use crate::sensor::SensorPayload;

    #[test]
    fn registry_details_maps_only_to_the_value_data_property() {
        // `Details` meant `ValueName` until #292, which made 180 SigmaHQ rules
        // match the name of the value instead of what was written into it.
        assert_eq!(
            field_maps::registry_event_mappings().get_etw_field("Details"),
            Some("CapturedData"),
            "Details must map only to the value data"
        );
    }

    #[test]
    fn fieldless_provider_payload_is_not_matchable() {
        let empty = SensorPayload::Scripting(PowerShellScriptFields {
            script_block_text: None,
            script_block_id: None,
            path: None,
            process_id: None,
            image: None,
            user: None,
        });
        assert!(!has_matchable_fields(&empty));

        let populated = SensorPayload::Scripting(PowerShellScriptFields {
            script_block_text: Some("Get-Process".to_string()),
            script_block_id: None,
            path: None,
            process_id: None,
            image: None,
            user: None,
        });
        assert!(has_matchable_fields(&populated));

        let empty_module = SensorPayload::PowerShellModule(PowerShellModuleFields {
            context_info: None,
            payload: None,
            process_id: None,
            image: None,
            user: None,
        });
        assert!(!has_matchable_fields(&empty_module));

        let populated_module = SensorPayload::PowerShellModule(PowerShellModuleFields {
            context_info: Some("Host Application = powershell.exe".to_string()),
            payload: None,
            process_id: None,
            image: None,
            user: None,
        });
        assert!(has_matchable_fields(&populated_module));
    }
}
