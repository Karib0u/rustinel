//! Decoder tests driven by ETW records recorded on a real Windows host.
//!
//! Each file under `tests/fixtures/etw` holds the records one scenario produced,
//! in arrival order, with the build and date they were recorded on. Feeding them
//! through the decoders exercises the same code the live sensor runs, without a
//! session. See `docs/development.md` for how to record and add a fixture.

use super::decode::{decode_kernel_file, decode_kernel_registry, decode_routed, DecodedEtwEvents};
use super::props::{EtwHeader, RecordedRecord};
use super::routing::{kernel_file_route, kernel_registry_route};
use super::state::EtwState;
use crate::sensor::{RawEvent, RawPayload, SensorAction};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct Provenance {
    windows_build: String,
    recorded: String,
    host: String,
    scenario: String,
}

#[derive(Debug, Deserialize)]
struct FixtureFile {
    provenance: Provenance,
    records: Vec<RecordedRecord>,
}

macro_rules! fixture {
    ($name:literal) => {
        load(
            $name,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/etw/",
                $name,
                ".json"
            )),
        )
    };
}

fn load(name: &str, text: &str) -> FixtureFile {
    let file: FixtureFile = serde_json::from_str(text)
        .unwrap_or_else(|err| panic!("fixture {name} is not valid: {err}"));
    let p = &file.provenance;
    assert!(
        !p.windows_build.is_empty() && !p.recorded.is_empty() && !p.host.is_empty(),
        "fixture {name} must record its Windows build, date and host"
    );
    assert!(
        !p.scenario.is_empty(),
        "fixture {name} must say what it shows"
    );
    assert!(!file.records.is_empty(), "fixture {name} has no records");
    file
}

fn state() -> EtwState {
    EtwState::with_process_identities([], Arc::new(crate::state::HostState::default()))
}

/// Route and decode one recorded record the way `decode_record` does, minus the
/// schema lookup the recording replaces.
fn feed(state: &EtwState, record: &RecordedRecord) -> DecodedEtwEvents {
    let header = &record.header;
    let props = &record.properties;
    if header.provider_id() == state.routing.kernel_registry_guid {
        return match kernel_registry_route(header.event_id()) {
            Some(route) => decode_kernel_registry(props, header, route, state),
            None => DecodedEtwEvents::default(),
        };
    }
    if header.provider_id() == state.routing.kernel_file_guid {
        return DecodedEtwEvents::single(
            kernel_file_route(header.event_id())
                .and_then(|route| decode_kernel_file(props, header, route, state)),
        );
    }
    DecodedEtwEvents::single(
        state
            .routing
            .route(header)
            .and_then(|(category, action)| decode_routed(props, header, category, action, state)),
    )
}

/// Every event the fixture produces, replays first, in order.
fn run(file: &FixtureFile) -> Vec<RawEvent> {
    let state = state();
    let mut out = Vec::new();
    for record in &file.records {
        let decoded = feed(&state, record);
        out.extend(decoded.replayed);
        out.extend(decoded.primary);
    }
    out
}

fn files(events: &[RawEvent]) -> Vec<(SensorAction, &crate::models::FileEventFields, u16)> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            RawPayload::File(f) => Some((e.action, f, e.normalization.event_id)),
            _ => None,
        })
        .collect()
}

fn registry(events: &[RawEvent]) -> Vec<(SensorAction, &crate::models::RegistryEventFields, u16)> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            RawPayload::Registry(f) => Some((e.action, f, e.normalization.event_id)),
            _ => None,
        })
        .collect()
}

#[test]
fn fixtures_carry_provenance() {
    // `fixture!` asserts this on load; touch every file so a bad one fails here.
    for file in [
        fixture!("process_lifecycle"),
        fixture!("image_load"),
        fixture!("file_lifecycle"),
        fixture!("registry_lifecycle"),
        fixture!("dns_query"),
        fixture!("network_connect"),
        fixture!("powershell_module_logging"),
        fixture!("powershell_script_block"),
        fixture!("wmi_activity"),
        fixture!("task_registered"),
    ] {
        assert!(file.provenance.recorded.starts_with("20"));
    }
}

#[test]
fn process_start_and_stop_keep_native_facts() {
    let events = run(&fixture!("process_lifecycle"));
    assert_eq!(events.len(), 2);

    let (start, stop) = (&events[0], &events[1]);
    assert_eq!(
        (start.action, start.normalization.event_id),
        (SensorAction::Start, 1)
    );
    assert_eq!(
        (stop.action, stop.normalization.event_id),
        (SensorAction::Stop, 5)
    );
    assert_eq!(start.pid, Some(7004));
    let key = start.process_start_key.expect("start carries a start key");
    assert_eq!(
        stop.process_start_key,
        Some(key),
        "stop names the same lifetime"
    );

    let RawPayload::Process(p) = &start.payload else {
        panic!("not a process payload");
    };
    assert_eq!(p.parent_process_id, Some(6340));
    assert_eq!(p.integrity_level.as_deref(), Some("High"), "S-1-16-12288");
    assert!(p.image.as_deref().is_some_and(|i| i.ends_with("cmd.exe")));
    assert!(
        p.command_line.is_none(),
        "the provider carries no command line"
    );
    let RawPayload::Process(p) = &stop.payload else {
        panic!("not a process payload");
    };
    assert_eq!(p.image.as_deref(), Some("cmd.exe"));
}

/// Windows 11 reports an image load as Kernel-Process event 5 with opcode 0.
/// Routing on the opcode alone dropped them all (fixed in #547).
#[test]
fn image_load_event_5_with_opcode_zero_is_routed() {
    let file = fixture!("image_load");
    assert_eq!(file.records[0].header.event_id, 5);
    assert_eq!(file.records[0].header.opcode, 0);

    let events = run(&file);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, SensorAction::Load);
    assert_eq!(events[0].normalization.event_id, 7, "Sysmon image load");
    let RawPayload::ImageLoad(f) = &events[0].payload else {
        panic!("not an image load");
    };
    assert_eq!(
        f.image_loaded.as_deref(),
        Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        "device path converted to a DOS path"
    );
    assert_eq!(f.process_id.as_deref(), Some("6340"));
}

#[test]
fn file_lifecycle_resolves_pathless_events_and_classifies_actions() {
    let events = run(&fixture!("file_lifecycle"));
    let files = files(&events);
    assert_eq!(files.len(), events.len());

    let dir = r"C:\Users\theo-rdp\AppData\Local\Temp\rustinel-fixture-e78e5e\";
    for (_, f, _) in &files {
        let target = f
            .target_filename
            .as_deref()
            .expect("every event has a path");
        assert!(
            target.starts_with(dir),
            "{target} is a DOS path in the temp dir"
        );
    }

    let actions: Vec<_> = files.iter().map(|(a, ..)| *a).collect();
    for wanted in [
        SensorAction::Create,
        SensorAction::Modify,
        SensorAction::Set,
        SensorAction::Rename,
        SensorAction::Delete,
    ] {
        assert!(
            actions.contains(&wanted),
            "{wanted:?} missing from {actions:?}"
        );
    }

    // SetInformation with FileBasicInformation is the timestomp signal.
    let set: Vec<_> = files
        .iter()
        .filter(|(a, ..)| *a == SensorAction::Set)
        .collect();
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].2, 2, "Sysmon 2, file creation time changed");

    let rename = files
        .iter()
        .find(|(a, ..)| *a == SensorAction::Rename)
        .unwrap();
    assert!(rename
        .1
        .target_filename
        .as_deref()
        .unwrap()
        .ends_with("fixture-renamed.txt"));
    assert_eq!(rename.2, 71);
    let delete = files
        .iter()
        .find(|(a, ..)| *a == SensorAction::Delete)
        .unwrap();
    assert!(delete
        .1
        .target_filename
        .as_deref()
        .unwrap()
        .ends_with("fixture-renamed.txt"));
    assert_eq!(delete.2, 23);

    // Plain opens of an existing file (disposition OPEN) are not creations.
    let creates = files
        .iter()
        .filter(|(a, ..)| *a == SensorAction::Create)
        .count();
    let open_only = fixture!("file_lifecycle")
        .records
        .iter()
        .filter(|r| r.header.event_id == 12)
        .count();
    assert!(
        creates < open_only,
        "{creates} creates out of {open_only} handle requests"
    );
}

#[test]
fn pathless_file_events_are_marked_as_derived() {
    let events = run(&fixture!("file_lifecycle"));
    let modify = events
        .iter()
        .find(|e| e.action == SensorAction::Modify)
        .expect("a write resolved from the index");
    assert!(
        format!("{:?}", modify.provenance.entries()).contains("TargetFilename"),
        "a path joined from an earlier naming event is derived"
    );
}

/// Registry events were classified from an opcode that is always 0 (#279), and
/// `Details` carried the value name instead of the data written (#292).
#[test]
fn registry_lifecycle_classifies_by_event_id_and_reports_value_data() {
    let file = fixture!("registry_lifecycle");
    assert!(
        file.records.iter().all(|r| r.header.opcode != 0),
        "the recorded opcodes are the manifest's, not 0: routing must not read them"
    );

    let events = run(&file);
    let reg = registry(&events);
    let shape: Vec<_> = reg.iter().map(|(a, _, id)| (*a, *id)).collect();
    assert_eq!(
        shape,
        [
            (SensorAction::Create, 12),
            (SensorAction::Set, 13),
            (SensorAction::Set, 13),
            (SensorAction::Delete, 12),
            (SensorAction::Delete, 12),
        ],
        "the failed OpenKey and the closes emit nothing"
    );

    let target = |i: usize| reg[i].1.target_object.as_deref().unwrap();
    assert!(target(1).ends_with(r"Software\RustinelFixture\Run"));
    assert!(target(2).ends_with(r"Software\RustinelFixture\Flag"));

    // #292: Details is the data written, rendered as Sysmon renders it.
    assert_eq!(
        reg[1].1.details.as_deref(),
        Some(r"C:\Windows\System32\cmd.exe /c fixture")
    );
    assert_eq!(reg[2].1.details.as_deref(), Some("DWORD (0x00000001)"));
    assert!(!reg[1].1.details.as_deref().unwrap().contains("Run"));
    assert_eq!(reg[3].1.details, None, "a delete carries no data");
}

#[test]
fn registry_write_before_its_naming_event_is_replayed_once_named() {
    let mut file = fixture!("registry_lifecycle");
    // [failed open, create, naming, set, ...]: swap the first value write ahead
    // of the OpenKey that names its key.
    file.records.swap(2, 3);
    assert_eq!(file.records[2].header.event_id, 5);

    let state = state();
    let mut emitted = Vec::new();
    for (i, record) in file.records.iter().enumerate() {
        let decoded = feed(&state, record);
        if i == 2 {
            assert!(decoded.primary.is_none(), "pathless write is held back");
        }
        emitted.extend(decoded.replayed);
        emitted.extend(decoded.primary);
    }
    let reg = registry(&emitted);
    assert_eq!(reg.len(), 5, "held write comes back when the key is named");
    assert!(reg.iter().any(|(_, f, _)| f
        .details
        .as_deref()
        .is_some_and(|d| d.contains("cmd.exe /c fixture"))));
}

#[test]
fn dns_client_events_keep_query_and_status() {
    let events = run(&fixture!("dns_query"));
    assert_eq!(events.len(), 4);
    let dns: Vec<_> = events
        .iter()
        .map(|e| match &e.payload {
            RawPayload::Dns(f) => (e.normalization.event_id, f),
            _ => panic!("not dns"),
        })
        .collect();
    assert!(dns
        .iter()
        .all(|(_, f)| f.query_name.as_deref() == Some("login.live.com")));
    assert!(
        dns.iter()
            .all(|(_, f)| f.process_id.as_deref() == Some("1640")),
        "header pid fallback"
    );
    assert_eq!(dns[0].0, 3006);
    assert_eq!(dns[2].1.query_status.as_deref(), Some("87"));
    assert_eq!(dns[3].1.query_status.as_deref(), Some("0"));
    assert!(dns[3]
        .1
        .query_results
        .as_deref()
        .unwrap()
        .contains("::ffff:20.190.159.23"));
    assert!(events.iter().all(|e| e.action == SensorAction::Query));
}

#[test]
fn network_connect_decodes_addresses_and_ports() {
    let events = run(&fixture!("network_connect"));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, SensorAction::Connect);
    assert_eq!(events[0].normalization.event_id, 3);
    let RawPayload::Network(f) = &events[0].payload else {
        panic!("not a network payload");
    };
    assert_eq!(f.destination_ip.as_deref(), Some("20.190.159.23"));
    assert_eq!(f.destination_port.as_deref(), Some("443"));
    assert_eq!(f.source_ip.as_deref(), Some("192.168.1.28"));
    assert_eq!(f.protocol.as_deref(), Some("tcp"));
    assert_eq!(f.initiated, Some(true));
}

#[test]
fn powershell_module_logging_is_a_separate_logsource() {
    let events = run(&fixture!("powershell_module_logging"));
    assert_eq!(events.len(), 1);
    let RawPayload::PowerShellModule(f) = &events[0].payload else {
        panic!("4103 must not decode as a script block");
    };
    assert_eq!(events[0].normalization.event_id, 4103);
    assert!(f.context_info.as_deref().unwrap().contains("Application"));
    assert!(f.payload.as_deref().unwrap().contains("CommandInvocation"));
    assert_eq!(f.process_id.as_deref(), Some("6340"));
}

#[test]
fn powershell_script_block_is_a_separate_logsource() {
    let events = run(&fixture!("powershell_script_block"));
    assert_eq!(events.len(), 1);
    let RawPayload::Scripting(f) = &events[0].payload else {
        panic!("4104 must decode as a script block");
    };
    assert_eq!(events[0].normalization.event_id, 4104);
    assert_eq!(
        f.script_block_text.as_deref(),
        Some("Get-Process | Select-Object -First 1")
    );
    assert_eq!(f.message_number.as_deref(), Some("1"));
    assert_eq!(f.message_total.as_deref(), Some("1"));
}

#[test]
fn wmi_activity_maps_each_template() {
    let events = run(&fixture!("wmi_activity"));
    assert_eq!(events.len(), 5);
    let wmi: Vec<_> = events
        .iter()
        .map(|e| match &e.payload {
            RawPayload::Wmi(f) => (e.normalization.event_id, f),
            _ => panic!("not wmi"),
        })
        .collect();
    // 11: client call. The ClientProcessId property supplies the pid.
    assert_eq!(wmi[0].0, 11);
    assert_eq!(wmi[0].1.process_id.as_deref(), Some("3868"));
    assert_eq!(
        wmi[0].1.destination_hostname.as_deref(),
        Some("LAB-WINDOWS")
    );
    assert_eq!(
        wmi[0].1.event_namespace.as_deref(),
        Some(r"\\localhost\root\cimv2")
    );
    // 5857: provider loaded; the result code is rendered in hex.
    assert_eq!(wmi[2].0, 5857);
    assert_eq!(wmi[2].1.provider_name.as_deref(), Some("CIMWin32"));
    assert_eq!(wmi[2].1.host_process.as_deref(), Some("wmiprvse.exe"));
    assert_eq!(wmi[2].1.result_code.as_deref(), Some("0x0"));
    // 17 names its namespace through `Namespace` rather than `NamespaceName`.
    assert_eq!(wmi[4].0, 17);
    assert_eq!(wmi[4].1.event_namespace.as_deref(), Some(r"root\cimv2"));
}

#[test]
fn task_registration_keeps_name_and_user() {
    let events = run(&fixture!("task_registered"));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, SensorAction::Register);
    let RawPayload::Task(f) = &events[0].payload else {
        panic!("not a task payload");
    };
    assert_eq!(f.task_name.as_deref(), Some(r"\RustinelFixtureTask"));
    assert_eq!(f.user_name.as_deref(), Some(r"lab-windows\theo-rdp"));
    assert_eq!(
        events[0].pid,
        Some(1860),
        "header pid, the payload names none"
    );
}
