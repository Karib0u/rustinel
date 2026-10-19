//! Decode recorded Endpoint Security messages through the production
//! `build_sensor_event`, on any Mac, without a client or root.
//!
//! The fixtures under `tests/fixtures/esf` come from
//! `scripts/macos/record-esf-fixtures.sh`; see `docs/development.md`.

use std::path::PathBuf;

use serde::Deserialize;

use super::view::{EsEvent, EsRecord};
use super::{build_sensor_event, ExecIdentities};
use crate::sensor::{RawEvent, RawPayload, RawProcessPlatform, SensorAction};

#[derive(Deserialize)]
struct Provenance {
    macos: String,
    date: String,
    scenario: String,
}

#[derive(Deserialize)]
struct Fixture {
    provenance: Provenance,
    records: Vec<EsRecord>,
}

fn load(name: &str) -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/esf")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    let fixture: Fixture = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    assert!(
        !fixture.provenance.macos.is_empty()
            && !fixture.provenance.date.is_empty()
            && !fixture.provenance.scenario.is_empty(),
        "{name} needs provenance"
    );
    assert!(!fixture.records.is_empty(), "{name} has no records");
    fixture
}

/// Decode in arrival order with one identity table, as the live handler does.
fn decode(fixture: &Fixture) -> Vec<(&EsRecord, Option<RawEvent>)> {
    let mut identities = ExecIdentities::default();
    fixture
        .records
        .iter()
        .map(|record| (record, build_sensor_event(record, &mut identities)))
        .collect()
}

fn process(event: &RawEvent) -> &crate::sensor::RawProcessEvent {
    match &event.payload {
        RawPayload::Process(process) => process,
        _ => panic!("expected a process payload"),
    }
}

fn file(event: &RawEvent) -> &crate::models::FileEventFields {
    match &event.payload {
        RawPayload::File(file) => file,
        _ => panic!("expected a file payload"),
    }
}

#[test]
fn process_lifecycle_decodes_every_exec_and_exit() {
    let fixture = load("process_lifecycle");
    let mut execs = 0;
    let mut exits = 0;
    for (record, event) in decode(&fixture) {
        match &record.event {
            EsEvent::Exec(exec) => {
                execs += 1;
                let event = event.expect("exec decodes");
                let p = process(&event);
                assert!(matches!(event.action, SensorAction::Start));
                assert_eq!(
                    p.image.as_deref(),
                    Some(exec.target.executable.path.as_str())
                );
                assert_eq!(p.process_id, exec.target.pid as u32);
                assert_eq!(event.source_seq, record.global_seq_num);
                let RawProcessPlatform::MacOS(platform) = p.platform.as_ref() else {
                    panic!("expected macOS platform data");
                };
                let meta = platform.exec.as_ref().expect("exec metadata");
                assert_eq!(meta.codesigning_flags, Some(exec.target.codesigning_flags));
                assert_eq!(
                    meta.is_platform_binary,
                    Some(exec.target.is_platform_binary)
                );
                assert_eq!(meta.script, exec.script);
                assert!(meta.file_identity.is_some());
                if exec.args.is_empty() {
                    assert!(p.command_line.is_none());
                } else {
                    assert_eq!(p.command_line, Some(exec.args.join(" ")));
                }
            }
            EsEvent::Exit => {
                exits += 1;
                let event = event.expect("exit decodes");
                assert!(matches!(event.action, SensorAction::Stop));
                assert_eq!(event.pid, Some(record.actor.pid as u32));
            }
            _ => {}
        }
    }
    assert!(execs > 0 && exits > 0, "fixture lacks execs or exits");
}

#[test]
fn script_and_signature_metadata_follow_the_recording() {
    let fixture = load("process_lifecycle");
    let decoded = decode(&fixture);
    let mut saw_script = false;
    let mut saw_signed = false;
    for (record, event) in &decoded {
        let EsEvent::Exec(exec) = &record.event else {
            continue;
        };
        let event = event.as_ref().unwrap();
        let RawProcessPlatform::MacOS(platform) = process(event).platform.as_ref() else {
            unreachable!()
        };
        let meta = platform.exec.as_ref().unwrap();
        saw_script |= exec.script.is_some() && meta.script.is_some();
        let signed = exec.target.codesigning_flags & 0x2000_0000 != 0;
        assert_eq!(meta.signed, Some(signed));
        assert_eq!(meta.cdhash.is_some(), signed);
        assert_eq!(
            meta.signature_status.as_deref(),
            Some(match (signed, exec.target.codesigning_flags & 1 != 0) {
                (false, _) => "unsigned",
                (true, true) => "valid",
                (true, false) => "invalid",
            })
        );
        saw_signed |= signed;
    }
    assert!(saw_script, "fixture lacks a script exec");
    assert!(saw_signed, "fixture lacks a signed exec");
}

#[test]
fn an_exec_links_to_a_parent_seen_earlier_in_the_recording() {
    let fixture = load("file_lifecycle");
    let decoded = decode(&fixture);
    let linked = decoded
        .iter()
        .filter_map(|(_, event)| event.as_ref())
        .filter(|event| matches!(event.action, SensorAction::Start))
        .filter(|event| event.parent_process_start_key.is_some())
        .count();
    // `mv` and `rm` are children of the recorded `sh -c`, so their parent resolves.
    assert!(linked > 0, "no exec resolved its parent start key");
}

#[test]
fn file_lifecycle_decodes_create_rename_modify_and_delete() {
    let fixture = load("file_lifecycle");
    let (mut create, mut delete, mut rename, mut modify) = (0, 0, 0, 0);
    for (record, event) in decode(&fixture) {
        match &record.event {
            EsEvent::Create { .. } => {
                if let Some(event) = event {
                    create += 1;
                    assert!(matches!(event.action, SensorAction::Create));
                    assert!(file(&event)
                        .target_filename
                        .as_deref()
                        .unwrap()
                        .starts_with('/'));
                }
            }
            EsEvent::Unlink { target } => {
                delete += 1;
                let event = event.expect("unlink decodes");
                assert!(matches!(event.action, SensorAction::Delete));
                assert_eq!(
                    file(&event).target_filename.as_deref(),
                    Some(target.path.as_str())
                );
                assert!(file(&event).file_identity.is_none());
            }
            EsEvent::Rename { source, .. } => {
                rename += 1;
                let event = event.expect("rename decodes");
                assert!(matches!(event.action, SensorAction::Rename));
                assert_eq!(
                    file(&event).source_filename.as_deref(),
                    Some(source.path.as_str())
                );
                assert_eq!(file(&event).file_identity.is_some(), source.stat.ino != 0);
            }
            EsEvent::Close { modified, target } => {
                if *modified {
                    modify += 1;
                    let event = event.expect("modified close decodes");
                    assert!(matches!(event.action, SensorAction::Modify));
                    assert_eq!(
                        file(&event).target_filename.as_deref(),
                        Some(target.path.as_str())
                    );
                } else {
                    assert!(event.is_none(), "unmodified close must be dropped");
                }
            }
            _ => {}
        }
    }
    assert!(create > 0 && delete > 0 && rename > 0 && modify > 0);
}

#[test]
fn file_events_carry_the_actor_from_the_recording() {
    let fixture = load("file_lifecycle");
    for (record, event) in decode(&fixture) {
        let Some(event) = event else { continue };
        if !matches!(event.payload, RawPayload::File(_)) {
            continue;
        }
        let file = file(&event);
        assert_eq!(event.pid, Some(record.actor.pid as u32));
        assert_eq!(
            file.user.as_deref(),
            Some(record.actor.euid.to_string().as_str())
        );
        assert_eq!(file.image.is_some(), !record.actor.executable.is_empty());
        assert_eq!(
            event.process_start_key.is_some(),
            record.actor.start_time_ns.is_some()
        );
    }
}
