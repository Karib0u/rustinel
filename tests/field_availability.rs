use std::collections::HashSet;

use rustinel::field_availability::{
    availability_for_event, compatibility_json, coverage_markdown, missing_always_fields,
    unavailable_fields_markdown, Availability, FIELD_AVAILABILITY,
};
use rustinel::models::{
    EventCategory, EventFields, ImageLoadFields, NormalizedEvent, ProcessCreationFields,
    TaskCreationFields,
};
use rustinel::sensor::Platform;

fn event(
    category: EventCategory,
    event_id: u16,
    opcode: u8,
    fields: EventFields,
) -> NormalizedEvent {
    NormalizedEvent {
        timestamp: "2026-09-09T00:00:00Z".to_string(),
        source_seq: None,
        ingest_seq: 1,
        platform: Platform::Windows,
        provider: "etw".to_string(),
        category,
        event_id,
        event_id_string: event_id.to_string(),
        opcode,
        fields,
        provenance: Default::default(),
        process_context: None,
    }
}

fn generated_region(document: &str) -> &str {
    const BEGIN: &str = "<!-- BEGIN GENERATED FIELD AVAILABILITY -->";
    const END: &str = "<!-- END GENERATED FIELD AVAILABILITY -->";
    let start = document.find(BEGIN).expect("generated section starts");
    let end = document[start..]
        .find(END)
        .map(|offset| start + offset + END.len())
        .expect("generated section ends");
    &document[start..end]
}

#[test]
fn generated_artifacts_match_the_contract() {
    assert_eq!(
        include_str!("../compatibility/field-availability.json"),
        compatibility_json()
    );
    assert_eq!(
        generated_region(include_str!("../docs/field-availability.md")),
        unavailable_fields_markdown().trim_end()
    );
    assert_eq!(
        generated_region(include_str!("../docs/coverage.md")),
        coverage_markdown().trim_end()
    );
}

#[test]
fn keys_are_unique_and_limited_statuses_have_reasons() {
    let mut keys = HashSet::new();
    for contract in FIELD_AVAILABILITY {
        for field in contract.fields {
            let key = format!(
                "{:?}|{}|{:?}|{:?}|{}|{}",
                contract.platform,
                contract.category,
                contract.event_id,
                contract.action,
                contract.provider,
                field.field
            );
            assert!(keys.insert(key.clone()), "duplicate contract key: {key}");
            match field.availability {
                Availability::Always => {}
                Availability::Conditional(reason) | Availability::Never(reason) => {
                    assert!(!reason.trim().is_empty(), "{key} has no reason");
                }
            }
        }
    }
}

#[test]
fn required_permanent_gaps_are_recorded() {
    let has_never = |platform, category: &str, field: &str| {
        FIELD_AVAILABILITY.iter().any(|contract| {
            contract.platform == platform
                && contract.category == category
                && contract.fields.iter().any(|entry| {
                    entry.field == field && matches!(entry.availability, Availability::Never(_))
                })
        })
    };

    for field in ["User", "CurrentDirectory"] {
        assert!(has_never(Platform::Windows, "process_creation", field));
    }
    for field in ["Signed", "Signature"] {
        assert!(has_never(Platform::Windows, "image_load", field));
    }
    assert!(has_never(Platform::Windows, "task_creation", "TaskContent"));
    assert!(has_never(Platform::Windows, "dns_query", "RecordType"));
    assert!(has_never(Platform::Windows, "pipe_created", "*"));
    assert!(has_never(Platform::Windows, "create_remote_thread", "*"));
}

#[test]
fn never_fields_cannot_leak_through_the_sigma_accessor() {
    let image = event(
        EventCategory::ImageLoad,
        7,
        10,
        EventFields::ImageLoad(ImageLoadFields {
            image_loaded: Some(r"C:\Windows\System32\kernel32.dll".to_string()),
            process_id: Some("42".to_string()),
            image: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            signed: Some("true".to_string()),
            signature: Some("Fake Signer".to_string()),
            user: None,
        }),
    );
    assert!(matches!(
        availability_for_event(&image, "Signed"),
        Some(Availability::Never(_))
    ));
    assert_eq!(image.get_field("Signed"), None);
    assert_eq!(image.get_field("Signature"), None);

    let task = event(
        EventCategory::Task,
        106,
        0,
        EventFields::TaskCreation(TaskCreationFields {
            task_name: Some("task".to_string()),
            task_content: Some("<Task/>".to_string()),
            user_name: None,
            user: None,
            process_id: None,
            image: None,
        }),
    );
    assert_eq!(task.get_field("TaskContent"), None);
}

#[test]
fn missing_always_fields_detect_decoder_contract_drift() {
    let process = event(
        EventCategory::Process,
        1,
        1,
        EventFields::ProcessCreation(ProcessCreationFields {
            linux_identity: Default::default(),
            image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
            image_source: None,
            image_truncated: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: None,
            process_id: None,
            process_start_time: None,
            cgroup_id: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
            parent_process_id_derived: false,
            windows: Default::default(),
            exec: None,
        }),
    );
    assert_eq!(missing_always_fields(&process), vec!["ProcessId"]);
}

#[test]
fn macos_exec_metadata_is_exposed_by_the_contract() {
    let fields = serde_json::from_value(serde_json::json!({
        "Image": "/bin/sh", "ProcessId": "42", "ProcessStartTime": 100,
        "User": "0", "RealUserId": "501", "PreExecImage": "/bin/bash",
        "ParentImage": "/sbin/launchd", "ParentCommandLine": "/sbin/launchd",
        "Script": "/tmp/example.sh", "Signed": "true", "SignatureStatus": "valid",
        "SigningId": "com.apple.sh", "TeamId": "TEAM", "CdHash": "abcd",
        "CodeSigningFlags": "536870913", "IsPlatformBinary": true
    }))
    .unwrap();
    let mut process = event(
        EventCategory::Process,
        1,
        1,
        EventFields::ProcessCreation(fields),
    );
    process.platform = Platform::MacOS;
    process.provider = "esf".to_string();
    assert!(missing_always_fields(&process).is_empty());
    for field in [
        "RealUserId",
        "PreExecImage",
        "ParentImage",
        "ParentCommandLine",
        "Script",
        "Signed",
        "SignatureStatus",
        "SigningId",
        "TeamId",
        "CdHash",
        "CodeSigningFlags",
        "IsPlatformBinary",
    ] {
        assert!(
            matches!(
                availability_for_event(&process, field),
                Some(Availability::Always | Availability::Conditional(_))
            ),
            "{field}"
        );
        assert!(process.get_field(field).is_some(), "{field}");
    }
}
