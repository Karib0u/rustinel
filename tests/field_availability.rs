use std::collections::HashSet;

use rustinel::field_availability::{
    availability_for_event, compatibility_json, coverage_markdown, missing_always_fields,
    populated_never_fields, unavailable_fields_markdown, Availability, FIELD_AVAILABILITY,
    SCHEMA_VERSION,
};
use rustinel::models::{
    EventCategory, EventFields, FieldViewName, ImageLoadFields, NormalizedEvent,
    ProcessCreationFields, TaskCreationFields,
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
        process_name: None,
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
fn compatibility_entries_always_state_since() {
    let artifact: serde_json::Value =
        serde_json::from_str(&compatibility_json()).expect("compatibility artifact is valid JSON");
    assert_eq!(artifact["schema_version"], SCHEMA_VERSION);

    let entries = artifact["entries"]
        .as_array()
        .expect("compatibility entries are an array");
    assert!(!entries.is_empty());
    for entry in entries {
        assert_eq!(entry["view"], "sysmon");
        assert!(
            entry
                .as_object()
                .is_some_and(|entry| entry.contains_key("since")),
            "compatibility entry omits since: {entry}"
        );
    }
}

#[test]
fn known_field_transitions_keep_their_release_provenance() {
    let since = |platform, category: &str, field: &str| {
        FIELD_AVAILABILITY
            .iter()
            .filter(|contract| {
                contract.view == FieldViewName::SYSMON
                    && contract.platform == platform
                    && contract.category == category
            })
            .flat_map(|contract| contract.fields)
            .find(|entry| entry.field == field)
            .and_then(|entry| entry.since)
    };

    assert_eq!(
        since(Platform::Windows, "registry_event", "Details"),
        Some("1.4.0")
    );
    assert_eq!(
        since(Platform::Windows, "service_creation", "ImagePath"),
        Some("1.4.1")
    );
    assert_eq!(
        since(Platform::Windows, "process_creation", "IntegrityLevel"),
        Some("1.4.1")
    );
    assert_eq!(
        since(Platform::Linux, "network_connection", "SourceIp"),
        Some("1.6.0")
    );
    assert_eq!(
        since(Platform::MacOS, "dns_query", "ProcessId"),
        Some("1.7.0")
    );
}

#[test]
fn keys_are_unique_and_limited_statuses_have_reasons() {
    let mut keys = HashSet::new();
    for contract in FIELD_AVAILABILITY {
        for field in contract.fields {
            let key = format!(
                "{}|{:?}|{}|{:?}|{:?}|{}|{}",
                contract.view.as_str(),
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
            contract.view == FieldViewName::SYSMON
                && contract.platform == platform
                && contract.category == category
                && contract.fields.iter().any(|entry| {
                    entry.field == field && matches!(entry.availability, Availability::Never(_))
                })
        })
    };

    assert!(has_never(
        Platform::Windows,
        "process_creation",
        "CurrentDirectory"
    ));
    for field in ["User", "ParentUser"] {
        let availability = FIELD_AVAILABILITY
            .iter()
            .find(|contract| {
                contract.view == FieldViewName::SYSMON
                    && contract.platform == Platform::Windows
                    && contract.category == "process_creation"
            })
            .and_then(|contract| contract.fields.iter().find(|entry| entry.field == field))
            .map(|entry| entry.availability);
        assert!(matches!(availability, Some(Availability::Conditional(_))));
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
fn every_windows_shape_declares_its_real_channel_or_a_permanent_gap() {
    for contract in FIELD_AVAILABILITY.iter().filter(|contract| {
        contract.view == FieldViewName::SYSMON && contract.platform == Platform::Windows
    }) {
        let channel = contract
            .fields
            .iter()
            .find(|field| field.field == "Channel" || field.field == "*")
            .unwrap_or_else(|| {
                panic!(
                    "{}/{} has no Channel contract",
                    contract.provider, contract.category
                )
            });
        match channel.value {
            Some(value) => {
                assert!(!value.is_empty());
                assert_eq!(channel.availability, Availability::Always);
            }
            None => assert!(matches!(channel.availability, Availability::Never(_))),
        }
    }
}

#[test]
fn windows_shapes_record_the_verified_channel_names() {
    for (category, event_id, expected) in [
        (
            "ps_module",
            4103,
            "Microsoft-Windows-PowerShell/Operational",
        ),
        (
            "ps_script",
            4104,
            "Microsoft-Windows-PowerShell/Operational",
        ),
        ("ps_classic_start", 400, "Windows PowerShell"),
        (
            "dns_query",
            3006,
            "Microsoft-Windows-DNS-Client/Operational",
        ),
        (
            "dns_query",
            3008,
            "Microsoft-Windows-DNS-Client/Operational",
        ),
        (
            "task_creation",
            106,
            "Microsoft-Windows-TaskScheduler/Operational",
        ),
        ("service_creation", 7045, "System"),
        ("security", 4624, "Security"),
    ] {
        let contract = FIELD_AVAILABILITY
            .iter()
            .find(|contract| {
                contract.view == FieldViewName::SYSMON
                    && contract.platform == Platform::Windows
                    && contract.category == category
                    && contract.event_id == Some(event_id)
            })
            .unwrap_or_else(|| panic!("missing {category} event {event_id} contract"));
        let channel = contract
            .fields
            .iter()
            .find(|field| field.field == "Channel")
            .and_then(|field| field.value);
        assert_eq!(channel, Some(expected), "{category} event {event_id}");
    }
}

#[test]
fn never_fields_cannot_leak_through_the_sigma_accessor() {
    let image = event(
        EventCategory::ImageLoad,
        7,
        10,
        EventFields::ImageLoad(ImageLoadFields {
            hashes: None,
            imphash: None,
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
    assert_eq!(populated_never_fields(&image), vec!["Signed", "Signature"]);

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
fn measured_windows_process_user_is_visible_under_the_contract() {
    let fields = serde_json::from_value(serde_json::json!({
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ProcessId": "42",
        "User": "NT AUTHORITY\\SYSTEM"
    }))
    .unwrap();
    let process = event(
        EventCategory::Process,
        1,
        1,
        EventFields::ProcessCreation(fields),
    );

    assert!(matches!(
        availability_for_event(&process, "User"),
        Some(Availability::Conditional(_))
    ));
    assert_eq!(process.get_field("User"), Some("NT AUTHORITY\\SYSTEM"));
    assert!(populated_never_fields(&process).is_empty());
}

#[test]
fn missing_always_fields_detect_decoder_contract_drift() {
    let process = event(
        EventCategory::Process,
        1,
        1,
        EventFields::ProcessCreation(ProcessCreationFields {
            hashes: None,
            imphash: None,
            container: Default::default(),
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
            parent_user: None,
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
