//! ECS contract and alert enrichment integration tests.

#[cfg(test)]
mod common;

use common::{
    assert_ecs_field_eq, dns_query_event, ecs_json, file_create_event, network_connect_event,
    process_start_event, TestNormalizer, TEST_DESTINATION_IP, TEST_DOMAIN, TEST_PID, TEST_USER,
};
use rustinel::models::{
    Alert, AlertSeverity, DetectionEngine, DnsQueryFields, EventCategory, EventFields,
    FileEventFields, ImageLoadFields, NetworkConnectionFields, NormalizedEvent,
    PowerShellScriptFields, ProcessCreationFields, RegistryEventFields, ServiceCreationFields,
    TaskCreationFields, WmiEventFields,
};
use rustinel::sensor::Platform;
use serde_json::json;

fn alert(category: EventCategory, event_id: u16, opcode: u8, fields: EventFields) -> Alert {
    Alert {
        severity: AlertSeverity::High,
        rule_name: format!("{category:?} Test"),
        rule_description: None,
        rule_id: None,
        engine: DetectionEngine::Sigma,
        event: NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "test".to_string(),
            category,
            event_id,
            event_id_string: event_id.to_string(),
            opcode,
            fields,
            process_context: None,
        },
        match_details: None,
    }
}

#[test]
fn process_context_enriches_non_process_alerts_without_overwriting_event_fields() {
    let fixture = TestNormalizer::new(false);
    let start = process_start_event(Platform::Windows);
    let normalized_start = fixture
        .normalizer
        .normalize(&start)
        .expect("normalize process start");
    assert_eq!(normalized_start.category, EventCategory::Process);

    let mut file = fixture
        .normalizer
        .normalize(&file_create_event(Platform::Windows))
        .expect("normalize file event");
    fixture
        .normalizer
        .enrich_process_context(&mut file, TEST_PID);

    let mut alert = alert(EventCategory::File, 11, 64, file.fields);
    alert.event.process_context = file.process_context;
    let json = ecs_json(&alert);

    assert_ecs_field_eq(&json, "process.executable", r"C:\Windows\System32\curl.exe");
    assert_ecs_field_eq(
        &json,
        "process.command_line",
        format!(r"C:\Windows\System32\curl.exe https://{TEST_DOMAIN}"),
    );
    assert_ecs_field_eq(&json, "process.pid", TEST_PID);
    assert_ecs_field_eq(
        &json,
        "process.parent.executable",
        r"C:\Windows\explorer.exe",
    );
    assert_ecs_field_eq(&json, "process.parent.command_line", "parent-shell");
    assert_ecs_field_eq(&json, "process.parent.pid", 1000);
    assert_ecs_field_eq(
        &json,
        "process.working_directory",
        r"C:\Users\alice\AppData\Local\Temp",
    );
    assert_ecs_field_eq(&json, "user.name", TEST_USER);
    assert_ecs_field_eq(
        &json,
        "file.path",
        r"C:\Users\alice\AppData\Local\Temp\rustinel-fixture.txt",
    );
}

#[test]
fn ecs_category_coverage_maps_event_contract_fields() {
    let cases = vec![
        (
            alert(
                EventCategory::Process,
                1,
                1,
                EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                    command_line: Some("cmd.exe /c whoami".to_string()),
                    process_id: Some("111".to_string()),
                    process_start_time: None,
                    parent_process_id: None,
                    parent_image: None,
                    parent_command_line: None,
                    current_directory: None,
                    integrity_level: None,
                    user: Some("ACME\\alice".to_string()),
                    original_file_name: None,
                    product: None,
                    description: None,
                    target_image: None,
                    logon_id: None,
                    logon_guid: None,
                }),
            ),
            "edr.process",
            json!(["process"]),
            json!(["start"]),
            "process-start",
            "process.executable",
        ),
        (
            alert(
                EventCategory::Network,
                3,
                12,
                EventFields::NetworkConnection(NetworkConnectionFields {
                    destination_ip: Some("198.51.100.10".to_string()),
                    source_ip: Some("10.0.0.5".to_string()),
                    destination_port: Some("443".to_string()),
                    source_port: Some("51324".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(r"C:\Windows\System32\curl.exe".to_string()),
                    user: Some("alice".to_string()),
                    destination_hostname: Some("example.test".to_string()),
                    protocol: Some("tcp".to_string()),
                }),
            ),
            "edr.network",
            json!(["network"]),
            json!(["connection"]),
            "network-connection",
            "destination.ip",
        ),
        (
            alert(
                EventCategory::File,
                11,
                64,
                EventFields::FileEvent(FileEventFields {
                    source_filename: None,
                    target_filename: Some(r"C:\Temp\payload.dll".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                    creation_utc_time: Some("2026-01-01T00:00:00Z".to_string()),
                    previous_creation_utc_time: None,
                    user: Some("alice".to_string()),
                }),
            ),
            "edr.file",
            json!(["file"]),
            json!(["creation"]),
            "file-create",
            "file.path",
        ),
        (
            alert(
                EventCategory::Registry,
                13,
                39,
                EventFields::RegistryEvent(RegistryEventFields {
                    target_object: Some(r"HKLM\Software\Test\Value".to_string()),
                    details: Some("DWORD (0x00000001)".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(r"C:\Windows\System32\reg.exe".to_string()),
                    event_type: Some("SetValue".to_string()),
                    user: Some("alice".to_string()),
                    new_name: None,
                }),
            ),
            "edr.registry",
            json!(["registry"]),
            json!(["change"]),
            "SetValue",
            "registry.path",
        ),
        (
            alert(
                EventCategory::Dns,
                22,
                0,
                EventFields::DnsQuery(DnsQueryFields {
                    query_name: Some("example.test".to_string()),
                    query_results: Some("198.51.100.10 198.51.100.10".to_string()),
                    record_type: Some("A".to_string()),
                    query_status: Some("NOERROR".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(r"C:\Windows\System32\curl.exe".to_string()),
                }),
            ),
            "edr.dns",
            json!(["network"]),
            json!(["protocol"]),
            "dns-query",
            "dns.question.name",
        ),
        (
            alert(
                EventCategory::ImageLoad,
                7,
                10,
                EventFields::ImageLoad(ImageLoadFields {
                    image_loaded: Some(r"C:\Temp\payload.dll".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(r"C:\Windows\System32\rundll32.exe".to_string()),
                    original_file_name: Some("payload.dll".to_string()),
                    product: None,
                    description: None,
                    signed: Some("false".to_string()),
                    signature: None,
                    user: Some("alice".to_string()),
                }),
            ),
            "edr.library",
            json!(["library"]),
            json!(["start"]),
            "image-load",
            "dll.path",
        ),
        (
            alert(
                EventCategory::Scripting,
                4104,
                0,
                EventFields::PowerShellScript(PowerShellScriptFields {
                    script_block_text: Some("Invoke-Expression".to_string()),
                    script_block_id: Some("block-1".to_string()),
                    path: Some(r"C:\Temp\a.ps1".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(
                        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
                    ),
                    user: Some("alice".to_string()),
                }),
            ),
            "edr.scripting",
            json!(["process"]),
            json!(["info"]),
            "powershell-script",
            "edr.powershell.script_block_text",
        ),
        (
            alert(
                EventCategory::Wmi,
                5857,
                0,
                EventFields::WmiEvent(WmiEventFields {
                    operation: Some("WmiMethod".to_string()),
                    user: Some("alice".to_string()),
                    query: Some("SELECT * FROM Win32_Process".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(r"C:\Windows\System32\wmic.exe".to_string()),
                    event_namespace: Some("root\\cimv2".to_string()),
                    event_type: Some("Consumer".to_string()),
                    destination_hostname: Some("host1".to_string()),
                }),
            ),
            "edr.wmi",
            json!(["api"]),
            json!(["info"]),
            "WmiMethod",
            "edr.wmi.query",
        ),
        (
            alert(
                EventCategory::Service,
                7045,
                0,
                EventFields::ServiceCreation(ServiceCreationFields {
                    service_name: Some("Updater".to_string()),
                    service_file_name: Some(r"C:\Temp\updater.exe".to_string()),
                    service_type: Some("own".to_string()),
                    start_type: Some("auto".to_string()),
                    account_name: Some("LocalSystem".to_string()),
                    user: Some("alice".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(r"C:\Windows\System32\services.exe".to_string()),
                }),
            ),
            "edr.service",
            json!(["configuration"]),
            json!(["creation"]),
            "service-create",
            "service.name",
        ),
        (
            alert(
                EventCategory::Task,
                106,
                0,
                EventFields::TaskCreation(TaskCreationFields {
                    task_name: Some("\\Updater".to_string()),
                    task_content: Some("<Task />".to_string()),
                    user_name: Some("alice".to_string()),
                    user: Some("alice".to_string()),
                    process_id: Some("111".to_string()),
                    image: Some(r"C:\Windows\System32\schtasks.exe".to_string()),
                }),
            ),
            "edr.task",
            json!(["configuration"]),
            json!(["creation"]),
            "task-create",
            "edr.task.name",
        ),
    ];

    for (alert, dataset, category, event_type, action, required_field) in cases {
        let json = ecs_json(&alert);
        assert_ecs_field_eq(&json, "event.dataset", dataset);
        assert_ecs_field_eq(&json, "event.category", category);
        assert_ecs_field_eq(&json, "event.type", event_type);
        assert_ecs_field_eq(&json, "event.action", action);
        assert!(
            json.get(required_field).is_some(),
            "missing category-specific ECS field {required_field}"
        );
    }
}

#[test]
fn related_ip_and_user_are_deduplicated() {
    let mut network = network_connect_event(Platform::Windows);
    if let rustinel::sensor::SensorPayload::Network(fields) = &mut network.payload {
        fields.source_ip = Some(TEST_DESTINATION_IP.to_string());
        fields.user = Some(r"ACME\alice".to_string());
    }

    let normalizer = TestNormalizer::new(false);
    let normalized = normalizer
        .normalizer
        .normalize(&network)
        .expect("normalize network");
    let alert = alert(
        EventCategory::Network,
        normalized.event_id,
        normalized.opcode,
        normalized.fields,
    );
    let json = ecs_json(&alert);

    assert_ecs_field_eq(&json, "related.ip", json!([TEST_DESTINATION_IP]));
    assert_ecs_field_eq(&json, "related.user", json!(["alice"]));
}

#[test]
fn macos_file_create_alert_maps_ecs_fields() {
    let normalizer = TestNormalizer::new(false);
    let normalized = normalizer
        .normalizer
        .normalize(&file_create_event(Platform::MacOS))
        .expect("normalize macos file event");
    assert_eq!(normalized.platform, Platform::MacOS);

    let alert = Alert {
        severity: AlertSeverity::High,
        rule_name: "macOS File Create".to_string(),
        rule_description: None,
        rule_id: None,
        engine: DetectionEngine::Sigma,
        event: normalized,
        match_details: None,
    };
    let json = ecs_json(&alert);

    assert_ecs_field_eq(&json, "event.dataset", "edr.file");
    assert_ecs_field_eq(&json, "event.category", json!(["file"]));
    assert_ecs_field_eq(&json, "event.type", json!(["creation"]));
    assert_ecs_field_eq(&json, "event.action", "file-create");
    assert_ecs_field_eq(&json, "file.path", "/tmp/rustinel-fixture.txt");
    assert_ecs_field_eq(&json, "host.os.type", "macos");
    assert_ecs_field_eq(&json, "host.os.family", "darwin");
}

#[test]
fn dns_alert_populates_category_specific_fields() {
    let normalizer = TestNormalizer::new(false);
    let normalized = normalizer
        .normalizer
        .normalize(&dns_query_event(Platform::Windows))
        .expect("normalize dns");
    let alert = alert(
        EventCategory::Dns,
        normalized.event_id,
        normalized.opcode,
        normalized.fields,
    );
    let json = ecs_json(&alert);

    assert_ecs_field_eq(&json, "dns.question.name", TEST_DOMAIN);
    assert_ecs_field_eq(&json, "dns.resolved_ip", json!([TEST_DESTINATION_IP]));
    assert_ecs_field_eq(&json, "network.protocol", "dns");
}

#[test]
fn ecs_version_field_is_9_4_0() {
    let json = ecs_json(&alert(
        EventCategory::Process,
        1,
        1,
        EventFields::ProcessCreation(ProcessCreationFields {
            image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
            command_line: None,
            process_id: None,
            process_start_time: None,
            parent_image: None,
            parent_process_id: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
            original_file_name: None,
            product: None,
            description: None,
            target_image: None,
            logon_id: None,
            logon_guid: None,
        }),
    ));
    assert_ecs_field_eq(&json, "ecs.version", "9.4.0");
}

#[test]
fn test_rule_id_mapping_and_omit_behavior() {
    // 1. Sigma with ID
    let alert_sigma_with_id = Alert {
        severity: AlertSeverity::High,
        rule_name: "Test Rule".to_string(),
        rule_description: None,
        rule_id: Some("sigma::abc-123".to_string()),
        engine: DetectionEngine::Sigma,
        event: NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            platform: Platform::Windows,
            provider: "test".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                command_line: None,
                process_id: None,
                process_start_time: None,
                parent_image: None,
                parent_process_id: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
                original_file_name: None,
                product: None,
                description: None,
                target_image: None,
                logon_id: None,
                logon_guid: None,
            }),
            process_context: None,
        },
        match_details: None,
    };
    let json_sigma_with_id = ecs_json(&alert_sigma_with_id);
    assert_ecs_field_eq(&json_sigma_with_id, "rule.id", "sigma::abc-123");

    // 2. Sigma without ID (omitted)
    let alert_sigma_no_id = Alert {
        severity: AlertSeverity::High,
        rule_name: "Test Rule".to_string(),
        rule_description: None,
        rule_id: None,
        engine: DetectionEngine::Sigma,
        event: alert_sigma_with_id.event.clone(),
        match_details: None,
    };
    let json_sigma_no_id = ecs_json(&alert_sigma_no_id);
    assert!(json_sigma_no_id
        .get("rule")
        .and_then(|r| r.get("id"))
        .is_none());

    // 3. YARA with ID
    let alert_yara_with_id = Alert {
        severity: AlertSeverity::Critical,
        rule_name: "YaraRule".to_string(),
        rule_description: None,
        rule_id: Some("yara::yara-rule-uuid".to_string()),
        engine: DetectionEngine::Yara,
        event: alert_sigma_with_id.event.clone(),
        match_details: None,
    };
    let json_yara_with_id = ecs_json(&alert_yara_with_id);
    assert_ecs_field_eq(&json_yara_with_id, "rule.id", "yara::yara-rule-uuid");

    // 4. YARA without ID (omitted)
    let alert_yara_no_id = Alert {
        severity: AlertSeverity::Critical,
        rule_name: "YaraRule".to_string(),
        rule_description: None,
        rule_id: None,
        engine: DetectionEngine::Yara,
        event: alert_sigma_with_id.event.clone(),
        match_details: None,
    };
    let json_yara_no_id = ecs_json(&alert_yara_no_id);
    assert!(json_yara_no_id
        .get("rule")
        .and_then(|r| r.get("id"))
        .is_none());

    // 5. IOC (always present, formatted as ioc::kind::indicator)
    let alert_ioc = Alert {
        severity: AlertSeverity::Medium,
        rule_name: "ioc:domain:example.com".to_string(),
        rule_description: None,
        rule_id: Some("ioc::domain::example.com".to_string()),
        engine: DetectionEngine::Ioc,
        event: alert_sigma_with_id.event.clone(),
        match_details: None,
    };
    let json_ioc = ecs_json(&alert_ioc);
    assert_ecs_field_eq(&json_ioc, "rule.id", "ioc::domain::example.com");
}
