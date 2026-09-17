//! `windows/security` logsource routing, from a decoded audit record to a
//! Sigma match and its ECS alert.
//!
//! The decoder itself is Windows-only and covered by its unit tests. What this
//! file protects is the part every platform builds: that a Security audit
//! payload normalizes, reaches rules written against the `windows/security`
//! logsource, and lands in the right ECS fields.

#[cfg(test)]
mod common;

use std::time::SystemTime;

use common::{assert_ecs_field_eq, ecs_json, SigmaFixture, TestNormalizer};
use rustinel::{
    engine::{Engine, LogSource, LogSourceStatus},
    models::{EventCategory, EventFields, NormalizedEvent, SecurityAuditFields},
    sensor::{Platform, SensorAction, SensorEvent, SensorNormalization, SensorPayload},
};

fn audit_fields(pairs: &[(&str, &str)]) -> SecurityAuditFields {
    let mut fields = SecurityAuditFields::default();
    for (name, value) in pairs {
        fields.insert(name, value);
    }
    fields
}

fn security_event(event_id: u16, action: SensorAction, pairs: &[(&str, &str)]) -> SensorEvent {
    let fields = audit_fields(pairs);
    let pid = fields.process_id();

    SensorEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::Windows,
        provider: "windows_event_log",
        action,
        normalization: SensorNormalization {
            event_id,
            action_code: 0,
        },
        pid,
        timestamp: SystemTime::now(),
        source_seq: None,
        process_start_key: None,
        parent_process_start_key: None,
        payload: SensorPayload::Security(fields),
    }
}

fn normalize(event: &SensorEvent) -> NormalizedEvent {
    TestNormalizer::new()
        .normalizer
        .normalize(event)
        .expect("a security audit event should normalize")
}

fn windows_security_engine(fixture: &SigmaFixture) -> Engine {
    let mut engine = Engine::new_for_platform(Platform::Windows);
    engine
        .load_rules(fixture.rules_dir())
        .expect("sigma rules should load");
    assert_eq!(engine.stats().failed_rules, Vec::<(String, String)>::new());
    engine
}

#[test]
fn windows_security_is_an_active_logsource() {
    let engine = Engine::new_for_platform(Platform::Windows);
    let classification = engine.classify_logsource(&LogSource {
        product: Some("windows".to_string()),
        service: Some("security".to_string()),
        category: None,
    });

    assert_eq!(classification.status, LogSourceStatus::Supported);
    assert_eq!(
        classification.collector_active,
        Some(true),
        "windows/security rules must load against a live collector"
    );
}

#[test]
fn security_audit_events_normalize_under_their_own_field_names() {
    let event = security_event(
        4697,
        SensorAction::Register,
        &[
            ("SubjectUserName", "alice"),
            ("SubjectDomainName", "ACME"),
            ("SubjectLogonId", "0x3e4"),
            ("ServiceName", "RustinelIssue315"),
            ("ServiceFileName", r"C:\Windows\Temp\payload.exe"),
        ],
    );

    let normalized = normalize(&event);
    assert_eq!(normalized.category, EventCategory::Security);
    assert_eq!(normalized.event_id, 4697);
    assert_eq!(normalized.get_field("EventID"), Some("4697"));
    assert_eq!(normalized.get_field("Channel"), Some("Security"));
    assert_eq!(normalized.get_field("SubjectLogonId"), Some("0x3e4"));
    assert_eq!(
        normalized.get_field("ServiceFileName"),
        Some(r"C:\Windows\Temp\payload.exe")
    );
    assert!(matches!(normalized.fields, EventFields::SecurityAudit(_)));
}

#[test]
fn hayabusa_security_channel_rule_matches_logon_event() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "security_channel.yml",
        r#"title: Security Channel Logon
logsource:
  product: windows
  service: security
detection:
  selection:
    Channel: Security
    EventID: 4624
    TargetUserName: alice
  condition: selection
level: high
"#,
    );
    let normalized = normalize(&security_event(
        4624,
        SensorAction::Start,
        &[("TargetUserName", "alice")],
    ));

    let alert = windows_security_engine(&fixture)
        .check_event(&normalized)
        .into_iter()
        .next()
        .expect("Channel and EventID must match the Security event");
    assert_eq!(alert.rule_name, "Security Channel Logon");
}

/// One rule per supported event family, each written the way SigmaHQ writes
/// them for this channel: `product: windows`, `service: security`, no category,
/// and an `EventID` selection.
#[test]
fn each_supported_event_family_matches_a_windows_security_rule() {
    let cases: Vec<(&str, &str, SensorEvent)> = vec![
        (
            "service.yml",
            "Security Service Installation",
            security_event(
                4697,
                SensorAction::Register,
                &[
                    ("ServiceName", "RustinelIssue315"),
                    ("ServiceFileName", r"C:\Windows\Temp\payload.exe"),
                ],
            ),
        ),
        (
            "share.yml",
            "Security Admin Share Write",
            security_event(
                5145,
                SensorAction::Access,
                &[
                    ("ShareName", r"\\*\ADMIN$"),
                    ("RelativeTargetName", "PSEXESVC.exe"),
                    ("IpAddress", "10.0.0.9"),
                ],
            ),
        ),
        (
            "object_access.yml",
            "Security Credential File Access",
            security_event(
                4663,
                SensorAction::Access,
                &[
                    ("ObjectType", "File"),
                    ("ObjectName", r"C:\Windows\NTDS\ntds.dit"),
                    ("ProcessId", "0x4d8"),
                    ("ProcessName", r"C:\Windows\System32\ntdsutil.exe"),
                ],
            ),
        ),
        (
            "logon.yml",
            "Security Network Logon From Host",
            security_event(
                4624,
                SensorAction::Start,
                &[
                    ("LogonType", "3"),
                    ("AuthenticationPackageName", "NTLM"),
                    ("TargetUserName", "bob"),
                    ("IpAddress", "10.0.0.9"),
                ],
            ),
        ),
        (
            "handle.yml",
            "Security SAM Handle Request",
            security_event(
                4656,
                SensorAction::Access,
                &[
                    ("ObjectType", "Key"),
                    ("ObjectName", r"\REGISTRY\MACHINE\SECURITY"),
                    ("AccessMask", "0x20019"),
                ],
            ),
        ),
        (
            "directory.yml",
            "Security Delegation Attribute Change",
            security_event(
                5136,
                SensorAction::Modify,
                &[
                    ("AttributeLDAPDisplayName", "msDS-AllowedToDelegateTo"),
                    ("AttributeValue", "cifs/dc01.acme.test"),
                    ("ObjectClass", "user"),
                ],
            ),
        ),
    ];

    let rules = [
        (
            "service.yml",
            r#"title: Security Service Installation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4697
    ServiceFileName|contains: '\Temp\'
  condition: selection
level: high
"#,
        ),
        (
            "share.yml",
            r#"title: Security Admin Share Write
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName|contains: 'ADMIN$'
    RelativeTargetName|endswith: '.exe'
  condition: selection
level: high
"#,
        ),
        (
            "object_access.yml",
            r#"title: Security Credential File Access
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectName|endswith: '\ntds.dit'
  condition: selection
level: critical
"#,
        ),
        (
            "logon.yml",
            r#"title: Security Network Logon From Host
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
  condition: selection
level: medium
"#,
        ),
        (
            "handle.yml",
            r#"title: Security SAM Handle Request
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4656
    ObjectName|endswith: '\SECURITY'
  condition: selection
level: high
"#,
        ),
        (
            "directory.yml",
            r#"title: Security Delegation Attribute Change
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: 'msDS-AllowedToDelegateTo'
  condition: selection
level: high
"#,
        ),
    ];

    let fixture = SigmaFixture::new();
    for (filename, yaml) in rules {
        fixture.write_rule(filename, yaml);
    }
    let engine = windows_security_engine(&fixture);
    assert_eq!(engine.stats().total_rules, 6);
    assert_eq!(engine.stats().inactive_collector_rules, 0);

    for (filename, expected_rule, event) in cases {
        let normalized = normalize(&event);
        let alert = engine
            .check_event(&normalized)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("{filename} should match {expected_rule}"));
        assert_eq!(alert.rule_name, expected_rule);
        assert_ecs_field_eq(&ecs_json(&alert), "event.dataset", "edr.security");
    }
}

/// A rule keyed on a different event ID in the same channel must not fire: the
/// channel is one logsource, so `EventID` is the only thing separating the
/// families.
#[test]
fn a_rule_for_another_event_id_does_not_match() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "other.yml",
        r#"title: Security Logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: low
"#,
    );
    let engine = windows_security_engine(&fixture);

    let event = security_event(
        4697,
        SensorAction::Register,
        &[("ServiceName", "RustinelIssue315")],
    );
    assert!(engine.check_event(&normalize(&event)).is_empty());
}

#[test]
fn security_alerts_map_identity_network_and_object_fields_to_ecs() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "share.yml",
        r#"title: Security Admin Share Write
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName|contains: 'ADMIN$'
  condition: selection
level: high
"#,
    );
    let engine = windows_security_engine(&fixture);

    let event = security_event(
        5145,
        SensorAction::Access,
        &[
            ("SubjectUserSid", "S-1-5-21-1-2-3-1001"),
            ("SubjectUserName", "alice"),
            ("SubjectDomainName", "ACME"),
            ("SubjectLogonId", "0x3e4"),
            ("ObjectType", "File"),
            ("ShareName", r"\\*\ADMIN$"),
            ("RelativeTargetName", "PSEXESVC.exe"),
            ("IpAddress", "10.0.0.9"),
            ("IpPort", "50123"),
        ],
    );
    let alert = engine
        .check_event(&normalize(&event))
        .into_iter()
        .next()
        .expect("the share rule should match");
    let json = ecs_json(&alert);

    assert_ecs_field_eq(&json, "event.dataset", "edr.security");
    assert_ecs_field_eq(&json, "event.code", "5145");
    assert_ecs_field_eq(&json, "event.action", "network-share-object-checked");
    assert_ecs_field_eq(&json, "event.category", serde_json::json!(["file"]));
    assert_ecs_field_eq(&json, "user.name", "alice");
    assert_ecs_field_eq(&json, "user.domain", "ACME");
    assert_ecs_field_eq(&json, "user.id", "S-1-5-21-1-2-3-1001");
    assert_ecs_field_eq(&json, "winlog.logon.id", "0x3e4");
    assert_ecs_field_eq(&json, "source.ip", "10.0.0.9");
    assert_ecs_field_eq(&json, "source.port", 50123);

    // The whole decoded record travels with the alert, under Windows' own
    // names, so nothing the rule matched on is lost on the way to a SIEM.
    let record = json
        .get("edr.security")
        .expect("the decoded audit record should be present");
    assert_eq!(
        record.get("ShareName").and_then(|v| v.as_str()),
        Some(r"\\*\ADMIN$")
    );
    assert_eq!(
        record.get("RelativeTargetName").and_then(|v| v.as_str()),
        Some("PSEXESVC.exe")
    );
}

#[test]
fn object_access_ecs_category_follows_the_audited_object_type() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "handle.yml",
        r#"title: Security Handle Request
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4656
  condition: selection
level: low
"#,
    );
    let engine = windows_security_engine(&fixture);

    let cases = [
        ("Key", "registry", r"\REGISTRY\MACHINE\SECURITY"),
        ("File", "file", r"C:\Windows\NTDS\ntds.dit"),
        ("Process", "process", "lsass.exe"),
    ];

    for (object_type, expected_category, object_name) in cases {
        let event = security_event(
            4656,
            SensorAction::Access,
            &[("ObjectType", object_type), ("ObjectName", object_name)],
        );
        let alert = engine
            .check_event(&normalize(&event))
            .into_iter()
            .next()
            .expect("the handle rule should match");
        let json = ecs_json(&alert);
        assert_ecs_field_eq(
            &json,
            "event.category",
            serde_json::json!([expected_category]),
        );
    }
}

/// A Security-channel process ID is hex. The raw value stays matchable and the
/// pipeline still gets a number it can use.
#[test]
fn hex_process_ids_stay_raw_for_rules_and_parse_for_the_pipeline() {
    let event = security_event(
        4663,
        SensorAction::Access,
        &[
            ("ProcessId", "0x4d8"),
            ("ProcessName", r"C:\Windows\System32\notepad.exe"),
            ("ObjectType", "File"),
            ("ObjectName", r"C:\Temp\secrets.txt"),
        ],
    );

    assert_eq!(event.pid, Some(0x4d8));
    let normalized = normalize(&event);
    assert_eq!(normalized.get_field("ProcessId"), Some("0x4d8"));
}

/// The families added for #479, each against the SigmaHQ rule it unblocked.
///
/// Detection blocks are copied from SigmaHQ `da9bb07` unchanged; only the
/// metadata is trimmed. Each case also carries a near miss, so a rule that
/// matched everything would fail the test.
#[test]
fn added_security_families_match_the_sigmahq_rules_they_unblock() {
    let rules = [
        (
            "win_security_susp_scheduled_task_creation.yml",
            r#"title: Suspicious Scheduled Task Creation
logsource:
    product: windows
    service: security
detection:
    selection_eid:
        EventID: 4698
    selection_paths:
        TaskContent|contains:
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\Users\Public\'
            - '\WINDOWS\Temp\'
            - 'C:\Temp\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Temporary Internet'
            - 'C:\ProgramData\'
            - 'C:\Perflogs\'
    selection_commands:
        TaskContent|contains:
            - 'regsvr32'
            - 'rundll32'
            - 'cmd.exe</Command>'
            - 'cmd</Command>'
            - '<Arguments>/c '
            - '<Arguments>/k '
            - '<Arguments>/r '
            - 'powershell'
            - 'pwsh'
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'certutil'
            - 'bitsadmin'
            - 'bash.exe'
            - 'bash '
            - 'scrcons'
            - 'wmic '
            - 'wmic.exe'
            - 'forfiles'
            - 'scriptrunner'
            - 'hh.exe'
    condition: all of selection_*
level: high
"#,
        ),
        (
            "win_security_susp_failed_logon_reasons.yml",
            r#"title: Account Tampering - Suspicious Failed Logon Reasons
logsource:
    product: windows
    service: security
detection:
    selection_eid:
        EventID:
            - 4625
            - 4776
    selection_status:
        - Status:
              - '0xC0000072'
              - '0xC000006F'
              - '0xC0000070'
              - '0xC0000413'
              - '0xC000018C'
              - '0xC000015B'
        - SubStatus:
              - '0xC0000072'
              - '0xC000006F'
              - '0xC0000070'
              - '0xC0000413'
              - '0xC000018C'
              - '0xC000015B'
    filter:
        SubjectUserSid: 'S-1-0-0'
    condition: all of selection_* and not filter
level: medium
"#,
        ),
        (
            "win_security_user_added_to_local_administrators.yml",
            r#"title: User Added to Local Administrator Group
logsource:
    product: windows
    service: security
detection:
    selection_eid:
        EventID: 4732
    selection_group:
        - TargetUserName|startswith: 'Administr'
        - TargetSid: 'S-1-5-32-544'
    filter_main_computer_accounts:
        SubjectUserName|endswith: '$'
    condition: all of selection_* and not 1 of filter_*
level: medium
"#,
        ),
        (
            "win_security_audit_log_cleared.yml",
            r#"title: Security Eventlog Cleared
logsource:
    product: windows
    service: security
detection:
    selection_517:
        EventID: 517
        Provider_Name: Security
    selection_1102:
        EventID: 1102
        Provider_Name: Microsoft-Windows-Eventlog
    condition: 1 of selection_*
level: high
"#,
        ),
        (
            "win_security_net_ntlm_downgrade.yml",
            r#"title: NetNTLM Downgrade Attack
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4657
        ObjectName|contains|all:
            - '\REGISTRY\MACHINE\SYSTEM'
            - 'ControlSet'
            - '\Control\Lsa'
        ObjectValueName:
            - 'LmCompatibilityLevel'
            - 'NtlmMinClientSec'
            - 'RestrictSendingNTLMTraffic'
    condition: selection
level: high
"#,
        ),
        (
            "win_security_hktl_edr_silencer.yml",
            r#"title: HackTool - EDRSilencer Execution - Filter Added
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5441
            - 5447
        FilterName|contains: 'Custom Outbound Filter'
    condition: selection
level: high
"#,
        ),
        (
            "win_security_susp_outbound_kerberos_connection.yml",
            r#"title: Uncommon Outbound Kerberos Connection - Security
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
        DestPort: 88
    filter_main_lsass:
        Application|startswith:
            - '\device\harddiskvolume'
            - 'C:'
        Application|endswith: '\Windows\System32\lsass.exe'
    condition: selection and not 1 of filter_main_*
level: medium
"#,
        ),
    ];

    let task = |command: &str, arguments: &str| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\">\r\n\
             <Actions Context=\"Author\">\r\n<Exec>\r\n<Command>{command}</Command>\r\n\
             <Arguments>{arguments}</Arguments>\r\n</Exec>\r\n</Actions>\r\n</Task>"
        )
    };
    let staged_task = task("cmd.exe", r"/c C:\Users\Public\stage.bat");
    let benign_task = task(r"C:\Program Files\Vendor\update.exe", "--quiet");

    // (event, the rule it must fire, or None for a near miss)
    let cases: Vec<(SensorEvent, Option<&str>)> = vec![
        (
            security_event(
                4698,
                SensorAction::Register,
                &[
                    ("TaskName", r"\RustinelIssue479"),
                    ("TaskContent", &staged_task),
                ],
            ),
            Some("Suspicious Scheduled Task Creation"),
        ),
        (
            security_event(
                4698,
                SensorAction::Register,
                &[("TaskName", r"\Vendor"), ("TaskContent", &benign_task)],
            ),
            None,
        ),
        // Credential validation has no subject, so the NULL SID filter
        // cannot exclude it.
        (
            security_event(
                4776,
                SensorAction::Start,
                &[
                    ("TargetUserName", "disabled-user"),
                    ("Status", "0xC0000072"),
                ],
            ),
            Some("Account Tampering - Suspicious Failed Logon Reasons"),
        ),
        // A network logon failure is attributed to the NULL SID, which the
        // rule filters out.
        (
            security_event(
                4625,
                SensorAction::Start,
                &[
                    ("SubjectUserSid", "S-1-0-0"),
                    ("TargetUserName", "disabled-user"),
                    ("Status", "0xC000006E"),
                    ("SubStatus", "0xC0000072"),
                ],
            ),
            None,
        ),
        (
            security_event(
                4732,
                SensorAction::Modify,
                &[
                    ("SubjectUserName", "alice"),
                    ("TargetUserName", "Administrateurs"),
                    ("TargetSid", "S-1-5-32-544"),
                    ("MemberSid", "S-1-5-21-1-2-3-1010"),
                ],
            ),
            Some("User Added to Local Administrator Group"),
        ),
        (
            security_event(
                4732,
                SensorAction::Modify,
                &[
                    ("SubjectUserName", "alice"),
                    ("TargetUserName", "Remote Desktop Users"),
                    ("TargetSid", "S-1-5-32-555"),
                ],
            ),
            None,
        ),
        (
            security_event(
                1102,
                SensorAction::Delete,
                &[
                    ("Provider_Name", "Microsoft-Windows-Eventlog"),
                    ("SubjectUserName", "alice"),
                ],
            ),
            Some("Security Eventlog Cleared"),
        ),
        (
            security_event(
                4657,
                SensorAction::Set,
                &[
                    (
                        "ObjectName",
                        r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa",
                    ),
                    ("ObjectValueName", "LmCompatibilityLevel"),
                    ("NewValue", "2"),
                ],
            ),
            Some("NetNTLM Downgrade Attack"),
        ),
        (
            security_event(
                5447,
                SensorAction::Modify,
                &[
                    ("FilterName", "Custom Outbound Filter"),
                    ("ChangeType", "%%16385"),
                ],
            ),
            Some("HackTool - EDRSilencer Execution - Filter Added"),
        ),
        (
            security_event(
                5156,
                SensorAction::Connect,
                &[
                    ("ProcessId", "5104"),
                    (
                        "Application",
                        r"\device\harddiskvolume3\windows\system32\windowspowershell\v1.0\powershell.exe",
                    ),
                    ("DestPort", "88"),
                ],
            ),
            Some("Uncommon Outbound Kerberos Connection - Security"),
        ),
        (
            security_event(
                5156,
                SensorAction::Connect,
                &[
                    ("ProcessId", "712"),
                    (
                        "Application",
                        r"\device\harddiskvolume3\Windows\System32\lsass.exe",
                    ),
                    ("DestPort", "88"),
                ],
            ),
            None,
        ),
    ];

    let fixture = SigmaFixture::new();
    for (filename, yaml) in rules {
        fixture.write_rule(filename, yaml);
    }
    let engine = windows_security_engine(&fixture);
    assert_eq!(engine.stats().total_rules, rules.len());
    assert_eq!(engine.stats().inactive_collector_rules, 0);

    for (event, expected) in cases {
        let alerts = engine.check_event(&normalize(&event));
        let names: Vec<&str> = alerts
            .iter()
            .map(|alert| alert.rule_name.as_str())
            .collect();
        let id = event.normalization.event_id;
        match expected {
            Some(rule) => assert_eq!(names, [rule], "event {id}"),
            None => assert!(names.is_empty(), "event {id} near miss matched {names:?}"),
        }
    }
}

#[test]
fn scheduled_task_audit_alerts_carry_the_task_definition_in_ecs() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "task.yml",
        r#"title: Security Scheduled Task Update
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4702
    TaskContentNew|contains: 'powershell'
  condition: selection
level: high
"#,
    );
    let engine = windows_security_engine(&fixture);

    let definition =
        "<Task><Actions><Exec><Command>powershell.exe</Command></Exec></Actions></Task>";
    let event = security_event(
        4702,
        SensorAction::Modify,
        &[
            ("SubjectUserName", "alice"),
            ("TaskName", r"\RustinelIssue479"),
            ("TaskContentNew", definition),
        ],
    );
    let alert = engine
        .check_event(&normalize(&event))
        .into_iter()
        .next()
        .expect("the task update rule should match");
    let json = ecs_json(&alert);

    assert_ecs_field_eq(&json, "event.code", "4702");
    assert_ecs_field_eq(&json, "event.action", "scheduled-task-updated");
    assert_ecs_field_eq(
        &json,
        "event.category",
        serde_json::json!(["configuration"]),
    );
    assert_ecs_field_eq(&json, "event.type", serde_json::json!(["change"]));
    assert_ecs_field_eq(&json, "edr.task.name", r"\RustinelIssue479");
    assert_ecs_field_eq(&json, "edr.task.content", definition);
}

#[test]
fn account_and_network_audit_events_classify_in_ecs() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "any.yml",
        r#"title: Any Security Event
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4625
      - 4732
      - 5157
  condition: selection
level: low
"#,
    );
    let engine = windows_security_engine(&fixture);

    let cases = [
        (
            security_event(4625, SensorAction::Start, &[("IpAddress", "198.51.100.10")]),
            "logon-failed",
            serde_json::json!(["authentication"]),
            serde_json::json!(["start"]),
        ),
        (
            security_event(4732, SensorAction::Modify, &[("TargetSid", "S-1-5-32-544")]),
            "added-member-to-group",
            serde_json::json!(["iam"]),
            serde_json::json!(["group", "change"]),
        ),
        (
            security_event(5157, SensorAction::Connect, &[("ProcessID", "5104")]),
            "network-connection-blocked",
            serde_json::json!(["network"]),
            serde_json::json!(["connection", "denied"]),
        ),
    ];

    for (event, action, category, kind) in cases {
        let alert = engine
            .check_event(&normalize(&event))
            .into_iter()
            .next()
            .expect("the catch-all rule should match");
        let json = ecs_json(&alert);
        assert_ecs_field_eq(&json, "event.action", action);
        assert_ecs_field_eq(&json, "event.category", category);
        assert_ecs_field_eq(&json, "event.type", kind);
    }
}
