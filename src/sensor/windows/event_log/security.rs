//! Windows Security channel audit event decoding.
//!
//! The Security channel is one Sigma logsource (`windows/security`) carrying
//! unrelated event families. Rules address them by `EventID` and by the field
//! names Windows itself writes, so the decoder keeps both: the subscription is
//! scoped to the supported IDs, and each ID has an allowlist of the properties
//! decoded from it.
//!
//! The shared field-availability contract is therefore the single statement
//! of what this collector populates. Adding an event family is adding a keyed
//! row there and extending the kernel subscription below.
//!
//! Most families need their audit subcategory enabled, and the object-access
//! families additionally need a SACL on the object; the required policy for
//! each event is in `docs/windows-logging.md`.

use anyhow::{anyhow, Context, Result};

use crate::field_availability::contract_for_event_id;
use crate::models::SecurityAuditFields;
use crate::sensor::{Platform, RawEvent, RawPayload, SensorAction, SensorNormalization};

use super::{parse_system_time, EventLogSource};

/// One `Select` of the structured subscription query: the listed event IDs,
/// from one provider.
///
/// The Event Log query parser rejects an XPath expression with more than 23
/// terms. Measured on Windows 11: a provider test and 22 `EventID` comparisons
/// is the largest accepted, one more fails with "the specified query is
/// invalid". The families together are well past that, so each gets its own
/// `Select`, and a test holds every one of them under the limit.
macro_rules! select {
    ($provider:literal; $first:literal $(, $rest:literal)* $(,)?) => {
        concat!(
            "<Select Path=\"Security\">*[System[Provider[@Name='",
            $provider,
            "'] and (EventID=",
            $first,
            $(" or EventID=", $rest,)*
            ")]]</Select>"
        )
    };
}

/// Every family subscribed unconditionally.
macro_rules! default_selects {
    () => {
        concat!(
            // Logon, logon failure, explicit credentials, credential validation.
            select!("Microsoft-Windows-Security-Auditing"; 4624, 4625, 4648, 4771, 4776),
            // Object access, registry values, shares, directory service changes.
            select!("Microsoft-Windows-Security-Auditing"; 4656, 4657, 4663, 5136, 5145),
            // Service installation and scheduled tasks.
            select!("Microsoft-Windows-Security-Auditing"; 4697, 4698, 4699, 4700, 4701, 4702),
            // Account management, and Credential Manager reads (5379).
            select!(
                "Microsoft-Windows-Security-Auditing";
                4720, 4722, 4724, 4726, 4728, 4732, 4738, 4740, 4741, 4743, 4756, 4765, 4766,
                4781, 4794, 5379
            ),
            // Audit policy, filtering platform policy, and device changes.
            select!("Microsoft-Windows-Security-Auditing"; 4719, 4817, 5447, 6416),
            // The Event Log service writes the log-cleared record itself.
            select!("Microsoft-Windows-Eventlog"; 1102),
        )
    };
}

/// The long-tail families behind `windows.security_long_tail_events`.
macro_rules! long_tail_selects {
    () => {
        select!("Microsoft-Windows-Security-Auditing"; 4672, 4799, 5140)
    };
}

/// The per-connection families behind
/// `windows.security_filtering_platform_connections`.
macro_rules! filtering_platform_selects {
    () => {
        select!("Microsoft-Windows-Security-Auditing"; 5152, 5156, 5157)
    };
}

/// The domain-controller families behind
/// `windows.security_domain_controller_events`.
macro_rules! domain_controller_selects {
    () => {
        concat!(
            // Kerberos ticket requests and directory object operations.
            select!("Microsoft-Windows-Security-Auditing"; 4768, 4769, 4662, 4742),
            // SAM and directory handles, privileged services, directory object
            // creation and deletion.
            select!("Microsoft-Windows-Security-Auditing"; 4661, 4673, 5137, 5141),
        )
    };
}

/// A structured query: the default families plus each named option.
///
/// Written out rather than built at runtime: the query is what the kernel
/// filters on, so an event family is only reachable if it appears both here and
/// in the table, and a reviewer can see the two agree.
macro_rules! query {
    ($($option:ident),* $(,)?) => {
        concat!(
            "<QueryList><Query Id=\"0\" Path=\"Security\">",
            default_selects!(),
            $($option!(),)*
            "</Query></QueryList>"
        )
    };
}

const QUERY: &str = query!();

/// [`QUERY`] plus the per-connection Windows Filtering Platform events, for
/// `windows.security_filtering_platform_connections`.
const QUERY_WITH_FILTERING_PLATFORM_CONNECTIONS: &str = query!(filtering_platform_selects);

/// [`QUERY`] plus the long-tail events, for `windows.security_long_tail_events`.
const QUERY_WITH_LONG_TAIL: &str = query!(long_tail_selects);

/// [`QUERY`] plus the domain-controller events, for
/// `windows.security_domain_controller_events`.
const QUERY_WITH_DOMAIN_CONTROLLER: &str = query!(domain_controller_selects);

const QUERY_WITH_CONNECTIONS_AND_LONG_TAIL: &str =
    query!(filtering_platform_selects, long_tail_selects);
const QUERY_WITH_CONNECTIONS_AND_DOMAIN_CONTROLLER: &str =
    query!(filtering_platform_selects, domain_controller_selects);
const QUERY_WITH_LONG_TAIL_AND_DOMAIN_CONTROLLER: &str =
    query!(long_tail_selects, domain_controller_selects);

/// All options.
const QUERY_WITH_ALL: &str = query!(
    filtering_platform_selects,
    long_tail_selects,
    domain_controller_selects
);

pub(super) const fn source(
    filtering_platform_connections: bool,
    long_tail_events: bool,
    domain_controller_events: bool,
) -> EventLogSource {
    let query = match (
        filtering_platform_connections,
        long_tail_events,
        domain_controller_events,
    ) {
        (false, false, false) => QUERY,
        (true, false, false) => QUERY_WITH_FILTERING_PLATFORM_CONNECTIONS,
        (false, true, false) => QUERY_WITH_LONG_TAIL,
        (false, false, true) => QUERY_WITH_DOMAIN_CONTROLLER,
        (true, true, false) => QUERY_WITH_CONNECTIONS_AND_LONG_TAIL,
        (true, false, true) => QUERY_WITH_CONNECTIONS_AND_DOMAIN_CONTROLLER,
        (false, true, true) => QUERY_WITH_LONG_TAIL_AND_DOMAIN_CONTROLLER,
        (true, true, true) => QUERY_WITH_ALL,
    };
    EventLogSource::new("security-audit", "Security", query, decode)
}

/// The action an audit event reports, for logging and downstream routing.
fn action_for_event(event_id: u16) -> SensorAction {
    match event_id {
        4624 | 4625 | 4648 | 4768 | 4769 | 4771 | 4776 => SensorAction::Start,
        4740 | 4742 => SensorAction::Modify,
        4697 | 4698 | 6416 => SensorAction::Register,
        4720 | 4741 | 5137 => SensorAction::Create,
        1102 | 4699 | 4726 | 4743 | 5141 => SensorAction::Delete,
        4781 => SensorAction::Rename,
        4657 => SensorAction::Set,
        5152 | 5156 | 5157 => SensorAction::Connect,
        4700 | 4701 | 4702 | 4719 | 4722 | 4724 | 4728 | 4732 | 4738 | 4756 | 4765 | 4766
        | 4794 | 4817 | 5136 | 5447 => SensorAction::Modify,
        _ => SensorAction::Access,
    }
}

fn decode(xml: &str) -> Result<RawEvent> {
    let document = roxmltree::Document::parse(xml).context("invalid security event XML")?;
    let system = document
        .descendants()
        .find(|node| node.has_tag_name("System"))
        .context("security event XML has no System element")?;

    let event_id = child_text(system, "EventID")
        .context("security event XML has no EventID")?
        .parse::<u16>()
        .context("security event XML has an invalid EventID")?;

    let contract =
        contract_for_event_id(Platform::Windows, "security", event_id, "windows_event_log")
            .ok_or_else(|| anyhow!("unsupported Security event ID {event_id}"))?;

    let channel = child_text(system, "Channel").context("security event XML has no Channel")?;
    let expected_channel = contract
        .fields
        .iter()
        .find(|field| field.field == "Channel")
        .and_then(|field| field.value);
    if Some(channel) != expected_channel {
        return Err(anyhow!(
            "unexpected channel {channel:?} for Security event {event_id}"
        ));
    }

    // The contract names the provider that writes each event ID, so an ID
    // reused by another provider in the channel is not mistaken for it.
    let provider = system
        .children()
        .find(|node| node.has_tag_name("Provider"))
        .and_then(|node| node.attribute("Name"));
    if provider != Some(contract.source) {
        return Err(anyhow!(
            "unexpected provider {provider:?} for Security event {event_id}"
        ));
    }
    let allowed = |name: &str| contract.fields.iter().any(|field| field.field == name);

    let mut fields = SecurityAuditFields::default();
    for (name, value) in event_properties(&document) {
        if allowed(name) {
            fields.insert(name, value);
        }
    }

    if fields.fields.is_empty() {
        return Err(anyhow!("Security event {event_id} carried no decoded data"));
    }
    if allowed("Provider_Name") {
        fields.insert("Provider_Name", contract.source);
    }

    let timestamp = system
        .children()
        .find(|node| node.has_tag_name("TimeCreated"))
        .and_then(|node| node.attribute("SystemTime"))
        .and_then(parse_system_time)
        .context("security event XML has no valid TimeCreated timestamp")?;
    let source_seq = child_text(system, "EventRecordID")
        .context("security event XML has no EventRecordID")?
        .parse::<u64>()
        .context("security event XML has an invalid EventRecordID")?;

    // The `ProcessId` in the payload stays as Windows renders it, in hex, for
    // rules to match. The pipeline needs a number to reach the process cache,
    // so the parsed value rides along on the event instead.
    let pid = fields.process_id();

    Ok(RawEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::Windows,
        provider: "windows_event_log",
        action: action_for_event(event_id),
        normalization: SensorNormalization {
            event_id,
            action_code: 0,
        },
        pid,
        timestamp,
        source_seq: Some(source_seq),
        process_start_key: None,
        parent_process_start_key: None,
        payload: RawPayload::Security(fields),
    })
}

/// The event's named properties, in document order.
///
/// Manifest-based audit events render them as `<EventData><Data Name=...>`.
/// The Event Log service's own events, such as 1102, use a `UserData` template
/// instead: one wrapper element whose leaf children are the properties.
fn event_properties<'a, 'input>(
    document: &'a roxmltree::Document<'input>,
) -> impl Iterator<Item = (&'a str, &'a str)> {
    let event_data = document
        .descendants()
        .filter(|node| node.has_tag_name("Data"))
        .filter_map(|node| Some((node.attribute("Name")?, node.text().unwrap_or_default())));
    let user_data = document
        .descendants()
        .filter(|node| node.has_tag_name("UserData"))
        .flat_map(|node| node.descendants())
        .filter(|node| node.is_element() && !node.children().any(|child| child.is_element()))
        .filter(|node| !node.has_tag_name("UserData"))
        .map(|node| (node.tag_name().name(), node.text().unwrap_or_default()));
    event_data.chain(user_data)
}

fn child_text<'a, 'input>(node: roxmltree::Node<'a, 'input>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|child| child.has_tag_name(name))
        .and_then(|child| child.text())
}

#[cfg(test)]
mod tests {
    use super::{
        decode, source, QUERY, QUERY_WITH_ALL, QUERY_WITH_CONNECTIONS_AND_DOMAIN_CONTROLLER,
        QUERY_WITH_CONNECTIONS_AND_LONG_TAIL, QUERY_WITH_DOMAIN_CONTROLLER,
        QUERY_WITH_FILTERING_PLATFORM_CONNECTIONS, QUERY_WITH_LONG_TAIL,
        QUERY_WITH_LONG_TAIL_AND_DOMAIN_CONTROLLER,
    };
    use crate::engine::Engine;
    use crate::field_availability::FIELD_AVAILABILITY;
    use crate::normalizer::Normalizer;
    use crate::sensor::{RawPayload, SensorAction};
    use crate::state::HostState;
    use std::sync::Arc;

    fn security_event(event_id: u16, event_data: &str) -> String {
        format!(
            r#"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="2026-08-25T12:34:56.1234567Z"/>
    <EventRecordID>81234</EventRecordID>
    <Channel>Security</Channel>
    <Computer>lab-windows</Computer>
  </System>
  <EventData>
{event_data}
  </EventData>
</Event>"#
        )
    }

    fn fields(xml: &str) -> crate::models::SecurityAuditFields {
        let event = decode(xml).expect("event should decode");
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        fields
    }

    const SUBJECT: &str = r#"    <Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="SubjectDomainName">ACME</Data>
    <Data Name="SubjectLogonId">0x3e4</Data>"#;

    #[test]
    fn decodes_a_service_installation() {
        let xml = security_event(
            4697,
            &format!(
                r#"{SUBJECT}
    <Data Name="ServiceName">RustinelIssue315</Data>
    <Data Name="ServiceFileName">C:\Windows\Temp\payload.exe</Data>
    <Data Name="ServiceType">0x10</Data>
    <Data Name="ServiceStartType">3</Data>
    <Data Name="ServiceAccount">LocalSystem</Data>"#
            ),
        );

        let event = decode(&xml).expect("4697 should decode");
        assert_eq!(event.action, SensorAction::Register);
        assert_eq!(event.normalization.event_id, 4697);
        assert_eq!(event.provider, "windows_event_log");
        assert_eq!(event.source_seq, Some(81234));

        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("ServiceName"), Some("RustinelIssue315"));
        assert_eq!(
            fields.get("ServiceFileName"),
            Some(r"C:\Windows\Temp\payload.exe")
        );
        assert_eq!(fields.get("ServiceStartType"), Some("3"));
        assert_eq!(fields.get("ServiceAccount"), Some("LocalSystem"));
        assert_eq!(fields.get("SubjectUserName"), Some("alice"));
        assert_eq!(fields.get("SubjectLogonId"), Some("0x3e4"));
    }

    #[test]
    fn rejects_a_record_from_a_different_channel() {
        let xml = security_event(4624, SUBJECT).replace(
            "<Channel>Security</Channel>",
            "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>",
        );
        assert!(decode(&xml).is_err());
    }

    #[test]
    fn decodes_a_successful_logon() {
        let xml = security_event(
            4624,
            &format!(
                r#"{SUBJECT}
    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetDomainName">ACME</Data>
    <Data Name="TargetLogonId">0x1a2b3c</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="LogonProcessName">NtLmSsp</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="WorkstationName">WKSTN01</Data>
    <Data Name="IpAddress">10.0.0.9</Data>
    <Data Name="IpPort">49512</Data>
    <Data Name="ProcessId">0x0</Data>
    <Data Name="ProcessName">-</Data>"#
            ),
        );

        let event = decode(&xml).expect("4624 should decode");
        assert_eq!(event.action, SensorAction::Start);

        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("LogonType"), Some("3"));
        assert_eq!(fields.get("AuthenticationPackageName"), Some("NTLM"));
        assert_eq!(fields.get("IpAddress"), Some("10.0.0.9"));
        assert_eq!(fields.get("TargetUserName"), Some("bob"));
        // Preserve placeholders for every allowlisted field, not only the IP
        // field from the reported regression. Rules can filter any of them.
        assert_eq!(fields.get("ProcessName"), Some("-"));
        // Presentation and enrichment consumers still omit placeholders.
        assert_eq!(fields.get_non_placeholder("ProcessName"), None);
    }

    #[test]
    fn sigmahq_external_smb_rule_distinguishes_placeholder_private_public_and_missing_ip() {
        let rules = tempfile::tempdir().expect("create Sigma rule directory");
        std::fs::write(
            rules.path().join("external-smb.yml"),
            r#"title: External Remote SMB Logon from Public IP
id: 78d5cab4-557e-454f-9fb9-a222bd0d5edc
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
    filter_main_local_ranges:
        IpAddress|cidr:
            - '::1/128'
            - '10.0.0.0/8'
            - '127.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '169.254.0.0/16'
            - 'fc00::/7'
            - 'fe80::/10'
    filter_main_empty:
        IpAddress: '-'
    condition: selection and not 1 of filter_main_*
level: high
"#,
        )
        .expect("write SigmaHQ regression rule");

        let mut engine = Engine::new_for_platform(crate::sensor::Platform::Windows);
        engine
            .load_rules(rules.path())
            .expect("load SigmaHQ regression rule");
        let normalizer = Normalizer::new(Arc::new(HostState::default()));

        let cases = [
            ("placeholder", Some("-"), false),
            ("private", Some("10.0.0.9"), false),
            ("public", Some("198.51.100.10"), true),
            // An absent field does not satisfy either filter and remains
            // intentionally distinct from an explicit Windows placeholder.
            ("missing", None, true),
        ];

        for (name, ip_address, should_alert) in cases {
            let ip_data = ip_address
                .map(|value| format!(r#"    <Data Name="IpAddress">{value}</Data>"#))
                .unwrap_or_default();
            let xml = security_event(
                4624,
                &format!(
                    r#"{SUBJECT}
    <Data Name="LogonType">3</Data>
{ip_data}"#
                ),
            );
            let decoded = decode(&xml).expect("4624 should decode");
            let normalized = normalizer
                .normalize(&decoded)
                .expect("Security event should normalize");

            assert_eq!(normalized.get_field("IpAddress"), ip_address, "{name}");
            assert_eq!(
                !engine.evaluate_event(&normalized).is_empty(),
                should_alert,
                "{name} IpAddress case"
            );
        }
    }

    #[test]
    fn decodes_an_object_access_attempt() {
        let xml = security_event(
            4663,
            &format!(
                r#"{SUBJECT}
    <Data Name="ObjectServer">Security</Data>
    <Data Name="ObjectType">File</Data>
    <Data Name="ObjectName">C:\Users\alice\Documents\secrets.docx</Data>
    <Data Name="HandleId">0x8f4</Data>
    <Data Name="AccessList">%%4416
				</Data>
    <Data Name="AccessMask">0x1</Data>
    <Data Name="ProcessId">0x4d8</Data>
    <Data Name="ProcessName">C:\Windows\System32\notepad.exe</Data>"#
            ),
        );

        let event = decode(&xml).expect("4663 should decode");
        assert_eq!(event.action, SensorAction::Access);
        // Hex in the payload for rules, parsed for the pipeline.
        assert_eq!(event.pid, Some(0x4d8));

        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("ProcessId"), Some("0x4d8"));
        assert_eq!(fields.get("ObjectType"), Some("File"));
        assert_eq!(
            fields.get("ObjectName"),
            Some(r"C:\Users\alice\Documents\secrets.docx")
        );
        assert!(fields.get("AccessList").unwrap().contains("%%4416"));
    }

    #[test]
    fn decodes_a_handle_request() {
        let xml = security_event(
            4656,
            &format!(
                r#"{SUBJECT}
    <Data Name="ObjectServer">Security</Data>
    <Data Name="ObjectType">Key</Data>
    <Data Name="ObjectName">\REGISTRY\MACHINE\SECURITY</Data>
    <Data Name="AccessMask">0x20019</Data>
    <Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>"#
            ),
        );

        let fields = fields(&xml);
        assert_eq!(fields.get("ObjectType"), Some("Key"));
        assert_eq!(
            fields.get("ObjectName"),
            Some(r"\REGISTRY\MACHINE\SECURITY")
        );
        assert_eq!(fields.get("AccessMask"), Some("0x20019"));
    }

    #[test]
    fn decodes_a_network_share_check() {
        let xml = security_event(
            5145,
            &format!(
                r#"{SUBJECT}
    <Data Name="ObjectType">File</Data>
    <Data Name="IpAddress">10.0.0.9</Data>
    <Data Name="IpPort">50123</Data>
    <Data Name="ShareName">\\*\ADMIN$</Data>
    <Data Name="ShareLocalPath">\??\C:\Windows</Data>
    <Data Name="RelativeTargetName">PSEXESVC.exe</Data>
    <Data Name="AccessMask">0x100081</Data>"#
            ),
        );

        let fields = fields(&xml);
        assert_eq!(fields.get("ShareName"), Some(r"\\*\ADMIN$"));
        assert_eq!(fields.get("RelativeTargetName"), Some("PSEXESVC.exe"));
        assert_eq!(fields.get("IpAddress"), Some("10.0.0.9"));
    }

    #[test]
    fn decodes_a_directory_service_change() {
        let xml = security_event(
            5136,
            &format!(
                r#"{SUBJECT}
    <Data Name="DSName">acme.test</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">CN=svc-backup,CN=Users,DC=acme,DC=test</Data>
    <Data Name="ObjectClass">user</Data>
    <Data Name="AttributeLDAPDisplayName">msDS-AllowedToDelegateTo</Data>
    <Data Name="AttributeValue">cifs/dc01.acme.test</Data>
    <Data Name="OperationType">%%14674</Data>"#
            ),
        );

        let event = decode(&xml).expect("5136 should decode");
        assert_eq!(event.action, SensorAction::Modify);

        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(
            fields.get("AttributeLDAPDisplayName"),
            Some("msDS-AllowedToDelegateTo")
        );
        assert_eq!(fields.get("AttributeValue"), Some("cifs/dc01.acme.test"));
        assert_eq!(fields.get("ObjectClass"), Some("user"));
    }

    #[test]
    fn drops_properties_outside_the_event_allowlist() {
        let xml = security_event(
            4697,
            &format!(
                r#"{SUBJECT}
    <Data Name="ServiceName">RustinelIssue315</Data>
    <Data Name="ServiceFileName">C:\Windows\Temp\payload.exe</Data>
    <Data Name="ObjectName">C:\not-a-4697-property</Data>"#
            ),
        );

        let fields = fields(&xml);
        assert_eq!(fields.get("ServiceName"), Some("RustinelIssue315"));
        assert_eq!(fields.get("ObjectName"), None);
    }

    #[test]
    fn rejects_an_unsupported_event_id() {
        let xml = security_event(4688, r#"    <Data Name="SubjectUserName">alice</Data>"#);
        assert!(decode(&xml).is_err());
    }

    #[test]
    fn rejects_a_different_provider() {
        let xml = security_event(4697, r#"    <Data Name="ServiceName">svc</Data>"#)
            .replace("Microsoft-Windows-Security-Auditing", "Other Provider");
        assert!(decode(&xml).is_err());
    }

    /// The provider is checked per event ID: 1102 is only the Event Log
    /// service's, and the Security auditing IDs are never its.
    #[test]
    fn each_event_id_is_accepted_only_from_its_own_provider() {
        let audit_1102 = security_event(1102, SUBJECT);
        assert!(decode(&audit_1102).is_err());

        let eventlog_4624 = security_event(4624, r#"    <Data Name="LogonType">3</Data>"#).replace(
            "Microsoft-Windows-Security-Auditing",
            "Microsoft-Windows-Eventlog",
        );
        assert!(decode(&eventlog_4624).is_err());
    }

    fn scheduled_task_xml(command: &str, arguments: &str) -> String {
        // The task definition is XML escaped inside the event XML, exactly as
        // the channel renders it.
        format!(
            "&lt;?xml version=\"1.0\" encoding=\"UTF-16\"?&gt;\r\n\
             &lt;Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"&gt;\r\n\
             &lt;Actions Context=\"Author\"&gt;\r\n\
             &lt;Exec&gt;\r\n\
             &lt;Command&gt;{command}&lt;/Command&gt;\r\n\
             &lt;Arguments&gt;{arguments}&lt;/Arguments&gt;\r\n\
             &lt;/Exec&gt;\r\n\
             &lt;/Actions&gt;\r\n\
             &lt;/Task&gt;"
        )
    }

    #[test]
    fn decodes_a_scheduled_task_registration_with_its_action() {
        let content = scheduled_task_xml("cmd.exe", r"/c C:\Users\Public\stage.bat");
        let xml = security_event(
            4698,
            &format!(
                r#"{SUBJECT}
    <Data Name="TaskName">\RustinelIssue479</Data>
    <Data Name="TaskContent">{content}</Data>
    <Data Name="ClientProcessStartKey">6192449487634712</Data>
    <Data Name="ClientProcessId">7424</Data>
    <Data Name="ParentProcessId">6044</Data>
    <Data Name="RpcCallClientLocality">0</Data>
    <Data Name="FQDN">lab-windows</Data>"#
            ),
        );

        let event = decode(&xml).expect("4698 should decode");
        assert_eq!(event.action, SensorAction::Register);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("TaskName"), Some(r"\RustinelIssue479"));
        let task = fields.get("TaskContent").expect("TaskContent is decoded");
        // Unescaped once by the XML parser: rules match the task XML itself.
        assert!(task.contains("<Command>cmd.exe</Command>"), "{task}");
        assert!(
            task.contains(r"<Arguments>/c C:\Users\Public\stage.bat</Arguments>"),
            "{task}"
        );
        assert_eq!(fields.get("ClientProcessId"), Some("7424"));
    }

    #[test]
    fn decodes_a_scheduled_task_update_as_its_new_content() {
        let content = scheduled_task_xml("powershell.exe", r"-File C:\ProgramData\u.ps1");
        let xml = security_event(
            4702,
            &format!(
                r#"{SUBJECT}
    <Data Name="TaskName">\RustinelIssue479</Data>
    <Data Name="TaskContentNew">{content}</Data>"#
            ),
        );

        let event = decode(&xml).expect("4702 should decode");
        assert_eq!(event.action, SensorAction::Modify);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert!(fields
            .get("TaskContentNew")
            .is_some_and(|task| task.contains("<Command>powershell.exe</Command>")));
        assert_eq!(fields.get("TaskContent"), None);
    }

    #[test]
    fn decodes_a_failed_logon_with_its_status_codes() {
        let xml = security_event(
            4625,
            r#"    <Data Name="SubjectUserSid">S-1-0-0</Data>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="SubjectDomainName">-</Data>
    <Data Name="SubjectLogonId">0x0</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">rustinel479$</Data>
    <Data Name="TargetDomainName">LAB-WINDOWS</Data>
    <Data Name="Status">0xc000006e</Data>
    <Data Name="FailureReason">%%2310</Data>
    <Data Name="SubStatus">0xc0000072</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="LogonProcessName">NtLmSsp </Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="WorkstationName">LAB-WINDOWS</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0x0</Data>
    <Data Name="ProcessName">-</Data>
    <Data Name="IpAddress">198.51.100.10</Data>
    <Data Name="IpPort">49712</Data>"#,
        );

        let event = decode(&xml).expect("4625 should decode");
        assert_eq!(event.action, SensorAction::Start);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("Status"), Some("0xc000006e"));
        assert_eq!(fields.get("SubStatus"), Some("0xc0000072"));
        assert_eq!(fields.get("FailureReason"), Some("%%2310"));
        assert_eq!(fields.get("IpAddress"), Some("198.51.100.10"));
        assert_eq!(fields.get("SubjectUserSid"), Some("S-1-0-0"));
    }

    /// Credential validation names no subject; its template has none.
    #[test]
    fn decodes_a_credential_validation_without_a_subject() {
        let xml = security_event(
            4776,
            r#"    <Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>
    <Data Name="TargetUserName">rustinel479$</Data>
    <Data Name="Workstation">LAB-WINDOWS</Data>
    <Data Name="Status">0xc0000072</Data>"#,
        );

        let fields = fields(&xml);
        assert_eq!(fields.get("Workstation"), Some("LAB-WINDOWS"));
        assert_eq!(fields.get("Status"), Some("0xc0000072"));
        assert_eq!(fields.get("SubjectUserSid"), None);
    }

    #[test]
    fn decodes_account_management_events() {
        let created = security_event(
            4720,
            &format!(
                r#"    <Data Name="TargetUserName">rustinel479$</Data>
    <Data Name="TargetDomainName">LAB-WINDOWS</Data>
    <Data Name="TargetSid">S-1-5-21-1-2-3-1010</Data>
{SUBJECT}
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">rustinel479$</Data>
    <Data Name="OldUacValue">0x0</Data>
    <Data Name="NewUacValue">0x15</Data>
    <Data Name="SidHistory">-</Data>"#
            ),
        );
        let event = decode(&created).expect("4720 should decode");
        assert_eq!(event.action, SensorAction::Create);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("SamAccountName"), Some("rustinel479$"));
        assert_eq!(fields.get("NewUacValue"), Some("0x15"));
        assert_eq!(fields.get("SidHistory"), Some("-"));

        let added = security_event(
            4732,
            &format!(
                r#"    <Data Name="MemberName">-</Data>
    <Data Name="MemberSid">S-1-5-21-1-2-3-1010</Data>
    <Data Name="TargetUserName">Administrators</Data>
    <Data Name="TargetDomainName">Builtin</Data>
    <Data Name="TargetSid">S-1-5-32-544</Data>
{SUBJECT}
    <Data Name="PrivilegeList">-</Data>"#
            ),
        );
        let event = decode(&added).expect("4732 should decode");
        assert_eq!(event.action, SensorAction::Modify);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("TargetSid"), Some("S-1-5-32-544"));
        assert_eq!(fields.get("MemberSid"), Some("S-1-5-21-1-2-3-1010"));

        let renamed = security_event(
            4781,
            &format!(
                r#"    <Data Name="OldTargetUserName">rustinel479$</Data>
    <Data Name="NewTargetUserName">rustinel479renamed$</Data>
    <Data Name="TargetDomainName">LAB-WINDOWS</Data>
    <Data Name="TargetSid">S-1-5-21-1-2-3-1010</Data>
{SUBJECT}"#
            ),
        );
        let event = decode(&renamed).expect("4781 should decode");
        assert_eq!(event.action, SensorAction::Rename);
    }

    #[test]
    fn decodes_an_account_lockout_and_the_gated_long_tail() {
        let locked = security_event(
            4740,
            &format!(
                r#"    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetDomainName">DC01</Data>
    <Data Name="TargetSid">S-1-5-21-1-2-3-1105</Data>
{SUBJECT}
    <Data Name="CallerComputerName">WS-042</Data>"#
            ),
        );
        let event = decode(&locked).expect("4740 should decode");
        assert_eq!(event.action, SensorAction::Modify);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("TargetUserName"), Some("bob"));
        assert_eq!(fields.get("CallerComputerName"), Some("WS-042"));

        let privileged = fields_of(
            4672,
            &format!(
                r#"{SUBJECT}
    <Data Name="PrivilegeList">SeDebugPrivilege</Data>"#
            ),
        );
        assert_eq!(privileged.get("PrivilegeList"), Some("SeDebugPrivilege"));

        let share = fields_of(
            5140,
            &format!(
                r#"{SUBJECT}
    <Data Name="ObjectType">File</Data>
    <Data Name="IpAddress">10.0.0.9</Data>
    <Data Name="IpPort">49822</Data>
    <Data Name="ShareName">\\*\C$</Data>
    <Data Name="ShareLocalPath">\??\C:\</Data>
    <Data Name="AccessMask">0x1</Data>
    <Data Name="AccessList">%%1541</Data>"#
            ),
        );
        assert_eq!(share.get("ShareName"), Some(r"\\*\C$"));
        assert_eq!(share.get("IpAddress"), Some("10.0.0.9"));

        let enumerated = fields_of(
            4799,
            &format!(
                r#"    <Data Name="TargetUserName">Administrators</Data>
    <Data Name="TargetDomainName">Builtin</Data>
    <Data Name="TargetSid">S-1-5-32-544</Data>
{SUBJECT}
    <Data Name="CallerProcessId">0x1a4</Data>
    <Data Name="CallerProcessName">C:\Windows\System32\net.exe</Data>"#
            ),
        );
        assert_eq!(enumerated.get("TargetSid"), Some("S-1-5-32-544"));
        assert_eq!(
            enumerated.get("CallerProcessName"),
            Some(r"C:\Windows\System32\net.exe")
        );
    }

    fn fields_of(event_id: u16, event_data: &str) -> crate::models::SecurityAuditFields {
        fields(&security_event(event_id, event_data))
    }

    #[test]
    fn decodes_audit_policy_changes() {
        let xml = security_event(
            4719,
            &format!(
                r#"{SUBJECT}
    <Data Name="CategoryId">%%8274</Data>
    <Data Name="SubcategoryId">%%12804</Data>
    <Data Name="SubcategoryGuid">{{0CCE9227-69AE-11D9-BED3-505054503030}}</Data>
    <Data Name="AuditPolicyChanges">%%8448</Data>"#
            ),
        );

        let fields = fields(&xml);
        assert_eq!(
            fields.get("SubcategoryGuid"),
            Some("{0CCE9227-69AE-11D9-BED3-505054503030}")
        );
        assert_eq!(fields.get("AuditPolicyChanges"), Some("%%8448"));
    }

    /// 1102 is rendered with a `UserData` template, not `EventData`, and
    /// SigmaHQ selects it by `Provider_Name`.
    #[test]
    fn decodes_a_security_log_clear_from_its_user_data() {
        let xml = r#"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"/>
    <EventID>1102</EventID>
    <TimeCreated SystemTime="2026-09-15T12:34:56.1234567Z"/>
    <EventRecordID>1</EventRecordID>
    <Channel>Security</Channel>
    <Computer>lab-windows</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid>
      <SubjectUserName>alice</SubjectUserName>
      <SubjectDomainName>ACME</SubjectDomainName>
      <SubjectLogonId>0x3e4</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>"#;

        let event = decode(xml).expect("1102 should decode");
        assert_eq!(event.action, SensorAction::Delete);
        assert_eq!(event.source_seq, Some(1));
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(
            fields.get("Provider_Name"),
            Some("Microsoft-Windows-Eventlog")
        );
        assert_eq!(fields.get("SubjectUserName"), Some("alice"));
        assert_eq!(fields.get("SubjectLogonId"), Some("0x3e4"));
        // The wrapper element is structure, not a property.
        assert_eq!(fields.get("LogFileCleared"), None);
    }

    #[test]
    fn decodes_a_registry_value_modification() {
        let xml = security_event(
            4657,
            &format!(
                r#"{SUBJECT}
    <Data Name="ObjectName">\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths</Data>
    <Data Name="ObjectValueName">C:\Users\Public</Data>
    <Data Name="HandleId">0x2a8</Data>
    <Data Name="OperationType">%%1904</Data>
    <Data Name="OldValueType">-</Data>
    <Data Name="OldValue">-</Data>
    <Data Name="NewValueType">%%1876</Data>
    <Data Name="NewValue">0</Data>
    <Data Name="ProcessId">0x1a2c</Data>
    <Data Name="ProcessName">C:\Windows\regedit.exe</Data>"#
            ),
        );

        let event = decode(&xml).expect("4657 should decode");
        assert_eq!(event.action, SensorAction::Set);
        assert_eq!(event.pid, Some(0x1a2c));
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("ObjectValueName"), Some(r"C:\Users\Public"));
        assert_eq!(fields.get("NewValue"), Some("0"));
    }

    /// The connection template spells the process ID `ProcessID`, in decimal.
    #[test]
    fn decodes_a_filtering_platform_connection() {
        let xml = security_event(
            5156,
            r#"    <Data Name="ProcessID">5104</Data>
    <Data Name="Application">\device\harddiskvolume3\windows\system32\windowspowershell\v1.0\powershell.exe</Data>
    <Data Name="Direction">%%14593</Data>
    <Data Name="SourceAddress">192.168.1.28</Data>
    <Data Name="SourcePort">50112</Data>
    <Data Name="DestAddress">93.184.215.14</Data>
    <Data Name="DestPort">88</Data>
    <Data Name="Protocol">6</Data>
    <Data Name="FilterRTID">0</Data>
    <Data Name="LayerName">%%14611</Data>
    <Data Name="LayerRTID">48</Data>"#,
        );

        let event = decode(&xml).expect("5156 should decode");
        assert_eq!(event.action, SensorAction::Connect);
        assert_eq!(event.pid, Some(5104));
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("ProcessID"), Some("5104"));
        assert_eq!(fields.get("DestPort"), Some("88"));
        assert_eq!(fields.get("LayerRTID"), Some("48"));
    }

    #[test]
    fn decodes_a_filtering_platform_filter_change_and_a_device() {
        let filter = security_event(
            5447,
            r#"    <Data Name="ProcessId">1204</Data>
    <Data Name="UserSid">S-1-5-19</Data>
    <Data Name="UserName">AUTORITE NT\SERVICE LOCAL</Data>
    <Data Name="ChangeType">%%16385</Data>
    <Data Name="FilterName">Custom Outbound Filter</Data>
    <Data Name="LayerName">ALE Connect v4 Layer</Data>"#,
        );
        let fields_5447 = fields(&filter);
        assert_eq!(
            fields_5447.get("FilterName"),
            Some("Custom Outbound Filter")
        );
        assert_eq!(fields_5447.get("ChangeType"), Some("%%16385"));

        let device = security_event(
            6416,
            &format!(
                r#"{SUBJECT}
    <Data Name="DeviceId">USBSTOR\Disk&amp;Ven_Rustinel&amp;Prod_Issue479\0001</Data>
    <Data Name="DeviceDescription">USB Mass Storage Device</Data>
    <Data Name="ClassName">DiskDrive</Data>"#
            ),
        );
        let event = decode(&device).expect("6416 should decode");
        assert_eq!(event.action, SensorAction::Register);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("ClassName"), Some("DiskDrive"));
        assert_eq!(
            fields.get("DeviceId"),
            Some(r"USBSTOR\Disk&Ven_Rustinel&Prod_Issue479\0001")
        );
    }

    /// Kerberos templates name the account `TargetUserName` and carry no
    /// `Subject*` block.
    #[test]
    fn decodes_kerberos_ticket_requests() {
        let tgt = security_event(
            4768,
            r#"    <Data Name="TargetUserName">svc-sql</Data>
    <Data Name="TargetDomainName">ACME.TEST</Data>
    <Data Name="TargetSid">S-1-5-21-1-2-3-1108</Data>
    <Data Name="ServiceName">krbtgt</Data>
    <Data Name="ServiceSid">S-1-5-21-1-2-3-502</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="PreAuthType">0</Data>
    <Data Name="IpAddress">::ffff:10.0.0.9</Data>
    <Data Name="IpPort">51234</Data>"#,
        );
        let event = decode(&tgt).expect("4768 should decode");
        assert_eq!(event.action, SensorAction::Start);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        // PreAuthType 0 is the AS-REP roasting signal.
        assert_eq!(fields.get("PreAuthType"), Some("0"));
        assert_eq!(fields.get("TicketEncryptionType"), Some("0x17"));
        assert_eq!(fields.get("IpAddress"), Some("::ffff:10.0.0.9"));
        assert_eq!(fields.get("SubjectUserName"), None);

        let tgs = fields_of(
            4769,
            r#"    <Data Name="TargetUserName">alice@ACME.TEST</Data>
    <Data Name="TargetDomainName">ACME.TEST</Data>
    <Data Name="ServiceName">svc-sql</Data>
    <Data Name="ServiceSid">S-1-5-21-1-2-3-1108</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">::ffff:10.0.0.9</Data>
    <Data Name="IpPort">51240</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
    <Data Name="TransmittedServices">-</Data>"#,
        );
        // RC4 against a user service account is the Kerberoasting signal.
        assert_eq!(tgs.get("TicketEncryptionType"), Some("0x17"));
        assert_eq!(tgs.get("ServiceName"), Some("svc-sql"));
        assert_eq!(tgs.get("Status"), Some("0x0"));
    }

    #[test]
    fn decodes_a_directory_object_operation() {
        let xml = security_event(
            4662,
            &format!(
                r#"{SUBJECT}
    <Data Name="ObjectServer">DS</Data>
    <Data Name="ObjectType">%{{19195a5b-6da0-11d0-afd3-00c04fd930c9}}</Data>
    <Data Name="ObjectName">%{{3f7a1c0e-0000-0000-0000-000000000001}}</Data>
    <Data Name="OperationType">Object Access</Data>
    <Data Name="HandleId">0x0</Data>
    <Data Name="AccessList">%%7688
			</Data>
    <Data Name="AccessMask">0x100</Data>
    <Data Name="Properties">%%7688
		{{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}}
	{{19195a5b-6da0-11d0-afd3-00c04fd930c9}}</Data>
    <Data Name="AdditionalInfo">-</Data>
    <Data Name="AdditionalInfo2"></Data>"#
            ),
        );
        let event = decode(&xml).expect("4662 should decode");
        assert_eq!(event.action, SensorAction::Access);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        // The replication-rights GUID DCSync rules look for.
        assert!(fields
            .get("Properties")
            .is_some_and(|value| value.contains("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")));
        assert_eq!(fields.get("AccessMask"), Some("0x100"));
        assert_eq!(fields.get("ObjectServer"), Some("DS"));
    }

    #[test]
    fn decodes_a_computer_account_change() {
        let xml = security_event(
            4742,
            &format!(
                r#"    <Data Name="ComputerAccountChange">-</Data>
    <Data Name="TargetUserName">WS-042$</Data>
    <Data Name="TargetDomainName">ACME</Data>
    <Data Name="TargetSid">S-1-5-21-1-2-3-1120</Data>
{SUBJECT}
    <Data Name="SamAccountName">-</Data>
    <Data Name="AllowedToDelegateTo">cifs/dc01.acme.test</Data>
    <Data Name="OldUacValue">0x80</Data>
    <Data Name="NewUacValue">0x1080</Data>
    <Data Name="UserAccountControl">%%2096</Data>
    <Data Name="DnsHostName">-</Data>
    <Data Name="ServicePrincipalNames">-</Data>"#
            ),
        );
        let event = decode(&xml).expect("4742 should decode");
        assert_eq!(event.action, SensorAction::Modify);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(
            fields.get("AllowedToDelegateTo"),
            Some("cifs/dc01.acme.test")
        );
        assert_eq!(fields.get("NewUacValue"), Some("0x1080"));
        assert_eq!(fields.get("TargetUserName"), Some("WS-042$"));
    }

    #[test]
    fn decodes_sam_handles_and_privileged_service_calls() {
        let handle = security_event(
            4661,
            &format!(
                r#"{SUBJECT}
    <Data Name="ObjectServer">Security Account Manager</Data>
    <Data Name="ObjectType">SAM_DOMAIN</Data>
    <Data Name="ObjectName">DC=acme,DC=test</Data>
    <Data Name="HandleId">0x7f8</Data>
    <Data Name="TransactionId">{{00000000-0000-0000-0000-000000000000}}</Data>
    <Data Name="AccessList">%%5400</Data>
    <Data Name="AccessMask">0x20094</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="Properties">-</Data>
    <Data Name="RestrictedSidCount">0</Data>
    <Data Name="ProcessId">0x2b4</Data>
    <Data Name="ProcessName">C:\Windows\System32\lsass.exe</Data>"#
            ),
        );
        let event = decode(&handle).expect("4661 should decode");
        assert_eq!(event.pid, Some(0x2b4));
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("ObjectType"), Some("SAM_DOMAIN"));
        assert_eq!(fields.get("AccessMask"), Some("0x20094"));

        let service = fields_of(
            4673,
            &format!(
                r#"{SUBJECT}
    <Data Name="ObjectServer">NT Local Security Authority / Authentication Service</Data>
    <Data Name="Service">LsaRegisterLogonProcess()</Data>
    <Data Name="PrivilegeList">SeTcbPrivilege</Data>
    <Data Name="ProcessId">0x3a0</Data>
    <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>"#
            ),
        );
        assert_eq!(service.get("PrivilegeList"), Some("SeTcbPrivilege"));
        assert_eq!(service.get("Service"), Some("LsaRegisterLogonProcess()"));
    }

    #[test]
    fn decodes_directory_object_creation_and_deletion() {
        let created = security_event(
            5137,
            &format!(
                r#"    <Data Name="OpCorrelationID">{{aaaaaaaa-0000-0000-0000-000000000001}}</Data>
    <Data Name="AppCorrelationID">-</Data>
{SUBJECT}
    <Data Name="DSName">acme.test</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">CN=Rustinel GPO,CN=Policies,CN=System,DC=acme,DC=test</Data>
    <Data Name="ObjectGUID">{{bbbbbbbb-0000-0000-0000-000000000002}}</Data>
    <Data Name="ObjectClass">groupPolicyContainer</Data>"#
            ),
        );
        let event = decode(&created).expect("5137 should decode");
        assert_eq!(event.action, SensorAction::Create);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("ObjectClass"), Some("groupPolicyContainer"));

        let deleted = security_event(
            5141,
            &format!(
                r#"{SUBJECT}
    <Data Name="DSName">acme.test</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">CN=Rustinel GPO,CN=Policies,CN=System,DC=acme,DC=test</Data>
    <Data Name="ObjectGUID">{{bbbbbbbb-0000-0000-0000-000000000002}}</Data>
    <Data Name="ObjectClass">groupPolicyContainer</Data>
    <Data Name="TreeDelete">%%14679</Data>"#
            ),
        );
        let event = decode(&deleted).expect("5141 should decode");
        assert_eq!(event.action, SensorAction::Delete);
        let RawPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("TreeDelete"), Some("%%14679"));
    }

    #[test]
    fn decodes_a_credential_manager_read() {
        let fields = fields_of(
            5379,
            &format!(
                r#"{SUBJECT}
    <Data Name="TargetName">MicrosoftAccount:user=02qbnmaybaimkvrv</Data>
    <Data Name="Type">0</Data>
    <Data Name="CountOfCredentialsReturned">0</Data>
    <Data Name="ReadOperation">%%8100</Data>
    <Data Name="ReturnCode">3221226021</Data>
    <Data Name="ProcessCreationTime">2026-10-19T15:02:43.4847929Z</Data>
    <Data Name="ClientProcessId">4412</Data>"#
            ),
        );
        assert_eq!(
            fields.get("TargetName"),
            Some("MicrosoftAccount:user=02qbnmaybaimkvrv")
        );
        assert_eq!(fields.get("ClientProcessId"), Some("4412"));
        assert_eq!(fields.get("ReturnCode"), Some("3221226021"));
        assert_eq!(fields.get("ReadOperation"), Some("%%8100"));
    }

    /// `(provider, event IDs)` for each `Select` of a structured query.
    fn selects(query: &str) -> Vec<(String, Vec<u16>)> {
        let document = roxmltree::Document::parse(query).expect("the query is valid XML");
        document
            .descendants()
            .filter(|node| node.has_tag_name("Select"))
            .map(|node| {
                assert_eq!(node.attribute("Path"), Some("Security"));
                let xpath = node.text().expect("a Select holds an XPath");
                let provider = xpath
                    .split("@Name='")
                    .nth(1)
                    .and_then(|rest| rest.split('\'').next())
                    .expect("each Select names its provider")
                    .to_string();
                let ids = xpath
                    .split("EventID=")
                    .skip(1)
                    .map(|rest| {
                        let digits: String =
                            rest.chars().take_while(char::is_ascii_digit).collect();
                        digits
                            .parse()
                            .expect("an EventID comparison holds a number")
                    })
                    .collect();
                (provider, ids)
            })
            .collect()
    }

    /// Every `(provider, event ID)` a query subscribes to.
    fn subscribed(query: &str) -> std::collections::BTreeSet<(String, u16)> {
        selects(query)
            .into_iter()
            .flat_map(|(provider, ids)| ids.into_iter().map(move |id| (provider.clone(), id)))
            .collect()
    }

    const FILTERING_PLATFORM_CONNECTION_EVENTS: [u16; 3] = [5152, 5156, 5157];
    const LONG_TAIL_EVENTS: [u16; 3] = [4672, 4799, 5140];
    const DOMAIN_CONTROLLER_EVENTS: [u16; 8] = [4661, 4662, 4673, 4742, 4768, 4769, 5137, 5141];

    #[test]
    fn the_subscription_query_covers_exactly_the_supported_events() {
        let supported: std::collections::BTreeSet<(String, u16)> = FIELD_AVAILABILITY
            .iter()
            .filter(|contract| {
                contract.platform == crate::sensor::Platform::Windows
                    && contract.category == "security"
                    && contract.provider == "windows_event_log"
            })
            .map(|contract| {
                (
                    contract.source.to_string(),
                    contract
                        .event_id
                        .expect("Security contracts are keyed by ID"),
                )
            })
            .collect();

        let full = subscribed(QUERY_WITH_ALL);
        assert_eq!(
            full, supported,
            "the subscription query and the decoder table must agree"
        );

        let default = subscribed(QUERY);
        let ids = |query: &str| -> Vec<u16> {
            subscribed(query)
                .difference(&default)
                .map(|(_, id)| *id)
                .collect()
        };
        assert_eq!(
            ids(QUERY_WITH_FILTERING_PLATFORM_CONNECTIONS),
            FILTERING_PLATFORM_CONNECTION_EVENTS,
            "only the per-connection events are behind the option"
        );
        assert_eq!(
            ids(QUERY_WITH_LONG_TAIL),
            LONG_TAIL_EVENTS,
            "only the long-tail events are behind the option"
        );
        assert_eq!(
            ids(QUERY_WITH_DOMAIN_CONTROLLER),
            DOMAIN_CONTROLLER_EVENTS,
            "only the domain-controller events are behind the option"
        );
        assert!(
            subscribed(QUERY).contains(&("Microsoft-Windows-Security-Auditing".to_string(), 5379)),
            "5379 is on the default subscription"
        );
        assert_eq!(source(false, false, false).query, QUERY);
        assert_eq!(
            source(true, false, false).query,
            QUERY_WITH_FILTERING_PLATFORM_CONNECTIONS
        );
        assert_eq!(source(false, true, false).query, QUERY_WITH_LONG_TAIL);
        assert_eq!(
            source(false, false, true).query,
            QUERY_WITH_DOMAIN_CONTROLLER
        );
        assert_eq!(
            source(true, true, false).query,
            QUERY_WITH_CONNECTIONS_AND_LONG_TAIL
        );
        assert_eq!(
            source(true, false, true).query,
            QUERY_WITH_CONNECTIONS_AND_DOMAIN_CONTROLLER
        );
        assert_eq!(
            source(false, true, true).query,
            QUERY_WITH_LONG_TAIL_AND_DOMAIN_CONTROLLER
        );
        assert_eq!(source(true, true, true).query, QUERY_WITH_ALL);
    }

    /// The Event Log query parser rejects an XPath of more than 23 terms; see
    /// `select!`.
    #[test]
    fn every_select_stays_within_the_event_log_term_limit() {
        for query in [
            QUERY,
            QUERY_WITH_FILTERING_PLATFORM_CONNECTIONS,
            QUERY_WITH_LONG_TAIL,
            QUERY_WITH_DOMAIN_CONTROLLER,
            QUERY_WITH_ALL,
        ] {
            for (provider, ids) in selects(query) {
                assert!(
                    ids.len() <= 22,
                    "a {provider} Select with {} event IDs exceeds the parser's limit",
                    ids.len()
                );
            }
        }
    }
}
