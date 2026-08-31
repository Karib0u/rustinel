//! Windows Security channel audit event decoding.
//!
//! The Security channel is one Sigma logsource (`windows/security`) carrying
//! unrelated event families. Rules address them by `EventID` and by the field
//! names Windows itself writes, so the decoder keeps both: the subscription is
//! scoped to the supported IDs, and each ID has an allowlist of the properties
//! decoded from it.
//!
//! [`SUPPORTED_EVENTS`] is therefore the single statement of what this
//! collector populates. Adding an event family is adding a row to it, and
//! nothing else in the pipeline needs to change.
//!
//! Only 4624 is audited by default. The other five need their audit
//! subcategory enabled, and the two object-access families additionally need a
//! SACL on the object; the required policy is in `docs/operations.md`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use chrono::DateTime;

use crate::models::SecurityAuditFields;
use crate::sensor::{Platform, SensorAction, SensorEvent, SensorNormalization, SensorPayload};

use super::EventLogSource;

const PROVIDER: &str = "Microsoft-Windows-Security-Auditing";

/// The identity block every audited event carries: who did it, and in which
/// logon session.
const SUBJECT_FIELDS: &[&str] = &[
    "SubjectUserSid",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonId",
];

/// Supported audit events, and the properties decoded from each.
///
/// The lists are the event's own schema, restricted to the properties that
/// carry detection value. A property Windows emits but that is absent here is
/// dropped rather than passed through, which keeps the field model closed and
/// reviewable.
const SUPPORTED_EVENTS: &[(u16, &[&str])] = &[
    // An account was successfully logged on.
    (
        4624,
        &[
            "TargetUserSid",
            "TargetUserName",
            "TargetDomainName",
            "TargetLogonId",
            "LogonType",
            "LogonProcessName",
            "AuthenticationPackageName",
            "WorkstationName",
            "LogonGuid",
            "LmPackageName",
            "KeyLength",
            "ProcessId",
            "ProcessName",
            "IpAddress",
            "IpPort",
            "ImpersonationLevel",
            "RestrictedAdminMode",
            "TargetOutboundUserName",
            "TargetOutboundDomainName",
            "VirtualAccount",
            "TargetLinkedLogonId",
            "ElevatedToken",
        ],
    ),
    // A handle to an object was requested.
    (
        4656,
        &[
            "ObjectServer",
            "ObjectType",
            "ObjectName",
            "HandleId",
            "AccessList",
            "AccessMask",
            "AccessReason",
            "PrivilegeList",
            "ProcessId",
            "ProcessName",
        ],
    ),
    // An attempt was made to access an object.
    (
        4663,
        &[
            "ObjectServer",
            "ObjectType",
            "ObjectName",
            "HandleId",
            "AccessList",
            "AccessMask",
            "ProcessId",
            "ProcessName",
        ],
    ),
    // A service was installed in the system.
    (
        4697,
        &[
            "ServiceName",
            "ServiceFileName",
            "ServiceType",
            "ServiceStartType",
            "ServiceAccount",
        ],
    ),
    // A directory service object was modified.
    (
        5136,
        &[
            "DSName",
            "DSType",
            "ObjectDN",
            "ObjectGUID",
            "ObjectClass",
            "AttributeLDAPDisplayName",
            "AttributeSyntaxOID",
            "AttributeValue",
            "OperationType",
        ],
    ),
    // A network share object was checked to see whether the client can be
    // granted the desired access.
    (
        5145,
        &[
            "ObjectType",
            "IpAddress",
            "IpPort",
            "ShareName",
            "ShareLocalPath",
            "RelativeTargetName",
            "AccessMask",
            "AccessList",
            "AccessReason",
        ],
    ),
];

/// XPath filter scoping the subscription to [`SUPPORTED_EVENTS`].
///
/// Written out rather than built at runtime: the query is what the kernel
/// filters on, so an event family is only reachable if it appears both here and
/// in the table above, and a reviewer can see the two agree.
const QUERY: &str = "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] \
     and (EventID=4624 or EventID=4656 or EventID=4663 or EventID=4697 \
     or EventID=5136 or EventID=5145)]]";

pub(super) const fn source() -> EventLogSource {
    EventLogSource::new("security-audit", "Security", QUERY, decode)
}

/// The action an audit event reports, for logging and downstream routing.
fn action_for_event(event_id: u16) -> SensorAction {
    match event_id {
        4624 => SensorAction::Start,
        4697 => SensorAction::Register,
        5136 => SensorAction::Modify,
        _ => SensorAction::Access,
    }
}

fn decode(xml: &str) -> Result<SensorEvent> {
    let document = roxmltree::Document::parse(xml).context("invalid security event XML")?;
    let system = document
        .descendants()
        .find(|node| node.has_tag_name("System"))
        .context("security event XML has no System element")?;

    let event_id = child_text(system, "EventID")
        .context("security event XML has no EventID")?
        .parse::<u16>()
        .context("security event XML has an invalid EventID")?;

    let provider = system
        .children()
        .find(|node| node.has_tag_name("Provider"))
        .and_then(|node| node.attribute("Name"));
    if provider != Some(PROVIDER) {
        return Err(anyhow!("unexpected Security event provider {provider:?}"));
    }

    let allowed = SUPPORTED_EVENTS
        .iter()
        .find_map(|(id, fields)| (*id == event_id).then_some(*fields))
        .ok_or_else(|| anyhow!("unsupported Security event ID {event_id}"))?;

    let mut fields = SecurityAuditFields::default();
    for node in document.descendants() {
        if !node.has_tag_name("Data") {
            continue;
        }
        let Some(name) = node.attribute("Name") else {
            continue;
        };
        if !SUBJECT_FIELDS.contains(&name) && !allowed.contains(&name) {
            continue;
        }
        fields.insert(name, node.text().unwrap_or_default());
    }

    if fields.fields.is_empty() {
        return Err(anyhow!("Security event {event_id} carried no decoded data"));
    }

    let timestamp = system
        .children()
        .find(|node| node.has_tag_name("TimeCreated"))
        .and_then(|node| node.attribute("SystemTime"))
        .and_then(parse_system_time)
        .unwrap_or_else(SystemTime::now);

    // The `ProcessId` in the payload stays as Windows renders it, in hex, for
    // rules to match. The pipeline needs a number to reach the process cache,
    // so the parsed value rides along on the event instead.
    let pid = fields.process_id();

    Ok(SensorEvent {
        platform: Platform::Windows,
        provider: "windows_event_log",
        action: action_for_event(event_id),
        normalization: SensorNormalization {
            event_id,
            action_code: 0,
        },
        pid,
        timestamp,
        process_start_key: None,
        payload: SensorPayload::Security(fields),
    })
}

fn child_text<'a, 'input>(node: roxmltree::Node<'a, 'input>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|child| child.has_tag_name(name))
        .and_then(|child| child.text())
}

fn parse_system_time(value: &str) -> Option<SystemTime> {
    let timestamp = DateTime::parse_from_rfc3339(value).ok()?;
    let seconds = timestamp.timestamp();
    let nanos = timestamp.timestamp_subsec_nanos();
    if seconds < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::new(seconds as u64, nanos))
}

#[cfg(test)]
mod tests {
    use super::{decode, PROVIDER, QUERY, SUPPORTED_EVENTS};
    use crate::sensor::{SensorAction, SensorPayload};

    fn security_event(event_id: u16, event_data: &str) -> String {
        format!(
            r#"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="2026-08-25T12:34:56.1234567Z"/>
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
        let SensorPayload::Security(fields) = event.payload else {
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

        let SensorPayload::Security(fields) = event.payload else {
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

        let SensorPayload::Security(fields) = event.payload else {
            panic!("expected a security payload");
        };
        assert_eq!(fields.get("LogonType"), Some("3"));
        assert_eq!(fields.get("AuthenticationPackageName"), Some("NTLM"));
        assert_eq!(fields.get("IpAddress"), Some("10.0.0.9"));
        assert_eq!(fields.get("TargetUserName"), Some("bob"));
        // `-` is how the channel spells "does not apply to this event", not a
        // value a rule should be able to match on.
        assert_eq!(fields.get("ProcessName"), None);
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

        let SensorPayload::Security(fields) = event.payload else {
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

        let SensorPayload::Security(fields) = event.payload else {
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
            .replace(PROVIDER, "Other Provider");
        assert!(decode(&xml).is_err());
    }

    #[test]
    fn the_subscription_query_covers_exactly_the_supported_events() {
        for (event_id, _) in SUPPORTED_EVENTS {
            assert!(
                QUERY.contains(&format!("EventID={event_id}")),
                "event {event_id} is decoded but not subscribed to"
            );
        }
        assert_eq!(
            QUERY.matches("EventID=").count(),
            SUPPORTED_EVENTS.len(),
            "the subscription query and the decoder table must agree"
        );
    }
}
