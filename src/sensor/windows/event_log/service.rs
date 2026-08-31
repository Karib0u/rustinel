//! Service Control Manager event decoding.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use chrono::DateTime;

use crate::models::ServiceCreationFields;
use crate::sensor::{Platform, SensorAction, SensorEvent, SensorNormalization, SensorPayload};

use super::EventLogSource;

const SERVICE_EVENT_ID: u16 = 7045;
/// The provider that writes System event 7045, and the value `service: system`
/// rules select on as `Provider_Name`.
const SERVICE_PROVIDER: &str = "Service Control Manager";

pub(super) const fn source() -> EventLogSource {
    EventLogSource::new(
        "service-installation",
        "System",
        "*[System[Provider[@Name='Service Control Manager'] and EventID=7045]]",
        decode,
    )
}

fn decode(xml: &str) -> Result<SensorEvent> {
    let document = roxmltree::Document::parse(xml).context("invalid service event XML")?;
    let system = document
        .descendants()
        .find(|node| node.has_tag_name("System"))
        .context("service event XML has no System element")?;

    let event_id = child_text(system, "EventID")
        .context("service event XML has no EventID")?
        .parse::<u16>()
        .context("service event XML has an invalid EventID")?;
    if event_id != SERVICE_EVENT_ID {
        return Err(anyhow!("unexpected System event ID {event_id}"));
    }

    let provider = system
        .children()
        .find(|node| node.has_tag_name("Provider"))
        .and_then(|node| node.attribute("Name"));
    if provider != Some(SERVICE_PROVIDER) {
        return Err(anyhow!("unexpected event 7045 provider {provider:?}"));
    }

    let field = |name: &str| {
        document.descendants().find_map(|node| {
            (node.has_tag_name("Data") && node.attribute("Name") == Some(name))
                .then(|| node.text().unwrap_or_default().to_string())
        })
    };

    let service_name = field("ServiceName").filter(|value| !value.is_empty());
    let service_file_name = field("ImagePath").filter(|value| !value.is_empty());
    if service_name.is_none() || service_file_name.is_none() {
        return Err(anyhow!("event 7045 is missing ServiceName or ImagePath"));
    }

    let user = system
        .children()
        .find(|node| node.has_tag_name("Security"))
        .and_then(|node| node.attribute("UserID"))
        .map(str::to_string);
    let timestamp = system
        .children()
        .find(|node| node.has_tag_name("TimeCreated"))
        .and_then(|node| node.attribute("SystemTime"))
        .and_then(parse_system_time)
        .unwrap_or_else(SystemTime::now);

    Ok(SensorEvent {
        platform: Platform::Windows,
        provider: "windows_event_log",
        action: SensorAction::Register,
        normalization: SensorNormalization {
            event_id: SERVICE_EVENT_ID,
            action_code: 0,
        },
        pid: None,
        timestamp,
        process_start_key: None,
        payload: SensorPayload::Service(ServiceCreationFields {
            // Carried from the record rather than assumed: the guard above has
            // already rejected anything else, so this is the provider the
            // Windows Event Log actually named.
            provider_name: provider.map(str::to_string),
            service_name,
            service_file_name,
            service_type: field("ServiceType").filter(|value| !value.is_empty()),
            start_type: field("StartType").filter(|value| !value.is_empty()),
            account_name: field("AccountName").filter(|value| !value.is_empty()),
            user,
            process_id: None,
            image: None,
        }),
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
    use super::decode;
    use crate::sensor::{SensorAction, SensorPayload};

    const EVENT_7045: &str = r#"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}"/>
    <EventID Qualifiers="16384">7045</EventID>
    <TimeCreated SystemTime="2026-08-25T12:34:56.1234567Z"/>
    <Channel>System</Channel>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="ServiceName">RustinelIssue287</Data>
    <Data Name="ImagePath">C:\Program Files\test service.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">demand start</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>"#;

    #[test]
    fn decodes_all_service_creation_fields() {
        let event = decode(EVENT_7045).expect("7045 should decode");
        assert_eq!(event.action, SensorAction::Register);
        assert_eq!(event.normalization.event_id, 7045);
        assert_eq!(event.provider, "windows_event_log");

        let SensorPayload::Service(fields) = event.payload else {
            panic!("expected service payload");
        };
        assert_eq!(
            fields.provider_name.as_deref(),
            Some("Service Control Manager"),
            "Provider_Name must name the Windows provider, not the sensor"
        );
        assert_eq!(fields.service_name.as_deref(), Some("RustinelIssue287"));
        assert_eq!(
            fields.service_file_name.as_deref(),
            Some(r"C:\Program Files\test service.exe")
        );
        assert_eq!(fields.service_type.as_deref(), Some("user mode service"));
        assert_eq!(fields.start_type.as_deref(), Some("demand start"));
        assert_eq!(fields.account_name.as_deref(), Some("LocalSystem"));
        assert_eq!(fields.user.as_deref(), Some("S-1-5-18"));
    }

    #[test]
    fn rejects_a_different_provider() {
        let xml = EVENT_7045.replace("Service Control Manager", "Other Provider");
        assert!(decode(&xml).is_err());
    }
}
