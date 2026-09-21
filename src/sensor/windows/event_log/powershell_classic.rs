//! Classic Windows PowerShell Event Log decoding.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use chrono::DateTime;

use crate::models::PowerShellClassicStartFields;
use crate::sensor::{Platform, SensorAction, SensorEvent, SensorNormalization, SensorPayload};

use super::EventLogSource;

const EVENT_ID: u16 = 400;
const CHANNEL: &str = "Windows PowerShell";
const PROVIDER: &str = "PowerShell";

pub(super) const fn source() -> EventLogSource {
    EventLogSource::new(
        "powershell-classic-start",
        CHANNEL,
        "*[System[Provider[@Name='PowerShell'] and EventID=400]]",
        decode,
    )
}

fn decode(xml: &str) -> Result<SensorEvent> {
    let document = roxmltree::Document::parse(xml).context("invalid PowerShell event XML")?;
    let system = document
        .descendants()
        .find(|node| node.has_tag_name("System"))
        .context("PowerShell event XML has no System element")?;

    let event_id = child_text(system, "EventID")
        .context("PowerShell event XML has no EventID")?
        .parse::<u16>()
        .context("PowerShell event XML has an invalid EventID")?;
    if event_id != EVENT_ID {
        return Err(anyhow!("unexpected Windows PowerShell event ID {event_id}"));
    }

    let channel = child_text(system, "Channel").context("PowerShell event XML has no Channel")?;
    if channel != CHANNEL {
        return Err(anyhow!(
            "unexpected channel {channel:?} for Windows PowerShell event {event_id}"
        ));
    }

    let provider = system
        .children()
        .find(|node| node.has_tag_name("Provider"))
        .and_then(|node| node.attribute("Name"));
    if provider != Some(PROVIDER) {
        return Err(anyhow!("unexpected event 400 provider {provider:?}"));
    }

    let event_data = document
        .descendants()
        .find(|node| node.has_tag_name("EventData"))
        .context("PowerShell event 400 has no EventData element")?;
    let data = event_data
        .children()
        .filter(|node| node.has_tag_name("Data"))
        .nth(2)
        .and_then(|node| node.text())
        .filter(|value| !value.is_empty())
        .context("PowerShell event 400 has no engine-start Data value")?;

    let timestamp = system
        .children()
        .find(|node| node.has_tag_name("TimeCreated"))
        .and_then(|node| node.attribute("SystemTime"))
        .and_then(parse_system_time)
        .context("PowerShell event XML has no valid TimeCreated timestamp")?;
    let source_seq = child_text(system, "EventRecordID")
        .context("PowerShell event XML has no EventRecordID")?
        .parse::<u64>()
        .context("PowerShell event XML has an invalid EventRecordID")?;
    let pid = system
        .children()
        .find(|node| node.has_tag_name("Execution"))
        .and_then(|node| node.attribute("ProcessID"))
        .and_then(|value| value.parse::<u32>().ok());

    Ok(SensorEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::Windows,
        provider: "windows_event_log",
        action: SensorAction::Start,
        normalization: SensorNormalization {
            event_id: EVENT_ID,
            action_code: 0,
        },
        pid,
        timestamp,
        source_seq: Some(source_seq),
        process_start_key: None,
        parent_process_start_key: None,
        payload: SensorPayload::PowerShellClassicStart(PowerShellClassicStartFields {
            data: Some(data.to_string()),
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

    const EVENT_400: &str = r#"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="PowerShell"/>
    <EventID Qualifiers="0">400</EventID>
    <TimeCreated SystemTime="2026-09-21T19:03:42.8436669Z"/>
    <EventRecordID>1132233</EventRecordID>
    <Execution ProcessID="12740" ThreadID="0"/>
    <Channel>Windows PowerShell</Channel>
    <Security/>
  </System>
  <EventData>
    <Data>Available</Data>
    <Data>None</Data>
    <Data>NewEngineState=Available
PreviousEngineState=None
HostName=ConsoleHost
HostVersion=5.1.26100.9444
HostApplication=powershell.exe -NoProfile
EngineVersion=2.0
RunspaceId=2a928607-64a6-4806-ac3f-d9f2cd92ef54</Data>
  </EventData>
</Event>"#;

    #[test]
    fn decodes_classic_engine_start_data() {
        let event = decode(EVENT_400).expect("event 400 should decode");
        assert_eq!(event.action, SensorAction::Start);
        assert_eq!(event.normalization.event_id, 400);
        assert_eq!(event.provider, "windows_event_log");
        assert_eq!(event.source_seq, Some(1_132_233));
        assert_eq!(event.pid, Some(12_740));

        let SensorPayload::PowerShellClassicStart(fields) = event.payload else {
            panic!("expected classic PowerShell start payload");
        };
        let data = fields.data.expect("event 400 Data");
        assert!(data.contains("HostName=ConsoleHost"));
        assert!(data.contains("EngineVersion=2.0"));
    }

    #[test]
    fn rejects_a_different_event_or_channel() {
        assert!(decode(&EVENT_400.replace(">400<", ">600<")).is_err());
        assert!(decode(&EVENT_400.replace("Windows PowerShell", "System")).is_err());
    }
}
