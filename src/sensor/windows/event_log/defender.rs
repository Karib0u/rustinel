//! Microsoft Defender Operational channel events.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use chrono::DateTime;

use crate::field_availability::contract_for_event_id;
use crate::models::SecurityAuditFields;
use crate::sensor::{Platform, SensorAction, SensorEvent, SensorNormalization, SensorPayload};

use super::EventLogSource;

const CHANNEL: &str = "Microsoft-Windows-Windows Defender/Operational";
const PROVIDER: &str = "Microsoft-Windows-Windows Defender";
const QUERY: &str = "*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=5001 or EventID=5010 or EventID=5012 or EventID=5007 or EventID=5013 or EventID=1006 or EventID=1015 or EventID=1116 or EventID=1117 or EventID=1119 or EventID=1009 or EventID=1013 or EventID=1121 or EventID=3002 or EventID=3007 or EventID=5101)]]";

pub(super) const fn source() -> EventLogSource {
    EventLogSource::new("defender-operational", CHANNEL, QUERY, decode)
}

fn decode(xml: &str) -> Result<SensorEvent> {
    let document = roxmltree::Document::parse(xml).context("invalid Defender event XML")?;
    let system = document
        .descendants()
        .find(|node| node.has_tag_name("System"))
        .context("Defender event XML has no System element")?;
    let event_id = child_text(system, "EventID")
        .context("Defender event XML has no EventID")?
        .parse::<u16>()
        .context("Defender event XML has an invalid EventID")?;
    let contract = contract_for_event_id(
        Platform::Windows,
        "windefend",
        event_id,
        "windows_event_log",
    )
    .ok_or_else(|| anyhow!("unsupported Defender event ID {event_id}"))?;

    let channel = child_text(system, "Channel").context("Defender event XML has no Channel")?;
    if channel != CHANNEL {
        return Err(anyhow!("unexpected Defender channel {channel:?}"));
    }
    let provider = system
        .children()
        .find(|node| node.has_tag_name("Provider"))
        .and_then(|node| node.attribute("Name"));
    if provider != Some(PROVIDER) {
        return Err(anyhow!("unexpected Defender provider {provider:?}"));
    }

    let mut fields = SecurityAuditFields::default();
    for node in document
        .descendants()
        .filter(|node| node.has_tag_name("Data"))
    {
        if let Some(name) = node.attribute("Name") {
            if contract.fields.iter().any(|field| field.field == name) {
                let value = node.text().unwrap_or_default();
                fields.insert(name, value);
                let alias = match name {
                    "Old Value" => Some("OldValue"),
                    "New Value" => Some("NewValue"),
                    "Process Name" => Some("ProcessName"),
                    "Source Name" => Some("SourceName"),
                    "Threat Name" => Some("ThreatName"),
                    "Feature Name" => Some("Feature_Name"),
                    _ => None,
                };
                if let Some(alias) = alias {
                    if contract.fields.iter().any(|field| field.field == alias) {
                        fields.insert(alias, value);
                    }
                }
            }
        }
    }
    fields.insert("Provider_Name", PROVIDER);

    let timestamp = system
        .children()
        .find(|node| node.has_tag_name("TimeCreated"))
        .and_then(|node| node.attribute("SystemTime"))
        .and_then(parse_system_time)
        .context("Defender event XML has no valid TimeCreated timestamp")?;
    let source_seq = child_text(system, "EventRecordID")
        .context("Defender event XML has no EventRecordID")?
        .parse::<u64>()
        .context("Defender event XML has an invalid EventRecordID")?;

    let action = match event_id {
        5007 | 5013 => SensorAction::Modify,
        1009 | 1013 => SensorAction::Delete,
        1006 | 1015 | 1116 | 1117 | 1119 | 1121 => SensorAction::Create,
        _ => SensorAction::Set,
    };
    Ok(SensorEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::Windows,
        provider: "windows_event_log",
        action,
        normalization: SensorNormalization {
            event_id,
            action_code: 0,
        },
        pid: None,
        timestamp,
        source_seq: Some(source_seq),
        process_start_key: None,
        parent_process_start_key: None,
        payload: SensorPayload::Defender(fields),
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
    if seconds < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::new(seconds as u64, timestamp.timestamp_subsec_nanos()))
}

#[cfg(test)]
mod tests {
    use super::{decode, CHANNEL, PROVIDER, QUERY};
    use crate::sensor::SensorPayload;

    fn event(id: u16, data: &str) -> String {
        format!(
            "<Event><System><Provider Name='{PROVIDER}'/><EventID>{id}</EventID><TimeCreated SystemTime='2026-09-24T05:13:50.0780643Z'/><EventRecordID>7702</EventRecordID><Channel>{CHANNEL}</Channel></System><EventData>{data}</EventData></Event>"
        )
    }

    #[test]
    fn decodes_protection_disabled() {
        let xml = event(5001, "<Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18</Data>");
        let decoded = decode(&xml).unwrap();
        assert_eq!(decoded.normalization.event_id, 5001);
        assert_eq!(decoded.source_seq, Some(7702));
        let SensorPayload::Defender(fields) = decoded.payload else {
            panic!("Defender payload expected")
        };
        assert_eq!(fields.get("Provider_Name"), Some(PROVIDER));
        assert_eq!(
            fields.get("Product Name"),
            Some("Microsoft Defender Antivirus")
        );
    }

    #[test]
    fn decodes_exclusion_change_with_native_names() {
        let xml = event(5007, "<Data Name='Old Value'>-</Data><Data Name='New Value'>HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Tools = 0x0</Data><Data Name='Unknown'>discard</Data>");
        let decoded = decode(&xml).unwrap();
        let SensorPayload::Defender(fields) = decoded.payload else {
            panic!("Defender payload expected")
        };
        assert!(fields.get("New Value").unwrap().contains("Exclusions"));
        assert_eq!(fields.get("NewValue"), fields.get("New Value"));
        assert_eq!(fields.get("Old Value"), Some("-"));
        assert_eq!(fields.get("OldValue"), Some("-"));
        assert_eq!(fields.get("Unknown"), None);
    }

    #[test]
    fn rejects_other_source_or_id() {
        assert!(decode(&event(5000, "")).is_err());
        assert!(decode(&event(5001, "").replace(PROVIDER, "Other")).is_err());
        assert!(decode(&event(5001, "").replace(CHANNEL, "System")).is_err());
    }

    #[test]
    fn rule_aliases_keep_the_native_fields() {
        for (id, native, alias) in [
            (1116, "Source Name", "SourceName"),
            (1116, "Threat Name", "ThreatName"),
            (1121, "Process Name", "ProcessName"),
            (3002, "Feature Name", "Feature_Name"),
        ] {
            let xml = event(id, &format!("<Data Name='{native}'>sample</Data>"));
            let decoded = decode(&xml).unwrap();
            let SensorPayload::Defender(fields) = decoded.payload else {
                panic!("Defender payload expected")
            };
            assert_eq!(fields.get(native), Some("sample"));
            assert_eq!(fields.get(alias), Some("sample"));
        }
    }

    #[test]
    fn every_subscribed_id_has_a_decoder_contract() {
        for id in [
            5001, 5010, 5012, 5007, 5013, 1006, 1015, 1116, 1117, 1119, 1009, 1013, 1121, 3002,
            3007, 5101,
        ] {
            assert!(
                QUERY.contains(&format!("EventID={id}")),
                "missing query ID {id}"
            );
            let decoded = decode(&event(id, "<Data Name='Product Name'>Defender</Data>"))
                .unwrap_or_else(|err| panic!("ID {id}: {err}"));
            assert_eq!(decoded.normalization.event_id, id);
        }
    }
}
