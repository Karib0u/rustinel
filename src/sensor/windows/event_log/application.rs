//! Windows Application channel records used by the Sigma corpus.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use chrono::DateTime;

use crate::field_availability::{application_contract, Availability};
use crate::models::ApplicationEventFields;
use crate::sensor::{Platform, SensorAction, SensorEvent, SensorNormalization, SensorPayload};

use super::EventLogSource;

macro_rules! select {
    ($provider:literal; $first:literal $(, $rest:literal)* $(,)?) => {
        concat!(
            "<Select Path=\"Application\">*[System[Provider[@Name='",
            $provider,
            "'] and (EventID=",
            $first,
            $(" or EventID=", $rest,)*
            ")]]</Select>"
        )
    };
}

// Event Log XPath does not support a provider-name prefix test. SQL Server
// instance names vary, so these four IDs are filtered by provider in decode.
const QUERY: &str = concat!(
    "<QueryList><Query Id=\"0\" Path=\"Application\">",
    select!("Application Error"; 1000),
    select!("Windows Error Reporting"; 1001),
    select!("Microsoft-Windows-Audit-CVE"; 1),
    select!("Audit-CVE"; 1),
    select!("Microsoft-Windows-SoftwareRestrictionPolicies"; 865, 866, 867, 868, 882),
    select!("MsiInstaller"; 1033, 1034, 1040, 1042, 11724),
    select!("ESENT"; 216, 325, 326, 327),
    "<Select Path=\"Application\">*[System[(EventID=8128 or EventID=15457 or EventID=18456 or EventID=33205)]]</Select>",
    select!("Microsoft-Windows-Backup"; 524),
    select!("ScreenConnect"; 200, 201),
    select!("Microsoft-Windows-User Profiles Service"; 1511),
    select!("Windows Server Update Services"; 7053),
    select!("MSMQ"; 2027),
    select!("MSExchange Control Panel"; 4),
    "</Query></QueryList>"
);

pub(super) const fn source() -> EventLogSource {
    EventLogSource::new("application", "Application", QUERY, decode)
}

fn decode(xml: &str) -> Result<SensorEvent> {
    let document = roxmltree::Document::parse(xml).context("invalid Application event XML")?;
    let system = document
        .descendants()
        .find(|node| node.has_tag_name("System"))
        .context("Application event XML has no System element")?;
    let event_id = child_text(system, "EventID")
        .context("Application event XML has no EventID")?
        .parse::<u16>()
        .context("Application event XML has an invalid EventID")?;
    let provider = system
        .children()
        .find(|node| node.has_tag_name("Provider"))
        .and_then(|node| node.attribute("Name"))
        .context("Application event XML has no provider")?;
    let contract = application_contract(event_id, provider)
        .ok_or_else(|| anyhow!("unsupported Application event {event_id} from {provider}"))?;
    let channel = child_text(system, "Channel").context("Application event XML has no Channel")?;
    if channel != "Application" {
        return Err(anyhow!(
            "unexpected channel {channel:?} for Application event"
        ));
    }

    let allowed = |name: &str| {
        contract.fields.iter().any(|field| {
            field.field == name && !matches!(field.availability, Availability::Never(_))
        })
    };
    let mut fields = ApplicationEventFields::default();
    fields.insert("Provider_Name", provider);
    let level = child_text(system, "Level").context("Application event XML has no Level")?;
    fields.insert("Level", level);

    let values: Vec<&str> = document
        .descendants()
        .find(|node| node.has_tag_name("EventData"))
        .into_iter()
        .flat_map(|node| node.children().filter(|child| child.has_tag_name("Data")))
        .map(|node| node.text().unwrap_or_default())
        .collect();
    for (index, node) in document
        .descendants()
        .find(|node| node.has_tag_name("EventData"))
        .into_iter()
        .flat_map(|node| node.children().filter(|child| child.has_tag_name("Data")))
        .enumerate()
    {
        if let Some(name) = node.attribute("Name").filter(|name| allowed(name)) {
            fields.insert(name, values[index]);
        }
    }
    if allowed("Data") {
        let data = values.join("\n");
        fields.insert("Data", &data);
    }
    if provider == "Application Error" && event_id == 1000 {
        for (name, index) in [
            ("AppName", 0),
            ("AppVersion", 1),
            ("ModuleName", 3),
            ("ExceptionCode", 6),
        ] {
            if let Some(value) = values.get(index).filter(|_| allowed(name)) {
                fields.insert(name, value);
            }
        }
    }

    let timestamp = system
        .children()
        .find(|node| node.has_tag_name("TimeCreated"))
        .and_then(|node| node.attribute("SystemTime"))
        .and_then(parse_system_time)
        .context("Application event XML has no valid timestamp")?;
    let source_seq = child_text(system, "EventRecordID")
        .context("Application event XML has no EventRecordID")?
        .parse::<u64>()
        .context("Application event XML has an invalid EventRecordID")?;

    Ok(SensorEvent {
        process_name: None,
        provenance: Default::default(),
        platform: Platform::Windows,
        provider: "windows_event_log",
        action: SensorAction::Access,
        normalization: SensorNormalization {
            event_id,
            action_code: 0,
        },
        pid: None,
        timestamp,
        source_seq: Some(source_seq),
        process_start_key: None,
        parent_process_start_key: None,
        payload: SensorPayload::Application(fields),
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
    (seconds >= 0)
        .then(|| UNIX_EPOCH + Duration::new(seconds as u64, timestamp.timestamp_subsec_nanos()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn xml(provider: &str, id: u16, data: &str) -> String {
        format!(
            r#"<Event><System><Provider Name="{provider}"/><EventID>{id}</EventID><Level>2</Level><TimeCreated SystemTime="2026-09-24T10:00:00Z"/><EventRecordID>42</EventRecordID><Channel>Application</Channel></System><EventData>{data}</EventData></Event>"#
        )
    }

    #[test]
    fn preserves_native_provider_and_positional_application_error_fields() {
        let event = decode(&xml("Application Error", 1000,
            "<Data>lsass.exe</Data><Data>10.0.1</Data><Data>stamp</Data><Data>netlogon.dll</Data><Data>10.0.1</Data><Data>stamp</Data><Data>c0000409</Data>"))
            .unwrap();
        let SensorPayload::Application(fields) = event.payload else {
            panic!("expected Application payload")
        };
        assert_eq!(fields.get("Provider_Name"), Some("Application Error"));
        assert_eq!(fields.get("AppName"), Some("lsass.exe"));
        assert_eq!(fields.get("ModuleName"), Some("netlogon.dll"));
        assert_eq!(fields.get("ExceptionCode"), Some("c0000409"));
        assert!(fields.get("Data").unwrap().contains("netlogon.dll"));
        assert!(fields.get("Message").is_none());
    }

    #[test]
    fn provider_and_event_id_must_match_a_contract() {
        assert!(decode(&xml("Application Error", 1001, "<Data>test</Data>")).is_err());
        assert!(decode(&xml("Other Provider", 1000, "<Data>test</Data>")).is_err());
        let event = decode(&xml(
            "MSSQLSERVER$AUDIT",
            33205,
            "<Data>statement:EXEC</Data>",
        ))
        .unwrap();
        let SensorPayload::Application(fields) = event.payload else {
            panic!("expected Application payload")
        };
        assert_eq!(fields.get("Provider_Name"), Some("MSSQLSERVER$AUDIT"));
    }

    #[test]
    fn application_query_subscribes_on_the_host() {
        let temp = tempfile::tempdir().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = super::super::EventLogSubscription::start(
            source(),
            tx,
            Arc::clone(&shutdown),
            temp.path().join("Application.xml"),
        )
        .expect("Application query must subscribe");
        shutdown.store(true, Ordering::Relaxed);
        worker.join().expect("Application subscription must stop");
    }
}
