//! Replay result rendering.
//!
//! Replay writes its results wherever it is pointed, and both forms say plainly
//! that they came from a replay: the console report is headed by the recording
//! it replayed, and every ECS alert carries `edr.replay` provenance. Neither
//! form touches the live alert log, which is what keeps a rule experiment out of
//! the record of what actually happened on the endpoint.
//!
//! Nothing here reads the clock. Replaying one recording twice against one
//! configuration produces byte-identical output, so a detection change shows up
//! as a diff and nothing else does.

use std::io::Write;

use crate::models::ecs::{EcsAlert, ReplayProvenance};
use crate::models::{Alert, NormalizedEvent};

/// Longest field value printed in the console report before truncation. Script
/// blocks and command lines can be arbitrarily long; the console is for reading.
const MAX_VALUE_CHARS: usize = 200;

/// Event fields worth showing in a console alert, in the order they are printed.
/// Only the ones the matched event actually carries are rendered.
const CONSOLE_FIELDS: &[&str] = &[
    "Image",
    "ProcessId",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "TargetFilename",
    "TargetObject",
    "Details",
    "DestinationIp",
    "DestinationPort",
    "DestinationHostname",
    "Initiated",
    "QueryName",
    "QueryResults",
    "ImageLoaded",
    "ServiceName",
    "ServiceFileName",
    "TaskName",
    "ScriptBlockText",
    "User",
];

/// How replay results are rendered.
pub enum Format {
    /// A human-readable alert list, the default.
    Console,
    /// ECS NDJSON, one alert per line, as `--output` requests.
    Ecs,
}

/// Sink that renders replay results in one format to one stream.
pub struct ReplayWriter<'a> {
    format: Format,
    stream: &'a mut dyn Write,
    provenance: ReplayProvenance,
}

impl<'a> ReplayWriter<'a> {
    pub fn new(format: Format, stream: &'a mut dyn Write, provenance: ReplayProvenance) -> Self {
        Self {
            format,
            stream,
            provenance,
        }
    }

    /// Write the replay header. Only the console report has one; ECS NDJSON
    /// carries its provenance on every line instead.
    pub fn header(&mut self, lines: &[String]) -> std::io::Result<()> {
        if !matches!(self.format, Format::Console) {
            return Ok(());
        }
        for line in lines {
            writeln!(self.stream, "{line}")?;
        }
        writeln!(self.stream)
    }

    /// Write one alert.
    pub fn alert(&mut self, index: usize, alert: &Alert) -> std::io::Result<()> {
        match self.format {
            Format::Console => self.console_alert(index, alert),
            Format::Ecs => self.ecs_alert(alert),
        }
    }

    /// Write the closing summary. Console only, for the same reason as the
    /// header.
    pub fn summary(&mut self, lines: &[String]) -> std::io::Result<()> {
        if !matches!(self.format, Format::Console) {
            return Ok(());
        }
        for line in lines {
            writeln!(self.stream, "{line}")?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }

    fn console_alert(&mut self, index: usize, alert: &Alert) -> std::io::Result<()> {
        writeln!(
            self.stream,
            "[{index}] {severity:?} {engine:?} {rule}",
            severity = alert.severity,
            engine = alert.engine,
            rule = alert.rule_name,
        )?;
        if let Some(description) = &alert.rule_description {
            self.console_line("description", description)?;
        }
        if let Some(rule_id) = &alert.rule_id {
            self.console_line("rule", rule_id)?;
        }
        self.console_line("time", &alert.event.timestamp)?;
        self.console_line("event", &describe_event(&alert.event))?;

        for key in CONSOLE_FIELDS {
            if let Some(value) = alert.event.get_field(key) {
                self.console_line(key, value)?;
            }
        }

        writeln!(self.stream)
    }

    fn console_line(&mut self, key: &str, value: &str) -> std::io::Result<()> {
        writeln!(self.stream, "    {key:<20} {}", truncate(value))
    }

    fn ecs_alert(&mut self, alert: &Alert) -> std::io::Result<()> {
        let mut ecs = EcsAlert::from(alert);
        ecs.edr_replay = Some(self.provenance.clone());
        let line = serde_json::to_string(&ecs)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        writeln!(self.stream, "{line}")
    }
}

fn describe_event(event: &NormalizedEvent) -> String {
    format!(
        "{category:?} EventID {event_id} ({platform}/{provider})",
        category = event.category,
        event_id = event.event_id,
        platform = event.platform.as_str(),
        provider = event.provider,
    )
}

/// Shorten a value for the console, counting characters rather than bytes so a
/// multi-byte value is never cut mid-character.
fn truncate(value: &str) -> String {
    let single_line = value.replace(['\n', '\r'], " ");
    if single_line.chars().count() <= MAX_VALUE_CHARS {
        return single_line;
    }
    let head: String = single_line.chars().take(MAX_VALUE_CHARS).collect();
    format!("{head}...")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AlertSeverity, DetectionEngine, EventCategory, EventFields, ProcessCreationFields,
    };
    use crate::sensor::Platform;

    fn provenance() -> ReplayProvenance {
        ReplayProvenance {
            recording: "session.ndjson".to_string(),
            platform: "windows".to_string(),
            recorded_at: "2026-08-16T10:00:00Z".to_string(),
        }
    }

    fn alert() -> Alert {
        Alert {
            severity: AlertSeverity::High,
            rule_name: "Encoded PowerShell".to_string(),
            rule_description: None,
            rule_id: Some("sigma::encoded-powershell".to_string()),
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-08-16T10:00:01Z".to_string(),
                platform: Platform::Windows,
                provider: "etw".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some(r"C:\Windows\System32\powershell.exe".to_string()),
                    original_file_name: None,
                    product: None,
                    description: None,
                    company: None,
                    file_version: None,
                    target_image: None,
                    command_line: Some("powershell.exe -enc ZQBjAGgAbwA=".to_string()),
                    process_id: Some("4242".to_string()),
                    process_start_time: None,
                    parent_process_id: None,
                    parent_image: None,
                    parent_command_line: None,
                    current_directory: None,
                    integrity_level: None,
                    user: None,
                    logon_id: None,
                    logon_guid: None,
                }),
                process_context: None,
            },
            match_details: None,
        }
    }

    fn render(format: Format) -> String {
        let mut buffer = Vec::new();
        {
            let mut writer = ReplayWriter::new(format, &mut buffer, provenance());
            writer
                .header(&["Replay of session.ndjson".to_string()])
                .unwrap();
            writer.alert(1, &alert()).unwrap();
            writer.summary(&["1 alert".to_string()]).unwrap();
        }
        String::from_utf8(buffer).expect("output is utf-8")
    }

    #[test]
    fn the_console_report_names_the_rule_and_the_matched_event() {
        let output = render(Format::Console);

        assert!(output.contains("Replay of session.ndjson"), "{output}");
        assert!(
            output.contains("[1] High Sigma Encoded PowerShell"),
            "{output}"
        );
        assert!(
            output.contains("powershell.exe -enc ZQBjAGgAbwA="),
            "{output}"
        );
        assert!(
            output.contains("Process EventID 1 (windows/etw)"),
            "{output}"
        );
        assert!(output.contains("1 alert"), "{output}");
    }

    #[test]
    fn ecs_output_is_one_alert_per_line_marked_as_replayed() {
        let output = render(Format::Ecs);

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1, "header and summary stay off the ECS stream");

        let value: serde_json::Value = serde_json::from_str(lines[0]).expect("ECS line parses");
        assert_eq!(value["event.kind"], "alert");
        assert_eq!(value["rule.name"], "Encoded PowerShell");
        assert_eq!(value["edr.replay"]["recording"], "session.ndjson");
        assert_eq!(value["edr.replay"]["platform"], "windows");
        assert_eq!(value["edr.replay"]["recorded_at"], "2026-08-16T10:00:00Z");
    }

    #[test]
    fn live_alerts_carry_no_replay_provenance() {
        let ecs = EcsAlert::from(&alert());
        let value = serde_json::to_value(&ecs).expect("ECS serializes");

        assert!(
            value.get("edr.replay").is_none(),
            "a live alert must not look like a replayed one"
        );
    }

    #[test]
    fn long_values_are_shortened_without_splitting_a_character() {
        let value = "é".repeat(MAX_VALUE_CHARS + 10);

        let shortened = truncate(&value);

        assert_eq!(shortened.chars().count(), MAX_VALUE_CHARS + 3);
        assert!(shortened.ends_with("..."));
    }
}
