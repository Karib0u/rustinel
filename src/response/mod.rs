//! Active response engine (optional prevention).
//!
//! Non-blocking alert intake with a background worker that can terminate
//! processes on critical alerts.

use crate::config::ResponseConfig;
use crate::models::{Alert, AlertSeverity, DetectionEngine, EventFields};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const TARGET_RESPONSE: &str = "response";

#[derive(Debug)]
struct ResponseTask {
    severity: AlertSeverity,
    rule_name: String,
    engine: DetectionEngine,
    pid: Option<u32>,
    image: Option<String>,
}

#[derive(Clone)]
pub struct ResponseEngine {
    enabled: bool,
    min_severity: AlertSeverity,
    tx: mpsc::Sender<ResponseTask>,
}

impl ResponseEngine {
    pub fn new(cfg: &ResponseConfig) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel(cfg.channel_capacity);
        let min_severity = parse_min_severity(&cfg.min_severity);
        let allowlist_images = normalize_allowlist_images(&cfg.allowlist_images);
        let allowlist_paths = normalize_allowlist_paths(&cfg.allowlist_paths);
        let prevention_enabled = cfg.prevention_enabled;
        let enabled = cfg.enabled;
        let self_pid = std::process::id();

        let handle = tokio::spawn(async move {
            info!(
                target: TARGET_RESPONSE,
                enabled,
                prevention_enabled,
                min_severity = ?min_severity,
                "Active response worker started"
            );

            while let Some(task) = rx.recv().await {
                handle_task(
                    task,
                    prevention_enabled,
                    self_pid,
                    &allowlist_images,
                    &allowlist_paths,
                );
            }

            info!(target: TARGET_RESPONSE, "Active response worker shutting down");
        });

        (
            Self {
                enabled,
                min_severity,
                tx,
            },
            handle,
        )
    }

    pub fn handle_alert(&self, alert: &Alert) {
        if !self.enabled {
            return;
        }

        let effective_severity = match alert.engine {
            DetectionEngine::Yara => AlertSeverity::Critical,
            DetectionEngine::Sigma | DetectionEngine::Ioc => alert.severity,
        };

        if !severity_at_least(effective_severity, self.min_severity) {
            return;
        }

        let (pid, image) = extract_process_info(alert);

        let task = ResponseTask {
            severity: effective_severity,
            rule_name: alert.rule_name.clone(),
            engine: alert.engine,
            pid,
            image,
        };

        if let Err(err) = self.tx.try_send(task) {
            warn!(
                target: TARGET_RESPONSE,
                error = %err,
                "Active response queue full, dropping task"
            );
        }
    }
}

fn handle_task(
    task: ResponseTask,
    prevention_enabled: bool,
    self_pid: u32,
    allowlist_images: &[String],
    allowlist_paths: &[String],
) {
    let pid = match task.pid {
        Some(pid) => pid,
        None => {
            warn!(
                target: TARGET_RESPONSE,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                "Active response skipped: missing pid"
            );
            return;
        }
    };

    if pid <= 4 || pid == self_pid {
        info!(
            target: TARGET_RESPONSE,
            pid,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            "Active response skipped: protected pid"
        );
        return;
    }

    let image = match task.image.as_deref() {
        Some(image) => image,
        None => {
            warn!(
                target: TARGET_RESPONSE,
                pid,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                "Active response skipped: missing image"
            );
            return;
        }
    };

    if is_allowlisted(image, allowlist_images, allowlist_paths) {
        info!(
            target: TARGET_RESPONSE,
            pid,
            image = %image,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            "Active response skipped: allowlisted"
        );
        return;
    }

    if !prevention_enabled {
        info!(
            target: TARGET_RESPONSE,
            pid,
            image = %image,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            dry_run = true,
            "Active response would terminate process"
        );
        return;
    }

    match terminate_process(pid) {
        Ok(()) => {
            info!(
                target: TARGET_RESPONSE,
                pid,
                image = %image,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                "Active response terminated process"
            );
        }
        Err(err) => {
            error!(
                target: TARGET_RESPONSE,
                pid,
                image = %image,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                error = %err,
                "Active response failed to terminate process"
            );
        }
    }
}

fn parse_min_severity(value: &str) -> AlertSeverity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => AlertSeverity::Critical,
        "high" => AlertSeverity::High,
        "medium" => AlertSeverity::Medium,
        "low" => AlertSeverity::Low,
        other => {
            warn!(
                target: TARGET_RESPONSE,
                min_severity = %other,
                "Unknown response.min_severity; defaulting to critical"
            );
            AlertSeverity::Critical
        }
    }
}

fn severity_rank(severity: AlertSeverity) -> u8 {
    match severity {
        AlertSeverity::Low => 0,
        AlertSeverity::Medium => 1,
        AlertSeverity::High => 2,
        AlertSeverity::Critical => 3,
    }
}

fn severity_at_least(severity: AlertSeverity, min: AlertSeverity) -> bool {
    severity_rank(severity) >= severity_rank(min)
}

fn extract_process_info(alert: &Alert) -> (Option<u32>, Option<String>) {
    let mut pid = None;
    let mut image = None;

    match &alert.event.fields {
        EventFields::ProcessCreation(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::FileEvent(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::RegistryEvent(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::NetworkConnection(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::DnsQuery(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::ImageLoad(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::PowerShellScript(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::WmiEvent(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::ServiceCreation(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::TaskCreation(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::RemoteThread(f) => {
            if let Some(target_pid) = parse_pid(f.target_process_id.as_deref()) {
                pid = Some(target_pid);
                image = f.target_image.clone();
            } else {
                pid = parse_pid(f.source_process_id.as_deref());
                image = f.source_image.clone();
            }
        }
        EventFields::Generic(_) => {}
    }

    if pid.is_none() {
        pid = alert
            .event
            .process_context
            .as_ref()
            .and_then(|ctx| parse_pid(ctx.process_id.as_deref()));
    }

    if image.is_none() {
        image = alert
            .event
            .process_context
            .as_ref()
            .and_then(|ctx| ctx.image.clone());
    }

    (pid, image)
}

fn parse_pid(value: Option<&str>) -> Option<u32> {
    let value = value?.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

fn normalize_path(value: &str) -> String {
    value.trim().replace('/', "\\").to_ascii_lowercase()
}

fn normalize_allowlist_paths(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|v| !v.trim().is_empty())
        .map(|value| {
            let mut normalized = normalize_path(value);
            if !normalized.ends_with('\\') {
                normalized.push('\\');
            }
            normalized
        })
        .collect()
}

fn normalize_allowlist_images(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|v| !v.trim().is_empty())
        .map(|value| normalize_path(value))
        .collect()
}

fn image_basename(path: &str) -> &str {
    let path = path.trim_end_matches('\\').trim_end_matches('/');
    let separator = path.rfind('\\').or_else(|| path.rfind('/'));
    match separator {
        Some(idx) => &path[idx + 1..],
        None => path,
    }
}

fn is_allowlisted(image: &str, allowlist_images: &[String], allowlist_paths: &[String]) -> bool {
    let normalized = normalize_path(image);

    if allowlist_paths
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        return true;
    }

    let basename = image_basename(&normalized);
    for entry in allowlist_images {
        if entry.contains('\\') || entry.contains('/') {
            if normalized == *entry {
                return true;
            }
        } else if basename == entry {
            return true;
        }
    }

    false
}

#[cfg(windows)]
fn terminate_process(pid: u32) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }
        .map_err(|err| format!("OpenProcess failed: {}", err))?;

    let result = unsafe { TerminateProcess(handle, 1) };
    unsafe {
        let _ = CloseHandle(handle);
    }

    match result {
        Ok(()) => Ok(()),
        Err(err) => Err(format!("TerminateProcess failed: {}", err)),
    }
}

#[cfg(not(windows))]
fn terminate_process(_pid: u32) -> Result<(), String> {
    Err("Active response termination is only supported on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
        ProcessCreationFields,
    };

    #[test]
    fn test_parse_pid_decimal() {
        assert_eq!(parse_pid(Some("1234")), Some(1234));
    }

    #[test]
    fn test_parse_pid_hex() {
        assert_eq!(parse_pid(Some("0x4D2")), Some(1234));
    }

    #[test]
    fn test_allowlist_image_basename() {
        let allowlist_images = vec!["cmd.exe".to_string()];
        let allowlist_paths = vec![];
        assert!(is_allowlisted(
            "C:\\Windows\\System32\\cmd.exe",
            &normalize_allowlist_images(&allowlist_images),
            &normalize_allowlist_paths(&allowlist_paths),
        ));
    }

    #[test]
    fn test_allowlist_path_prefix() {
        let allowlist_paths = vec!["C:\\Windows\\".to_string()];
        let allowlist_images = vec![];
        assert!(is_allowlisted(
            "C:\\Windows\\System32\\svchost.exe",
            &normalize_allowlist_images(&allowlist_images),
            &normalize_allowlist_paths(&allowlist_paths),
        ));
    }

    #[test]
    fn test_extract_process_info() {
        let alert = Alert {
            severity: AlertSeverity::High,
            rule_name: "Test".to_string(),
            rule_description: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-02-03T00:00:00Z".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some("C:\\Temp\\evil.exe".to_string()),
                    process_id: Some("4242".to_string()),
                    command_line: None,
                    original_file_name: None,
                    product: None,
                    description: None,
                    target_image: None,
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
        };

        let (pid, image) = extract_process_info(&alert);
        assert_eq!(pid, Some(4242));
        assert_eq!(image, Some("C:\\Temp\\evil.exe".to_string()));
    }
}
