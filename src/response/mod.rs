//! Active response engine (optional prevention).
//!
//! Non-blocking alert intake with a background worker that can terminate
//! processes on critical alerts.

use crate::config::ResponseConfig;
use crate::models::{Alert, AlertSeverity, DetectionEngine, EventFields};
use crate::utils::{
    hash_command_line, normalize_path_for_comparison, validate_process_identity, ProcessIdentity,
};
use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const TARGET_RESPONSE: &str = "response";
static IDENTITY_MISMATCH_SKIPS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct ResponseTask {
    severity: AlertSeverity,
    rule_name: String,
    engine: DetectionEngine,
    pid: Option<u32>,
    image: Option<String>,
    identity: Option<ProcessIdentity>,
}

#[derive(Clone)]
pub struct ResponseEngine {
    config: Arc<ArcSwap<ResponseConfig>>,
    self_pid: u32,
    tx: mpsc::Sender<ResponseTask>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseDecision {
    Disabled,
    BelowSeverity {
        severity: AlertSeverity,
        min_severity: AlertSeverity,
    },
    MissingPid,
    ProtectedPid {
        pid: u32,
    },
    MissingImage {
        pid: u32,
    },
    Allowlisted {
        pid: u32,
        image: String,
    },
    DryRun {
        pid: u32,
        image: String,
    },
    Terminate {
        pid: u32,
        image: String,
    },
}

impl ResponseEngine {
    pub fn new(cfg: Arc<ArcSwap<ResponseConfig>>) -> (Self, tokio::task::JoinHandle<()>) {
        let channel_capacity = cfg.load().channel_capacity;
        let (tx, mut rx) = mpsc::channel(channel_capacity);
        let self_pid = std::process::id();
        let worker_cfg = cfg.clone();

        let handle = tokio::spawn(async move {
            let initial = worker_cfg.load();
            debug!(
                target: TARGET_RESPONSE,
                enabled = initial.enabled,
                prevention_enabled = initial.prevention_enabled,
                min_severity = %initial.min_severity,
                "Active response worker started"
            );

            let mut prepared = PreparedConfig::from_raw(&worker_cfg.load());

            while let Some(task) = rx.recv().await {
                let current_raw = worker_cfg.load();
                prepared.refresh_if_changed(&current_raw);

                if !prepared.enabled {
                    continue;
                }

                handle_task(
                    task,
                    prepared.prevention_enabled,
                    self_pid,
                    &prepared.allowlist_images,
                    &prepared.allowlist_paths,
                );
            }

            debug!(target: TARGET_RESPONSE, "Active response worker shutting down");
        });

        (
            Self {
                config: cfg,
                self_pid,
                tx,
            },
            handle,
        )
    }

    pub fn handle_alert(&self, alert: &Alert) {
        let decision = self.decision_for_alert(alert);
        if matches!(
            decision,
            ResponseDecision::Disabled | ResponseDecision::BelowSeverity { .. }
        ) {
            return;
        }

        let (pid, image) = extract_process_info(alert);

        let task = ResponseTask {
            severity: effective_alert_severity(alert),
            rule_name: alert.rule_name.clone(),
            engine: alert.engine,
            pid,
            image,
            identity: extract_process_identity(alert),
        };

        if let Err(err) =
            crate::telemetry::try_send(crate::telemetry::ChannelId::ActiveResponse, &self.tx, task)
        {
            warn!(
                target: TARGET_RESPONSE,
                error = %err,
                "Active response queue full, dropping task"
            );
        }
    }

    pub fn decision_for_alert(&self, alert: &Alert) -> ResponseDecision {
        let current_cfg = self.config.load();
        if !current_cfg.enabled {
            return ResponseDecision::Disabled;
        }

        let severity = effective_alert_severity(alert);
        let min_severity = parse_min_severity(&current_cfg.min_severity);
        if !severity_at_least(severity, min_severity) {
            return ResponseDecision::BelowSeverity {
                severity,
                min_severity,
            };
        }

        let (pid, image) = extract_process_info(alert);
        let allowlist_images = normalize_allowlist_images(&current_cfg.allowlist_images);
        let allowlist_paths = normalize_allowlist_paths(&current_cfg.allowlist_paths);
        decide_response(
            pid,
            image.as_deref(),
            current_cfg.prevention_enabled,
            self.self_pid,
            &allowlist_images,
            &allowlist_paths,
        )
    }
}

/// Pre-computed / cached view of a `ResponseConfig`, rebuilt only when
/// the underlying `Arc` pointer changes (i.e. on hot-reload).
struct PreparedConfig {
    /// Pointer to the raw config this snapshot was built from.
    source: Arc<ResponseConfig>,
    enabled: bool,
    prevention_enabled: bool,
    allowlist_images: Vec<String>,
    allowlist_paths: Vec<String>,
}

impl PreparedConfig {
    fn from_raw(raw: &Arc<ResponseConfig>) -> Self {
        Self {
            source: Arc::clone(raw),
            enabled: raw.enabled,
            prevention_enabled: raw.prevention_enabled,
            allowlist_images: normalize_allowlist_images(&raw.allowlist_images),
            allowlist_paths: normalize_allowlist_paths(&raw.allowlist_paths),
        }
    }

    /// Rebuild the cached snapshot only if the underlying `Arc` pointer has changed.
    fn refresh_if_changed(&mut self, current: &Arc<ResponseConfig>) {
        if !Arc::ptr_eq(&self.source, current) {
            *self = Self::from_raw(current);
        }
    }
}

fn effective_alert_severity(alert: &Alert) -> AlertSeverity {
    match alert.engine {
        DetectionEngine::Yara => AlertSeverity::Critical,
        DetectionEngine::Sigma | DetectionEngine::Ioc => alert.severity,
    }
}

fn decide_response(
    pid: Option<u32>,
    image: Option<&str>,
    prevention_enabled: bool,
    self_pid: u32,
    allowlist_images: &[String],
    allowlist_paths: &[String],
) -> ResponseDecision {
    let pid = match pid {
        Some(pid) => pid,
        None => return ResponseDecision::MissingPid,
    };

    if pid <= 4 || pid == self_pid {
        return ResponseDecision::ProtectedPid { pid };
    }

    let image = match image {
        Some(image) => image,
        None => return ResponseDecision::MissingImage { pid },
    };

    if is_allowlisted(image, allowlist_images, allowlist_paths) {
        return ResponseDecision::Allowlisted {
            pid,
            image: image.to_string(),
        };
    }

    if prevention_enabled {
        ResponseDecision::Terminate {
            pid,
            image: image.to_string(),
        }
    } else {
        ResponseDecision::DryRun {
            pid,
            image: image.to_string(),
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
    match decide_response(
        task.pid,
        task.image.as_deref(),
        prevention_enabled,
        self_pid,
        allowlist_images,
        allowlist_paths,
    ) {
        ResponseDecision::MissingPid => {
            warn!(
                target: TARGET_RESPONSE,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                "Active response skipped: missing pid"
            );
        }
        ResponseDecision::ProtectedPid { pid } => {
            info!(
                target: TARGET_RESPONSE,
                pid,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                "Active response skipped: protected pid"
            );
        }
        ResponseDecision::MissingImage { pid } => {
            warn!(
                target: TARGET_RESPONSE,
                pid,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                "Active response skipped: missing image"
            );
        }
        ResponseDecision::Allowlisted { pid, image } => {
            info!(
                target: TARGET_RESPONSE,
                pid,
                image = %image,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                "Active response skipped: allowlisted"
            );
        }
        ResponseDecision::DryRun { pid, image } => {
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
        }
        ResponseDecision::Terminate { pid, image } => {
            let expected_identity = task.identity.unwrap_or_else(|| ProcessIdentity {
                pid,
                image: image.clone(),
                start_time: None,
                command_line_hash: None,
            });

            match validate_process_identity(&expected_identity) {
                Ok(current_identity) => match terminate_process(pid) {
                    Ok(()) => {
                        info!(
                            target: TARGET_RESPONSE,
                            pid,
                            image = %image,
                            current_image = %current_identity.image,
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
                },
                Err(err) => {
                    let skipped_identity_mismatch_count =
                        IDENTITY_MISMATCH_SKIPS.fetch_add(1, Ordering::Relaxed) + 1;
                    warn!(
                        target: TARGET_RESPONSE,
                        pid,
                        image = %image,
                        rule = %task.rule_name,
                        engine = ?task.engine,
                        severity = ?task.severity,
                        skipped_identity_mismatch_count,
                        reason = %err,
                        "Active response skipped: process identity mismatch"
                    );
                }
            }
        }
        ResponseDecision::Disabled | ResponseDecision::BelowSeverity { .. } => {}
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
        EventFields::PowerShellModule(f) => {
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

fn extract_process_identity(alert: &Alert) -> Option<ProcessIdentity> {
    let (pid, image, start_time, command_line) = match &alert.event.fields {
        EventFields::ProcessCreation(f) => (
            parse_pid(f.process_id.as_deref()),
            f.image.clone(),
            f.process_start_time,
            f.command_line.as_deref(),
        ),
        _ => (
            alert
                .event
                .process_context
                .as_ref()
                .and_then(|ctx| parse_pid(ctx.process_id.as_deref())),
            alert
                .event
                .process_context
                .as_ref()
                .and_then(|ctx| ctx.image.clone()),
            alert
                .event
                .process_context
                .as_ref()
                .and_then(|ctx| ctx.process_start_time),
            alert
                .event
                .process_context
                .as_ref()
                .and_then(|ctx| ctx.command_line.as_deref()),
        ),
    };

    Some(ProcessIdentity {
        pid: pid?,
        image: image?,
        start_time,
        command_line_hash: command_line.map(hash_command_line),
    })
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

fn normalize_allowlist_paths(values: &[String]) -> Vec<String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const SEP: char = '/';
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const SEP: char = '\\';

    values
        .iter()
        .filter(|v| !v.trim().is_empty())
        .map(|value| {
            let mut normalized = normalize_path_for_comparison(value);
            if !normalized.ends_with(SEP) {
                normalized.push(SEP);
            }
            normalized
        })
        .collect()
}

fn normalize_allowlist_images(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|v| !v.trim().is_empty())
        .map(|value| normalize_path_for_comparison(value))
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
    let normalized = normalize_path_for_comparison(image);

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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminate_process(pid: u32) -> Result<(), String> {
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if ret == 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        Err(format!("kill({}, SIGKILL) failed: {}", pid, err))
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn terminate_process(_pid: u32) -> Result<(), String> {
    Err("Active response termination is not supported on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
        ProcessCreationFields,
    };
    use crate::sensor::Platform;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    struct LogWriter(LogBuffer);

    impl Write for LogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                 .0
                .lock()
                .expect("log buffer lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogBuffer {
        type Writer = LogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LogWriter(self.clone())
        }
    }

    fn test_process_alert(pid: Option<&str>, image: Option<&str>) -> Alert {
        Alert {
            severity: AlertSeverity::Low,
            rule_name: "Test process rule".to_string(),
            rule_description: None,
            rule_id: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-02-03T00:00:00Z".to_string(),
                platform: Platform::Linux,
                provider: "test".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: image.map(str::to_string),
                    process_id: pid.map(str::to_string),
                    process_start_time: None,
                    command_line: None,
                    original_file_name: None,
                    product: None,
                    description: None,
                    company: None,
                    file_version: None,
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
        }
    }

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
        #[cfg(windows)]
        {
            let allowlist_paths = vec!["C:\\Windows\\".to_string()];
            let allowlist_images = vec![];
            assert!(is_allowlisted(
                "C:\\Windows\\System32\\svchost.exe",
                &normalize_allowlist_images(&allowlist_images),
                &normalize_allowlist_paths(&allowlist_paths),
            ));
        }
        #[cfg(not(windows))]
        {
            let allowlist_paths = vec!["/usr/bin/".to_string()];
            let allowlist_images = vec![];
            assert!(is_allowlisted(
                "/usr/bin/bash",
                &normalize_allowlist_images(&allowlist_images),
                &normalize_allowlist_paths(&allowlist_paths),
            ));
        }
    }

    #[test]
    fn handle_alert_logs_allowlisted_decision() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let logs = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                let cfg = std::sync::Arc::new(arc_swap::ArcSwap::from(std::sync::Arc::new(
                    ResponseConfig {
                        enabled: true,
                        prevention_enabled: true,
                        min_severity: "low".to_string(),
                        channel_capacity: 4,
                        allowlist_images: vec![],
                        allowlist_paths: vec!["/usr/bin/".to_string()],
                    },
                )));
                let (engine, worker) = ResponseEngine::new(cfg);

                engine.handle_alert(&test_process_alert(Some("4242"), Some("/usr/bin/sleep")));
                drop(engine);
                worker.await.expect("response worker");
            });
        });

        let output =
            String::from_utf8(logs.0.lock().expect("log buffer lock").clone()).expect("UTF-8 logs");
        assert!(
            output.contains("Active response skipped: allowlisted"),
            "expected allowlist decision in logs, got: {output}"
        );
        assert!(output.contains("pid=4242"));
        assert!(output.contains("image=/usr/bin/sleep"));
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn validate_process_identity_accepts_current_process() {
        let pid = std::process::id();
        let identity = crate::utils::query_process_identity(pid).expect("current process identity");
        assert!(validate_process_identity(&identity).is_ok());
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn validate_process_identity_rejects_image_mismatch() {
        let pid = std::process::id();
        let mut identity =
            crate::utils::query_process_identity(pid).expect("current process identity");
        identity.image = if cfg!(windows) {
            r"C:\definitely-not-rustinel.exe".to_string()
        } else {
            "/definitely/not/rustinel".to_string()
        };

        assert!(validate_process_identity(&identity).is_err());
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn validate_process_identity_rejects_start_time_mismatch_when_available() {
        let pid = std::process::id();
        let mut identity =
            crate::utils::query_process_identity(pid).expect("current process identity");
        let Some(start_time) = identity.start_time else {
            return;
        };
        identity.start_time = Some(start_time.saturating_add(1));

        assert!(validate_process_identity(&identity).is_err());
    }

    #[test]
    fn test_extract_process_info() {
        let alert = test_process_alert(Some("4242"), Some("C:\\Temp\\evil.exe"));

        let (pid, image) = extract_process_info(&alert);
        assert_eq!(pid, Some(4242));
        assert_eq!(image, Some("C:\\Temp\\evil.exe".to_string()));
    }
}
