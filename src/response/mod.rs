//! Active response engine (optional prevention).
//!
//! Non-blocking alert intake with a background worker that can terminate
//! processes on alerts that meet the configured severity threshold.

mod process;

use crate::config::ResponseConfig;
use crate::models::{Alert, AlertSeverity, DetectionEngine, EventFields};
use crate::utils::{
    hash_command_line, normalize_path_for_comparison, LogRateLimiter, ProcessIdentity,
};
use arc_swap::ArcSwap;
use process::ProcessTarget;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const TARGET_RESPONSE: &str = "response";
const RESPONSE_WARNING_WINDOW: Duration = Duration::from_secs(60);
static IDENTITY_MISMATCH_SKIPS: AtomicU64 = AtomicU64::new(0);
static RESPONSE_WARNINGS: LazyLock<Mutex<LogRateLimiter>> =
    LazyLock::new(|| Mutex::new(LogRateLimiter::new(RESPONSE_WARNING_WINDOW)));

fn warn_limited(key: &str, emit: impl FnOnce(u64)) {
    let decision = match RESPONSE_WARNINGS.lock() {
        Ok(mut limiter) => limiter.should_emit(key),
        Err(poisoned) => poisoned.into_inner().should_emit(key),
    };
    if decision.should_emit {
        emit(decision.suppressed_since_last_emit);
    }
}

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
            severity: alert.severity,
            rule_name: alert.rule_name.clone(),
            engine: alert.engine,
            pid,
            image,
            identity: extract_process_identity(alert),
        };

        if let Err(err) =
            crate::telemetry::try_send(crate::telemetry::ChannelId::ActiveResponse, &self.tx, task)
        {
            warn_limited("queue", |suppressed_warnings| {
                warn!(
                    target: TARGET_RESPONSE,
                    error = %err,
                    suppressed_warnings,
                    "Active response queue unavailable; dropping task"
                );
            });
        }
    }

    pub fn decision_for_alert(&self, alert: &Alert) -> ResponseDecision {
        let current_cfg = self.config.load();
        if !current_cfg.enabled {
            return ResponseDecision::Disabled;
        }

        let severity = alert.severity;
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
    handle_task_with_hook(
        task,
        prevention_enabled,
        self_pid,
        allowlist_images,
        allowlist_paths,
        |_, _| {},
    );
}

// The hook lets tests redirect bare PID lookups after validation while keeping
// the native process reference unchanged. Production uses a no-op hook.
fn handle_task_with_hook(
    task: ResponseTask,
    prevention_enabled: bool,
    self_pid: u32,
    allowlist_images: &[String],
    allowlist_paths: &[String],
    after_validation: impl FnOnce(&mut u32, &mut ProcessTarget),
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
            warn_limited("missing_pid", |suppressed_warnings| {
                warn!(
                    target: TARGET_RESPONSE,
                    rule = %task.rule_name,
                    engine = ?task.engine,
                    severity = ?task.severity,
                    suppressed_warnings,
                    "Active response skipped: missing pid"
                );
            });
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
            warn_limited("missing_image", |suppressed_warnings| {
                warn!(
                    target: TARGET_RESPONSE,
                    pid,
                    rule = %task.rule_name,
                    engine = ?task.engine,
                    severity = ?task.severity,
                    suppressed_warnings,
                    "Active response skipped: missing image"
                );
            });
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
        ResponseDecision::Terminate { mut pid, image } => {
            let expected_identity = task.identity.unwrap_or_else(|| ProcessIdentity {
                pid,
                image: image.clone(),
                start_time: None,
                command_line_hash: None,
            });

            match ProcessTarget::open(&expected_identity) {
                Ok(mut target) => {
                    after_validation(&mut pid, &mut target);
                    match target.terminate() {
                        Ok(()) => {
                            info!(
                                target: TARGET_RESPONSE,
                                pid,
                                image = %image,
                                current_image = %target.identity.image,
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
                Err(err) => {
                    let skipped_identity_mismatch_count =
                        IDENTITY_MISMATCH_SKIPS.fetch_add(1, Ordering::Relaxed) + 1;
                    warn_limited("identity_mismatch", |suppressed_warnings| {
                        warn!(
                            target: TARGET_RESPONSE,
                            pid,
                            image = %image,
                            rule = %task.rule_name,
                            engine = ?task.engine,
                            severity = ?task.severity,
                            skipped_identity_mismatch_count,
                            suppressed_warnings,
                            reason = %err,
                            "Active response skipped: process identity mismatch"
                        );
                    });
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
        AlertSeverity::Informational => 0,
        AlertSeverity::Low => 1,
        AlertSeverity::Medium => 2,
        AlertSeverity::High => 3,
        AlertSeverity::Critical => 4,
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
        EventFields::PowerShellClassicStart(_) => {}
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
        EventFields::SecurityAudit(f) => {
            pid = f.process_id();
            image = f.get_non_placeholder("ProcessName").map(str::to_string);
        }
        EventFields::ApplicationEvent(_) => {}
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
    crate::utils::path_allowlist::PathAllowlistPolicy::ResponseDirectory.normalize_prefixes(values)
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

    if crate::utils::path_allowlist::matches_normalized(&normalized, allowlist_paths) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
        ProcessCreationFields,
    };
    #[cfg(any(windows, target_os = "linux"))]
    use crate::utils::validate_process_identity;
    use crate::vocab::Platform;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::fmt::MakeWriter;

    // Spawn this test in a separate copy of the test executable. It needs no
    // example build, shell, privileges, or platform-specific external program.
    #[test]
    fn response_child_fixture() {
        let Some(ready) = std::env::var_os("RUSTINEL_RESPONSE_TEST_READY") else {
            return;
        };
        std::fs::write(ready, b"ready").expect("write child readiness marker");
        std::thread::sleep(Duration::from_secs(60));
    }

    struct ResponseChild {
        child: std::process::Child,
        _ready_dir: tempfile::TempDir,
    }

    impl ResponseChild {
        fn spawn() -> Self {
            let ready_dir = tempfile::tempdir().expect("child readiness directory");
            let ready = ready_dir.path().join("ready");
            let child =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args(["--exact", "response::tests::response_child_fixture"])
                    .env("RUSTINEL_RESPONSE_TEST_READY", &ready)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("spawn response child");
            let mut child = Self {
                child,
                _ready_dir: ready_dir,
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !ready.exists() {
                assert!(
                    child.child.try_wait().expect("child status").is_none(),
                    "child exited before ready"
                );
                assert!(
                    std::time::Instant::now() < deadline,
                    "child readiness timed out"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            child
        }

        fn task(&self) -> ResponseTask {
            let identity =
                crate::utils::query_process_identity(self.child.id()).expect("child identity");
            ResponseTask {
                severity: AlertSeverity::Critical,
                rule_name: "Response child test".to_string(),
                engine: DetectionEngine::Sigma,
                pid: Some(identity.pid),
                image: Some(identity.image.clone()),
                identity: Some(identity),
            }
        }

        fn assert_running(&mut self) {
            assert!(
                self.child.try_wait().expect("child status").is_none(),
                "response killed a child that should survive"
            );
        }

        fn wait_for_exit(&mut self) {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while self.child.try_wait().expect("child status").is_none() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "response did not terminate child"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for ResponseChild {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn response_terminates_validated_child() {
        let mut child = ResponseChild::spawn();
        handle_task(child.task(), true, std::process::id(), &[], &[]);
        child.wait_for_exit();
    }

    #[test]
    fn response_dry_run_preserves_child() {
        let mut child = ResponseChild::spawn();
        let mut validated = false;
        handle_task_with_hook(child.task(), false, std::process::id(), &[], &[], |_, _| {
            validated = true
        });
        assert!(!validated, "dry run must not open a termination target");
        child.assert_running();
    }

    #[test]
    fn response_rejects_mismatched_child_identity() {
        let mut child = ResponseChild::spawn();
        for mismatch in 0..3 {
            let mut task = child.task();
            let identity = task.identity.as_mut().expect("expected identity");
            match mismatch {
                0 => identity.image = "/different/executable".to_string(),
                1 => identity.start_time = Some(identity.start_time.expect("child start time") + 1),
                // macOS cannot query a command-line hash.
                _ if cfg!(target_os = "macos") => continue,
                _ => identity.command_line_hash = Some("different hash".to_string()),
            }
            let mut validated = false;
            handle_task_with_hook(task, true, std::process::id(), &[], &[], |_, _| {
                validated = true
            });
            assert!(!validated, "mismatched identity must skip termination");
            child.assert_running();
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn response_target_swap_after_validation_preserves_replacement() {
        let mut original = ResponseChild::spawn();
        let mut replacement = None;
        handle_task_with_hook(
            original.task(),
            true,
            std::process::id(),
            &[],
            &[],
            |pid, target| {
                original
                    .child
                    .kill()
                    .expect("end original process after validation");
                original.child.wait().expect("reap original process");
                let child = ResponseChild::spawn();
                // Deterministically simulate PID lookup resolving to a replacement.
                // Kernel PID reuse cannot be forced portably in unprivileged CI.
                // Termination must use the retained handle even if the stored PID
                // and all identity metadata are redirected to the replacement.
                *pid = child.child.id();
                target.identity = child.task().identity.expect("replacement identity");
                replacement = Some(child);
            },
        );
        let mut replacement = replacement.expect("swap hook ran after validation");
        std::thread::sleep(Duration::from_millis(100));
        replacement.assert_running();
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn response_termination_uses_retained_handle_despite_pid_change() {
        let mut original = ResponseChild::spawn();
        let mut replacement = ResponseChild::spawn();
        let mut validated = false;
        handle_task_with_hook(
            original.task(),
            true,
            std::process::id(),
            &[],
            &[],
            |pid, target| {
                validated = true;
                *pid = replacement.child.id();
                target.identity = replacement.task().identity.expect("replacement identity");
            },
        );
        assert!(validated, "original identity was validated");
        original.wait_for_exit();
        replacement.assert_running();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn response_pidfd_liveness_rejects_exited_process() {
        let mut child = ResponseChild::spawn();
        let target = ProcessTarget::open(&child.task().identity.expect("child identity"))
            .expect("open live child pidfd");
        child.child.kill().expect("end child");
        child.child.wait().expect("reap child");
        assert!(target.ensure_live().is_err());
        assert!(target.terminate().is_err());
    }

    #[test]
    fn yara_response_intake_respects_severity_and_preserves_it_in_tasks() {
        let (tx, mut rx) = mpsc::channel(4);
        let engine = ResponseEngine {
            config: Arc::new(ArcSwap::from_pointee(ResponseConfig {
                enabled: true,
                prevention_enabled: false,
                min_severity: "high".to_string(),
                channel_capacity: 4,
                allowlist_images: vec![],
                allowlist_paths: vec![],
            })),
            self_pid: std::process::id(),
            tx,
        };
        let mut alert = test_process_alert(Some("99999999"), Some("/tmp/sample"));
        alert.engine = DetectionEngine::Yara;

        engine.handle_alert(&alert);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        alert.severity = AlertSeverity::High;
        engine.handle_alert(&alert);
        let task = rx.try_recv().expect("high YARA response task");
        assert_eq!(task.severity, AlertSeverity::High);
        assert_eq!(task.engine, DetectionEngine::Yara);
    }

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
            sigma_metadata: None,
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-02-03T00:00:00Z".to_string(),
                source_seq: None,
                ingest_seq: 0,
                platform: Platform::Linux,
                provider: "test".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    hashes: None,
                    imphash: None,
                    container: Default::default(),
                    linux_identity: Default::default(),
                    cgroup_id: None,
                    exec: Default::default(),
                    parent_process_id_derived: false,
                    windows: Default::default(),
                    image: image.map(str::to_string),
                    image_source: None,
                    image_truncated: None,
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
                    parent_user: None,
                    current_directory: None,
                    integrity_level: None,
                    user: None,
                }),
                process_name: None,
                provenance: Default::default(),
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
