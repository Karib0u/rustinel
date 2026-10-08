use crate::alerts::AlertSink;
use crate::config;
use crate::utils::fs::{ensure_output_directory, open_output_file};
use anyhow::{bail, Context};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const STARTUP_BANNER_INNER_WIDTH: usize = 49;
pub use crate::vocab::TARGET_CONSOLE;
const DEFAULT_CONSOLE_FILTER: &str = "warn,console=info,engine=info,response=info";

struct RestrictedFileAppender {
    inner: File,
    directory: PathBuf,
    filename_prefix: String,
    date: chrono::NaiveDate,
    group: Option<u32>,
}

impl Write for RestrictedFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let current_date = chrono::Utc::now().date_naive();
        if current_date != self.date {
            prepare_log_directory(&self.directory, self.group)?;
            self.inner = open_log_file(
                &self.directory,
                &self.filename_prefix,
                current_date,
                self.group,
            )?;
            self.date = current_date;
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Build an `EnvFilter` from the logging configuration, with fallback to `info`.
pub fn build_log_filter(logging: &config::LogConfig) -> EnvFilter {
    if let Some(raw_filter) = logging.filter.as_deref() {
        let filter = raw_filter.trim();
        if !filter.is_empty() {
            match EnvFilter::try_new(filter) {
                Ok(parsed) => return parsed,
                Err(err) => {
                    eprintln!(
                        "Invalid logging.filter '{}': {}. Falling back to logging.level '{}'",
                        filter, err, logging.level
                    );
                }
            }
        }
    }

    match EnvFilter::try_new(logging.level.trim()) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!(
                "Invalid logging.level '{}': {}. Falling back to 'info'",
                logging.level, err
            );
            EnvFilter::try_new("info").expect("hardcoded 'info' filter should always parse")
        }
    }
}

/// Build the filter for an interactive console layer.
///
/// The operational file keeps the configured stream. With the default info
/// level, the console shows milestones and detections while suppressing
/// component internals. Explicit debug or trace levels opt into the full
/// stream for troubleshooting. A custom filter remains authoritative for
/// both outputs.
fn build_console_log_filter(logging: &config::LogConfig, base_filter: &EnvFilter) -> EnvFilter {
    let has_custom_filter = logging
        .filter
        .as_deref()
        .map(str::trim)
        .is_some_and(|filter| !filter.is_empty());
    if has_custom_filter {
        return base_filter.clone();
    }

    let level = logging.level.trim().to_ascii_lowercase();
    let filter = match level.as_str() {
        "debug" | "trace" => logging.level.trim(),
        "warn" => "warn",
        "error" => "error",
        _ => DEFAULT_CONSOLE_FILTER,
    };

    EnvFilter::try_new(filter).unwrap_or_else(|_| {
        EnvFilter::try_new(DEFAULT_CONSOLE_FILTER)
            .expect("hardcoded console filter should always parse")
    })
}

pub fn log_startup_banner(runtime: &str) {
    info!(target: TARGET_CONSOLE, "╔═══════════════════════════════════════════════════╗");
    info!(
        target: TARGET_CONSOLE,
        "║ {:^width$} ║",
        format!("Rustinel v{} ({})", APP_VERSION, runtime),
        width = STARTUP_BANNER_INNER_WIDTH
    );
    info!(
        target: TARGET_CONSOLE,
        "║ {:^width$} ║",
        "High-Performance Endpoint Detection Agent",
        width = STARTUP_BANNER_INNER_WIDTH
    );
    info!(target: TARGET_CONSOLE, "╚═══════════════════════════════════════════════════╝");
}

/// Initialize dual-pipeline logging system.
/// Returns WorkerGuards that MUST be kept alive for the duration of the program.
#[cfg(windows)]
pub fn init_logging(
    cfg: &config::AppConfig,
) -> anyhow::Result<(
    tracing_appender::non_blocking::WorkerGuard,
    tracing_appender::non_blocking::WorkerGuard,
    AlertSink,
)> {
    let (app_writer, app_guard) = build_daily_writer(
        "operational",
        &cfg.logging.directory,
        &cfg.logging.filename,
        cfg.security.log_group(),
    )?;
    let base_filter = build_log_filter(&cfg.logging);
    let console_filter = build_console_log_filter(&cfg.logging, &base_filter);

    let app_layer = fmt::layer()
        .with_writer(app_writer)
        .compact()
        .with_ansi(false)
        .with_target(true)
        .with_filter(base_filter.clone());

    let (alert_writer, alert_guard) = build_daily_writer(
        "alerts",
        &cfg.alerts.directory,
        &cfg.alerts.filename,
        cfg.security.log_group(),
    )?;
    let alert_sink = AlertSink::new(alert_writer);

    let ansi_supported = std::env::var("WT_SESSION").is_ok();
    let console_layer = if cfg.logging.console_output {
        Some(
            fmt::layer()
                .compact()
                .with_ansi(ansi_supported)
                .with_target(false)
                .with_filter(console_filter),
        )
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(app_layer)
        .with(console_layer)
        .init();

    Ok((app_guard, alert_guard, alert_sink))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn init_logging(
    cfg: &config::AppConfig,
) -> anyhow::Result<(
    tracing_appender::non_blocking::WorkerGuard,
    tracing_appender::non_blocking::WorkerGuard,
    AlertSink,
)> {
    let (app_writer, app_guard) = build_daily_writer(
        "operational",
        &cfg.logging.directory,
        &cfg.logging.filename,
        cfg.security.log_group(),
    )?;
    let base_filter = build_log_filter(&cfg.logging);
    let console_filter = build_console_log_filter(&cfg.logging, &base_filter);

    let app_layer = fmt::layer()
        .with_writer(app_writer)
        .compact()
        .with_ansi(false)
        .with_target(true)
        .with_filter(base_filter.clone());

    let (alert_writer, alert_guard) = build_daily_writer(
        "alerts",
        &cfg.alerts.directory,
        &cfg.alerts.filename,
        cfg.security.log_group(),
    )?;

    if cfg.logging.console_output {
        let console_layer = fmt::layer()
            .compact()
            .with_ansi(true)
            .with_target(false)
            .with_filter(console_filter);
        tracing_subscriber::registry()
            .with(app_layer)
            .with(console_layer)
            .init();
    } else {
        tracing_subscriber::registry().with(app_layer).init();
    }

    Ok((app_guard, alert_guard, AlertSink::new(alert_writer)))
}

/// Initialize operational logging only, without the alert pipeline.
///
/// Used by `rustinel capture`, which never emits alerts: initializing the alert
/// appender would create an alert file for a session that has nothing to write
/// to it, blurring the line between recordings and detection output.
pub fn init_operational_logging(
    cfg: &config::AppConfig,
) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let (app_writer, app_guard) = build_daily_writer(
        "operational",
        &cfg.logging.directory,
        &cfg.logging.filename,
        cfg.security.log_group(),
    )?;
    let base_filter = build_log_filter(&cfg.logging);
    let console_filter = build_console_log_filter(&cfg.logging, &base_filter);

    let app_layer = fmt::layer()
        .with_writer(app_writer)
        .compact()
        .with_ansi(false)
        .with_target(true)
        .with_filter(base_filter.clone());

    let console_layer = if cfg.logging.console_output {
        Some(
            fmt::layer()
                .compact()
                .with_ansi(console_ansi_supported())
                .with_target(false)
                .with_filter(console_filter),
        )
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(app_layer)
        .with(console_layer)
        .init();

    Ok(app_guard)
}

/// Initialize logging to stderr only, touching no log directory.
///
/// Used by `rustinel replay`, which must run unprivileged on a host that has
/// never had Rustinel installed. Opening the managed log directory would either
/// fail or create operational logs for a session that observed nothing. stderr
/// keeps diagnostics — a rule that failed to compile, say — out of the replay
/// report on stdout.
pub fn init_replay_logging(cfg: &config::AppConfig) {
    let base_filter = build_log_filter(&cfg.logging);
    let layer = fmt::layer()
        .with_writer(std::io::stderr)
        .compact()
        .with_ansi(console_ansi_supported())
        .with_target(false)
        .with_filter(build_console_log_filter(&cfg.logging, &base_filter));

    // A replay running inside a process that already has a subscriber keeps
    // that one; this is best-effort diagnostics, not a reason to fail.
    let _ = tracing_subscriber::registry().with(layer).try_init();
}

/// Windows terminals other than Windows Terminal render ANSI escapes literally.
#[cfg(windows)]
fn console_ansi_supported() -> bool {
    std::env::var("WT_SESSION").is_ok()
}

#[cfg(not(windows))]
fn console_ansi_supported() -> bool {
    true
}

fn build_daily_writer(
    label: &str,
    directory: &Path,
    filename: &str,
    group: Option<u32>,
) -> anyhow::Result<(
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
)> {
    if Path::new(filename).file_name() != Some(std::ffi::OsStr::new(filename)) {
        bail!("invalid {} log filename {:?}", label, filename);
    }
    prepare_log_directory(directory, group).with_context(|| {
        format!(
            "failed to prepare {} log directory {}",
            label,
            directory.display()
        )
    })?;
    let date = chrono::Utc::now().date_naive();
    let appender = RestrictedFileAppender {
        inner: open_log_file(directory, filename, date, group).with_context(|| {
            format!(
                "failed to open {} log file in {}",
                label,
                directory.display()
            )
        })?,
        directory: directory.to_path_buf(),
        filename_prefix: filename.to_owned(),
        date,
        group,
    };
    Ok(tracing_appender::non_blocking(appender))
}

fn prepare_log_directory(directory: &Path, group: Option<u32>) -> io::Result<()> {
    if let Some(gid) = group {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::symlink_metadata(directory)?;
            // Setgid gives new files the group without CAP_CHOWN, which the
            // managed systemd unit does not grant.
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.gid() != gid
                || metadata.mode() & 0o2000 == 0
                || metadata.mode() & 0o027 != 0
                || metadata.mode() & 0o050 != 0o050
            {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                    "integration log directory must be root-owned with the integration group and mode 2750"));
            }
            crate::utils::trust::verify_root_controlled_parents(directory, gid)
                .map_err(|err| io::Error::new(io::ErrorKind::PermissionDenied, err.to_string()))?;
        }
        #[cfg(not(unix))]
        {
            let _ = gid;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "integration log access requires Unix",
            ));
        }
    }
    ensure_output_directory(directory)
}

fn open_log_file(
    directory: &Path,
    filename: &str,
    date: chrono::NaiveDate,
    group: Option<u32>,
) -> io::Result<File> {
    let file = open_output_file(&directory.join(format!("{filename}.{date}")), true)?;
    if let Some(gid) = group {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = file.metadata()?;
            if metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "integration logs must not have hard links",
                ));
            }
            // SAFETY: the descriptor belongs to `file`, which is borrowed for the
            // call, and uid `!0` leaves the owner unchanged.
            if metadata.gid() != gid && unsafe { libc::fchown(file.as_raw_fd(), !0, gid) } != 0 {
                let err = io::Error::last_os_error();
                return Err(io::Error::new(
                    err.kind(),
                    format!(
                        "cannot assign the integration group to {filename}.{date} ({err}); \
                         chgrp the existing log files to the integration group"
                    ),
                ));
            }
            file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        }
        #[cfg(not(unix))]
        let _ = gid;
    }
    Ok(file)
}

#[cfg(all(test, unix))]
mod permission_tests {
    use super::{build_daily_writer, open_log_file, RestrictedFileAppender};
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[ignore = "requires root; exercised by Unix CI"]
    fn integration_group_logs_stay_read_only_across_rotation() {
        use crate::config::security::test_support::Fixture;
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new();
        let directory = fixture.root.path().join("logs");
        fs::create_dir(&directory).unwrap();
        fixture.permissions(&directory, 0o2750);
        super::prepare_log_directory(&directory, Some(fixture.gid)).unwrap();
        let today = chrono::Utc::now().date_naive();
        let yesterday = today.pred_opt().unwrap();
        let mut appender = RestrictedFileAppender {
            inner: open_log_file(&directory, "alerts.json", yesterday, Some(fixture.gid)).unwrap(),
            directory: directory.clone(),
            filename_prefix: "alerts.json".into(),
            date: yesterday,
            group: Some(fixture.gid),
        };
        appender.write_all(b"alert\n").unwrap();
        for date in [yesterday, today] {
            let path = directory.join(format!("alerts.json.{date}"));
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o640);
            assert_eq!(metadata.gid(), fixture.gid);
            assert_eq!(metadata.uid(), 0);
            assert!(fixture
                .wrapper("cat \"$LOG_FILE\"")
                .env("LOG_FILE", &path)
                .output()
                .unwrap()
                .status
                .success());
            assert!(!fixture
                .wrapper("printf tamper >> \"$LOG_FILE\"")
                .env("LOG_FILE", &path)
                .output()
                .unwrap()
                .status
                .success());
            assert!(!fixture
                .wrapper("rm \"$LOG_FILE\"")
                .env("LOG_FILE", &path)
                .output()
                .unwrap()
                .status
                .success());
            drop(open_log_file(&directory, "alerts.json", date, Some(fixture.gid)).unwrap());
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o640);
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o2770)).unwrap();
        assert!(super::prepare_log_directory(&directory, Some(fixture.gid)).is_err());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(
            super::prepare_log_directory(&directory, Some(fixture.gid)).is_err(),
            "without setgid, new files need CAP_CHOWN to get the group"
        );
        fixture.permissions(&directory, 0o2750);

        // Ubuntu's /var/log is root:syslog 0775: group write for another
        // group is fine, group write for the integration group is not.
        let parent = fixture.root.path();
        std::os::unix::fs::chown(parent, Some(0), Some(0)).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o775)).unwrap();
        super::prepare_log_directory(&directory, Some(fixture.gid)).unwrap();
        fixture.permissions(parent, 0o775);
        assert!(super::prepare_log_directory(&directory, Some(fixture.gid)).is_err());
        fixture.permissions(parent, 0o750);

        // A file left by an earlier release keeps root's group until reopened.
        let legacy = directory.join(format!("legacy.json.{today}"));
        fs::write(&legacy, b"old\n").unwrap();
        std::os::unix::fs::chown(&legacy, Some(0), Some(0)).unwrap();
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
        drop(open_log_file(&directory, "legacy.json", today, Some(fixture.gid)).unwrap());
        let metadata = fs::metadata(&legacy).unwrap();
        assert_eq!(
            (metadata.gid(), metadata.mode() & 0o777),
            (fixture.gid, 0o640)
        );

        drop(open_log_file(&directory, "private.json", today, None).unwrap());
        assert_eq!(
            fs::metadata(directory.join(format!("private.json.{today}")))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn existing_directory_keeps_its_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("logs");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o1777)).unwrap();
        let (_writer, guard) =
            build_daily_writer("alerts", &directory, "alerts.json", None).unwrap();
        drop(guard);

        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
            0o1777
        );
    }

    #[test]
    fn symlinked_alert_file_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"safe").unwrap();
        let date = chrono::Utc::now().date_naive();
        std::os::unix::fs::symlink(&target, temp.path().join(format!("alerts.json.{date}")))
            .unwrap();
        assert!(build_daily_writer("alerts", temp.path(), "alerts.json", None).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"safe");
    }

    #[test]
    fn rotation_rejects_symlinked_alert_file() {
        let temp = tempfile::tempdir().unwrap();
        let today = chrono::Utc::now().date_naive();
        let yesterday = today.pred_opt().unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"safe").unwrap();
        std::os::unix::fs::symlink(&target, temp.path().join(format!("alerts.json.{today}")))
            .unwrap();
        let mut appender = RestrictedFileAppender {
            inner: open_log_file(temp.path(), "alerts.json", yesterday, None).unwrap(),
            directory: temp.path().to_path_buf(),
            filename_prefix: "alerts.json".to_owned(),
            date: yesterday,
            group: None,
        };
        assert!(appender.write_all(b"alert").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"safe");
    }
}

#[cfg(test)]
mod filter_tests {
    use super::{build_console_log_filter, build_log_filter, TARGET_CONSOLE};
    use crate::config;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::{fmt, layer::SubscriberExt, Layer};

    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn logging(level: &str, filter: Option<&str>) -> config::LogConfig {
        let mut logging = config::AppConfig::default().logging;
        logging.level = level.to_owned();
        logging.filter = filter.map(str::to_owned);
        logging
    }

    #[test]
    fn default_info_console_filter_is_compact() {
        let logging = logging("info", None);
        let file_filter = build_log_filter(&logging);
        let console_filter = build_console_log_filter(&logging, &file_filter);
        let rendered = console_filter.to_string();

        for directive in ["warn", "console=info", "engine=info", "response=info"] {
            assert!(rendered.split(',').any(|item| item == directive));
        }
    }

    #[test]
    fn debug_console_filter_follows_the_requested_level() {
        let logging = logging("debug", None);
        let file_filter = build_log_filter(&logging);
        let console_filter = build_console_log_filter(&logging, &file_filter);

        assert_eq!(console_filter.to_string(), "debug");
    }

    #[test]
    fn custom_filter_applies_to_the_console_as_well() {
        let logging = logging("info", Some("info,scanner=debug"));
        let file_filter = build_log_filter(&logging);
        let console_filter = build_console_log_filter(&logging, &file_filter);
        let rendered = console_filter.to_string();

        assert!(rendered.split(',').any(|item| item == "info"));
        assert!(rendered.split(',').any(|item| item == "scanner=debug"));
    }

    #[test]
    fn default_info_console_output_keeps_user_facing_events() {
        let logging = logging("info", None);
        let file_filter = build_log_filter(&logging);
        let console_filter = build_console_log_filter(&logging, &file_filter);
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer_output = Arc::clone(&output);
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .compact()
                .with_ansi(false)
                .with_writer(move || SharedWriter(Arc::clone(&writer_output)))
                .with_filter(console_filter),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "rustinel", "internal info");
            tracing::info!(target: TARGET_CONSOLE, "startup milestone");
            tracing::info!(target: "engine", "detection event");
            tracing::warn!(target: "rustinel", "actionable warning");
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("internal info"));
        assert!(output.contains("startup milestone"));
        assert!(output.contains("detection event"));
        assert!(output.contains("actionable warning"));
    }

    fn render_detection_summaries(level: &str, filter: Option<&str>) -> (String, String) {
        use crate::alerts::{AlertSink, Deduplicator};
        use crate::models::{Alert, AlertSeverity, DetectionEngine, NormalizedEvent};

        let logging = logging(level, filter);
        let console_filter = build_console_log_filter(&logging, &build_log_filter(&logging));
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer_output = Arc::clone(&output);
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .compact()
                .with_ansi(false)
                .with_writer(move || SharedWriter(Arc::clone(&writer_output)))
                .with_filter(console_filter),
        );
        let json_output = Arc::new(Mutex::new(Vec::new()));
        let (writer, guard) =
            tracing_appender::non_blocking(SharedWriter(Arc::clone(&json_output)));
        let dedup = Arc::new(Deduplicator::new(60, 100));
        let sink = AlertSink::new(writer).with_deduplicator(Arc::clone(&dedup));
        let event: NormalizedEvent = serde_json::from_value(serde_json::json!({
            "timestamp": "2026-09-06T08:54:30Z",
            "platform": "windows",
            "provider": "etw",
            "category": "Process",
            "event_id": 1,
            "opcode": 1,
            "fields": { "Image": "C:\\Windows\\System32\\whoami.exe", "ProcessId": "13504" }
        }))
        .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            for engine in [
                DetectionEngine::Sigma,
                DetectionEngine::Yara,
                DetectionEngine::Ioc,
            ] {
                let alert = Alert {
                    severity: AlertSeverity::Low,
                    rule_name: format!("{engine:?} test rule"),
                    rule_description: None,
                    rule_id: None,
                    sigma_metadata: None,
                    engine,
                    event: event.clone(),
                    match_details: None,
                };
                sink.write_alert(&alert);
                sink.write_alert(&alert);
                sink.write_alert(&alert);
            }
            dedup.flush_all(&sink);
        });
        drop(guard);
        let console = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let json = String::from_utf8(json_output.lock().unwrap().clone()).unwrap();
        (console, json)
    }

    #[test]
    fn default_console_shows_real_alerts_from_all_engines_and_deduplicates() {
        let (console, json) = render_detection_summaries("info", None);
        assert_eq!(console.matches("Detection triggered").count(), 3);
        assert_eq!(console.matches("Detection repeats aggregated").count(), 3);
        for engine in ["Sigma", "Yara", "Ioc"] {
            assert!(console.contains(&format!("engine={engine}")), "{console}");
            assert!(
                console.contains(&format!("{engine} test rule")),
                "{console}"
            );
        }
        assert!(console.contains("severity=Low"), "{console}");
        assert!(console.contains("whoami.exe"), "{console}");
        assert!(console.contains("pid=13504"), "{console}");
        assert_eq!(console.matches("repeats=2").count(), 3);
        assert_eq!(json.lines().count(), 6);
    }

    #[test]
    fn quiet_filters_hide_summaries_without_disabling_json_alerts() {
        for (level, filter) in [("warn", None), ("info", Some("warn,engine=off"))] {
            let (console, json) = render_detection_summaries(level, filter);
            assert!(console.is_empty(), "{console}");
            assert_eq!(json.lines().count(), 6);
            for line in json.lines() {
                let alert: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(alert["event.kind"], "alert");
            }
        }
    }
}
