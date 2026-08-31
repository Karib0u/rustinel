use crate::alerts::AlertSink;
use crate::config;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const STARTUP_BANNER_INNER_WIDTH: usize = 49;
/// Tracing target for messages intended for an interactive console.
pub const TARGET_CONSOLE: &str = "console";
const DEFAULT_CONSOLE_FILTER: &str = "warn,console=info,engine=info,response=info";

struct RestrictedFileAppender {
    inner: rolling::RollingFileAppender,
    directory: PathBuf,
    filename_prefix: String,
    permission_date: chrono::NaiveDate,
}

impl Write for RestrictedFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        // RollingFileAppender's daily rotation boundary is UTC.
        let current_date = chrono::Utc::now().date_naive();
        if current_date != self.permission_date {
            restrict_log_file_permissions(&self.directory, &self.filename_prefix)?;
            self.permission_date = current_date;
        }
        Ok(written)
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
) -> (
    tracing_appender::non_blocking::WorkerGuard,
    tracing_appender::non_blocking::WorkerGuard,
    AlertSink,
) {
    let (app_writer, app_guard) =
        build_daily_writer("operational", &cfg.logging.directory, &cfg.logging.filename);
    let base_filter = build_log_filter(&cfg.logging);
    let console_filter = build_console_log_filter(&cfg.logging, &base_filter);

    let app_layer = fmt::layer()
        .with_writer(app_writer)
        .compact()
        .with_ansi(false)
        .with_target(true)
        .with_filter(base_filter.clone());

    let (alert_writer, alert_guard) =
        build_daily_writer("alerts", &cfg.alerts.directory, &cfg.alerts.filename);
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

    (app_guard, alert_guard, alert_sink)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn init_logging(
    cfg: &config::AppConfig,
) -> (
    tracing_appender::non_blocking::WorkerGuard,
    tracing_appender::non_blocking::WorkerGuard,
    AlertSink,
) {
    let (app_writer, app_guard) =
        build_daily_writer("operational", &cfg.logging.directory, &cfg.logging.filename);
    let base_filter = build_log_filter(&cfg.logging);
    let console_filter = build_console_log_filter(&cfg.logging, &base_filter);

    let app_layer = fmt::layer()
        .with_writer(app_writer)
        .compact()
        .with_ansi(false)
        .with_target(true)
        .with_filter(base_filter.clone());

    let (alert_writer, alert_guard) =
        build_daily_writer("alerts", &cfg.alerts.directory, &cfg.alerts.filename);

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

    (app_guard, alert_guard, AlertSink::new(alert_writer))
}

/// Initialize operational logging only, without the alert pipeline.
///
/// Used by `rustinel capture`, which never emits alerts: initializing the alert
/// appender would create an alert file for a session that has nothing to write
/// to it, blurring the line between recordings and detection output.
pub fn init_operational_logging(
    cfg: &config::AppConfig,
) -> tracing_appender::non_blocking::WorkerGuard {
    let (app_writer, app_guard) =
        build_daily_writer("operational", &cfg.logging.directory, &cfg.logging.filename);
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

    app_guard
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
) -> (
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
) {
    if let Some(writer) = try_build_daily_writer(label, directory, filename) {
        return writer;
    }

    let fallback_directory = std::env::temp_dir().join("rustinel-logs");
    if let Some(writer) = try_build_daily_writer(label, &fallback_directory, filename) {
        eprintln!(
            "Falling back to {:?} for {} logs",
            fallback_directory, label
        );
        return writer;
    }

    eprintln!(
        "Unable to initialize {} file logging; using a sink writer instead",
        label
    );
    tracing_appender::non_blocking(std::io::sink())
}

fn try_build_daily_writer(
    label: &str,
    directory: &Path,
    filename: &str,
) -> Option<(
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
)> {
    if let Err(err) = fs::create_dir_all(directory) {
        eprintln!(
            "Unable to create {} log directory {:?}: {}",
            label, directory, err
        );
        return None;
    }

    if let Err(err) = restrict_log_directory_permissions(directory) {
        eprintln!(
            "Unable to restrict {} log directory permissions for {:?}: {}",
            label, directory, err
        );
        return None;
    }

    match rolling::RollingFileAppender::builder()
        .rotation(rolling::Rotation::DAILY)
        .filename_prefix(filename)
        .build(directory)
    {
        Ok(appender) => {
            if let Err(err) = restrict_log_file_permissions(directory, filename) {
                eprintln!(
                    "Unable to restrict {} log file permissions in {:?}: {}",
                    label, directory, err
                );
                return None;
            }
            Some(tracing_appender::non_blocking(RestrictedFileAppender {
                inner: appender,
                directory: directory.to_path_buf(),
                filename_prefix: filename.to_owned(),
                permission_date: chrono::Utc::now().date_naive(),
            }))
        }
        Err(err) => {
            eprintln!(
                "Unable to initialize {} rolling log appender in {:?}: {}",
                label, directory, err
            );
            None
        }
    }
}

#[cfg(unix)]
fn restrict_log_directory_permissions(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_log_directory_permissions(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_log_file_permissions(directory: &Path, filename_prefix: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let expected_prefix = format!("{filename_prefix}.");
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .file_name()
                .to_string_lossy()
                .starts_with(&expected_prefix)
        {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_log_file_permissions(_directory: &Path, _filename_prefix: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod permission_tests {
    use super::{restrict_log_directory_permissions, restrict_log_file_permissions};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn restricts_log_directory_and_matching_files() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("logs");
        fs::create_dir(&directory).unwrap();
        let log_file = directory.join("alerts.json.2026-07-12");
        let unrelated_file = directory.join("other.log");
        fs::write(&log_file, b"alert").unwrap();
        fs::write(&unrelated_file, b"other").unwrap();
        fs::set_permissions(&unrelated_file, fs::Permissions::from_mode(0o644)).unwrap();

        restrict_log_directory_permissions(&directory).unwrap();
        restrict_log_file_permissions(&directory, "alerts.json").unwrap();

        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&log_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&unrelated_file).unwrap().permissions().mode() & 0o777,
            0o644
        );
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
}
