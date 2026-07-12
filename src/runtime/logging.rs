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

pub fn log_startup_banner(runtime: &str) {
    info!(target: "rustinel", "╔═══════════════════════════════════════════════════╗");
    info!(
        target: "rustinel",
        "║ {:^width$} ║",
        format!("Rustinel v{} ({})", APP_VERSION, runtime),
        width = STARTUP_BANNER_INNER_WIDTH
    );
    info!(
        target: "rustinel",
        "║ {:^width$} ║",
        "High-Performance Endpoint Detection Agent",
        width = STARTUP_BANNER_INNER_WIDTH
    );
    info!(target: "rustinel", "╚═══════════════════════════════════════════════════╝");
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
                .with_filter(base_filter),
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
            .with_target(true)
            .with_filter(base_filter);
        tracing_subscriber::registry()
            .with(app_layer)
            .with(console_layer)
            .init();
    } else {
        tracing_subscriber::registry().with(app_layer).init();
    }

    (app_guard, alert_guard, AlertSink::new(alert_writer))
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
