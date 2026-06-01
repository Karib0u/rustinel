use crate::alerts::AlertSink;
use crate::config;
use std::fs;
use std::path::Path;
use tracing::info;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const STARTUP_BANNER_INNER_WIDTH: usize = 49;

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

    match rolling::RollingFileAppender::builder()
        .rotation(rolling::Rotation::DAILY)
        .filename_prefix(filename)
        .build(directory)
    {
        Ok(appender) => Some(tracing_appender::non_blocking(appender)),
        Err(err) => {
            eprintln!(
                "Unable to initialize {} rolling log appender in {:?}: {}",
                label, directory, err
            );
            None
        }
    }
}
