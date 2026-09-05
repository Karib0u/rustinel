//! Shared configuration overrides, logging, and startup reporting.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing_appender::non_blocking::WorkerGuard;

use crate::alerts::dedup::{spawn_flush_worker, Deduplicator};
use crate::alerts::AlertSink;
use crate::config;
use crate::runtime::logging::{init_logging, log_startup_banner};
use crate::runtime::telemetry::TelemetryReporter;

pub(super) fn load_config(
    console_output_override: Option<bool>,
    log_level_override: Option<String>,
    config_path: Option<PathBuf>,
) -> anyhow::Result<(config::AppConfig, Option<PathBuf>)> {
    let resolved_config_path = config::AppConfig::resolve_config_path(config_path.clone());
    let mut cfg = match config::AppConfig::from_config_path(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Failed to load configuration: {}", err);
            eprintln!("Hint: run rustinel doctor --config <path> to inspect configuration and runtime prerequisites.");
            let context = if cfg!(windows) {
                "Failed to load configuration"
            } else {
                "configuration error"
            };
            return Err(anyhow::anyhow!("{}: {}", context, err));
        }
    };
    if let Some(console_output) = console_output_override {
        cfg.logging.console_output = console_output;
    }
    if let Some(level) = log_level_override {
        if !level.trim().is_empty() {
            cfg.logging.level = level;
        }
    }

    Ok((cfg, resolved_config_path))
}

pub(super) struct RuntimeLogging {
    pub alert_sink: AlertSink,
    pub dedup_worker_handle: Option<JoinHandle<()>>,
    pub telemetry_reporter: Option<TelemetryReporter>,
    // Kept in the platform runtime until its final shutdown messages are written.
    pub _guards: (WorkerGuard, WorkerGuard),
}

impl RuntimeLogging {
    pub fn start(cfg: &config::AppConfig, runtime_label: &str) -> Self {
        let (app_guard, alert_guard, mut alert_sink) = init_logging(cfg);
        let _guards = (app_guard, alert_guard);

        // 2a. Alert deduplication
        let dedup_worker_handle = if cfg.dedup.enabled {
            let dedup = Arc::new(Deduplicator::new(
                cfg.dedup.window_secs,
                cfg.dedup.max_entries,
            ));
            let tick = std::time::Duration::from_secs(cfg.dedup.window_secs.max(1));
            let handle = spawn_flush_worker(Arc::clone(&dedup), alert_sink.clone(), tick);
            alert_sink = alert_sink.with_deduplicator(dedup);
            Some(handle)
        } else {
            None
        };

        log_startup_banner(runtime_label);

        // 2b. Pipeline drop counters, published for `rustinel doctor`
        let telemetry_reporter = TelemetryReporter::start(cfg);

        Self {
            alert_sink,
            dedup_worker_handle,
            telemetry_reporter,
            _guards,
        }
    }
}
