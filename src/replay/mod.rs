//! Offline detection over a behavioral recording.
//!
//! Replay is the detection-development loop: capture a behavior once, then edit
//! rules or configuration and evaluate the same event stream again and again,
//! without re-running the sample and without an endpoint. It needs no sensor, no
//! elevated privileges, and no particular operating system — a Windows recording
//! replays on Linux and the other way round, because the events it holds are
//! already normalized.
//!
//! What replay is not is a second detection implementation. It loads the
//! configured detectors and hands each recorded event to the same
//! [`EventDetectors`] service the live pipeline uses, in the recorded order and
//! as fast as the host will read the file. What it deliberately leaves out is
//! everything a recording cannot support or a lab must not do:
//!
//! - YARA and hash IOC checks, which need the file behind the event. A recording
//!   holds events, not artifacts, so these are reported as skipped rather than
//!   attempted against paths that may not exist on the replay host.
//! - Active response, unconditionally, whatever the supplied configuration says.
//!   Replaying a recording must never act on the machine doing the replaying.
//! - Alert deduplication, so every match is reported. Suppressing repeats is
//!   right for an operator watching alerts and wrong for someone counting what a
//!   rule matched.
//! - Hot reload. The detector set is loaded once, because a finite replay that
//!   changed rules halfway through would not be reproducible.
//! - Alert-only process-context enrichment, which needs the live process cache.
//!
//! Results never reach the live alert log; see [`output`].

mod output;
mod recording;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context};

use crate::config::AppConfig;
use crate::engine::{Engine, EventDetectors};
use crate::ioc::IocEngine;
use crate::models::ecs::ReplayProvenance;
use crate::models::DetectionEngine;
use crate::utils::fs::restrict_file_permissions;

pub use output::Format;
pub use recording::Recording;

/// Arguments accepted by `rustinel replay`.
#[derive(Debug, Clone, Default)]
pub struct ReplayOptions {
    /// Recording payload to replay. Its manifest sidecar is found next to it.
    pub recording: PathBuf,
    /// Explicit configuration file path, selecting a detector set to compare
    /// against the configured one.
    pub config_path: Option<PathBuf>,
    /// Write ECS NDJSON here instead of a console alert list.
    pub output: Option<PathBuf>,
    /// Override for `logging.level`.
    pub log_level: Option<String>,
}

/// What a replay found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Recorded events evaluated.
    pub events: u64,
    /// Alerts reported, with no deduplication applied.
    pub alerts: u64,
    /// Alerts from the Sigma engine.
    pub sigma_alerts: u64,
    /// Alerts from the inline IOC checks.
    pub ioc_alerts: u64,
}

/// A prepared replay: a verified recording and the detectors to evaluate it
/// against, both fixed for the whole run.
pub struct Replay {
    recording: Recording,
    detectors: EventDetectors,
    /// The effective detector configuration, reported so a result set can be
    /// attributed to the rules that produced it.
    configuration: Vec<String>,
}

impl Replay {
    /// Load the configuration and detectors for a recording, verifying the
    /// recording before anything expensive happens.
    pub fn prepare(options: &ReplayOptions) -> anyhow::Result<Self> {
        Self::prepare_with_config(options, load_config(options)?)
    }

    /// Prepare against an already-loaded configuration, so a caller that needed
    /// the configuration first — to set up logging, say — does not load it twice.
    pub fn prepare_with_config(options: &ReplayOptions, config: AppConfig) -> anyhow::Result<Self> {
        let recording = Recording::open(&options.recording)?;

        if let Some(output) = options.output.as_deref() {
            ensure_output_is_not_the_alert_log(&config, output)?;
        }

        // The recording carries its own platform, so Sigma logsource routing
        // follows the endpoint that was recorded rather than the host replaying
        // it. This is what lets a Windows recording be replayed anywhere.
        let platform = recording.manifest().platform;
        let mut sigma =
            Engine::new_for_platform_with_match_debug(platform, config.alerts.match_debug);

        let mut configuration = Vec::new();

        if config.scanner.sigma_enabled {
            sigma
                .load_rules(&config.scanner.sigma_rules_path)
                .with_context(|| {
                    format!(
                        "failed to load Sigma rules from {}",
                        config.scanner.sigma_rules_path.display()
                    )
                })?;
            let stats = sigma.stats();
            configuration.push(format!(
                "  sigma      {} rules for {} from {}",
                stats.total_rules,
                platform.as_str(),
                config.scanner.sigma_rules_path.display(),
            ));
            if !stats.unsupported_rules.is_empty() {
                configuration.push(format!(
                    "             {} rule documents were dropped because their references are unavailable",
                    stats.unsupported_rules.len()
                ));
            }
        } else {
            configuration.push("  sigma      disabled by configuration".to_string());
        }

        let ioc = IocEngine::load(&config.ioc);
        if config.ioc.enabled {
            let stats = ioc.stats();
            let inline =
                stats.ip + stats.cidr + stats.domain_exact + stats.domain_suffix + stats.path_regex;
            configuration.push(format!(
                "  ioc        {inline} inline indicators (IP, domain, and path)"
            ));
        } else {
            configuration.push("  ioc        disabled by configuration".to_string());
        }

        configuration.push(
            "  skipped    YARA and hash IOC checks; a recording holds events, not file artifacts"
                .to_string(),
        );
        configuration
            .push("  response   disabled; replay never acts on the host it runs on".to_string());
        configuration.push("  dedup      disabled; every detector match is reported".to_string());

        Ok(Self {
            recording,
            detectors: EventDetectors::new(Arc::new(sigma), Arc::new(ioc)),
            configuration,
        })
    }

    /// The recording this replay will evaluate.
    pub fn recording(&self) -> &Recording {
        &self.recording
    }

    /// The effective detector configuration, one report line per entry.
    pub fn configuration(&self) -> &[String] {
        &self.configuration
    }

    /// Evaluate the whole recording, writing results as they are found.
    ///
    /// Events are processed sequentially, in recorded order, with no wall-clock
    /// delay between them. Their original timestamps travel into the alerts
    /// unchanged.
    pub fn run(&self, format: Format, stream: &mut dyn Write) -> anyhow::Result<ReplayReport> {
        let mut writer = output::ReplayWriter::new(format, stream, self.provenance());
        writer.header(&self.header())?;

        let mut report = ReplayReport::default();
        for event in self.recording.events()? {
            let event = event?;
            report.events += 1;

            for alert in self.detectors.evaluate(&event) {
                report.alerts += 1;
                match alert.engine {
                    // Exhaustive on purpose: a detector added later has to
                    // decide how a replay counts it. YARA cannot appear here,
                    // because replay never runs it.
                    DetectionEngine::Sigma | DetectionEngine::Yara => report.sigma_alerts += 1,
                    DetectionEngine::Ioc => report.ioc_alerts += 1,
                }
                writer.alert(report.alerts as usize, &alert)?;
            }
        }

        writer.summary(&summary_lines(&report))?;
        writer.flush()?;
        Ok(report)
    }

    fn provenance(&self) -> ReplayProvenance {
        let manifest = self.recording.manifest();
        ReplayProvenance {
            recording: manifest.payload.clone(),
            platform: manifest.platform.as_str().to_string(),
            recorded_at: manifest.started_at.clone(),
        }
    }

    fn header(&self) -> Vec<String> {
        let manifest = self.recording.manifest();
        let mut lines = vec![
            format!("Replay of {}", self.recording.payload_path().display()),
            format!(
                "  recorded   {} events on {} at {} by Rustinel v{}",
                manifest.events.written,
                manifest.platform.as_str(),
                manifest.started_at,
                manifest.rustinel_version,
            ),
        ];
        lines.extend(self.configuration.iter().cloned());
        lines
    }
}

/// Load the configuration a replay will use, with the CLI log-level override
/// applied.
fn load_config(options: &ReplayOptions) -> anyhow::Result<AppConfig> {
    let mut config = AppConfig::from_config_path(options.config_path.clone())
        .map_err(|err| anyhow::anyhow!("configuration error: {err}"))?;
    if let Some(level) = options.log_level.clone() {
        if !level.trim().is_empty() {
            config.logging.level = level;
        }
    }
    Ok(config)
}

/// Run `rustinel replay` end to end.
pub fn run_cli(options: ReplayOptions) -> anyhow::Result<()> {
    let config = load_config(&options)?;
    // Before the detectors load, so a rule that fails to compile is reported
    // rather than swallowed. Diagnostics go to stderr; the report goes to stdout.
    crate::runtime::logging::init_replay_logging(&config);

    let replay = Replay::prepare_with_config(&options, config)?;

    match options.output.as_deref() {
        Some(path) => {
            let mut file = std::fs::File::create(path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            // Replay results describe endpoint activity in the same detail as
            // alerts, so they get the same owner-only permissions.
            restrict_file_permissions(path)
                .with_context(|| format!("failed to restrict permissions on {}", path.display()))?;
            let report = replay.run(Format::Ecs, &mut file)?;
            file.flush()
                .with_context(|| format!("failed to write {}", path.display()))?;

            for line in replay.header() {
                eprintln!("{line}");
            }
            eprintln!();
            for line in summary_lines(&report) {
                eprintln!("{line}");
            }
            eprintln!("Replay alerts written to {}", path.display());
        }
        None => {
            let stdout = std::io::stdout();
            let mut stream = stdout.lock();
            replay.run(Format::Console, &mut stream)?;
        }
    }

    // A replay that found nothing is a normal outcome, not a failure: the exit
    // code reports whether the replay ran, not whether it alerted.
    Ok(())
}

fn summary_lines(report: &ReplayReport) -> Vec<String> {
    vec![
        format!(
            "{} events replayed, {} alerts ({} sigma, {} ioc)",
            report.events, report.alerts, report.sigma_alerts, report.ioc_alerts
        ),
        "Replay results: not live detections, and not written to the alert log.".to_string(),
    ]
}

/// Refuse to write replay results into the live alert directory, where they
/// would be indistinguishable from what the endpoint actually detected once a
/// SIEM has shipped them.
fn ensure_output_is_not_the_alert_log(config: &AppConfig, output: &Path) -> anyhow::Result<()> {
    let alerts_directory = absolute(&config.alerts.directory);
    let output_directory = absolute(output.parent().unwrap_or_else(|| Path::new(".")));

    if alerts_directory == output_directory {
        bail!(
            "refusing to write replay results into the live alert directory {}; replay output is \
             not a record of what happened on this endpoint, so write it somewhere else",
            config.alerts.directory.display()
        );
    }

    Ok(())
}

fn absolute(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_summary_reports_events_and_alerts_by_engine() {
        let lines = summary_lines(&ReplayReport {
            events: 12,
            alerts: 3,
            sigma_alerts: 2,
            ioc_alerts: 1,
        });

        assert_eq!(lines[0], "12 events replayed, 3 alerts (2 sigma, 1 ioc)");
        assert!(lines[1].contains("not live detections"));
    }

    #[test]
    fn writing_into_the_alert_directory_is_refused() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = AppConfig::default();
        config.alerts.directory = temp.path().to_path_buf();

        let err = ensure_output_is_not_the_alert_log(&config, &temp.path().join("replay.ndjson"))
            .expect_err("replay must not write into the alert directory");

        assert!(err.to_string().contains("live alert directory"), "{err}");
    }

    #[test]
    fn writing_elsewhere_is_allowed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = AppConfig::default();
        config.alerts.directory = temp.path().join("alerts");

        ensure_output_is_not_the_alert_log(&config, &temp.path().join("replay.ndjson"))
            .expect("a path outside the alert directory is fine");
    }
}
