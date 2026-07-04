use crate::config::{AppConfig, ConfigLoadOptions, ConfigSource, InstallLayout, InstallPlatform};
use serde::Serialize;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticStatus {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for DiagnosticStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiagnosticStatus::Pass => f.write_str("PASS"),
            DiagnosticStatus::Warn => f.write_str("WARN"),
            DiagnosticStatus::Fail => f.write_str("FAIL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallMode {
    Portable,
    Managed,
}

impl fmt::Display for InstallMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallMode::Portable => f.write_str("portable"),
            InstallMode::Managed => f.write_str("managed"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticResult {
    pub id: String,
    pub status: DiagnosticStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl DiagnosticResult {
    pub fn pass(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: DiagnosticStatus::Pass,
            message: message.into(),
            detail: None,
        }
    }

    pub fn warn(
        id: impl Into<String>,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status: DiagnosticStatus::Warn,
            message: message.into(),
            detail: Some(detail.into()),
        }
    }

    pub fn fail(
        id: impl Into<String>,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status: DiagnosticStatus::Fail,
            message: message.into(),
            detail: Some(detail.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigDiagnostic {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedPaths {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_file: Option<PathBuf>,
    pub sigma_rules: PathBuf,
    pub yara_rules: PathBuf,
    pub ioc_hashes: PathBuf,
    pub ioc_ips: PathBuf,
    pub ioc_domains: PathBuf,
    pub ioc_paths_regex: PathBuf,
    pub logs_dir: PathBuf,
    pub alerts_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub status: DiagnosticStatus,
    pub exit_code: i32,
    pub platform: String,
    pub mode: InstallMode,
    pub config: ConfigDiagnostic,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<ResolvedPaths>,
    pub results: Vec<DiagnosticResult>,
}

impl DoctorReport {
    pub fn from_results(
        platform: impl Into<String>,
        mode: InstallMode,
        config: ConfigDiagnostic,
        paths: Option<ResolvedPaths>,
        results: Vec<DiagnosticResult>,
    ) -> Self {
        let status = aggregate_status(&results);
        Self {
            status,
            exit_code: status.exit_code(),
            platform: platform.into(),
            mode,
            config,
            paths,
            results,
        }
    }
}

impl DiagnosticStatus {
    pub fn exit_code(self) -> i32 {
        match self {
            DiagnosticStatus::Pass => 0,
            DiagnosticStatus::Warn => 1,
            DiagnosticStatus::Fail => 2,
        }
    }
}

pub fn inspect(config_path: Option<PathBuf>) -> DoctorReport {
    inspect_with_options(ConfigLoadOptions::from_runtime(config_path))
}

pub fn inspect_with_options(options: ConfigLoadOptions) -> DoctorReport {
    let selected = options.selected_config();
    let selected_path = selected
        .as_ref()
        .map(|selected| absolute_path(selected.path.clone()));
    let mode = detect_mode(&options, selected.as_ref().map(|selected| selected.source));
    let config = ConfigDiagnostic {
        source: selected
            .as_ref()
            .map(|selected| config_source_label(selected.source).to_string())
            .unwrap_or_else(|| "defaults".to_string()),
        selected_path: selected_path.clone(),
    };

    let mut results = Vec::new();
    results.push(DiagnosticResult::pass(
        "install_mode",
        format!("Running in {mode} mode"),
    ));
    results.push(config_discovery_result(
        selected.as_ref(),
        selected_path.as_deref(),
    ));

    match AppConfig::from_options(options) {
        Ok(cfg) => {
            results.push(DiagnosticResult::pass(
                "config_parse",
                "Configuration parsed successfully",
            ));
            let paths = ResolvedPaths::from_config(&cfg, selected_path);
            results.push(directory_check(
                "logs_writable",
                "Log directory",
                &paths.logs_dir,
            ));
            results.push(directory_check(
                "alerts_writable",
                "Alert directory",
                &paths.alerts_dir,
            ));

            DoctorReport::from_results(
                platform_label(InstallPlatform::current()),
                mode,
                config,
                Some(paths),
                results,
            )
        }
        Err(err) => {
            results.push(DiagnosticResult::fail(
                "config_parse",
                "Configuration failed to parse",
                format!("{err}"),
            ));
            DoctorReport::from_results(
                platform_label(InstallPlatform::current()),
                mode,
                config,
                None,
                results,
            )
        }
    }
}

pub fn run_cli(config_path: Option<PathBuf>, json: bool) -> anyhow::Result<i32> {
    let report = inspect(config_path);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", format_human(&report));
    }
    Ok(report.exit_code)
}

pub fn format_human(report: &DoctorReport) -> String {
    let mut output = String::new();
    output.push_str("Rustinel doctor\n");
    output.push_str(&format!("Status: {}\n", report.status));
    output.push_str(&format!("Mode: {}\n", report.mode));
    output.push_str(&format!("Platform: {}\n", report.platform));

    match &report.config.selected_path {
        Some(path) => output.push_str(&format!(
            "Config: {} at {}\n",
            report.config.source,
            path.display()
        )),
        None => output.push_str("Config: defaults only\n"),
    }

    if let Some(paths) = &report.paths {
        output.push_str("\nResolved paths:\n");
        if let Some(path) = &paths.config_file {
            output.push_str(&format!("  config file: {}\n", path.display()));
        }
        output.push_str(&format!("  sigma rules: {}\n", paths.sigma_rules.display()));
        output.push_str(&format!("  yara rules: {}\n", paths.yara_rules.display()));
        output.push_str(&format!("  ioc hashes: {}\n", paths.ioc_hashes.display()));
        output.push_str(&format!("  ioc ips: {}\n", paths.ioc_ips.display()));
        output.push_str(&format!("  ioc domains: {}\n", paths.ioc_domains.display()));
        output.push_str(&format!(
            "  ioc paths regex: {}\n",
            paths.ioc_paths_regex.display()
        ));
        output.push_str(&format!("  logs dir: {}\n", paths.logs_dir.display()));
        output.push_str(&format!("  alerts dir: {}\n", paths.alerts_dir.display()));
    }

    output.push_str("\nChecks:\n");
    for result in &report.results {
        output.push_str(&format!(
            "  [{}] {}: {}\n",
            result.status, result.id, result.message
        ));
        if let Some(detail) = &result.detail {
            output.push_str(&format!("      {detail}\n"));
        }
    }

    output
}

fn aggregate_status(results: &[DiagnosticResult]) -> DiagnosticStatus {
    if results
        .iter()
        .any(|result| result.status == DiagnosticStatus::Fail)
    {
        DiagnosticStatus::Fail
    } else if results
        .iter()
        .any(|result| result.status == DiagnosticStatus::Warn)
    {
        DiagnosticStatus::Warn
    } else {
        DiagnosticStatus::Pass
    }
}

fn config_discovery_result(
    selected: Option<&crate::config::SelectedConfig>,
    selected_path: Option<&Path>,
) -> DiagnosticResult {
    match (selected, selected_path) {
        (Some(selected), Some(path)) => DiagnosticResult::pass(
            "config_discovery",
            format!(
                "Selected {} config at {}",
                config_source_label(selected.source),
                path.display()
            ),
        ),
        _ => DiagnosticResult::warn(
            "config_discovery",
            "No config file was discovered",
            "Using built-in defaults and environment overrides only",
        ),
    }
}

fn directory_check(id: &str, label: &str, path: &Path) -> DiagnosticResult {
    match std::fs::metadata(path) {
        Ok(metadata) if !metadata.is_dir() => DiagnosticResult::fail(
            id,
            format!("{label} is not a directory"),
            path.display().to_string(),
        ),
        Ok(metadata) if metadata.permissions().readonly() => DiagnosticResult::warn(
            id,
            format!("{label} is marked read-only"),
            path.display().to_string(),
        ),
        Ok(metadata) if !owner_writable(&metadata) => DiagnosticResult::warn(
            id,
            format!("{label} is not owner-writable"),
            path.display().to_string(),
        ),
        Ok(_) => DiagnosticResult::pass(id, format!("{label} exists and is writable")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => DiagnosticResult::warn(
            id,
            format!("{label} does not exist"),
            format!(
                "{} could not be checked without creating it",
                path.display()
            ),
        ),
        Err(err) => DiagnosticResult::fail(
            id,
            format!("{label} could not be inspected"),
            format!("{}: {err}", path.display()),
        ),
    }
}

#[cfg(unix)]
fn owner_writable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o200 != 0
}

#[cfg(not(unix))]
fn owner_writable(_metadata: &std::fs::Metadata) -> bool {
    true
}

fn detect_mode(options: &ConfigLoadOptions, source: Option<ConfigSource>) -> InstallMode {
    if source == Some(ConfigSource::Managed) {
        return InstallMode::Managed;
    }

    let managed = absolute_path(options.managed_config.clone());
    let selected = options
        .selected_config()
        .map(|selected| absolute_path(selected.path));
    if selected.as_ref() == Some(&managed) {
        InstallMode::Managed
    } else {
        InstallMode::Portable
    }
}

fn config_source_label(source: ConfigSource) -> &'static str {
    match source {
        ConfigSource::Explicit => "explicit",
        ConfigSource::Environment => "environment",
        ConfigSource::Managed => "managed",
        ConfigSource::Executable => "executable",
        ConfigSource::CurrentDirectory => "current-directory",
    }
}

fn platform_label(platform: InstallPlatform) -> String {
    match platform {
        InstallPlatform::Windows => "windows",
        InstallPlatform::Linux => "linux",
        InstallPlatform::Macos => "macos",
    }
    .to_string()
}

fn absolute_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }

    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path,
    }
}

impl ResolvedPaths {
    fn from_config(cfg: &AppConfig, config_file: Option<PathBuf>) -> Self {
        Self {
            config_file,
            sigma_rules: cfg.scanner.sigma_rules_path.clone(),
            yara_rules: cfg.scanner.yara_rules_path.clone(),
            ioc_hashes: cfg.ioc.hashes_path.clone(),
            ioc_ips: cfg.ioc.ips_path.clone(),
            ioc_domains: cfg.ioc.domains_path.clone(),
            ioc_paths_regex: cfg.ioc.paths_regex_path.clone(),
            logs_dir: cfg.logging.directory.clone(),
            alerts_dir: cfg.alerts.directory.clone(),
        }
    }

    #[allow(dead_code)]
    fn from_layout(layout: &InstallLayout) -> Self {
        let cfg = layout.managed_config();
        Self::from_config(&cfg, Some(layout.config_file.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_exit_code_is_zero_for_passes() {
        let report = DoctorReport::from_results(
            "linux",
            InstallMode::Portable,
            ConfigDiagnostic {
                source: "defaults".to_string(),
                selected_path: None,
            },
            None,
            vec![DiagnosticResult::pass("one", "ok")],
        );

        assert_eq!(report.status, DiagnosticStatus::Pass);
        assert_eq!(report.exit_code, 0);
    }

    #[test]
    fn aggregate_exit_code_is_one_for_warnings() {
        let report = DoctorReport::from_results(
            "linux",
            InstallMode::Portable,
            ConfigDiagnostic {
                source: "defaults".to_string(),
                selected_path: None,
            },
            None,
            vec![
                DiagnosticResult::pass("one", "ok"),
                DiagnosticResult::warn("two", "warning", "detail"),
            ],
        );

        assert_eq!(report.status, DiagnosticStatus::Warn);
        assert_eq!(report.exit_code, 1);
    }

    #[test]
    fn aggregate_exit_code_is_two_for_failures() {
        let report = DoctorReport::from_results(
            "linux",
            InstallMode::Portable,
            ConfigDiagnostic {
                source: "defaults".to_string(),
                selected_path: None,
            },
            None,
            vec![
                DiagnosticResult::warn("one", "warning", "detail"),
                DiagnosticResult::fail("two", "failed", "detail"),
            ],
        );

        assert_eq!(report.status, DiagnosticStatus::Fail);
        assert_eq!(report.exit_code, 2);
    }

    #[test]
    fn inspect_reports_parse_failures() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = temp.path().join("bad.toml");
        std::fs::write(&config, "[logging\nlevel = \"debug\"\n").expect("write config");

        let report = inspect_with_options(ConfigLoadOptions {
            explicit_config: Some(config),
            env_config: None,
            managed_config: temp.path().join("managed.toml"),
            exe_config: None,
            cwd_config: temp.path().join("cwd.toml"),
        });

        assert_eq!(report.status, DiagnosticStatus::Fail);
        assert_eq!(report.exit_code, 2);
        assert!(report
            .results
            .iter()
            .any(|result| result.id == "config_parse" && result.status == DiagnosticStatus::Fail));
    }
}
