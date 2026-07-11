use crate::config::{AppConfig, ConfigLoadOptions, ConfigSource, InstallLayout, InstallPlatform};
use serde::Serialize;
use std::fmt;
use std::path::{Path, PathBuf};
//
use crate::doctor::path::path_results;
use crate::doctor::prerequisites::platform_prerequisite_results;
use crate::doctor::rules::{inspect_rule_pack, rule_validation_results};
use crate::doctor::services::inspect_service;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl DiagnosticResult {
    pub fn pass(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: DiagnosticStatus::Pass,
            message: message.into(),
            detail: None,
            fix: None,
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
            fix: None,
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
            fix: None,
        }
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
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
pub struct RulePackDiagnostic {
    pub rules_dir: PathBuf,
    pub state_path: PathBuf,
    pub pack_id: String,
    pub version: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceDiagnostic {
    pub manager: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub status: DiagnosticStatus,
    pub exit_code: i32,
    pub version: String,
    pub platform: String,
    pub architecture: String,
    pub mode: InstallMode,
    pub config: ConfigDiagnostic,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<ResolvedPaths>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_pack: Option<RulePackDiagnostic>,
    pub service: ServiceDiagnostic,
    pub results: Vec<DiagnosticResult>,
}

impl DoctorReport {
    pub fn from_results(
        platform: impl Into<String>,
        mode: InstallMode,
        config: ConfigDiagnostic,
        paths: Option<ResolvedPaths>,
        rule_pack: Option<RulePackDiagnostic>,
        service: ServiceDiagnostic,
        results: Vec<DiagnosticResult>,
    ) -> Self {
        let status = aggregate_status(&results);
        Self {
            status,
            exit_code: status.exit_code(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: platform.into(),
            architecture: std::env::consts::ARCH.to_string(),
            mode,
            config,
            paths,
            rule_pack,
            service,
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
    let platform = InstallPlatform::current();
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

    let mut results = vec![
        platform_support_result(),
        DiagnosticResult::pass("version", format!("Rustinel {}", env!("CARGO_PKG_VERSION"))),
        DiagnosticResult::pass("install_mode", format!("Running in {mode} mode")),
        config_discovery_result(selected.as_ref(), selected_path.as_deref()),
    ];

    match AppConfig::from_options(options) {
        Ok(cfg) => {
            results.push(DiagnosticResult::pass(
                "config_parse",
                "Configuration parsed successfully",
            ));
            results.extend(config_safety_results(&cfg));
            let paths = ResolvedPaths::from_config(&cfg, selected_path);
            results.extend(path_results(&cfg, &paths));
            results.extend(rule_validation_results(&cfg, platform));
            results.extend(platform_prerequisite_results());

            let rule_pack = inspect_rule_pack(&paths, &mut results);
            let service = inspect_service(mode, &mut results);

            DoctorReport::from_results(
                platform_label(platform),
                mode,
                config,
                Some(paths),
                rule_pack,
                service,
                results,
            )
        }
        Err(err) => {
            results.push(
                DiagnosticResult::fail(
                    "config_parse",
                    "Configuration failed to parse",
                    format!("{err}"),
                )
                .with_fix("Run rustinel doctor --config <path> after correcting the config file"),
            );
            results.extend(platform_prerequisite_results());
            let service = inspect_service(mode, &mut results);

            DoctorReport::from_results(
                platform_label(platform),
                mode,
                config,
                None,
                None,
                service,
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
    output.push_str(&format!("Version: {}\n", report.version));
    output.push_str(&format!("Mode: {}\n", report.mode));
    output.push_str(&format!(
        "Platform: {} ({})\n",
        report.platform, report.architecture
    ));

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

    if let Some(pack) = &report.rule_pack {
        output.push_str("\nRules pack:\n");
        output.push_str(&format!("  id: {}\n", pack.pack_id));
        output.push_str(&format!("  version: {}\n", pack.version));
        output.push_str(&format!("  sha256: {}\n", pack.sha256));
        output.push_str(&format!("  state: {}\n", pack.state_path.display()));
        if let Some(path) = &pack.manifest_path {
            output.push_str(&format!("  manifest: {}\n", path.display()));
        }
    }

    output.push_str("\nService:\n");
    output.push_str(&format!("  manager: {}\n", report.service.manager));
    output.push_str(&format!("  status: {}\n", report.service.status));
    if let Some(detail) = &report.service.detail {
        output.push_str(&format!("  detail: {detail}\n"));
    }

    output.push_str("\nChecks:\n");
    for result in &report.results {
        output.push_str(&format!(
            "  [{}] {}: {}\n",
            result.status, result.id, result.message
        ));
        if let Some(detail) = &result.detail {
            output.push_str(&format!("      detail: {detail}\n"));
        }
        if let Some(fix) = &result.fix {
            output.push_str(&format!("      fix: {fix}\n"));
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
        )
        .with_fix("Create config.toml, set RUSTINEL_CONFIG, or pass --config <path>"),
    }
}

fn platform_support_result() -> DiagnosticResult {
    let platform = platform_label(InstallPlatform::current());
    let arch = std::env::consts::ARCH;
    match (platform.as_str(), arch) {
        ("linux" | "windows" | "macos", "x86_64" | "aarch64") => DiagnosticResult::pass(
            "platform_support",
            format!("{platform} on {arch} is supported"),
        ),
        ("linux" | "windows" | "macos", other) => DiagnosticResult::warn(
            "platform_support",
            format!("{platform} on {other} is not a primary release target"),
            "Official support is focused on x86_64 and aarch64 builds",
        ),
        _ => DiagnosticResult::fail(
            "platform_support",
            format!("{platform} is not supported"),
            "Supported platforms are Windows, Linux, and macOS",
        ),
    }
}

fn config_safety_results(cfg: &AppConfig) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    match crate::engine::SigmaEngineKind::resolve(None, &cfg.scanner.sigma_engine) {
        Ok(kind) => results.push(DiagnosticResult::pass(
            "sigma_engine",
            format!("Sigma engine '{}' is available", kind.as_str()),
        )),
        Err(err) => results.push(
            DiagnosticResult::fail(
                "sigma_engine",
                "Configured Sigma engine is unavailable",
                format!("{err}"),
            )
            .with_fix("Use scanner.sigma_engine = \"builtin\" or install a compatible build"),
        ),
    }

    let severity = cfg.response.min_severity.trim().to_ascii_lowercase();
    if matches!(severity.as_str(), "critical" | "high" | "medium" | "low") {
        results.push(DiagnosticResult::pass(
            "active_response_safety",
            "Active-response severity threshold is valid",
        ));
    } else {
        results.push(
            DiagnosticResult::fail(
                "active_response_safety",
                "Active-response severity threshold is invalid",
                format!("response.min_severity = {}", cfg.response.min_severity),
            )
            .with_fix("Use critical, high, medium, or low"),
        );
    }

    if cfg.response.enabled && cfg.response.allowlist_paths.is_empty() {
        results.push(
            DiagnosticResult::fail(
                "active_response_allowlist",
                "Active response has no trusted path allowlist",
                "response.allowlist_paths and allowlist.paths are both empty",
            )
            .with_fix("Configure allowlist.paths before enabling active response"),
        );
    } else if cfg.response.enabled && cfg.response.prevention_enabled {
        results.push(DiagnosticResult::pass(
            "active_response_allowlist",
            format!(
                "Active response prevention has {} trusted path prefixes",
                cfg.response.allowlist_paths.len()
            ),
        ));
    } else if cfg.response.enabled {
        results.push(DiagnosticResult::warn(
            "active_response_mode",
            "Active response is enabled without prevention",
            "Detection-only response workers will run, but process termination is disabled",
        ));
    } else {
        results.push(DiagnosticResult::pass(
            "active_response_mode",
            "Active response is disabled",
        ));
    }

    results
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

    fn service() -> ServiceDiagnostic {
        ServiceDiagnostic {
            manager: "test".to_string(),
            status: "not-installed".to_string(),
            detail: None,
        }
    }

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
            None,
            service(),
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
            None,
            service(),
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
            None,
            service(),
            vec![
                DiagnosticResult::warn("one", "warning", "detail"),
                DiagnosticResult::fail("two", "failed", "detail"),
            ],
        );

        assert_eq!(report.status, DiagnosticStatus::Fail);
        assert_eq!(report.exit_code, 2);
    }

    #[test]
    fn human_output_includes_fix_guidance() {
        let report = DoctorReport::from_results(
            "linux",
            InstallMode::Portable,
            ConfigDiagnostic {
                source: "defaults".to_string(),
                selected_path: None,
            },
            None,
            None,
            service(),
            vec![DiagnosticResult::warn("one", "warning", "detail").with_fix("fix it")],
        );

        let output = format_human(&report);
        assert!(output.contains("fix: fix it"));
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
