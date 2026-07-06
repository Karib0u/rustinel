use crate::config::{AppConfig, ConfigLoadOptions, ConfigSource, InstallLayout, InstallPlatform};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::service::ManagedServicePaths;
use crate::service::ServiceStatus;
#[cfg(windows)]
use crate::service::WINDOWS_SERVICE_NAME;
#[cfg(target_os = "macos")]
use crate::service::{launchd_status_from_output, LAUNCHD_LABEL};
#[cfg(target_os = "linux")]
use crate::service::{systemd_status_from_state, SYSTEMD_UNIT_NAME};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

const SUPPORTED_PACK_SCHEMA_VERSIONS: &[u32] = &[1, 2];

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

fn path_results(cfg: &AppConfig, paths: &ResolvedPaths) -> Vec<DiagnosticResult> {
    let mut results = vec![
        directory_check("logs_writable", "Log directory", &paths.logs_dir),
        directory_check("alerts_writable", "Alert directory", &paths.alerts_dir),
    ];

    if cfg.scanner.sigma_enabled {
        results.push(directory_exists_check(
            "sigma_rules_dir",
            "Sigma rules directory",
            &paths.sigma_rules,
        ));
    } else {
        results.push(DiagnosticResult::pass(
            "sigma_rules_dir",
            "Sigma rules are disabled by configuration",
        ));
    }

    if cfg.scanner.yara_enabled {
        results.push(directory_exists_check(
            "yara_rules_dir",
            "YARA rules directory",
            &paths.yara_rules,
        ));
    } else {
        results.push(DiagnosticResult::pass(
            "yara_rules_dir",
            "YARA rules are disabled by configuration",
        ));
    }

    if cfg.ioc.enabled {
        results.push(file_readable_check(
            "ioc_hashes",
            "IOC hashes file",
            &paths.ioc_hashes,
        ));
        results.push(file_readable_check(
            "ioc_ips",
            "IOC IPs file",
            &paths.ioc_ips,
        ));
        results.push(file_readable_check(
            "ioc_domains",
            "IOC domains file",
            &paths.ioc_domains,
        ));
        results.push(file_readable_check(
            "ioc_paths_regex",
            "IOC path regex file",
            &paths.ioc_paths_regex,
        ));
    } else {
        results.push(DiagnosticResult::pass(
            "ioc_files",
            "IOC detection is disabled by configuration",
        ));
    }

    results
}

fn rule_validation_results(cfg: &AppConfig, platform: InstallPlatform) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    if cfg.scanner.sigma_enabled {
        results.push(validate_sigma_rules(cfg, platform));
    } else {
        results.push(DiagnosticResult::pass(
            "sigma_rules_parse",
            "Sigma parsing skipped because Sigma detection is disabled",
        ));
    }

    if cfg.scanner.yara_enabled {
        results.push(validate_yara_rules(cfg));
    } else {
        results.push(DiagnosticResult::pass(
            "yara_rules_parse",
            "YARA parsing skipped because YARA detection is disabled",
        ));
    }

    if cfg.ioc.enabled {
        results.extend(validate_ioc_files(cfg));
    } else {
        results.push(DiagnosticResult::pass(
            "ioc_parse",
            "IOC parsing skipped because IOC detection is disabled",
        ));
    }

    results
}

fn validate_sigma_rules(cfg: &AppConfig, platform: InstallPlatform) -> DiagnosticResult {
    let engine_kind = match crate::engine::SigmaEngineKind::resolve(None, &cfg.scanner.sigma_engine)
    {
        Ok(kind) => kind,
        Err(err) => {
            return DiagnosticResult::fail(
                "sigma_rules_parse",
                "Sigma rules could not be parsed",
                format!("{err}"),
            )
            .with_fix("Correct scanner.sigma_engine before validating Sigma rules");
        }
    };
    let mut engine = crate::engine::Engine::new_for_platform_with_logging_level_and_match_debug(
        sensor_platform(platform),
        &cfg.logging.level,
        cfg.alerts.match_debug,
        engine_kind,
    );

    if let Err(err) = engine.load_rules(&cfg.scanner.sigma_rules_path) {
        return DiagnosticResult::fail(
            "sigma_rules_parse",
            "Sigma rule loading failed",
            format!("{err}"),
        )
        .with_fix("Fix unreadable or invalid Sigma rule files");
    }

    let stats = engine.stats();
    if !stats.failed_rules.is_empty() {
        let detail = stats
            .failed_rules
            .iter()
            .take(5)
            .map(|(path, err)| format!("{path}: {err}"))
            .collect::<Vec<_>>()
            .join("; ");
        return DiagnosticResult::fail(
            "sigma_rules_parse",
            format!(
                "{} Sigma rule files failed to parse",
                stats.failed_rules.len()
            ),
            detail,
        )
        .with_fix("Fix the listed Sigma rules or remove them from the active pack");
    }

    if stats.total_rules == 0 {
        return DiagnosticResult::warn(
            "sigma_rules_parse",
            "No Sigma rules loaded",
            cfg.scanner.sigma_rules_path.display().to_string(),
        )
        .with_fix("Install a rules pack or point scanner.sigma_rules_path at rules/current/sigma");
    }

    DiagnosticResult::pass(
        "sigma_rules_parse",
        format!(
            "Loaded {} Sigma rules with {} inactive collector rules",
            stats.total_rules, stats.inactive_collector_rules
        ),
    )
}

fn validate_yara_rules(cfg: &AppConfig) -> DiagnosticResult {
    match crate::scanner::Scanner::new(&cfg.scanner.yara_rules_path) {
        Ok(scanner) if scanner.failed_files() > 0 => DiagnosticResult::fail(
            "yara_rules_parse",
            format!("{} YARA files failed to compile", scanner.failed_files()),
            cfg.scanner.yara_rules_path.display().to_string(),
        )
        .with_fix("Fix the invalid YARA files or remove them from the active pack"),
        Ok(scanner) if scanner.files_found() == 0 => DiagnosticResult::warn(
            "yara_rules_parse",
            "No YARA files found",
            cfg.scanner.yara_rules_path.display().to_string(),
        )
        .with_fix("Install a rules pack or point scanner.yara_rules_path at rules/current/yara"),
        Ok(scanner) => DiagnosticResult::pass(
            "yara_rules_parse",
            format!(
                "Compiled {} of {} YARA files",
                scanner.compiled_files(),
                scanner.files_found()
            ),
        ),
        Err(err) => DiagnosticResult::fail(
            "yara_rules_parse",
            "YARA rule loading failed",
            format!("{err}"),
        )
        .with_fix("Fix unreadable or invalid YARA rule files"),
    }
}

fn validate_ioc_files(cfg: &AppConfig) -> Vec<DiagnosticResult> {
    vec![
        validate_ioc_hashes(&cfg.ioc.hashes_path),
        validate_ioc_ips(&cfg.ioc.ips_path),
        validate_ioc_domains(&cfg.ioc.domains_path),
        validate_ioc_path_regexes(&cfg.ioc.paths_regex_path),
    ]
}

fn validate_ioc_hashes(path: &Path) -> DiagnosticResult {
    validate_ioc_lines(path, "ioc_hashes_parse", "IOC hashes", |value| {
        if value.chars().all(|c| c.is_ascii_hexdigit()) && matches!(value.len(), 32 | 40 | 64) {
            Ok(())
        } else {
            Err("expected MD5, SHA-1, or SHA-256 hex")
        }
    })
}

fn validate_ioc_ips(path: &Path) -> DiagnosticResult {
    validate_ioc_lines(path, "ioc_ips_parse", "IOC IPs", |value| {
        if value.contains('/') {
            value
                .parse::<ipnetwork::IpNetwork>()
                .map(|_| ())
                .map_err(|_| "invalid CIDR")
        } else {
            value
                .parse::<std::net::IpAddr>()
                .map(|_| ())
                .map_err(|_| "invalid IP")
        }
    })
}

fn validate_ioc_domains(path: &Path) -> DiagnosticResult {
    validate_ioc_lines(path, "ioc_domains_parse", "IOC domains", |value| {
        if value.chars().any(char::is_whitespace) {
            Err("domain contains whitespace")
        } else if value.trim_matches('.').is_empty() {
            Err("domain is empty")
        } else {
            Ok(())
        }
    })
}

fn validate_ioc_path_regexes(path: &Path) -> DiagnosticResult {
    validate_ioc_lines(path, "ioc_paths_regex_parse", "IOC path regexes", |value| {
        regex::Regex::new(value)
            .map(|_| ())
            .map_err(|_| "invalid regex")
    })
}

fn validate_ioc_lines<F>(path: &Path, id: &str, label: &str, validate: F) -> DiagnosticResult
where
    F: Fn(&str) -> Result<(), &'static str>,
{
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return DiagnosticResult::warn(
                id,
                format!("{label} file is missing"),
                path.display().to_string(),
            )
            .with_fix("Install a rules pack or update the IOC path in config.toml");
        }
        Err(err) => {
            return DiagnosticResult::fail(
                id,
                format!("{label} file could not be read"),
                format!("{}: {err}", path.display()),
            )
            .with_fix("Fix permissions or update the IOC path in config.toml");
        }
    };

    let mut checked = 0usize;
    let mut invalid = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        let value = line
            .split_once(';')
            .map(|(value, _)| value)
            .unwrap_or(line)
            .trim();
        if value.is_empty() || value.starts_with('#') || value.starts_with("//") {
            continue;
        }
        checked += 1;
        if let Err(reason) = validate(value) {
            invalid.push(format!("line {}: {reason}", line_no + 1));
        }
    }

    if !invalid.is_empty() {
        return DiagnosticResult::fail(
            id,
            format!("{} {} entries are invalid", invalid.len(), label),
            invalid.into_iter().take(5).collect::<Vec<_>>().join("; "),
        )
        .with_fix("Correct the listed IOC entries or remove them from the active pack");
    }

    DiagnosticResult::pass(id, format!("{checked} {label} entries parsed"))
}

fn inspect_rule_pack(
    paths: &ResolvedPaths,
    results: &mut Vec<DiagnosticResult>,
) -> Option<RulePackDiagnostic> {
    let rules_dir = infer_rules_dir(paths);
    let state_path = rules_dir.join("state.json");
    let state = match crate::rules::read_state(&rules_dir) {
        Some(state) => state,
        None => {
            results.push(
                DiagnosticResult::warn(
                    "rules_pack_state",
                    "No installed rules pack state was found",
                    state_path.display().to_string(),
                )
                .with_fix("Install a rules pack with rustinel rules install <pack>"),
            );
            return None;
        }
    };

    if is_sha256_hex(&state.sha256) {
        results.push(DiagnosticResult::pass(
            "rules_pack_checksum",
            "Installed rules pack has a recorded SHA-256 checksum",
        ));
    } else {
        results.push(
            DiagnosticResult::fail(
                "rules_pack_checksum",
                "Installed rules pack checksum is invalid",
                state.sha256.clone(),
            )
            .with_fix("Reinstall the active rules pack"),
        );
    }

    results.push(DiagnosticResult::pass(
        "rules_pack_state",
        format!("Installed rules pack {} {}", state.pack_id, state.version),
    ));

    let manifest_path = rules_dir.join("current").join("pack.yml");
    let manifest_path = match validate_pack_manifest(&manifest_path, &state, results) {
        true => Some(manifest_path),
        false => None,
    };

    Some(RulePackDiagnostic {
        rules_dir,
        state_path,
        pack_id: state.pack_id,
        version: state.version,
        sha256: state.sha256,
        manifest_path,
    })
}

fn validate_pack_manifest(
    manifest_path: &Path,
    state: &crate::rules::RulesState,
    results: &mut Vec<DiagnosticResult>,
) -> bool {
    let bytes = match std::fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            results.push(
                DiagnosticResult::fail(
                    "rules_pack_manifest",
                    "Installed rules pack manifest is missing or unreadable",
                    format!("{}: {err}", manifest_path.display()),
                )
                .with_fix("Reinstall the active rules pack"),
            );
            return false;
        }
    };

    let manifest: DoctorPackManifest = match serde_yaml::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(err) => {
            results.push(
                DiagnosticResult::fail(
                    "rules_pack_manifest",
                    "Installed rules pack manifest is invalid",
                    format!("{err}"),
                )
                .with_fix("Reinstall the active rules pack"),
            );
            return false;
        }
    };

    if manifest.id != state.pack_id {
        results.push(
            DiagnosticResult::fail(
                "rules_pack_manifest",
                "Installed rules pack manifest does not match state.json",
                format!("manifest id {}, state id {}", manifest.id, state.pack_id),
            )
            .with_fix("Reinstall the active rules pack"),
        );
        return false;
    }

    if !SUPPORTED_PACK_SCHEMA_VERSIONS.contains(&manifest.pack_schema_version) {
        results.push(
            DiagnosticResult::fail(
                "rules_pack_schema",
                "Installed rules pack schema is unsupported",
                format!("schema {}", manifest.pack_schema_version),
            )
            .with_fix("Install a rules pack compatible with this Rustinel release"),
        );
        return false;
    }

    let req = match VersionReq::parse(&manifest.requires_rustinel) {
        Ok(req) => req,
        Err(err) => {
            results.push(
                DiagnosticResult::fail(
                    "rules_pack_compatibility",
                    "Rules pack compatibility requirement is invalid",
                    format!("{err}"),
                )
                .with_fix("Reinstall the active rules pack"),
            );
            return false;
        }
    };
    let current = Version::parse(env!("CARGO_PKG_VERSION").trim_start_matches('v'));
    match current {
        Ok(version) if req.matches(&version) => results.push(DiagnosticResult::pass(
            "rules_pack_compatibility",
            format!(
                "Rules pack requirement {} matches Rustinel {}",
                manifest.requires_rustinel, version
            ),
        )),
        Ok(version) => results.push(
            DiagnosticResult::fail(
                "rules_pack_compatibility",
                "Rules pack is not compatible with this binary",
                format!(
                    "requires {}, current {}",
                    manifest.requires_rustinel, version
                ),
            )
            .with_fix("Install a compatible rules pack or upgrade Rustinel"),
        ),
        Err(err) => results.push(DiagnosticResult::fail(
            "rules_pack_compatibility",
            "Current Rustinel version could not be parsed",
            format!("{err}"),
        )),
    }

    true
}

#[derive(Debug, Deserialize)]
struct DoctorPackManifest {
    id: String,
    pack_schema_version: u32,
    requires_rustinel: String,
}

fn inspect_service(mode: InstallMode, results: &mut Vec<DiagnosticResult>) -> ServiceDiagnostic {
    let service = read_service_status();
    let status_result = match mode {
        InstallMode::Portable => DiagnosticResult::pass(
            "native_service",
            "Portable mode does not require native service installation",
        ),
        InstallMode::Managed if service.status == "running" => DiagnosticResult::pass(
            "native_service",
            format!("Native service is {}", service.status),
        ),
        InstallMode::Managed if service.status == "not-installed" => DiagnosticResult::fail(
            "native_service",
            "Native service is not installed",
            service
                .detail
                .clone()
                .unwrap_or_else(|| service.manager.clone()),
        )
        .with_fix("Run rustinel service install from the managed installation"),
        InstallMode::Managed => DiagnosticResult::warn(
            "native_service",
            format!("Native service is {}", service.status),
            service
                .detail
                .clone()
                .unwrap_or_else(|| service.manager.clone()),
        )
        .with_fix("Run rustinel service status and inspect the native service manager"),
    };
    results.push(status_result);
    service
}

fn read_service_status() -> ServiceDiagnostic {
    #[cfg(target_os = "linux")]
    {
        read_systemd_status()
    }
    #[cfg(target_os = "macos")]
    {
        read_launchd_status()
    }
    #[cfg(windows)]
    {
        read_windows_service_status()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        ServiceDiagnostic {
            manager: "unsupported".to_string(),
            status: "unknown".to_string(),
            detail: Some("No native service backend is available".to_string()),
        }
    }
}

#[cfg(target_os = "linux")]
fn read_systemd_status() -> ServiceDiagnostic {
    let paths = ManagedServicePaths::current();
    let Some(unit_path) = paths.systemd_unit_path else {
        return service_diag("systemd", ServiceStatus::Unknown, "missing unit path");
    };
    if !unit_path.exists() {
        return service_diag(
            "systemd",
            ServiceStatus::NotInstalled,
            unit_path.display().to_string(),
        );
    }

    match std::process::Command::new("systemctl")
        .args(["is-active", SYSTEMD_UNIT_NAME])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            service_diag("systemd", systemd_status_from_state(&stdout), stdout.trim())
        }
        Err(err) => service_diag("systemd", ServiceStatus::Unknown, format!("{err}")),
    }
}

#[cfg(target_os = "macos")]
fn read_launchd_status() -> ServiceDiagnostic {
    let paths = ManagedServicePaths::current();
    let Some(plist_path) = paths.launchd_plist_path else {
        return service_diag("launchd", ServiceStatus::Unknown, "missing plist path");
    };
    if !plist_path.exists() {
        return service_diag(
            "launchd",
            ServiceStatus::NotInstalled,
            plist_path.display().to_string(),
        );
    }

    let target = format!("system/{LAUNCHD_LABEL}");
    match std::process::Command::new("launchctl")
        .args(["print", &target])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            service_diag("launchd", launchd_status_from_output(&stdout), target)
        }
        Ok(_) => service_diag("launchd", ServiceStatus::Stopped, target),
        Err(err) => service_diag("launchd", ServiceStatus::Unknown, format!("{err}")),
    }
}

#[cfg(windows)]
fn read_windows_service_status() -> ServiceDiagnostic {
    match std::process::Command::new("sc")
        .args(["query", WINDOWS_SERVICE_NAME])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let status = if stdout.contains("RUNNING") {
                ServiceStatus::Running
            } else if stdout.contains("START_PENDING") {
                ServiceStatus::Starting
            } else if stdout.contains("STOPPED") {
                ServiceStatus::Stopped
            } else {
                ServiceStatus::Unknown
            };
            service_diag("windows-service", status, WINDOWS_SERVICE_NAME)
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            service_diag(
                "windows-service",
                ServiceStatus::NotInstalled,
                stderr.trim().to_string(),
            )
        }
        Err(err) => service_diag("windows-service", ServiceStatus::Unknown, format!("{err}")),
    }
}

fn service_diag(
    manager: impl Into<String>,
    status: ServiceStatus,
    detail: impl Into<String>,
) -> ServiceDiagnostic {
    let detail = detail.into();
    ServiceDiagnostic {
        manager: manager.into(),
        status: status.to_string(),
        detail: (!detail.is_empty()).then_some(detail),
    }
}

fn platform_prerequisite_results() -> Vec<DiagnosticResult> {
    #[cfg(target_os = "linux")]
    {
        linux_prerequisite_results()
    }
    #[cfg(target_os = "macos")]
    {
        macos_prerequisite_results()
    }
    #[cfg(windows)]
    {
        windows_prerequisite_results()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        vec![DiagnosticResult::fail(
            "telemetry_prerequisites",
            "No telemetry backend is available for this platform",
            std::env::consts::OS,
        )]
    }
}

#[cfg(target_os = "linux")]
fn linux_prerequisite_results() -> Vec<DiagnosticResult> {
    vec![
        linux_kernel_result(),
        linux_privilege_result(),
        linux_btf_result(),
        linux_tracefs_result(),
        linux_systemd_result(),
        DiagnosticResult::pass(
            "linux_dns_hooks",
            "DNS hooks include sendto, sendmsg, and sendmmsg coverage",
        ),
        DiagnosticResult::pass(
            "telemetry_prerequisites",
            "Linux eBPF telemetry prerequisites were inspected",
        ),
    ]
}

#[cfg(target_os = "linux")]
fn linux_kernel_result() -> DiagnosticResult {
    match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(value) => DiagnosticResult::pass("linux_kernel", format!("Kernel {}", value.trim())),
        Err(err) => DiagnosticResult::warn(
            "linux_kernel",
            "Kernel version could not be read",
            format!("{err}"),
        ),
    }
}

#[cfg(target_os = "linux")]
fn linux_privilege_result() -> DiagnosticResult {
    if unsafe { libc::geteuid() } == 0 {
        return DiagnosticResult::pass("required_privileges", "Running with root privileges");
    }

    let caps = effective_capabilities();
    let has_needed = caps
        .map(|caps| has_cap(caps, 12) && has_cap(caps, 24) && has_cap(caps, 39))
        .unwrap_or(false);
    if has_needed {
        DiagnosticResult::pass(
            "required_privileges",
            "Process has CAP_NET_ADMIN, CAP_SYS_RESOURCE, and CAP_BPF",
        )
    } else {
        DiagnosticResult::fail(
            "required_privileges",
            "Linux eBPF telemetry requires root or eBPF capabilities",
            "Missing root or one of CAP_NET_ADMIN, CAP_SYS_RESOURCE, CAP_BPF",
        )
        .with_fix("Run as root or grant the managed service the required capabilities")
    }
}

#[cfg(target_os = "linux")]
fn linux_btf_result() -> DiagnosticResult {
    let path = Path::new("/sys/kernel/btf/vmlinux");
    if path.is_file() {
        DiagnosticResult::pass("linux_btf", "Kernel BTF is available")
    } else {
        DiagnosticResult::fail(
            "linux_btf",
            "Kernel BTF is not available",
            path.display().to_string(),
        )
        .with_fix("Install kernel BTF data or use a kernel with CONFIG_DEBUG_INFO_BTF")
    }
}

#[cfg(target_os = "linux")]
fn linux_tracefs_result() -> DiagnosticResult {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mounted = mounts.lines().any(|line| {
        let mut parts = line.split_whitespace();
        let _source = parts.next();
        let target = parts.next();
        let fs_type = parts.next();
        matches!(
            (target, fs_type),
            (Some("/sys/kernel/tracing"), Some("tracefs"))
                | (
                    Some("/sys/kernel/debug/tracing"),
                    Some("tracefs" | "debugfs")
                )
        )
    });
    if mounted {
        DiagnosticResult::pass("linux_tracefs", "tracefs or debugfs tracing is mounted")
    } else {
        DiagnosticResult::fail(
            "linux_tracefs",
            "tracefs is not mounted",
            "/sys/kernel/tracing or /sys/kernel/debug/tracing",
        )
        .with_fix("Mount tracefs before starting the agent")
    }
}

#[cfg(target_os = "linux")]
fn linux_systemd_result() -> DiagnosticResult {
    if Path::new("/run/systemd/system").is_dir() {
        DiagnosticResult::pass("linux_systemd", "systemd is available")
    } else {
        DiagnosticResult::warn(
            "linux_systemd",
            "systemd runtime directory was not found",
            "/run/systemd/system",
        )
        .with_fix("Use portable foreground mode or run on a systemd host for native service mode")
    }
}

#[cfg(target_os = "linux")]
fn effective_capabilities() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    u64::from_str_radix(value, 16).ok()
}

#[cfg(target_os = "linux")]
fn has_cap(caps: u64, bit: u8) -> bool {
    caps & (1u64 << bit) != 0
}

#[cfg(target_os = "macos")]
fn macos_prerequisite_results() -> Vec<DiagnosticResult> {
    vec![
        macos_privilege_result(),
        macos_app_location_result(),
        macos_endpoint_security_result(),
        macos_bpf_result(),
        DiagnosticResult::warn(
            "macos_full_disk_access",
            "Full Disk Access is not reliably detectable from this process",
            "Grant Full Disk Access to the signed application in System Settings",
        ),
        DiagnosticResult::pass(
            "telemetry_prerequisites",
            "macOS Endpoint Security and BPF prerequisites were inspected",
        ),
    ]
}

#[cfg(target_os = "macos")]
fn macos_privilege_result() -> DiagnosticResult {
    if unsafe { libc::geteuid() } == 0 {
        DiagnosticResult::pass("required_privileges", "Running with root privileges")
    } else {
        DiagnosticResult::fail(
            "required_privileges",
            "Endpoint Security telemetry requires root privileges",
            "current effective uid is not 0",
        )
        .with_fix("Run through the managed LaunchDaemon or use sudo for foreground checks")
    }
}

#[cfg(target_os = "macos")]
fn macos_app_location_result() -> DiagnosticResult {
    let expected = ManagedServicePaths::current().working_dir;
    match std::env::current_exe() {
        Ok(path) if path.starts_with(&expected) => DiagnosticResult::pass(
            "macos_app_location",
            "Running from the managed application location",
        ),
        Ok(path) => DiagnosticResult::warn(
            "macos_app_location",
            "Binary is not running from the managed application location",
            path.display().to_string(),
        )
        .with_fix(format!(
            "Use the signed application under {}",
            expected.display()
        )),
        Err(err) => DiagnosticResult::warn(
            "macos_app_location",
            "Current executable path could not be read",
            format!("{err}"),
        ),
    }
}

#[cfg(target_os = "macos")]
fn macos_endpoint_security_result() -> DiagnosticResult {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            return DiagnosticResult::warn(
                "macos_endpoint_security",
                "Endpoint Security entitlement could not be inspected",
                format!("{err}"),
            );
        }
    };
    match std::process::Command::new("codesign")
        .args(["-d", "--entitlements", ":-", &exe.to_string_lossy()])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("com.apple.developer.endpoint-security.client") {
                DiagnosticResult::pass(
                    "macos_endpoint_security",
                    "Endpoint Security entitlement is present",
                )
            } else {
                DiagnosticResult::fail(
                    "macos_endpoint_security",
                    "Endpoint Security entitlement is missing",
                    exe.display().to_string(),
                )
                .with_fix("Use a signed build with the Endpoint Security entitlement")
            }
        }
        Ok(output) => DiagnosticResult::warn(
            "macos_endpoint_security",
            "Endpoint Security entitlement could not be inspected",
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ),
        Err(err) => DiagnosticResult::warn(
            "macos_endpoint_security",
            "codesign could not be run",
            format!("{err}"),
        ),
    }
}

#[cfg(target_os = "macos")]
fn macos_bpf_result() -> DiagnosticResult {
    let has_bpf = (0..8)
        .map(|idx| PathBuf::from(format!("/dev/bpf{idx}")))
        .any(|path| path.exists());
    if has_bpf {
        DiagnosticResult::pass("macos_bpf", "BPF devices are available")
    } else {
        DiagnosticResult::fail("macos_bpf", "No /dev/bpf devices were found", "/dev/bpf*")
            .with_fix("Enable BPF access or run on a macOS host with BPF devices")
    }
}

#[cfg(windows)]
fn windows_prerequisite_results() -> Vec<DiagnosticResult> {
    vec![
        windows_admin_result(),
        DiagnosticResult::pass(
            "windows_etw",
            "ETW telemetry prerequisites are available in this build",
        ),
        DiagnosticResult::pass(
            "telemetry_prerequisites",
            "Windows ETW prerequisites were inspected",
        ),
    ]
}

#[cfg(windows)]
fn windows_admin_result() -> DiagnosticResult {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return DiagnosticResult::warn(
                "required_privileges",
                "Administrator status could not be inspected",
                "OpenProcessToken failed",
            );
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;
        if GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
        .is_err()
        {
            return DiagnosticResult::warn(
                "required_privileges",
                "Administrator status could not be inspected",
                "GetTokenInformation failed",
            );
        }
        if elevation.TokenIsElevated != 0 {
            DiagnosticResult::pass(
                "required_privileges",
                "Running with Administrator privileges",
            )
        } else {
            DiagnosticResult::fail(
                "required_privileges",
                "ETW telemetry requires Administrator privileges",
                "current token is not elevated",
            )
            .with_fix("Run as Administrator or through the managed Windows service")
        }
    }
}

fn directory_check(id: &str, label: &str, path: &Path) -> DiagnosticResult {
    match std::fs::metadata(path) {
        Ok(metadata) if !metadata.is_dir() => DiagnosticResult::fail(
            id,
            format!("{label} is not a directory"),
            path.display().to_string(),
        )
        .with_fix("Update config.toml to point at a directory"),
        Ok(metadata) if metadata.permissions().readonly() => DiagnosticResult::warn(
            id,
            format!("{label} is marked read-only"),
            path.display().to_string(),
        )
        .with_fix("Ensure the runtime user can write logs and alerts"),
        Ok(metadata) if !owner_writable(&metadata) => DiagnosticResult::warn(
            id,
            format!("{label} is not owner-writable"),
            path.display().to_string(),
        )
        .with_fix("Ensure the runtime user can write logs and alerts"),
        Ok(_) => DiagnosticResult::pass(id, format!("{label} exists and is writable")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => DiagnosticResult::warn(
            id,
            format!("{label} does not exist"),
            format!(
                "{} could not be checked without creating it",
                path.display()
            ),
        )
        .with_fix("Create the directory with ownership for the runtime user"),
        Err(err) => DiagnosticResult::fail(
            id,
            format!("{label} could not be inspected"),
            format!("{}: {err}", path.display()),
        )
        .with_fix("Fix permissions or update config.toml"),
    }
}

fn directory_exists_check(id: &str, label: &str, path: &Path) -> DiagnosticResult {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => DiagnosticResult::pass(id, format!("{label} exists")),
        Ok(_) => DiagnosticResult::fail(
            id,
            format!("{label} is not a directory"),
            path.display().to_string(),
        )
        .with_fix("Update config.toml to point at a directory"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => DiagnosticResult::fail(
            id,
            format!("{label} does not exist"),
            path.display().to_string(),
        )
        .with_fix("Install a rules pack or update config.toml"),
        Err(err) => DiagnosticResult::fail(
            id,
            format!("{label} could not be inspected"),
            format!("{}: {err}", path.display()),
        )
        .with_fix("Fix permissions or update config.toml"),
    }
}

fn file_readable_check(id: &str, label: &str, path: &Path) -> DiagnosticResult {
    match std::fs::File::open(path) {
        Ok(_) => DiagnosticResult::pass(id, format!("{label} is readable")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => DiagnosticResult::warn(
            id,
            format!("{label} does not exist"),
            path.display().to_string(),
        )
        .with_fix("Install a rules pack or update config.toml"),
        Err(err) => DiagnosticResult::fail(
            id,
            format!("{label} could not be read"),
            format!("{}: {err}", path.display()),
        )
        .with_fix("Fix permissions or update config.toml"),
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

fn sensor_platform(platform: InstallPlatform) -> crate::sensor::Platform {
    match platform {
        InstallPlatform::Windows => crate::sensor::Platform::Windows,
        InstallPlatform::Linux => crate::sensor::Platform::Linux,
        InstallPlatform::Macos => crate::sensor::Platform::MacOS,
    }
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

fn infer_rules_dir(paths: &ResolvedPaths) -> PathBuf {
    let sigma = &paths.sigma_rules;
    if sigma.file_name().and_then(|name| name.to_str()) == Some("sigma") {
        if let Some(parent) = sigma.parent() {
            if parent.file_name().and_then(|name| name.to_str()) == Some("current") {
                if let Some(root) = parent.parent() {
                    return root.to_path_buf();
                }
            }
            return parent.to_path_buf();
        }
    }
    PathBuf::from("rules")
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
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
