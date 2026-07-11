use crate::config::{AppConfig, InstallPlatform};
use crate::doctor::inspect::{DiagnosticResult, ResolvedPaths, RulePackDiagnostic};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const SUPPORTED_PACK_SCHEMA_VERSIONS: &[u32] = &[1, 2];

#[derive(Debug, Deserialize)]
struct DoctorPackManifest {
    id: String,
    pack_schema_version: u32,
    requires_rustinel: String,
}

pub(crate) fn inspect_rule_pack(
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
        Ok(version) if crate::rules::rustinel_version_matches_requirement(&req, &version) => {
            results.push(DiagnosticResult::pass(
                "rules_pack_compatibility",
                format!(
                    "Rules pack requirement {} matches Rustinel {}",
                    manifest.requires_rustinel, version
                ),
            ))
        }
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

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

pub(crate) fn rule_validation_results(
    cfg: &AppConfig,
    platform: InstallPlatform,
) -> Vec<DiagnosticResult> {
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

fn sensor_platform(platform: InstallPlatform) -> crate::sensor::Platform {
    match platform {
        InstallPlatform::Windows => crate::sensor::Platform::Windows,
        InstallPlatform::Linux => crate::sensor::Platform::Linux,
        InstallPlatform::Macos => crate::sensor::Platform::MacOS,
    }
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
