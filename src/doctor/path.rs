use crate::config::AppConfig;
use crate::doctor::inspect::{DiagnosticResult, ResolvedPaths};
use std::path::Path;

pub(crate) fn path_results(cfg: &AppConfig, paths: &ResolvedPaths) -> Vec<DiagnosticResult> {
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
