use crate::config::AppConfig;
use crate::doctor::inspect::{DiagnosticResult, InstallMode, ServiceDiagnostic};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::service::ManagedServicePaths;
use crate::service::ServiceStatus;
#[cfg(windows)]
use crate::service::WINDOWS_SERVICE_NAME;
#[cfg(target_os = "macos")]
use crate::service::{launchd_status_from_output, LAUNCHD_LABEL};
#[cfg(target_os = "linux")]
use crate::service::{systemd_status_from_state, SYSTEMD_UNIT_NAME};

pub(crate) fn inspect_service(
    mode: InstallMode,
    config: Option<&AppConfig>,
    results: &mut Vec<DiagnosticResult>,
) -> ServiceDiagnostic {
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
    #[cfg(target_os = "linux")]
    if mode == InstallMode::Managed {
        if let Some(config) = config {
            if let Some(result) = linux_service_capability_result(config, &service) {
                results.push(result);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = config;
    service
}

#[cfg(target_os = "linux")]
fn linux_service_capability_result(
    config: &AppConfig,
    service: &ServiceDiagnostic,
) -> Option<DiagnosticResult> {
    if service.status == "not-installed" {
        return None;
    }
    let paths = ManagedServicePaths::current();
    let unit_path = paths.systemd_unit_path?;
    let (caps, source) = if service.status == "running" {
        match running_service_capabilities() {
            Ok(caps) => (caps, "running service"),
            Err(err) => {
                return Some(DiagnosticResult::warn(
                    "linux_service_capabilities",
                    "Could not read the running service's effective capabilities",
                    err,
                ));
            }
        }
    } else {
        match std::fs::read_to_string(&unit_path) {
            Ok(unit) => match unit_capabilities(&unit) {
                Some(caps) => (caps, "installed unit"),
                None => {
                    return Some(DiagnosticResult::warn(
                        "linux_service_capabilities",
                        "Could not read the installed unit's capability directives",
                        unit_path.display().to_string(),
                    ));
                }
            },
            Err(err) => {
                return Some(DiagnosticResult::warn(
                    "linux_service_capabilities",
                    "Could not read the installed unit",
                    format!("{}: {err}", unit_path.display()),
                ));
            }
        }
    };
    Some(capability_result(config, caps, source))
}

#[cfg(target_os = "linux")]
fn running_service_capabilities() -> Result<u64, String> {
    let output = std::process::Command::new("systemctl")
        .args(["show", "--value", "-p", "MainPID", SYSTEMD_UNIT_NAME])
        .output()
        .map_err(|err| format!("systemctl show: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemctl show: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let pid: u32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|err| format!("invalid MainPID: {err}"))?;
    if pid == 0 {
        return Err("systemd reports MainPID=0".to_string());
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|err| format!("read /proc/{pid}/status: {err}"))?;
    parse_effective_capabilities(&status)
        .ok_or_else(|| format!("CapEff is missing from /proc/{pid}/status"))
}

#[cfg(target_os = "linux")]
fn parse_effective_capabilities(status: &str) -> Option<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?;
    u64::from_str_radix(value.trim(), 16).ok()
}

#[cfg(target_os = "linux")]
fn unit_capabilities(unit: &str) -> Option<u64> {
    let parse = |directive: &str| {
        let line = unit.lines().find_map(|line| line.strip_prefix(directive))?;
        let mut caps = 0u64;
        for name in line.split_whitespace() {
            let bit = match name {
                "CAP_DAC_READ_SEARCH" => 2,
                "CAP_KILL" => 5,
                "CAP_SYS_PTRACE" => 19,
                _ => continue,
            };
            caps |= 1u64 << bit;
        }
        Some(caps)
    };
    Some(parse("AmbientCapabilities=")? & parse("CapabilityBoundingSet=")?)
}

#[cfg(target_os = "linux")]
fn capability_result(config: &AppConfig, caps: u64, source: &str) -> DiagnosticResult {
    let mut missing = Vec::new();
    if caps & (1 << 19) == 0 {
        missing.push("CAP_SYS_PTRACE (/proc process enrichment)");
    }
    if (config.scanner.yara_enabled || config.ioc.enabled) && caps & (1 << 2) == 0 {
        missing.push("CAP_DAC_READ_SEARCH (YARA and IOC file reads)");
    }
    if config.response.enabled && config.response.prevention_enabled && caps & (1 << 5) == 0 {
        missing.push("CAP_KILL (active response)");
    }
    if missing.is_empty() {
        DiagnosticResult::pass(
            "linux_service_capabilities",
            format!("Required {source} capabilities are available"),
        )
    } else {
        DiagnosticResult::warn(
            "linux_service_capabilities",
            format!("Required {source} capabilities are missing"),
            missing.join(", "),
        )
        .with_fix("Run rustinel setup to update the unit and restart the service")
    }
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::doctor::inspect::DiagnosticStatus;

    #[test]
    fn missing_capabilities_follow_enabled_features() {
        let mut config = AppConfig::default();
        config.response.enabled = true;
        config.response.prevention_enabled = true;
        let result = capability_result(&config, 0, "test unit");
        assert_eq!(result.status, DiagnosticStatus::Warn);
        let detail = result.detail.unwrap();
        for name in ["CAP_KILL", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"] {
            assert!(detail.contains(name));
        }

        config.response.enabled = false;
        config.scanner.yara_enabled = false;
        config.ioc.enabled = false;
        let result = capability_result(&config, 1 << 19, "test unit");
        assert_eq!(result.status, DiagnosticStatus::Pass);
    }

    #[test]
    fn installed_unit_needs_both_capability_directives() {
        let unit = "AmbientCapabilities=CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\nCapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n";
        let caps = unit_capabilities(unit).unwrap();
        assert_eq!(caps & (1 << 5), 0);
        assert_ne!(caps & (1 << 19), 0);
        assert_ne!(caps & (1 << 2), 0);
        assert_eq!(
            parse_effective_capabilities("Name:\trustinel\nCapEff:\t0000000000080024\n"),
            Some((1 << 19) | (1 << 5) | (1 << 2))
        );
    }
}
