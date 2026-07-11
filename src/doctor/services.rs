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
