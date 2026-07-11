use crate::doctor::inspect::DiagnosticResult;
#[cfg(target_os = "macos")]
use crate::service::ManagedServicePaths;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

pub(crate) fn platform_prerequisite_results() -> Vec<DiagnosticResult> {
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
        .map(|caps| {
            has_cap(caps, 12) && has_cap(caps, 24) && has_cap(caps, 38) && has_cap(caps, 39)
        })
        .unwrap_or(false);
    if has_needed {
        DiagnosticResult::pass(
            "required_privileges",
            "Process has CAP_NET_ADMIN, CAP_SYS_RESOURCE, CAP_PERFMON, and CAP_BPF",
        )
    } else {
        DiagnosticResult::fail(
            "required_privileges",
            "Linux eBPF telemetry requires root or eBPF capabilities",
            "Missing root or one of CAP_NET_ADMIN, CAP_SYS_RESOURCE, CAP_PERFMON, CAP_BPF",
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
