use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use crate::cli::ServiceAction;
use crate::config::{layout_join, InstallLayout, InstallPlatform};

pub const WINDOWS_SERVICE_NAME: &str = "Rustinel";
pub const WINDOWS_SERVICE_DISPLAY_NAME: &str = "Rustinel ETW Sentinel";
pub const SERVICE_DESCRIPTION: &str = "High-performance endpoint detection agent";
pub const SYSTEMD_SERVICE_NAME: &str = "rustinel";
pub const SYSTEMD_UNIT_NAME: &str = "rustinel.service";
pub const LAUNCHD_LABEL: &str = "com.rustinel.agent";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    NotInstalled,
    Stopped,
    Starting,
    Running,
    Failed,
    Unknown,
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::NotInstalled => "not-installed",
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        };
        f.write_str(value)
    }
}

pub fn systemd_status_from_state(state: &str) -> ServiceStatus {
    match state.trim() {
        "active" => ServiceStatus::Running,
        "activating" => ServiceStatus::Starting,
        "inactive" | "deactivating" => ServiceStatus::Stopped,
        "failed" => ServiceStatus::Failed,
        "unknown" => ServiceStatus::Unknown,
        _ => ServiceStatus::Unknown,
    }
}

pub fn launchd_status_from_output(output: &str) -> ServiceStatus {
    if output.contains("state = running") {
        ServiceStatus::Running
    } else if output.contains("state = spawning") {
        ServiceStatus::Starting
    } else if output.contains("state = waiting")
        || output.contains("state = exited")
        || output.contains("last exit code = 0")
    {
        ServiceStatus::Stopped
    } else if output.contains("last exit code =") {
        ServiceStatus::Failed
    } else {
        ServiceStatus::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedServicePaths {
    pub platform: InstallPlatform,
    pub binary_path: PathBuf,
    pub config_path: PathBuf,
    pub working_dir: PathBuf,
    pub systemd_unit_path: Option<PathBuf>,
    pub launchd_plist_path: Option<PathBuf>,
    pub logs_dir: PathBuf,
}

impl ManagedServicePaths {
    pub fn for_platform(platform: InstallPlatform) -> Self {
        let layout = InstallLayout::managed(platform);
        match platform {
            InstallPlatform::Windows => Self {
                platform,
                binary_path: PathBuf::from(r"C:\Program Files\Rustinel\rustinel.exe"),
                config_path: layout.config_file,
                working_dir: PathBuf::from(r"C:\Program Files\Rustinel"),
                systemd_unit_path: None,
                launchd_plist_path: None,
                logs_dir: layout.logs_dir,
            },
            InstallPlatform::Linux => Self {
                platform,
                binary_path: PathBuf::from("/opt/rustinel/rustinel"),
                config_path: layout.config_file,
                working_dir: PathBuf::from("/opt/rustinel"),
                systemd_unit_path: Some(PathBuf::from("/etc/systemd/system/rustinel.service")),
                launchd_plist_path: None,
                logs_dir: layout.logs_dir,
            },
            InstallPlatform::Macos => Self {
                platform,
                binary_path: PathBuf::from(
                    "/usr/local/var/rustinel/Rustinel.app/Contents/MacOS/rustinel",
                ),
                config_path: layout.config_file,
                working_dir: PathBuf::from("/usr/local/var/rustinel"),
                systemd_unit_path: None,
                launchd_plist_path: Some(PathBuf::from(
                    "/Library/LaunchDaemons/com.rustinel.agent.plist",
                )),
                logs_dir: layout.logs_dir,
            },
        }
    }

    pub fn current() -> Self {
        Self::for_platform(InstallPlatform::current())
    }

    pub fn validate_install_inputs(&self) -> anyhow::Result<()> {
        ensure_regular_file(&self.binary_path, "managed binary")?;
        ensure_regular_file(&self.config_path, "managed configuration")?;
        Ok(())
    }
}

fn ensure_regular_file(path: &Path, description: &str) -> anyhow::Result<()> {
    if !path.is_file() {
        bail!(
            "Required {} does not exist or is not a file: {}",
            description,
            path.display()
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdDefinition {
    pub unit_name: String,
    pub contents: String,
}

impl SystemdDefinition {
    pub fn managed(paths: &ManagedServicePaths) -> Self {
        let contents = format!(
            "[Unit]\n\
Description=Rustinel endpoint detection agent\n\
Documentation=https://github.com/Karib0u/rustinel\n\
After=network.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={} run --config {} --no-console\n\
WorkingDirectory={}\n\
Restart=on-failure\n\
RestartSec=5s\n\
User=root\n\
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE\n\
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE\n\
NoNewPrivileges=true\n\
StandardOutput=journal\n\
StandardError=journal\n\
SyslogIdentifier=rustinel\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n",
            paths.binary_path.display(),
            paths.config_path.display(),
            paths.working_dir.display()
        );

        Self {
            unit_name: SYSTEMD_UNIT_NAME.to_string(),
            contents,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchdDefinition {
    pub label: String,
    pub contents: String,
}

impl LaunchdDefinition {
    pub fn managed(paths: &ManagedServicePaths) -> Self {
        let stdout_path = layout_join(paths.platform, &paths.logs_dir, "launchd.out.log");
        let stderr_path = layout_join(paths.platform, &paths.logs_dir, "launchd.err.log");
        let contents = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key>\n\
    <string>{}</string>\n\
    <key>ProgramArguments</key>\n\
    <array>\n\
        <string>{}</string>\n\
        <string>run</string>\n\
        <string>--config</string>\n\
        <string>{}</string>\n\
        <string>--no-console</string>\n\
    </array>\n\
    <key>WorkingDirectory</key>\n\
    <string>{}</string>\n\
    <key>RunAtLoad</key>\n\
    <true/>\n\
    <key>KeepAlive</key>\n\
    <true/>\n\
    <key>ProcessType</key>\n\
    <string>Interactive</string>\n\
    <key>StandardOutPath</key>\n\
    <string>{}</string>\n\
    <key>StandardErrorPath</key>\n\
    <string>{}</string>\n\
</dict>\n\
</plist>\n",
            xml_escape(LAUNCHD_LABEL),
            xml_escape(&paths.binary_path.to_string_lossy()),
            xml_escape(&paths.config_path.to_string_lossy()),
            xml_escape(&paths.working_dir.to_string_lossy()),
            xml_escape(&stdout_path.to_string_lossy()),
            xml_escape(&stderr_path.to_string_lossy())
        );

        Self {
            label: LAUNCHD_LABEL.to_string(),
            contents,
        }
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub trait ServiceBackend {
    fn name(&self) -> &'static str;
    fn install(&self) -> anyhow::Result<()>;
    fn uninstall(&self) -> anyhow::Result<()>;
    fn start(&self) -> anyhow::Result<()>;
    fn stop(&self) -> anyhow::Result<()>;
    fn status(&self) -> anyhow::Result<ServiceStatus>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceCommandResult {
    NoStatus,
    Status(ServiceStatus),
}

pub fn run_backend_action<B: ServiceBackend>(
    backend: &B,
    action: ServiceAction,
) -> anyhow::Result<ServiceCommandResult> {
    match action {
        ServiceAction::Install => {
            backend.install()?;
            Ok(ServiceCommandResult::NoStatus)
        }
        ServiceAction::Uninstall => {
            backend.uninstall()?;
            Ok(ServiceCommandResult::NoStatus)
        }
        ServiceAction::Start => {
            backend.start()?;
            Ok(ServiceCommandResult::NoStatus)
        }
        ServiceAction::Stop => {
            backend.stop()?;
            Ok(ServiceCommandResult::NoStatus)
        }
        ServiceAction::Restart => {
            match backend.status().unwrap_or(ServiceStatus::Unknown) {
                ServiceStatus::NotInstalled => backend.start()?,
                ServiceStatus::Stopped => backend.start()?,
                ServiceStatus::Starting | ServiceStatus::Running | ServiceStatus::Failed => {
                    backend.stop()?;
                    backend.start()?;
                }
                ServiceStatus::Unknown => {
                    backend
                        .stop()
                        .with_context(|| format!("failed to stop {}", backend.name()))?;
                    backend.start()?;
                }
            }
            Ok(ServiceCommandResult::NoStatus)
        }
        ServiceAction::Status => Ok(ServiceCommandResult::Status(backend.status()?)),
    }
}

pub fn execute_backend_action<B: ServiceBackend>(
    backend: &B,
    action: ServiceAction,
) -> anyhow::Result<()> {
    let result = run_backend_action(backend, action)?;
    match result {
        ServiceCommandResult::NoStatus => {
            println!("Service '{}' {}.", backend.name(), action_verb(action))
        }
        ServiceCommandResult::Status(status) => println!("{}", status),
    }
    Ok(())
}

fn action_verb(action: ServiceAction) -> &'static str {
    match action {
        ServiceAction::Install => "installed",
        ServiceAction::Uninstall => "uninstalled",
        ServiceAction::Start => "started",
        ServiceAction::Stop => "stopped",
        ServiceAction::Restart => "restarted",
        ServiceAction::Status => "status",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[test]
    fn systemd_definition_uses_managed_paths() {
        let paths = ManagedServicePaths::for_platform(InstallPlatform::Linux);
        let definition = SystemdDefinition::managed(&paths);

        assert_eq!(definition.unit_name, "rustinel.service");
        assert!(definition.contents.contains(
            "ExecStart=/opt/rustinel/rustinel run --config /etc/rustinel/config.toml --no-console"
        ));
        assert!(definition
            .contents
            .contains("WorkingDirectory=/opt/rustinel"));
        assert!(definition.contents.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn launchd_definition_uses_managed_paths() {
        let paths = ManagedServicePaths::for_platform(InstallPlatform::Macos);
        let definition = LaunchdDefinition::managed(&paths);

        assert_eq!(definition.label, "com.rustinel.agent");
        assert!(definition.contents.contains(
            "<string>/usr/local/var/rustinel/Rustinel.app/Contents/MacOS/rustinel</string>"
        ));
        assert!(definition
            .contents
            .contains("<string>/Library/Application Support/Rustinel/config.toml</string>"));
        assert!(definition
            .contents
            .contains("<string>/Library/Logs/Rustinel/launchd.err.log</string>"));
    }

    #[test]
    fn mock_backend_records_successful_restart_from_running() {
        let backend = MockBackend::new(ServiceStatus::Running);

        let result = run_backend_action(&backend, ServiceAction::Restart).expect("restart");

        assert_eq!(result, ServiceCommandResult::NoStatus);
        assert_eq!(backend.calls(), ["status", "stop", "start"]);
    }

    #[test]
    fn mock_backend_records_successful_restart_from_stopped() {
        let backend = MockBackend::new(ServiceStatus::Stopped);

        run_backend_action(&backend, ServiceAction::Restart).expect("restart");

        assert_eq!(backend.calls(), ["status", "start"]);
    }

    #[test]
    fn mock_backend_surfaces_failures() {
        let backend = MockBackend::new(ServiceStatus::Running).fail_on("stop");

        let err = run_backend_action(&backend, ServiceAction::Restart).expect_err("failure");

        assert!(err.to_string().contains("stop failed"));
        assert_eq!(backend.calls(), ["status", "stop"]);
    }

    #[test]
    fn mock_backend_reports_unknown_status() {
        let backend = MockBackend::new(ServiceStatus::Unknown);

        let result = run_backend_action(&backend, ServiceAction::Status).expect("status");

        assert_eq!(result, ServiceCommandResult::Status(ServiceStatus::Unknown));
        assert_eq!(backend.calls(), ["status"]);
    }

    #[test]
    fn systemd_status_values_are_normalized() {
        assert_eq!(systemd_status_from_state("active"), ServiceStatus::Running);
        assert_eq!(
            systemd_status_from_state("activating"),
            ServiceStatus::Starting
        );
        assert_eq!(
            systemd_status_from_state("inactive"),
            ServiceStatus::Stopped
        );
        assert_eq!(systemd_status_from_state("failed"), ServiceStatus::Failed);
        assert_eq!(
            systemd_status_from_state("unexpected"),
            ServiceStatus::Unknown
        );
    }

    #[test]
    fn launchd_status_values_are_normalized() {
        assert_eq!(
            launchd_status_from_output("state = running"),
            ServiceStatus::Running
        );
        assert_eq!(
            launchd_status_from_output("state = spawning"),
            ServiceStatus::Starting
        );
        assert_eq!(
            launchd_status_from_output("state = waiting"),
            ServiceStatus::Stopped
        );
        assert_eq!(
            launchd_status_from_output("last exit code = 17"),
            ServiceStatus::Failed
        );
        assert_eq!(
            launchd_status_from_output("pid = 0"),
            ServiceStatus::Unknown
        );
    }

    struct MockBackend {
        status: ServiceStatus,
        calls: RefCell<Vec<&'static str>>,
        fail_on: Option<&'static str>,
    }

    impl MockBackend {
        fn new(status: ServiceStatus) -> Self {
            Self {
                status,
                calls: RefCell::new(Vec::new()),
                fail_on: None,
            }
        }

        fn fail_on(mut self, action: &'static str) -> Self {
            self.fail_on = Some(action);
            self
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }

        fn record(&self, action: &'static str) -> anyhow::Result<()> {
            self.calls.borrow_mut().push(action);
            if self.fail_on == Some(action) {
                bail!("{action} failed");
            }
            Ok(())
        }
    }

    impl ServiceBackend for MockBackend {
        fn name(&self) -> &'static str {
            "mock"
        }

        fn install(&self) -> anyhow::Result<()> {
            self.record("install")
        }

        fn uninstall(&self) -> anyhow::Result<()> {
            self.record("uninstall")
        }

        fn start(&self) -> anyhow::Result<()> {
            self.record("start")
        }

        fn stop(&self) -> anyhow::Result<()> {
            self.record("stop")
        }

        fn status(&self) -> anyhow::Result<ServiceStatus> {
            self.record("status")?;
            Ok(self.status)
        }
    }
}
