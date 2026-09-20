use std::fs;
use std::io;
use std::process::{Command, Output};

use anyhow::{bail, Context};

use crate::cli::ServiceAction;
use crate::service::{
    execute_backend_action, launchd_status_from_output, run_backend_action, LaunchdDefinition,
    ManagedServicePaths, ServiceBackend, ServiceCommandResult, ServiceStatus, LAUNCHD_LABEL,
};

pub fn handle_service_command(action: ServiceAction) -> anyhow::Result<()> {
    let backend = LaunchdBackend::new();
    execute_backend_action(&backend, action)
}

pub fn run_service_action(action: ServiceAction) -> anyhow::Result<ServiceCommandResult> {
    let backend = LaunchdBackend::new();
    run_backend_action(&backend, action)
}

trait Launchctl {
    fn output(&self, args: &[&str]) -> io::Result<Output>;
}

struct ProcessLaunchctl;

impl Launchctl for ProcessLaunchctl {
    fn output(&self, args: &[&str]) -> io::Result<Output> {
        Command::new("launchctl").args(args).output()
    }
}

struct LaunchdBackend<L = ProcessLaunchctl> {
    paths: ManagedServicePaths,
    launchctl: L,
}

impl LaunchdBackend<ProcessLaunchctl> {
    fn new() -> Self {
        Self {
            paths: ManagedServicePaths::current(),
            launchctl: ProcessLaunchctl,
        }
    }
}

impl<L: Launchctl> LaunchdBackend<L> {
    fn plist_path(&self) -> anyhow::Result<&std::path::Path> {
        self.paths
            .launchd_plist_path
            .as_deref()
            .context("missing launchd plist path")
    }

    fn command(&self, args: &[&str]) -> anyhow::Result<()> {
        let output = self.command_output(args)?;
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("launchctl {} failed: {}", args.join(" "), stderr.trim());
    }

    fn command_output(&self, args: &[&str]) -> anyhow::Result<Output> {
        self.launchctl
            .output(args)
            .with_context(|| format!("failed to run launchctl {}", args.join(" ")))
    }

    fn service_target(&self) -> String {
        format!("system/{LAUNCHD_LABEL}")
    }

    fn print_service(&self) -> anyhow::Result<Output> {
        self.command_output(&["print", &self.service_target()])
    }
}

impl<L: Launchctl> ServiceBackend for LaunchdBackend<L> {
    fn name(&self) -> &'static str {
        LAUNCHD_LABEL
    }

    fn install(&self) -> anyhow::Result<()> {
        self.paths.validate_install_inputs()?;

        let plist_path = self.plist_path()?;
        let definition = LaunchdDefinition::managed(&self.paths);
        if let Some(parent) = plist_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let should_write = fs::read_to_string(plist_path)
            .map(|existing| existing != definition.contents)
            .unwrap_or(true);
        if should_write {
            fs::write(plist_path, definition.contents)
                .with_context(|| format!("failed to write {}", plist_path.display()))?;
        }

        // A LaunchDaemon plist is discovered automatically at boot. Loading it
        // here would immediately run the agent because the definition uses
        // RunAtLoad and KeepAlive, violating `setup --no-start`.
        self.command(&["enable", &self.service_target()])?;
        Ok(())
    }

    fn uninstall(&self) -> anyhow::Result<()> {
        let plist_path = self.plist_path()?;

        if plist_path.exists() {
            let _ = self.command(&["bootout", "system", &plist_path.to_string_lossy()]);
            fs::remove_file(plist_path)
                .with_context(|| format!("failed to remove {}", plist_path.display()))?;
        }

        Ok(())
    }

    fn start(&self) -> anyhow::Result<()> {
        let plist_path = self.plist_path()?;
        if !plist_path.exists() {
            bail!("LaunchDaemon is not installed: {}", plist_path.display());
        }

        if !self.print_service()?.status.success() {
            self.command(&["bootstrap", "system", &plist_path.to_string_lossy()])?;
        }
        self.command(&["kickstart", "-k", &self.service_target()])
    }

    fn stop(&self) -> anyhow::Result<()> {
        let plist_path = self.plist_path()?;
        if !plist_path.exists() {
            return Ok(());
        }

        let _ = self.command(&["bootout", "system", &plist_path.to_string_lossy()]);
        Ok(())
    }

    fn status(&self) -> anyhow::Result<ServiceStatus> {
        if !self.plist_path()?.exists() {
            return Ok(ServiceStatus::NotInstalled);
        }

        let output = self.print_service()?;
        if !output.status.success() {
            return Ok(ServiceStatus::Stopped);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(launchd_status_from_output(&stdout))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;

    use super::*;
    use crate::config::InstallPlatform;

    struct RecordingLaunchctl {
        calls: RefCell<Vec<String>>,
        outputs: RefCell<VecDeque<Output>>,
    }

    impl RecordingLaunchctl {
        fn succeeding() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outputs: RefCell::new(VecDeque::new()),
            }
        }

        fn with_outputs(outputs: impl IntoIterator<Item = Output>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outputs: RefCell::new(outputs.into_iter().collect()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl Launchctl for RecordingLaunchctl {
        fn output(&self, args: &[&str]) -> io::Result<Output> {
            self.calls.borrow_mut().push(args.join(" "));
            Ok(self
                .outputs
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(success_output))
        }
    }

    fn output(code: i32) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(code),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn success_output() -> Output {
        output(0)
    }

    fn test_paths(temp: &tempfile::TempDir) -> ManagedServicePaths {
        let root = temp.path();
        ManagedServicePaths {
            platform: InstallPlatform::Macos,
            binary_path: root.join("Rustinel.app/Contents/MacOS/rustinel"),
            config_path: root.join("config.toml"),
            working_dir: root.to_path_buf(),
            systemd_unit_path: None,
            launchd_plist_path: Some(root.join("com.rustinel.agent.plist")),
            logs_dir: PathBuf::from("/Library/Logs/Rustinel"),
        }
    }

    fn create_install_inputs(paths: &ManagedServicePaths) {
        fs::create_dir_all(paths.binary_path.parent().expect("binary parent"))
            .expect("binary directory");
        fs::write(&paths.binary_path, b"binary").expect("binary");
        fs::write(&paths.config_path, b"config").expect("config");
    }

    #[test]
    fn install_registers_without_loading_or_starting_the_job() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = test_paths(&temp);
        create_install_inputs(&paths);
        let backend = LaunchdBackend {
            paths,
            launchctl: RecordingLaunchctl::succeeding(),
        };

        backend.install().expect("install");

        assert_eq!(
            backend.launchctl.calls(),
            ["enable system/com.rustinel.agent"]
        );
        let plist = fs::read_to_string(backend.plist_path().expect("plist path")).expect("plist");
        assert!(plist.contains("<key>RunAtLoad</key>\n<true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n<true/>"));
    }

    #[test]
    fn repeated_install_does_not_restart_an_existing_job() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = test_paths(&temp);
        create_install_inputs(&paths);
        let backend = LaunchdBackend {
            paths,
            launchctl: RecordingLaunchctl::succeeding(),
        };

        backend.install().expect("first install");
        backend.install().expect("second install");

        assert_eq!(
            backend.launchctl.calls(),
            [
                "enable system/com.rustinel.agent",
                "enable system/com.rustinel.agent"
            ]
        );
    }

    #[test]
    fn start_loads_an_unloaded_job_then_kickstarts_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = test_paths(&temp);
        create_install_inputs(&paths);
        fs::write(
            paths.launchd_plist_path.as_ref().expect("plist path"),
            "plist",
        )
        .expect("plist");
        let plist_path = paths
            .launchd_plist_path
            .as_ref()
            .expect("plist path")
            .to_string_lossy()
            .into_owned();
        let backend = LaunchdBackend {
            paths,
            launchctl: RecordingLaunchctl::with_outputs([
                output(1),
                success_output(),
                success_output(),
            ]),
        };

        backend.start().expect("start");

        assert_eq!(
            backend.launchctl.calls(),
            [
                "print system/com.rustinel.agent".to_string(),
                format!("bootstrap system {plist_path}"),
                "kickstart -k system/com.rustinel.agent".to_string()
            ]
        );
    }
}
