use std::fs;
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

struct LaunchdBackend {
    paths: ManagedServicePaths,
}

impl LaunchdBackend {
    fn new() -> Self {
        Self {
            paths: ManagedServicePaths::current(),
        }
    }

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
        Command::new("launchctl")
            .args(args)
            .output()
            .with_context(|| format!("failed to run launchctl {}", args.join(" ")))
    }

    fn service_target(&self) -> String {
        format!("system/{LAUNCHD_LABEL}")
    }

    fn print_service(&self) -> anyhow::Result<Output> {
        self.command_output(&["print", &self.service_target()])
    }
}

impl ServiceBackend for LaunchdBackend {
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

        if self.print_service()?.status.success() {
            self.command(&["enable", &self.service_target()])?;
            return Ok(());
        }

        self.command(&["bootstrap", "system", &plist_path.to_string_lossy()])?;
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
