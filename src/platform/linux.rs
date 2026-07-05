use std::fs;
use std::process::Command;

use anyhow::{bail, Context};

use crate::cli::ServiceAction;
use crate::service::{
    execute_backend_action, systemd_status_from_state, ManagedServicePaths, ServiceBackend,
    ServiceStatus, SystemdDefinition, SYSTEMD_SERVICE_NAME,
};

pub fn handle_service_command(action: ServiceAction) -> anyhow::Result<()> {
    let backend = SystemdBackend::new();
    execute_backend_action(&backend, action)
}

struct SystemdBackend {
    paths: ManagedServicePaths,
}

impl SystemdBackend {
    fn new() -> Self {
        Self {
            paths: ManagedServicePaths::current(),
        }
    }

    fn unit_path(&self) -> anyhow::Result<&std::path::Path> {
        self.paths
            .systemd_unit_path
            .as_deref()
            .context("missing systemd unit path")
    }

    fn command(&self, args: &[&str]) -> anyhow::Result<()> {
        let output = Command::new("systemctl")
            .args(args)
            .output()
            .with_context(|| format!("failed to run systemctl {}", args.join(" ")))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("systemctl {} failed: {}", args.join(" "), stderr.trim());
    }

    fn command_output(&self, args: &[&str]) -> anyhow::Result<std::process::Output> {
        Command::new("systemctl")
            .args(args)
            .output()
            .with_context(|| format!("failed to run systemctl {}", args.join(" ")))
    }
}

impl ServiceBackend for SystemdBackend {
    fn name(&self) -> &'static str {
        SYSTEMD_SERVICE_NAME
    }

    fn install(&self) -> anyhow::Result<()> {
        self.paths.validate_install_inputs()?;

        let unit_path = self.unit_path()?;
        let definition = SystemdDefinition::managed(&self.paths);
        if let Some(parent) = unit_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let should_write = fs::read_to_string(unit_path)
            .map(|existing| existing != definition.contents)
            .unwrap_or(true);
        if should_write {
            fs::write(unit_path, definition.contents)
                .with_context(|| format!("failed to write {}", unit_path.display()))?;
        }

        self.command(&["daemon-reload"])?;
        self.command(&["enable", crate::service::SYSTEMD_UNIT_NAME])?;
        Ok(())
    }

    fn uninstall(&self) -> anyhow::Result<()> {
        let unit_path = self.unit_path()?;
        let installed = unit_path.exists();

        if installed {
            let _ = self.command(&["stop", crate::service::SYSTEMD_UNIT_NAME]);
            let _ = self.command(&["disable", crate::service::SYSTEMD_UNIT_NAME]);
            fs::remove_file(unit_path)
                .with_context(|| format!("failed to remove {}", unit_path.display()))?;
            self.command(&["daemon-reload"])?;
        }

        Ok(())
    }

    fn start(&self) -> anyhow::Result<()> {
        self.command(&["start", crate::service::SYSTEMD_UNIT_NAME])
    }

    fn stop(&self) -> anyhow::Result<()> {
        self.command(&["stop", crate::service::SYSTEMD_UNIT_NAME])
    }

    fn status(&self) -> anyhow::Result<ServiceStatus> {
        if !self.unit_path()?.exists() {
            return Ok(ServiceStatus::NotInstalled);
        }

        let output = self.command_output(&["is-active", crate::service::SYSTEMD_UNIT_NAME])?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(systemd_status_from_state(&stdout))
    }
}
