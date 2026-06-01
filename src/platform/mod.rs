#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub fn handle_service_command(action: crate::cli::ServiceAction) -> anyhow::Result<()> {
    windows::handle_service_command(action)
}

#[cfg(not(windows))]
pub fn handle_service_command(_action: crate::cli::ServiceAction) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "Service commands are only supported on Windows"
    ))
}
