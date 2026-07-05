#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub fn handle_service_command(action: crate::cli::ServiceAction) -> anyhow::Result<()> {
    windows::handle_service_command(action)
}

#[cfg(target_os = "linux")]
pub fn handle_service_command(action: crate::cli::ServiceAction) -> anyhow::Result<()> {
    linux::handle_service_command(action)
}

#[cfg(target_os = "macos")]
pub fn handle_service_command(action: crate::cli::ServiceAction) -> anyhow::Result<()> {
    macos::handle_service_command(action)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn handle_service_command(_action: crate::cli::ServiceAction) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "Service commands are only supported on Windows, Linux, and macOS"
    ))
}
