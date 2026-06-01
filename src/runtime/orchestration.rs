use crate::cli::{Cli, Commands};

#[cfg(windows)]
pub fn run() -> anyhow::Result<()> {
    if windows_service::service_dispatcher::start(
        crate::platform::windows::SERVICE_NAME,
        crate::runtime::windows::ffi_service_main,
    )
    .is_ok()
    {
        return Ok(());
    }

    let cli = Cli::parse_args();

    match cli.command {
        Some(Commands::Run { console }) => {
            crate::runtime::windows::run_console(console, cli.log_level)
        }
        None => crate::runtime::windows::run_console(false, cli.log_level),
        Some(Commands::Service { action }) => crate::platform::handle_service_command(action),
    }
}

#[cfg(target_os = "linux")]
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Some(Commands::Service { action }) => crate::platform::handle_service_command(action),
        Some(Commands::Run { .. }) | None => crate::runtime::linux::run(),
    }
}

#[cfg(target_os = "macos")]
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Some(Commands::Service { action }) => crate::platform::handle_service_command(action),
        Some(Commands::Run { .. }) | None => crate::runtime::macos::run(),
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn run() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "This platform is not supported. Rustinel runs on Windows (ETW), Linux (eBPF), and macOS (ESF)."
    ))
}
