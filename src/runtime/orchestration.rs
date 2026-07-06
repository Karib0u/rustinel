use crate::cli::{Cli, Commands};

#[cfg(windows)]
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    if let Some(Commands::Doctor { json }) = &cli.command {
        let code = crate::doctor::run_cli(cli.config.clone(), *json)?;
        std::process::exit(code);
    }

    if windows_service::service_dispatcher::start(
        crate::platform::windows::SERVICE_NAME,
        crate::runtime::windows::ffi_service_main,
    )
    .is_ok()
    {
        return Ok(());
    }

    match cli.command {
        Some(Commands::Run {
            no_console,
            sigma_engine,
            ..
        }) => crate::runtime::windows::run_console(
            !no_console,
            cli.log_level,
            cli.config,
            sigma_engine.map(|engine| engine.kind()),
        ),
        None => crate::runtime::windows::run_console(true, cli.log_level, cli.config, None),
        Some(Commands::Doctor { .. }) => unreachable!("doctor is handled before service dispatch"),
        Some(Commands::Service { action }) => crate::platform::handle_service_command(action),
        Some(Commands::Rules { action }) => crate::rules::run_cli(action, cli.config),
        Some(Commands::Setup {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }) => crate::setup::run_cli(crate::setup::SetupOptions {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }),
    }
}

#[cfg(target_os = "linux")]
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Some(Commands::Service { action }) => crate::platform::handle_service_command(action),
        Some(Commands::Doctor { json }) => {
            let code = crate::doctor::run_cli(cli.config, json)?;
            std::process::exit(code);
        }
        Some(Commands::Rules { action }) => crate::rules::run_cli(action, cli.config),
        Some(Commands::Setup {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }) => crate::setup::run_cli(crate::setup::SetupOptions {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }),
        Some(Commands::Run {
            no_console,
            sigma_engine,
            ..
        }) => crate::runtime::linux::run(
            !no_console,
            cli.log_level,
            cli.config,
            sigma_engine.map(|engine| engine.kind()),
        ),
        None => crate::runtime::linux::run(true, cli.log_level, cli.config, None),
    }
}

#[cfg(target_os = "macos")]
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Some(Commands::Service { action }) => crate::platform::handle_service_command(action),
        Some(Commands::Doctor { json }) => {
            let code = crate::doctor::run_cli(cli.config, json)?;
            std::process::exit(code);
        }
        Some(Commands::Rules { action }) => crate::rules::run_cli(action, cli.config),
        Some(Commands::Setup {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }) => crate::setup::run_cli(crate::setup::SetupOptions {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }),
        Some(Commands::Run {
            no_console,
            sigma_engine,
            ..
        }) => crate::runtime::macos::run(
            !no_console,
            cli.log_level,
            cli.config,
            sigma_engine.map(|engine| engine.kind()),
        ),
        None => crate::runtime::macos::run(true, cli.log_level, cli.config, None),
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn run() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "This platform is not supported. Rustinel runs on Windows (ETW), Linux (eBPF), and macOS (ESF)."
    ))
}
