#[derive(clap::Parser)]
#[command(name = "rustinel")]
#[command(version)]
#[command(about = "High-Performance Rust EDR", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
    /// Override logging level (e.g., error, warn, info, debug, trace)
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,
}

impl Cli {
    pub fn parse_args() -> Self {
        <Self as clap::Parser>::parse()
    }
}

/// Sigma detection backend selectable at runtime.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigmaEngineArg {
    /// Rustinel's built-in matcher.
    Builtin,
    /// The RSigma library engine (only available in builds with the
    /// `rsigma-engine` feature).
    #[cfg(feature = "rsigma-engine")]
    Rsigma,
}

impl SigmaEngineArg {
    pub fn kind(self) -> crate::engine::SigmaEngineKind {
        match self {
            SigmaEngineArg::Builtin => crate::engine::SigmaEngineKind::Builtin,
            #[cfg(feature = "rsigma-engine")]
            SigmaEngineArg::Rsigma => crate::engine::SigmaEngineKind::Rsigma,
        }
    }
}

#[derive(clap::Subcommand)]
pub enum Commands {
    /// Run in the foreground with console output
    Run {
        /// Compatibility alias; console output is enabled by default
        #[arg(long, conflicts_with = "no_console")]
        console: bool,
        /// Disable console output
        #[arg(long)]
        no_console: bool,
        /// Sigma detection backend to use (built-in matcher or RSigma engine).
        /// Overrides `scanner.sigma_engine` from the config file.
        #[arg(long, value_enum, value_name = "ENGINE")]
        sigma_engine: Option<SigmaEngineArg>,
    },
    /// Service management commands
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(clap::Subcommand, Copy, Clone)]
pub enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn run_defaults_to_console_output() {
        let cli = Cli::try_parse_from(["rustinel", "run"]).expect("valid CLI");

        match cli.command {
            Some(Commands::Run {
                console,
                no_console,
                ..
            }) => {
                assert!(!console);
                assert!(!no_console);
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn run_accepts_compat_console_alias() {
        let cli = Cli::try_parse_from(["rustinel", "run", "--console"]).expect("valid CLI");

        match cli.command {
            Some(Commands::Run {
                console,
                no_console,
                ..
            }) => {
                assert!(console);
                assert!(!no_console);
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn run_accepts_no_console() {
        let cli = Cli::try_parse_from(["rustinel", "run", "--no-console"]).expect("valid CLI");

        match cli.command {
            Some(Commands::Run {
                console,
                no_console,
                ..
            }) => {
                assert!(!console);
                assert!(no_console);
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn run_rejects_console_and_no_console_together() {
        let err = match Cli::try_parse_from(["rustinel", "run", "--console", "--no-console"]) {
            Ok(_) => panic!("conflicting flags should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
