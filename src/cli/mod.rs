#[derive(clap::Parser)]
#[command(name = "rustinel")]
#[command(version)]
#[command(about = "High-Performance Rust EDR", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
    /// Configuration file path
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,
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
///
/// Both variants parse in every build so the value is accepted uniformly;
/// selecting `rsigma` on a binary built without the `rsigma-engine` feature
/// fails at startup through the same resolver as the config and env value,
/// with a clear "built without rsigma-engine" message.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigmaEngineArg {
    /// Rustinel's built-in matcher.
    Builtin,
    /// The RSigma library engine (requires the `rsigma-engine` build feature).
    Rsigma,
}

impl SigmaEngineArg {
    pub fn kind(self) -> crate::engine::SigmaEngineKind {
        match self {
            SigmaEngineArg::Builtin => crate::engine::SigmaEngineKind::Builtin,
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
    /// Check configuration, paths, and runtime prerequisites
    Doctor {
        /// Emit structured JSON output
        #[arg(long)]
        json: bool,
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
    Restart,
    Status,
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

    #[test]
    fn run_accepts_sigma_engine_flag_in_every_build() {
        // `rsigma` must parse regardless of build features; availability is
        // enforced later by the startup resolver, not by the argument parser.
        let cli = Cli::try_parse_from(["rustinel", "run", "--sigma-engine", "rsigma"])
            .expect("rsigma value should parse in every build");
        match cli.command {
            Some(Commands::Run { sigma_engine, .. }) => {
                assert_eq!(sigma_engine, Some(SigmaEngineArg::Rsigma));
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn global_config_flag_is_accepted_before_subcommand() {
        let cli = Cli::try_parse_from(["rustinel", "--config", "/tmp/rustinel.toml", "run"])
            .expect("config path should parse");
        assert_eq!(
            cli.config,
            Some(std::path::PathBuf::from("/tmp/rustinel.toml"))
        );
    }

    #[test]
    fn global_config_flag_is_accepted_after_subcommand() {
        let cli = Cli::try_parse_from(["rustinel", "run", "--config", "/tmp/rustinel.toml"])
            .expect("config path should parse");
        assert_eq!(
            cli.config,
            Some(std::path::PathBuf::from("/tmp/rustinel.toml"))
        );
    }

    #[test]
    fn doctor_accepts_json_flag() {
        let cli = Cli::try_parse_from(["rustinel", "doctor", "--json"]).expect("valid CLI");

        match cli.command {
            Some(Commands::Doctor { json }) => assert!(json),
            _ => panic!("expected doctor command"),
        }
    }

    #[test]
    fn service_accepts_restart() {
        let cli =
            Cli::try_parse_from(["rustinel", "service", "restart"]).expect("restart should parse");

        match cli.command {
            Some(Commands::Service { action }) => {
                assert!(matches!(action, ServiceAction::Restart));
            }
            _ => panic!("expected service command"),
        }
    }

    #[test]
    fn service_accepts_status() {
        let cli =
            Cli::try_parse_from(["rustinel", "service", "status"]).expect("status should parse");

        match cli.command {
            Some(Commands::Service { action }) => {
                assert!(matches!(action, ServiceAction::Status));
            }
            _ => panic!("expected service command"),
        }
    }
}
