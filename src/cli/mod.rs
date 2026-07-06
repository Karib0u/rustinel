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
    /// Install Rustinel into the managed platform layout
    Setup {
        /// Rules pack level to install
        #[arg(long, value_enum, value_name = "PACK")]
        pack: Option<SetupPack>,
        /// Accept defaults and do not prompt
        #[arg(long)]
        yes: bool,
        /// Register the service but do not start it
        #[arg(long)]
        no_start: bool,
        /// Replace existing managed configuration
        #[arg(long)]
        force: bool,
        /// Rules catalog index URL
        #[arg(long, default_value = crate::rules::DEFAULT_CATALOG_URL)]
        catalog_url: String,
    },
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
    /// Rules catalog and active pack management
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupPack {
    Essential,
    Advanced,
}

impl SetupPack {
    pub fn level(self) -> &'static str {
        match self {
            Self::Essential => "essential",
            Self::Advanced => "advanced",
        }
    }
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

#[derive(clap::Subcommand, Clone)]
pub enum RulesAction {
    /// List rules packs available for this platform
    List {
        /// Rules catalog index URL
        #[arg(long, default_value = crate::rules::DEFAULT_CATALOG_URL)]
        catalog_url: String,
        /// Rules root directory, containing current, staging, and state.json
        #[arg(long, value_name = "PATH")]
        rules_dir: Option<std::path::PathBuf>,
    },
    /// Install a rules pack and make it active
    Install {
        /// Pack ID from `rustinel rules list`
        pack: String,
        /// Rules catalog index URL
        #[arg(long, default_value = crate::rules::DEFAULT_CATALOG_URL)]
        catalog_url: String,
        /// Rules root directory, containing current, staging, and state.json
        #[arg(long, value_name = "PATH")]
        rules_dir: Option<std::path::PathBuf>,
    },
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
    fn setup_accepts_managed_install_flags() {
        let cli = Cli::try_parse_from([
            "rustinel",
            "setup",
            "--pack",
            "advanced",
            "--yes",
            "--no-start",
            "--force",
        ])
        .expect("setup should parse");

        match cli.command {
            Some(Commands::Setup {
                pack,
                yes,
                no_start,
                force,
                catalog_url,
            }) => {
                assert_eq!(pack, Some(SetupPack::Advanced));
                assert!(yes);
                assert!(no_start);
                assert!(force);
                assert!(catalog_url.ends_with("/index.json"));
            }
            _ => panic!("expected setup command"),
        }
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

    #[test]
    fn rules_list_accepts_catalog_url() {
        let cli = Cli::try_parse_from([
            "rustinel",
            "rules",
            "list",
            "--catalog-url",
            "https://github.com/Karib0u/rustinel-rules/releases/download/v0.2.0/index.json",
        ])
        .expect("rules list should parse");

        match cli.command {
            Some(Commands::Rules {
                action: RulesAction::List { catalog_url, .. },
            }) => {
                assert!(catalog_url.ends_with("/index.json"));
            }
            _ => panic!("expected rules list command"),
        }
    }

    #[test]
    fn rules_install_requires_pack() {
        let cli = Cli::try_parse_from(["rustinel", "rules", "install", "linux-essential"])
            .expect("rules install should parse");

        match cli.command {
            Some(Commands::Rules {
                action: RulesAction::Install { pack, .. },
            }) => {
                assert_eq!(pack, "linux-essential");
            }
            _ => panic!("expected rules install command"),
        }
    }
}
