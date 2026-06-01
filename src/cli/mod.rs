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

#[derive(clap::Subcommand)]
pub enum Commands {
    /// Run in console mode (foreground)
    Run {
        /// Force console output
        #[arg(long)]
        console: bool,
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
