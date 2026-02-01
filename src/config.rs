//! Configuration module
//!
//! Provides structured configuration for the Rustinel agent.
//! Configuration can be loaded from:
//! 1. Default values (hardcoded)
//! 2. config.toml file (optional)
//! 3. Environment variables with EDR__ prefix
//!
//! Example environment variable override:
//! EDR__LOGGING__LEVEL=debug
//! EDR__SCANNER__SIGMA_RULES_PATH=custom/path

use serde::Deserialize;
use std::path::PathBuf;

/// Main application configuration
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub scanner: ScannerConfig,
    pub logging: LogConfig,
    pub alerts: AlertConfig,
    pub network: NetworkConfig,
}

/// Scanner configuration (Sigma and YARA rules)
#[derive(Debug, Deserialize)]
pub struct ScannerConfig {
    pub sigma_enabled: bool,
    pub sigma_rules_path: PathBuf,
    pub yara_enabled: bool,
    pub yara_rules_path: PathBuf,
}

/// Operational logging configuration (application debug logs)
#[derive(Debug, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub directory: PathBuf,
    pub filename: String,
    pub console_output: bool,
}

/// Security alerts configuration (JSON output for SIEM)
#[derive(Debug, Deserialize)]
pub struct AlertConfig {
    pub directory: PathBuf,
    pub filename: String,
}

/// Network event aggregation configuration
#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    /// Enable connection aggregation to reduce event volume
    pub aggregation_enabled: bool,
    /// Maximum number of unique connections to track
    pub aggregation_max_entries: usize,
    /// Number of inter-connection intervals to store for beacon detection
    pub aggregation_interval_buffer_size: usize,
}

impl AppConfig {
    /// Load configuration from defaults, config.toml, and environment variables
    pub fn new() -> Result<Self, config::ConfigError> {
        let s = config::Config::builder()
            // --- Defaults ---
            // Scanner
            .set_default("scanner.sigma_enabled", true)?
            .set_default("scanner.sigma_rules_path", "rules/sigma")?
            .set_default("scanner.yara_enabled", true)?
            .set_default("scanner.yara_rules_path", "rules/yara")?
            // Logging
            .set_default("logging.level", "info")?
            .set_default("logging.directory", "logs")?
            .set_default("logging.filename", "rustinel.log")?
            .set_default("logging.console_output", true)?
            // Alerts
            .set_default("alerts.directory", "logs")?
            .set_default("alerts.filename", "alerts.json")?
            // Network
            .set_default("network.aggregation_enabled", true)?
            .set_default("network.aggregation_max_entries", 20000)?
            .set_default("network.aggregation_interval_buffer_size", 50)?
            // --- Sources ---
            .add_source(config::File::with_name("config").required(false))
            .add_source(config::Environment::with_prefix("EDR").separator("__"))
            .build()?;

        s.try_deserialize()
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            scanner: ScannerConfig {
                sigma_enabled: true,
                sigma_rules_path: PathBuf::from("rules/sigma"),
                yara_enabled: true,
                yara_rules_path: PathBuf::from("rules/yara"),
            },
            logging: LogConfig {
                level: "info".to_string(),
                directory: PathBuf::from("logs"),
                filename: "rustinel.log".to_string(),
                console_output: true,
            },
            alerts: AlertConfig {
                directory: PathBuf::from("logs"),
                filename: "alerts.json".to_string(),
            },
            network: NetworkConfig {
                aggregation_enabled: true,
                aggregation_max_entries: 20_000,
                aggregation_interval_buffer_size: 50,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_loads_defaults() {
        let cfg = AppConfig::new().unwrap();
        assert!(cfg.scanner.sigma_enabled);
        assert_eq!(cfg.logging.level, "info");
        assert!(cfg.logging.console_output);
    }

    #[test]
    fn test_config_paths() {
        let cfg = AppConfig::new().unwrap();
        assert_eq!(cfg.scanner.sigma_rules_path, PathBuf::from("rules/sigma"));
        assert_eq!(cfg.scanner.yara_rules_path, PathBuf::from("rules/yara"));
    }
}
