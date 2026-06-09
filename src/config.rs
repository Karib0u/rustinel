//! Configuration module
//!
//! Provides structured configuration for the Rustinel agent.
//! Configuration can be loaded from:
//! 1. Default values (hardcoded)
//! 2. `config` file (optional) — searched first in the directory of the
//!    running executable, then in the current working directory (the latter
//!    takes precedence on conflicting keys)
//! 3. Environment variables with EDR__ prefix
//!
//! Example environment variable override:
//! EDR__LOGGING__LEVEL=debug
//! EDR__SCANNER__SIGMA_RULES_PATH=custom/path

use serde::Deserialize;
use std::path::PathBuf;

use crate::models::MatchDebugLevel;

/// Build an optional config-file source rooted at the directory containing the
/// running executable.
///
/// Windows services start with `C:\Windows\System32` as their working
/// directory, so a `config.toml` placed next to `rustinel.exe` (e.g. in
/// `C:\Rustinel`) is otherwise never found. This lets operators keep all
/// Rustinel files in one directory. The current working directory is still
/// searched and takes precedence, preserving the previous behavior.
fn exe_dir_config_source() -> Option<config::File<config::FileSourceFile, config::FileFormat>> {
    let config_base = exe_dir_config_base()?;
    let config_base = config_base.to_str()?;
    Some(config::File::with_name(config_base).required(false))
}

/// Compute the extension-less config file base path next to the running
/// executable (e.g. `C:\Rustinel\config`). The `config` crate appends the
/// supported extensions (`.toml`, `.yaml`, ...) when searching.
fn exe_dir_config_base() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;
    Some(exe_dir.join("config"))
}

/// Default trusted paths for the allowlist, chosen per platform.
/// These prevent YARA, IOC hash scanning, and active response from acting
/// on binaries shipped with the OS.
fn default_allowlist_paths() -> Vec<String> {
    #[cfg(windows)]
    {
        vec![
            "C:\\Windows\\".to_string(),
            "C:\\Program Files\\".to_string(),
            "C:\\Program Files (x86)\\".to_string(),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        // OS-shipped directories only. /Applications is intentionally excluded:
        // it holds user-installed software and is a common location for macOS
        // malware, so allowlisting it would blind scanning and response there.
        vec![
            "/usr/bin/".to_string(),
            "/usr/sbin/".to_string(),
            "/usr/libexec/".to_string(), // system helper executables
            "/bin/".to_string(),
            "/sbin/".to_string(),
            "/System/".to_string(), // OS-shipped frameworks and binaries
        ]
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        vec![
            "/usr/bin/".to_string(),
            "/usr/sbin/".to_string(),
            "/usr/lib/".to_string(),
            "/usr/lib64/".to_string(),   // RHEL/Fedora/CentOS
            "/usr/libexec/".to_string(), // system helper executables
            "/bin/".to_string(),
            "/sbin/".to_string(),
            "/lib/".to_string(),
            "/lib64/".to_string(),
        ]
    }
}

/// Main application configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub scanner: ScannerConfig,
    pub logging: LogConfig,
    pub alerts: AlertConfig,
    pub allowlist: AllowlistConfig,
    pub response: ResponseConfig,
    pub network: NetworkConfig,
    pub ioc: IocConfig,
    pub reload: ReloadConfig,
    pub dedup: DedupConfig,
}

/// Scanner configuration (Sigma and YARA rules)
#[derive(Debug, Clone, Deserialize)]
pub struct ScannerConfig {
    pub sigma_enabled: bool,
    pub sigma_rules_path: PathBuf,
    pub yara_enabled: bool,
    pub yara_rules_path: PathBuf,
    pub yara_allowlist_paths: Vec<String>,
    pub yara_memory_enabled: bool,
    pub yara_memory_queue_capacity: usize,
    pub yara_memory_delay_ms: u64,
    pub yara_memory_max_process_mb: u64,
    pub yara_memory_max_region_mb: u64,
    pub yara_memory_include_private: bool,
    pub yara_memory_include_image: bool,
    pub yara_memory_include_mapped: bool,
}

/// Global allowlist configuration shared across modules
#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistConfig {
    /// Trusted directory prefixes, applied to response/IOC hash/YARA scan
    pub paths: Vec<String>,
}

/// Operational logging configuration (application debug logs)
#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    pub level: String,
    /// Optional tracing filter expression. If set, overrides `level`.
    pub filter: Option<String>,
    pub directory: PathBuf,
    pub filename: String,
    pub console_output: bool,
}

/// Security alerts configuration (JSON output for SIEM)
#[derive(Debug, Clone, Deserialize)]
pub struct AlertConfig {
    pub directory: PathBuf,
    pub filename: String,
    pub match_debug: MatchDebugLevel,
}

/// Active response configuration (optional prevention/termination)
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseConfig {
    pub enabled: bool,
    pub prevention_enabled: bool,
    pub min_severity: String,
    pub channel_capacity: usize,
    pub allowlist_images: Vec<String>,
    pub allowlist_paths: Vec<String>,
}

/// Network event aggregation configuration
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    /// Enable connection aggregation to reduce event volume
    pub aggregation_enabled: bool,
    /// Maximum number of unique connections to track
    pub aggregation_max_entries: usize,
    /// Number of inter-connection intervals to store for beacon detection
    pub aggregation_interval_buffer_size: usize,
}

/// Atomic IOC detection configuration
#[derive(Debug, Clone, Deserialize)]
pub struct IocConfig {
    pub enabled: bool,
    pub hashes_path: PathBuf,
    pub ips_path: PathBuf,
    pub domains_path: PathBuf,
    pub paths_regex_path: PathBuf,
    pub default_severity: String,
    pub max_file_size_mb: u64,
    pub hash_allowlist_paths: Vec<String>,
}

/// Rule hot-reload configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ReloadConfig {
    pub enabled: bool,
    pub debounce_ms: u64,
}

/// Alert deduplication / aggregation configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DedupConfig {
    /// Enable sliding-window alert deduplication
    pub enabled: bool,
    /// Window length in seconds; repeated identical alerts are collapsed within this window
    pub window_secs: u64,
    /// Maximum number of distinct alert keys to track simultaneously
    pub max_entries: usize,
}

impl AppConfig {
    /// Load configuration from defaults, config.toml, and environment variables
    pub fn new() -> Result<Self, config::ConfigError> {
        let builder = config::Config::builder()
            // --- Defaults ---
            // Scanner
            .set_default("scanner.sigma_enabled", true)?
            .set_default("scanner.sigma_rules_path", "rules/sigma")?
            .set_default("scanner.yara_enabled", true)?
            .set_default("scanner.yara_rules_path", "rules/yara")?
            .set_default("scanner.yara_allowlist_paths", Vec::<String>::new())?
            .set_default("scanner.yara_memory_enabled", false)?
            .set_default("scanner.yara_memory_queue_capacity", 64i64)?
            .set_default("scanner.yara_memory_delay_ms", 750i64)?
            .set_default("scanner.yara_memory_max_process_mb", 64i64)?
            .set_default("scanner.yara_memory_max_region_mb", 8i64)?
            .set_default("scanner.yara_memory_include_private", true)?
            .set_default("scanner.yara_memory_include_image", false)?
            .set_default("scanner.yara_memory_include_mapped", false)?
            // Logging
            .set_default("logging.level", "info")?
            .set_default("logging.directory", "logs")?
            .set_default("logging.filename", "rustinel.log")?
            .set_default("logging.console_output", false)?
            // Alerts
            .set_default("alerts.directory", "logs")?
            .set_default("alerts.filename", "alerts.json")?
            .set_default("alerts.match_debug", "off")?
            // Global allowlist — platform-specific trusted paths.
            // These are the default values only; override via config.toml or
            // EDR__ALLOWLIST__PATHS environment variable.
            .set_default("allowlist.paths", default_allowlist_paths())?
            // Active Response
            .set_default("response.enabled", false)?
            .set_default("response.prevention_enabled", false)?
            .set_default("response.min_severity", "critical")?
            .set_default("response.channel_capacity", 128)?
            .set_default("response.allowlist_images", Vec::<String>::new())?
            .set_default("response.allowlist_paths", Vec::<String>::new())?
            // Network
            .set_default("network.aggregation_enabled", true)?
            .set_default("network.aggregation_max_entries", 20000)?
            .set_default("network.aggregation_interval_buffer_size", 50)?
            // IOC
            .set_default("ioc.enabled", true)?
            .set_default("ioc.hashes_path", "rules/ioc/hashes.txt")?
            .set_default("ioc.ips_path", "rules/ioc/ips.txt")?
            .set_default("ioc.domains_path", "rules/ioc/domains.txt")?
            .set_default("ioc.paths_regex_path", "rules/ioc/paths_regex.txt")?
            .set_default("ioc.default_severity", "high")?
            .set_default("ioc.max_file_size_mb", 50)?
            .set_default("ioc.hash_allowlist_paths", Vec::<String>::new())?
            // Hot Reload
            .set_default("reload.enabled", true)?
            .set_default("reload.debounce_ms", 2000)?
            // Alert deduplication
            .set_default("dedup.enabled", true)?
            .set_default("dedup.window_secs", 60i64)?
            .set_default("dedup.max_entries", 10000i64)?;

        // --- Sources ---
        // Config files are searched in two locations, lowest priority first.
        // The executable's directory is the fallback; the current working
        // directory overrides it on conflicting keys, preserving the historical
        // behavior where `config.toml` is read from the launch directory
        // (e.g. `C:\Windows\System32` for a service).
        let builder = match exe_dir_config_source() {
            Some(source) => builder.add_source(source),
            None => builder,
        };
        let s = builder
            .add_source(config::File::with_name("config").required(false))
            .add_source(config::Environment::with_prefix("EDR").separator("__"))
            .build()?;

        let mut cfg: Self = s.try_deserialize()?;
        cfg.apply_allowlist_fallbacks();
        Ok(cfg)
    }

    fn apply_allowlist_fallbacks(&mut self) {
        if self.response.allowlist_paths.is_empty() {
            self.response.allowlist_paths = self.allowlist.paths.clone();
        }

        if self.ioc.hash_allowlist_paths.is_empty() {
            self.ioc.hash_allowlist_paths = self.allowlist.paths.clone();
        }

        if self.scanner.yara_allowlist_paths.is_empty() {
            self.scanner.yara_allowlist_paths = self.allowlist.paths.clone();
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut cfg = Self {
            scanner: ScannerConfig {
                sigma_enabled: true,
                sigma_rules_path: PathBuf::from("rules/sigma"),
                yara_enabled: true,
                yara_rules_path: PathBuf::from("rules/yara"),
                yara_allowlist_paths: Vec::new(),
                yara_memory_enabled: false,
                yara_memory_queue_capacity: 64,
                yara_memory_delay_ms: 750,
                yara_memory_max_process_mb: 64,
                yara_memory_max_region_mb: 8,
                yara_memory_include_private: true,
                yara_memory_include_image: false,
                yara_memory_include_mapped: false,
            },
            logging: LogConfig {
                level: "info".to_string(),
                filter: None,
                directory: PathBuf::from("logs"),
                filename: "rustinel.log".to_string(),
                console_output: false,
            },
            alerts: AlertConfig {
                directory: PathBuf::from("logs"),
                filename: "alerts.json".to_string(),
                match_debug: MatchDebugLevel::Off,
            },
            allowlist: AllowlistConfig {
                paths: default_allowlist_paths(),
            },
            response: ResponseConfig {
                enabled: false,
                prevention_enabled: false,
                min_severity: "critical".to_string(),
                channel_capacity: 128,
                allowlist_images: Vec::new(),
                allowlist_paths: Vec::new(),
            },
            network: NetworkConfig {
                aggregation_enabled: true,
                aggregation_max_entries: 20_000,
                aggregation_interval_buffer_size: 50,
            },
            ioc: IocConfig {
                enabled: true,
                hashes_path: PathBuf::from("rules/ioc/hashes.txt"),
                ips_path: PathBuf::from("rules/ioc/ips.txt"),
                domains_path: PathBuf::from("rules/ioc/domains.txt"),
                paths_regex_path: PathBuf::from("rules/ioc/paths_regex.txt"),
                default_severity: "high".to_string(),
                max_file_size_mb: 50,
                hash_allowlist_paths: Vec::new(),
            },
            reload: ReloadConfig {
                enabled: true,
                debounce_ms: 2000,
            },
            dedup: DedupConfig {
                enabled: true,
                window_secs: 60,
                max_entries: 10_000,
            },
        };

        cfg.apply_allowlist_fallbacks();
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_dir_config_base_is_next_to_executable() {
        let exe = std::env::current_exe().expect("current exe path");
        let base = exe_dir_config_base().expect("exe dir config base");

        // The base lives in the same directory as the executable and is named
        // `config` (extension-less; the config crate appends .toml/.yaml/...).
        assert_eq!(base.parent(), exe.parent());
        assert_eq!(base.file_name().and_then(|n| n.to_str()), Some("config"));
    }

    #[test]
    fn test_config_loads_defaults() {
        let cfg = AppConfig::new().unwrap();
        assert!(cfg.scanner.sigma_enabled);
        assert_eq!(cfg.logging.level, "info");
        assert!(cfg.logging.filter.is_none());
        assert!(!cfg.logging.console_output);
        assert!(!cfg.response.enabled);
        assert!(!cfg.response.prevention_enabled);
        assert_eq!(cfg.response.min_severity, "critical");
        assert!(cfg.ioc.enabled);
        assert_eq!(cfg.ioc.default_severity, "high");
        assert!(cfg.reload.enabled);
        assert_eq!(cfg.reload.debounce_ms, 2000);
        assert_eq!(cfg.alerts.match_debug, MatchDebugLevel::Off);
    }

    #[test]
    fn test_config_paths() {
        let cfg = AppConfig::new().unwrap();
        assert_eq!(cfg.scanner.sigma_rules_path, PathBuf::from("rules/sigma"));
        assert_eq!(cfg.scanner.yara_rules_path, PathBuf::from("rules/yara"));
        assert_eq!(cfg.ioc.hashes_path, PathBuf::from("rules/ioc/hashes.txt"));
        assert_eq!(cfg.ioc.ips_path, PathBuf::from("rules/ioc/ips.txt"));
        assert_eq!(
            cfg.ioc.paths_regex_path,
            PathBuf::from("rules/ioc/paths_regex.txt")
        );
    }

    #[test]
    fn test_global_allowlist_propagates_to_modules() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.response.allowlist_paths, cfg.allowlist.paths);
        assert_eq!(cfg.ioc.hash_allowlist_paths, cfg.allowlist.paths);
        assert_eq!(cfg.scanner.yara_allowlist_paths, cfg.allowlist.paths);
    }

    #[test]
    fn test_dedup_defaults() {
        let cfg = AppConfig::default();
        assert!(cfg.dedup.enabled);
        assert_eq!(cfg.dedup.window_secs, 60);
        assert_eq!(cfg.dedup.max_entries, 10_000);
    }

    #[test]
    fn test_yara_memory_defaults_disabled() {
        let cfg = AppConfig::default();
        assert!(!cfg.scanner.yara_memory_enabled);
        assert_eq!(cfg.scanner.yara_memory_queue_capacity, 64);
        assert_eq!(cfg.scanner.yara_memory_max_process_mb, 64);
        assert_eq!(cfg.scanner.yara_memory_max_region_mb, 8);
        assert_eq!(cfg.scanner.yara_memory_delay_ms, 750);
        assert!(cfg.scanner.yara_memory_include_private);
        assert!(!cfg.scanner.yara_memory_include_image);
        assert!(!cfg.scanner.yara_memory_include_mapped);
    }

    #[test]
    fn test_module_specific_allowlist_not_overwritten() {
        let mut cfg = AppConfig::default();
        // Reset to simulate module-specific override scenario
        cfg.allowlist.paths = vec!["C:\\Shared\\".to_string()];
        cfg.response.allowlist_paths = vec!["C:\\ResponseOnly\\".to_string()];
        cfg.ioc.hash_allowlist_paths = Vec::new();
        cfg.scanner.yara_allowlist_paths = Vec::new();
        cfg.apply_allowlist_fallbacks();

        assert_eq!(
            cfg.response.allowlist_paths,
            vec!["C:\\ResponseOnly\\".to_string()]
        );
        assert_eq!(
            cfg.ioc.hash_allowlist_paths,
            vec!["C:\\Shared\\".to_string()]
        );
        assert_eq!(
            cfg.scanner.yara_allowlist_paths,
            vec!["C:\\Shared\\".to_string()]
        );
    }
}
