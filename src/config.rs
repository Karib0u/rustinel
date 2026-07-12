//! Configuration module
//!
//! Provides structured configuration for the Rustinel agent.
//! Configuration can be loaded from:
//! 1. Default values (hardcoded)
//! 2. First available config file from explicit path, RUSTINEL_CONFIG,
//!    managed platform path, executable directory, then current directory
//! 3. Environment variables with EDR__ prefix
//!
//! Example environment variable override:
//! EDR__LOGGING__LEVEL=debug
//! EDR__SCANNER__SIGMA_RULES_PATH=custom/path

use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::models::MatchDebugLevel;

const CONFIG_FILE_NAME: &str = "config.toml";
const CONFIG_PATH_ENV: &str = "RUSTINEL_CONFIG";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPlatform {
    Windows,
    Linux,
    Macos,
}

impl InstallPlatform {
    pub fn current() -> Self {
        #[cfg(windows)]
        {
            Self::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            Self::Linux
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallLayout {
    pub platform: InstallPlatform,
    pub config_file: PathBuf,
    pub rules_dir: PathBuf,
    pub sigma_rules_dir: PathBuf,
    pub yara_rules_dir: PathBuf,
    pub ioc_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub alerts_dir: PathBuf,
}

impl InstallLayout {
    pub fn managed(platform: InstallPlatform) -> Self {
        match platform {
            InstallPlatform::Windows => Self {
                platform,
                config_file: PathBuf::from(r"C:\ProgramData\Rustinel\config.toml"),
                rules_dir: PathBuf::from(r"C:\ProgramData\Rustinel\rules"),
                sigma_rules_dir: PathBuf::from(r"C:\ProgramData\Rustinel\rules\current\sigma"),
                yara_rules_dir: PathBuf::from(r"C:\ProgramData\Rustinel\rules\current\yara"),
                ioc_dir: PathBuf::from(r"C:\ProgramData\Rustinel\rules\current\ioc"),
                logs_dir: PathBuf::from(r"C:\ProgramData\Rustinel\logs"),
                alerts_dir: PathBuf::from(r"C:\ProgramData\Rustinel\logs"),
            },
            InstallPlatform::Linux => Self::from_roots(
                platform,
                PathBuf::from("/etc/rustinel/config.toml"),
                PathBuf::from("/var/lib/rustinel/rules"),
                PathBuf::from("/var/log/rustinel"),
            ),
            InstallPlatform::Macos => Self::from_roots(
                platform,
                PathBuf::from("/Library/Application Support/Rustinel/config.toml"),
                PathBuf::from("/Library/Application Support/Rustinel/rules"),
                PathBuf::from("/Library/Logs/Rustinel"),
            ),
        }
    }

    pub fn portable(exe_dir: impl Into<PathBuf>) -> Self {
        let root = exe_dir.into();
        let platform = InstallPlatform::current();
        let rules_dir = root.join("rules");
        let logs_dir = root.join("logs");
        Self {
            platform,
            config_file: root.join(CONFIG_FILE_NAME),
            rules_dir: rules_dir.clone(),
            sigma_rules_dir: rules_dir.join("sigma"),
            yara_rules_dir: rules_dir.join("yara"),
            ioc_dir: rules_dir.join("ioc"),
            alerts_dir: logs_dir.clone(),
            logs_dir,
        }
    }

    pub fn managed_current() -> Self {
        Self::managed(InstallPlatform::current())
    }

    pub fn managed_config(&self) -> AppConfig {
        let mut cfg = AppConfig::default();
        cfg.scanner.sigma_rules_path = self.sigma_rules_dir.clone();
        cfg.scanner.yara_rules_path = self.yara_rules_dir.clone();
        cfg.logging.directory = self.logs_dir.clone();
        cfg.alerts.directory = self.alerts_dir.clone();
        cfg.ioc.hashes_path = layout_join(self.platform, &self.ioc_dir, "hashes.txt");
        cfg.ioc.ips_path = layout_join(self.platform, &self.ioc_dir, "ips.txt");
        cfg.ioc.domains_path = layout_join(self.platform, &self.ioc_dir, "domains.txt");
        cfg.ioc.paths_regex_path = layout_join(self.platform, &self.ioc_dir, "paths_regex.txt");
        cfg
    }

    fn from_roots(
        platform: InstallPlatform,
        config_file: PathBuf,
        rules_dir: PathBuf,
        logs_dir: PathBuf,
    ) -> Self {
        let current_dir = layout_join(platform, &rules_dir, "current");
        let ioc_dir = layout_join(platform, &current_dir, "ioc");
        Self {
            platform,
            config_file,
            rules_dir: rules_dir.clone(),
            sigma_rules_dir: layout_join(platform, &current_dir, "sigma"),
            yara_rules_dir: layout_join(platform, &current_dir, "yara"),
            ioc_dir,
            alerts_dir: logs_dir.clone(),
            logs_dir,
        }
    }
}

pub(crate) fn layout_join(platform: InstallPlatform, base: &Path, child: &str) -> PathBuf {
    let separator = match platform {
        InstallPlatform::Windows => r"\",
        InstallPlatform::Linux | InstallPlatform::Macos => "/",
    };
    let base = base.to_string_lossy();
    let base = base.trim_end_matches(['/', '\\']);
    PathBuf::from(format!("{base}{separator}{child}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLoadOptions {
    pub explicit_config: Option<PathBuf>,
    pub env_config: Option<PathBuf>,
    pub managed_config: PathBuf,
    pub exe_config: Option<PathBuf>,
    pub cwd_config: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    Explicit,
    Environment,
    Managed,
    Executable,
    CurrentDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedConfig {
    pub source: ConfigSource,
    pub path: PathBuf,
}

impl ConfigLoadOptions {
    pub fn from_runtime(explicit_config: Option<PathBuf>) -> Self {
        Self {
            explicit_config,
            env_config: std::env::var_os(CONFIG_PATH_ENV).map(PathBuf::from),
            managed_config: InstallLayout::managed_current().config_file,
            exe_config: exe_dir_config_base().map(|base| base.with_extension("toml")),
            cwd_config: PathBuf::from(CONFIG_FILE_NAME),
        }
    }

    pub fn selected_config(&self) -> Option<SelectedConfig> {
        if let Some(path) = &self.explicit_config {
            return Some(SelectedConfig {
                source: ConfigSource::Explicit,
                path: path.clone(),
            });
        }

        if let Some(path) = &self.env_config {
            return Some(SelectedConfig {
                source: ConfigSource::Environment,
                path: path.clone(),
            });
        }

        if self.managed_config.exists() {
            return Some(SelectedConfig {
                source: ConfigSource::Managed,
                path: self.managed_config.clone(),
            });
        }

        if let Some(path) = &self.exe_config {
            if path.exists() {
                return Some(SelectedConfig {
                    source: ConfigSource::Executable,
                    path: path.clone(),
                });
            }
        }

        if self.cwd_config.exists() {
            return Some(SelectedConfig {
                source: ConfigSource::CurrentDirectory,
                path: self.cwd_config.clone(),
            });
        }

        None
    }
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
    /// Sigma matching backend: "builtin" (default) or "rsigma". Selecting
    /// "rsigma" requires a binary built with the `rsigma-engine` feature.
    pub sigma_engine: String,
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
    /// Enable connection aggregation metrics without suppressing network events
    pub aggregation_enabled: bool,
    /// Maximum number of unique connections to track
    pub aggregation_max_entries: usize,
    /// Window in seconds before a connection starts a new aggregate period
    pub aggregation_window_secs: u64,
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
    pub fallback_poll_interval_ms: u64,
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
        Self::from_options(ConfigLoadOptions::from_runtime(None))
    }

    pub fn from_config_path(config_path: Option<PathBuf>) -> Result<Self, config::ConfigError> {
        Self::from_options(ConfigLoadOptions::from_runtime(config_path))
    }

    pub fn from_options(options: ConfigLoadOptions) -> Result<Self, config::ConfigError> {
        let selected_config = options
            .selected_config()
            .map(|selected| absolute_config_path(selected.path));
        let config_dir = selected_config
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf);

        let builder = config::Config::builder()
            // --- Defaults ---
            // Scanner
            .set_default("scanner.sigma_enabled", true)?
            .set_default("scanner.sigma_rules_path", "rules/current/sigma")?
            .set_default("scanner.sigma_engine", "builtin")?
            .set_default("scanner.yara_enabled", true)?
            .set_default("scanner.yara_rules_path", "rules/current/yara")?
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
            // Global allowlist, platform-specific trusted paths.
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
            .set_default("network.aggregation_window_secs", 60)?
            .set_default("network.aggregation_interval_buffer_size", 50)?
            // IOC
            .set_default("ioc.enabled", true)?
            .set_default("ioc.hashes_path", "rules/current/ioc/hashes.txt")?
            .set_default("ioc.ips_path", "rules/current/ioc/ips.txt")?
            .set_default("ioc.domains_path", "rules/current/ioc/domains.txt")?
            .set_default("ioc.paths_regex_path", "rules/current/ioc/paths_regex.txt")?
            .set_default("ioc.default_severity", "high")?
            .set_default("ioc.max_file_size_mb", 50)?
            .set_default("ioc.hash_allowlist_paths", Vec::<String>::new())?
            // Hot Reload
            .set_default("reload.enabled", true)?
            .set_default("reload.debounce_ms", 2000)?
            .set_default("reload.fallback_poll_interval_ms", 60000i64)?
            // Alert deduplication
            .set_default("dedup.enabled", true)?
            .set_default("dedup.window_secs", 60i64)?
            .set_default("dedup.max_entries", 10000i64)?;

        let builder = match selected_config {
            Some(path) => builder.add_source(config::File::from(path).required(true)),
            None => builder,
        };
        let s = builder
            .add_source(config::Environment::with_prefix("EDR").separator("__"))
            .build()?;

        let mut cfg: Self = s.try_deserialize()?;
        if let Some(config_dir) = config_dir {
            cfg.resolve_relative_paths(&config_dir);
        }
        cfg.apply_allowlist_fallbacks();
        Ok(cfg)
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        resolve_path_from_config(
            &mut self.scanner.sigma_rules_path,
            base_dir,
            "SCANNER__SIGMA_RULES_PATH",
        );
        resolve_path_from_config(
            &mut self.scanner.yara_rules_path,
            base_dir,
            "SCANNER__YARA_RULES_PATH",
        );
        resolve_path_from_config(&mut self.logging.directory, base_dir, "LOGGING__DIRECTORY");
        resolve_path_from_config(&mut self.alerts.directory, base_dir, "ALERTS__DIRECTORY");
        resolve_path_from_config(&mut self.ioc.hashes_path, base_dir, "IOC__HASHES_PATH");
        resolve_path_from_config(&mut self.ioc.ips_path, base_dir, "IOC__IPS_PATH");
        resolve_path_from_config(&mut self.ioc.domains_path, base_dir, "IOC__DOMAINS_PATH");
        resolve_path_from_config(
            &mut self.ioc.paths_regex_path,
            base_dir,
            "IOC__PATHS_REGEX_PATH",
        );
        resolve_path_list_from_config(&mut self.allowlist.paths, base_dir, "ALLOWLIST__PATHS");
        resolve_path_list_from_config(
            &mut self.response.allowlist_paths,
            base_dir,
            "RESPONSE__ALLOWLIST_PATHS",
        );
        resolve_path_list_from_config(
            &mut self.scanner.yara_allowlist_paths,
            base_dir,
            "SCANNER__YARA_ALLOWLIST_PATHS",
        );
        resolve_path_list_from_config(
            &mut self.ioc.hash_allowlist_paths,
            base_dir,
            "IOC__HASH_ALLOWLIST_PATHS",
        );
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

fn resolve_path(path: &mut PathBuf, base_dir: &Path) {
    if path.is_relative() {
        *path = base_dir.join(&path);
    }
}

fn resolve_path_from_config(path: &mut PathBuf, base_dir: &Path, env_key: &str) {
    if std::env::var_os(format!("EDR__{env_key}")).is_none() {
        resolve_path(path, base_dir);
    }
}

fn absolute_config_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }

    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path,
    }
}

fn resolve_path_list(paths: &mut [String], base_dir: &Path) {
    for path in paths {
        let value = PathBuf::from(path.as_str());
        if value.is_relative() {
            *path = base_dir.join(value).to_string_lossy().into_owned();
        }
    }
}

fn resolve_path_list_from_config(paths: &mut [String], base_dir: &Path, env_key: &str) {
    if std::env::var_os(format!("EDR__{env_key}")).is_none() {
        resolve_path_list(paths, base_dir);
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut cfg = Self {
            scanner: ScannerConfig {
                sigma_enabled: true,
                sigma_rules_path: PathBuf::from("rules/current/sigma"),
                sigma_engine: "builtin".to_string(),
                yara_enabled: true,
                yara_rules_path: PathBuf::from("rules/current/yara"),
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
                aggregation_window_secs: 60,
                aggregation_interval_buffer_size: 50,
            },
            ioc: IocConfig {
                enabled: true,
                hashes_path: PathBuf::from("rules/current/ioc/hashes.txt"),
                ips_path: PathBuf::from("rules/current/ioc/ips.txt"),
                domains_path: PathBuf::from("rules/current/ioc/domains.txt"),
                paths_regex_path: PathBuf::from("rules/current/ioc/paths_regex.txt"),
                default_severity: "high".to_string(),
                max_file_size_mb: 50,
                hash_allowlist_paths: Vec::new(),
            },
            reload: ReloadConfig {
                enabled: true,
                debounce_ms: 2000,
                fallback_poll_interval_ms: 60000,
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
        assert_eq!(cfg.network.aggregation_window_secs, 60);
    }

    #[test]
    fn test_config_paths() {
        let cfg = AppConfig::new().unwrap();
        let cwd = std::env::current_dir().expect("current dir");
        assert_eq!(cfg.scanner.sigma_rules_path, cwd.join("rules/sigma"));
        assert_eq!(cfg.scanner.yara_rules_path, cwd.join("rules/yara"));
        assert_eq!(cfg.ioc.hashes_path, cwd.join("rules/ioc/hashes.txt"));
        assert_eq!(cfg.ioc.ips_path, cwd.join("rules/ioc/ips.txt"));
        assert_eq!(
            cfg.ioc.paths_regex_path,
            cwd.join("rules/ioc/paths_regex.txt")
        );
    }

    #[test]
    fn default_config_paths_remain_portable() {
        let cfg = AppConfig::default();
        assert_eq!(
            cfg.scanner.sigma_rules_path,
            PathBuf::from("rules/current/sigma")
        );
        assert_eq!(
            cfg.scanner.yara_rules_path,
            PathBuf::from("rules/current/yara")
        );
        assert_eq!(cfg.logging.directory, PathBuf::from("logs"));
    }

    #[test]
    fn explicit_config_has_highest_precedence_and_roots_relative_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let explicit_dir = temp.path().join("explicit");
        let env_dir = temp.path().join("env");
        std::fs::create_dir_all(&explicit_dir).expect("explicit dir");
        std::fs::create_dir_all(&env_dir).expect("env dir");
        let explicit = explicit_dir.join("custom.toml");
        let env_config = env_dir.join("config.toml");

        std::fs::write(
            &explicit,
            r#"
[scanner]
sigma_rules_path = "explicit-sigma"
yara_rules_path = "explicit-yara"

[logging]
level = "trace"
directory = "explicit-logs"

[alerts]
directory = "explicit-alerts"

[ioc]
hashes_path = "explicit-ioc/hashes.txt"
ips_path = "explicit-ioc/ips.txt"
domains_path = "explicit-ioc/domains.txt"
paths_regex_path = "explicit-ioc/paths_regex.txt"
"#,
        )
        .expect("write explicit config");
        std::fs::write(&env_config, "[logging]\nlevel = \"debug\"\n").expect("write env config");

        let cfg = AppConfig::from_options(ConfigLoadOptions {
            explicit_config: Some(explicit.clone()),
            env_config: Some(env_config),
            managed_config: temp.path().join("managed.toml"),
            exe_config: Some(temp.path().join("exe.toml")),
            cwd_config: temp.path().join("cwd.toml"),
        })
        .expect("load config");

        assert_eq!(cfg.logging.level, "trace");
        assert_eq!(
            cfg.scanner.sigma_rules_path,
            explicit_dir.join("explicit-sigma")
        );
        assert_eq!(cfg.logging.directory, explicit_dir.join("explicit-logs"));
        assert_eq!(cfg.alerts.directory, explicit_dir.join("explicit-alerts"));
        assert_eq!(
            cfg.ioc.hashes_path,
            explicit_dir.join("explicit-ioc/hashes.txt")
        );
    }

    #[test]
    fn config_discovery_prefers_managed_then_exe_then_cwd() {
        let temp = tempfile::tempdir().expect("tempdir");
        let managed = temp.path().join("managed.toml");
        let exe = temp.path().join("exe.toml");
        let cwd = temp.path().join("cwd.toml");

        std::fs::write(&managed, "[logging]\nlevel = \"warn\"\n").expect("write managed config");
        std::fs::write(&exe, "[logging]\nlevel = \"debug\"\n").expect("write exe config");
        std::fs::write(&cwd, "[logging]\nlevel = \"trace\"\n").expect("write cwd config");

        let cfg = AppConfig::from_options(ConfigLoadOptions {
            explicit_config: None,
            env_config: None,
            managed_config: managed.clone(),
            exe_config: Some(exe.clone()),
            cwd_config: cwd.clone(),
        })
        .expect("load managed config");
        assert_eq!(cfg.logging.level, "warn");

        std::fs::remove_file(&managed).expect("remove managed config");
        let cfg = AppConfig::from_options(ConfigLoadOptions {
            explicit_config: None,
            env_config: None,
            managed_config: managed,
            exe_config: Some(exe.clone()),
            cwd_config: cwd.clone(),
        })
        .expect("load exe config");
        assert_eq!(cfg.logging.level, "debug");

        std::fs::remove_file(&exe).expect("remove exe config");
        let cfg = AppConfig::from_options(ConfigLoadOptions {
            explicit_config: None,
            env_config: None,
            managed_config: temp.path().join("missing-managed.toml"),
            exe_config: Some(exe),
            cwd_config: cwd,
        })
        .expect("load cwd config");
        assert_eq!(cfg.logging.level, "trace");
    }

    #[test]
    fn env_config_has_precedence_after_explicit_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let env_config = temp.path().join("env.toml");
        let managed = temp.path().join("managed.toml");
        std::fs::write(&env_config, "[logging]\nlevel = \"debug\"\n").expect("write env config");
        std::fs::write(&managed, "[logging]\nlevel = \"warn\"\n").expect("write managed config");

        let cfg = AppConfig::from_options(ConfigLoadOptions {
            explicit_config: None,
            env_config: Some(env_config),
            managed_config: managed,
            exe_config: None,
            cwd_config: temp.path().join("cwd.toml"),
        })
        .expect("load env config");

        assert_eq!(cfg.logging.level, "debug");
    }

    #[test]
    fn managed_layouts_cover_all_platforms() {
        let windows = InstallLayout::managed(InstallPlatform::Windows);
        assert_eq!(
            windows.config_file.to_string_lossy(),
            r"C:\ProgramData\Rustinel\config.toml"
        );
        assert_eq!(
            windows.sigma_rules_dir.to_string_lossy(),
            r"C:\ProgramData\Rustinel\rules\current\sigma"
        );

        let linux = InstallLayout::managed(InstallPlatform::Linux);
        assert_eq!(
            linux.config_file,
            PathBuf::from("/etc/rustinel/config.toml")
        );
        assert_eq!(
            linux.sigma_rules_dir,
            PathBuf::from("/var/lib/rustinel/rules/current/sigma")
        );
        assert_eq!(
            linux.managed_config().logging.directory.to_string_lossy(),
            "/var/log/rustinel"
        );

        let macos = InstallLayout::managed(InstallPlatform::Macos);
        assert_eq!(
            macos.config_file,
            PathBuf::from("/Library/Application Support/Rustinel/config.toml")
        );
        assert_eq!(macos.logs_dir, PathBuf::from("/Library/Logs/Rustinel"));
        assert_eq!(
            macos
                .managed_config()
                .scanner
                .yara_rules_path
                .to_string_lossy(),
            "/Library/Application Support/Rustinel/rules/current/yara"
        );
    }

    #[test]
    fn portable_layout_stays_under_executable_directory() {
        let root = PathBuf::from("portable-root");
        let layout = InstallLayout::portable(&root);

        assert_eq!(layout.config_file, root.join("config.toml"));
        assert_eq!(layout.sigma_rules_dir, root.join("rules").join("sigma"));
        assert_eq!(layout.yara_rules_dir, root.join("rules").join("yara"));
        assert_eq!(layout.ioc_dir, root.join("rules").join("ioc"));
        assert_eq!(layout.logs_dir, root.join("logs"));
    }

    #[test]
    fn sigma_engine_defaults_to_builtin() {
        assert_eq!(AppConfig::default().scanner.sigma_engine, "builtin");
    }

    #[test]
    fn env_overrides_sigma_engine() {
        // Mutates process env, scoped to this test and restored below. No other
        // test asserts scanner.sigma_engine through AppConfig::new(), so setting
        // it here cannot make a parallel test flaky.
        std::env::set_var("EDR__SCANNER__SIGMA_ENGINE", "rsigma");
        let cfg = AppConfig::new().expect("config should load");
        std::env::remove_var("EDR__SCANNER__SIGMA_ENGINE");
        assert_eq!(cfg.scanner.sigma_engine, "rsigma");
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
