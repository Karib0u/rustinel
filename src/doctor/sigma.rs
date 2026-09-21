use std::path::PathBuf;

use crate::cli::SigmaPlatform;
use crate::config::AppConfig;
use crate::engine::compatibility::{self, SigmaCompatibilityReport};
use crate::sensor::Platform;

pub fn run_cli(
    config_path: Option<PathBuf>,
    rules_path: Option<PathBuf>,
    selected_platform: Option<SigmaPlatform>,
    json: bool,
) -> anyhow::Result<i32> {
    let platform = selected_platform
        .map(SigmaPlatform::sensor_platform)
        .unwrap_or_else(current_platform);
    let loaded = AppConfig::from_config_path(config_path);
    let report = match loaded {
        Ok(config) => {
            let rules_path = rules_path.unwrap_or_else(|| config.scanner.sigma_rules_path.clone());
            compatibility::analyze_rules(&rules_path, platform, &config).unwrap_or_else(|error| {
                SigmaCompatibilityReport::fatal(platform, rules_path, error.to_string())
            })
        }
        Err(error) => SigmaCompatibilityReport::fatal(
            platform,
            rules_path.unwrap_or_default(),
            format!("configuration could not be loaded: {error}"),
        ),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", compatibility::format_human(&report));
    }
    Ok(report.exit_code)
}

fn current_platform() -> Platform {
    #[cfg(windows)]
    {
        Platform::Windows
    }
    #[cfg(target_os = "macos")]
    {
        Platform::MacOS
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Platform::Linux
    }
}
