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
    let cfg = AppConfig::default();
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
    assert!(cfg.telemetry.enabled);
    assert_eq!(cfg.telemetry.snapshot_interval_secs, 30);
}

#[test]
fn test_config_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let explicit = temp.path().join("explicit.toml");
    let managed = temp.path().join("managed.toml");
    std::fs::write(
        &explicit,
        r#"
[scanner]
sigma_rules_path = "rules/sigma"
yara_rules_path = "rules/yara"

[ioc]
hashes_path = "rules/ioc/hashes.txt"
ips_path = "rules/ioc/ips.txt"
paths_regex_path = "rules/ioc/paths_regex.txt"
"#,
    )
    .expect("write explicit config");
    std::fs::write(
        &managed,
        "[scanner]\nsigma_rules_path = \"managed-sigma\"\n",
    )
    .expect("write managed config");

    let cfg = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: Some(explicit.clone()),
            env_config: None,
            managed_config: managed,
            exe_config: Some(temp.path().join("missing-exe.toml")),
            cwd_config: temp.path().join("missing-cwd.toml"),
        },
        Some(config::Map::new()),
    )
    .unwrap();
    let config_dir = explicit.parent().expect("config directory");

    assert_eq!(cfg.scanner.sigma_rules_path, config_dir.join("rules/sigma"));
    assert_eq!(cfg.scanner.yara_rules_path, config_dir.join("rules/yara"));
    assert_eq!(cfg.ioc.hashes_path, config_dir.join("rules/ioc/hashes.txt"));
    assert_eq!(cfg.ioc.ips_path, config_dir.join("rules/ioc/ips.txt"));
    assert_eq!(
        cfg.ioc.paths_regex_path,
        config_dir.join("rules/ioc/paths_regex.txt")
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
    let managed = temp.path().join("managed.toml");

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
    std::fs::write(&managed, "[logging]\nlevel = \"warn\"\n").expect("write managed config");

    let cfg = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: Some(explicit.clone()),
            env_config: Some(env_config),
            managed_config: managed,
            exe_config: Some(temp.path().join("exe.toml")),
            cwd_config: temp.path().join("cwd.toml"),
        },
        Some(config::Map::new()),
    )
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

    let cfg = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: None,
            env_config: None,
            managed_config: managed.clone(),
            exe_config: Some(exe.clone()),
            cwd_config: cwd.clone(),
        },
        Some(config::Map::new()),
    )
    .expect("load managed config");
    assert_eq!(cfg.logging.level, "warn");

    std::fs::remove_file(&managed).expect("remove managed config");
    let cfg = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: None,
            env_config: None,
            managed_config: managed,
            exe_config: Some(exe.clone()),
            cwd_config: cwd.clone(),
        },
        Some(config::Map::new()),
    )
    .expect("load exe config");
    assert_eq!(cfg.logging.level, "debug");

    std::fs::remove_file(&exe).expect("remove exe config");
    let cfg = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: None,
            env_config: None,
            managed_config: temp.path().join("missing-managed.toml"),
            exe_config: Some(exe),
            cwd_config: cwd,
        },
        Some(config::Map::new()),
    )
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

    let cfg = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: None,
            env_config: Some(env_config),
            managed_config: managed,
            exe_config: None,
            cwd_config: temp.path().join("cwd.toml"),
        },
        Some(config::Map::new()),
    )
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
fn test_windows_etw_flush_default() {
    let cfg = AppConfig::default();
    assert_eq!(cfg.windows.etw_flush_interval_ms, 20);
    assert_eq!(cfg.windows.etw_process_flush_interval_ms, 5);
}

#[test]
fn process_flush_is_independent_of_the_main_interval() {
    // Disabling the main session's handoff must not silently disable the
    // process session's, which is what collects `CommandLine` at all.
    let mut cfg = AppConfig::default();
    cfg.windows.etw_flush_interval_ms = 0;
    assert_eq!(cfg.windows.etw_process_flush_interval_ms, 5);
}

#[test]
fn config_builder_uses_windows_etw_flush_default() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cfg = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: None,
            env_config: None,
            managed_config: temp.path().join("missing-managed.toml"),
            exe_config: None,
            cwd_config: temp.path().join("missing-cwd.toml"),
        },
        Some(config::Map::new()),
    )
    .expect("load default config");

    assert_eq!(cfg.windows.etw_flush_interval_ms, 20);
    assert_eq!(cfg.windows.etw_process_flush_interval_ms, 5);
}

#[test]
fn test_process_cache_defaults() {
    let cfg = AppConfig::default();
    assert_eq!(cfg.process.max_entries, 65_536);
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
fn test_yara_scan_guards_are_active_by_default() {
    let cfg = AppConfig::default();
    assert_eq!(cfg.scanner.yara_scan_timeout_ms, 10_000);
    assert_eq!(cfg.scanner.yara_max_file_mb, 64);

    let limits = cfg.scanner.yara_scan_limits();
    assert_eq!(limits.timeout, std::time::Duration::from_secs(10));
    assert_eq!(limits.max_file_bytes, 64 * 1024 * 1024);
}

#[test]
fn test_yara_scan_guards_can_be_disabled() {
    let mut cfg = AppConfig::default();
    cfg.scanner.yara_scan_timeout_ms = 0;
    cfg.scanner.yara_max_file_mb = 0;

    let limits = cfg.scanner.yara_scan_limits();
    assert!(limits.timeout.is_zero());
    assert_eq!(limits.max_file_bytes, 0);
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
