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
fn retired_network_aggregation_section_still_loads() {
    // v1.5 and earlier shipped a `[network]` section for the connection
    // aggregator. The aggregator is gone; a fleet that still carries those keys
    // must keep starting rather than fail to load its configuration.
    let temp = tempfile::tempdir().expect("tempdir");
    let explicit = temp.path().join("legacy.toml");
    std::fs::write(
        &explicit,
        r#"
[process]
max_entries = 4096

[network]
aggregation_enabled = true
aggregation_max_entries = 20000
aggregation_window_secs = 60
aggregation_interval_buffer_size = 50
"#,
    )
    .expect("write legacy config");

    let cfg = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: Some(explicit),
            env_config: None,
            managed_config: temp.path().join("missing-managed.toml"),
            exe_config: Some(temp.path().join("missing-exe.toml")),
            cwd_config: temp.path().join("missing-cwd.toml"),
        },
        Some(config::Map::new()),
    )
    .expect("a config carrying the retired [network] section should still load");

    // The surrounding sections are still applied, so the retired keys are
    // ignored rather than aborting the load partway through.
    assert_eq!(cfg.process.max_entries, 4096);
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
    assert!(!cfg.windows.security_filtering_platform_connections);
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
    assert!(!cfg.windows.security_filtering_platform_connections);
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

#[test]
fn loader_defaults_match_the_documented_defaults() {
    // docs/configuration.md reads its defaults from AppConfig::default(), so
    // the builder defaults used at load time must agree with it.
    let temp = tempfile::tempdir().expect("tempdir");
    let loaded = AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: None,
            env_config: None,
            managed_config: temp.path().join("missing-managed.toml"),
            exe_config: Some(temp.path().join("missing-exe.toml")),
            cwd_config: temp.path().join("missing-cwd.toml"),
        },
        Some(config::Map::new()),
    )
    .expect("defaults load without a file");

    assert_eq!(
        serde_json::to_value(&loaded).expect("serialize loaded config"),
        serde_json::to_value(AppConfig::default()).expect("serialize default config")
    );
}

fn load_config_file(
    temp: &tempfile::TempDir,
    body: &str,
) -> Result<AppConfig, config::ConfigError> {
    let path = temp.path().join("config.toml");
    std::fs::write(&path, body).expect("write config");
    AppConfig::from_options_with_environment(
        ConfigLoadOptions {
            explicit_config: Some(path),
            env_config: None,
            managed_config: temp.path().join("missing-managed.toml"),
            exe_config: None,
            cwd_config: temp.path().join("missing-cwd.toml"),
        },
        Some(config::Map::new()),
    )
}

/// Self-signed, key discarded; only its parseability matters.
const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBjTCCATOgAwIBAgIUBFPqAIiESFnvGGbOaZtYZmLIf6MwCgYIKoZIzj0EAwIw\nGzEZMBcGA1UEAwwQcnVzdGluZWwtdGVzdC1jYTAgFw0yNjA5MTUxNzA3NThaGA8y\nMTI2MDgyMjE3MDc1OFowGzEZMBcGA1UEAwwQcnVzdGluZWwtdGVzdC1jYTBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABCit5ylJfNuHqehuKxUOm3q6CXRXVH+/fJ1y\nnYMfQeQJsVQVZaRmI7dauvxhD8VMQa2YYfjELVo9AlUDaBDInICjUzBRMB0GA1Ud\nDgQWBBSfmsUVS5pqGadGzN2i7tJF3Si2STAfBgNVHSMEGDAWgBSfmsUVS5pqGadG\nzN2i7tJF3Si2STAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBVF\neHG4bjDEXPymygwmkn5Y578VXlAB1+XGWbIHkDzdAiEAnivGnrOpFWPW2fZScC0g\nha+te7iF5L7AkZIkiziJjt0=\n-----END CERTIFICATE-----\n";

#[test]
fn webhook_destinations_load_with_defaults_and_relative_ca_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(temp.path().join("certs")).expect("certs dir");
    std::fs::write(temp.path().join("certs/ca.pem"), TEST_CA_PEM).expect("write ca");
    let cfg = load_config_file(
        &temp,
        r#"
[[alerts.webhook]]
url = "https://collector.example:8443/ingest/abc123"
headers = { Authorization = "Bearer s3cret-token" }
secret = "hmac-key"

[[alerts.webhook]]
name = "chat"
url = "http://127.0.0.1:9000/hook"
ca_file = "certs/ca.pem"
max_attempts = 2
queue_capacity = 16
"#,
    )
    .expect("webhooks load");

    let webhooks = &cfg.alerts.webhook;
    assert_eq!(webhooks.len(), 2);
    assert_eq!(webhooks[0].label(), "collector.example:8443");
    assert_eq!(webhooks[0].target(), "https://collector.example:8443");
    assert_eq!(webhooks[0].timeout_ms, 5_000);
    assert!(webhooks[0].tls_verify);
    assert_eq!(webhooks[0].max_attempts, 5);
    assert_eq!(webhooks[0].queue_capacity, 1_024);
    assert_eq!(webhooks[1].label(), "chat");
    assert_eq!(webhooks[1].max_attempts, 2);
    assert_eq!(webhooks[1].queue_capacity, 16);
    assert_eq!(
        webhooks[1].ca_file.as_deref(),
        Some(temp.path().join("certs/ca.pem").as_path())
    );
    assert_eq!(webhooks[1].load_ca_bundle().expect("ca parses").len(), 1);
}

#[test]
fn malformed_webhook_destinations_fail_at_load() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(temp.path().join("bad.pem"), "not a certificate").expect("write pem");
    let cases = [
        ("url = \"not a url\"", "url is not a valid URL"),
        (
            "url = \"ftp://example.com/\"",
            "scheme must be http or https",
        ),
        (
            "url = \"https://example.com/\"\nheaders = { \"bad header\" = \"x\" }",
            "header name",
        ),
        (
            "url = \"https://example.com/\"\nheaders = { X-Rustinel-Signature = \"forged\" }",
            "set by Rustinel",
        ),
        (
            "url = \"https://example.com/\"\nheaders = { Authorization = \"a\\nb\" }",
            "invalid characters",
        ),
        (
            "url = \"https://example.com/\"\ntimeout_ms = 0",
            "timeout_ms",
        ),
        (
            "url = \"https://example.com/\"\nqueue_capacity = 0",
            "queue_capacity",
        ),
        (
            "url = \"https://example.com/\"\nmax_attempts = 0",
            "max_attempts",
        ),
        (
            "url = \"https://example.com/\"\nmax_attempts = 21",
            "max_attempts",
        ),
        (
            "url = \"https://example.com/\"\nretry_initial_ms = 5000\nretry_max_ms = 10",
            "retry_max_ms",
        ),
        ("url = \"https://example.com/\"\nsecret = \"\"", "secret"),
        (
            "url = \"https://example.com/\"\nca_file = \"bad.pem\"",
            "ca_file",
        ),
        (
            "url = \"https://example.com/\"\nca_file = \"missing.pem\"",
            "ca_file",
        ),
    ];
    for (table, expected) in cases {
        let err = load_config_file(&temp, &format!("[[alerts.webhook]]\n{table}\n"))
            .expect_err(table)
            .to_string();
        assert!(err.contains(expected), "{table}: {err}");
        assert!(err.contains("alerts.webhook[0]"), "{table}: {err}");
    }

    let err = load_config_file(
        &temp,
        "[[alerts.webhook]]\nurl = \"https://a.example/1\"\n[[alerts.webhook]]\nurl = \"https://a.example/2\"\n",
    )
    .expect_err("duplicate labels")
    .to_string();
    assert!(
        err.contains("alerts.webhook[1]") && err.contains("distinct name"),
        "{err}"
    );
}

#[test]
fn webhook_validation_errors_and_debug_output_never_carry_secrets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let err = load_config_file(
        &temp,
        r#"
[[alerts.webhook]]
url = "https://hooks.example/services/T0KEN-IN-PATH"
headers = { Authorization = "Bearer s3cret-token" }
secret = "hmac-key"
timeout_ms = 0
"#,
    )
    .expect_err("zero timeout")
    .to_string();
    for secret in ["T0KEN-IN-PATH", "s3cret-token", "hmac-key"] {
        assert!(!err.contains(secret), "{err}");
    }

    let mut webhook = WebhookConfig::new("https://user:pw@hooks.example/services/T0KEN-IN-PATH");
    webhook.headers.insert(
        "Authorization".to_string(),
        "Bearer s3cret-token".to_string(),
    );
    webhook.secret = Some("hmac-key".to_string());
    let mut cfg = AppConfig::default();
    cfg.alerts.webhook.push(webhook);
    let debug = format!("{cfg:?}");
    let serialized = serde_json::to_string(&cfg).expect("serialize");
    for rendered in [&debug, &serialized] {
        for secret in ["T0KEN-IN-PATH", "s3cret-token", "hmac-key", "user:pw"] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(rendered.contains("https://hooks.example"), "{rendered}");
    }
}
