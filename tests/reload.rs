#[cfg(test)]
mod common;

use std::sync::Arc;

use common::{dns_query_event, process_start_event, SigmaFixture, TestNormalizer, YaraFixture};
use rustinel::{
    config::{ReloadConfig, ResponseConfig, ScannerConfig},
    engine::{Engine, SigmaEngineKind},
    ioc::IocEngine,
    models::MatchDebugLevel,
    reload::{spawn_reload_worker, DetectorStore, ReloadTarget},
    scanner::Scanner,
    sensor::Platform,
};
use tokio::sync::mpsc;

fn host_platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOS
    } else {
        Platform::Linux
    }
}

fn dummy_response_config() -> Arc<arc_swap::ArcSwap<ResponseConfig>> {
    Arc::new(arc_swap::ArcSwap::from(Arc::new(ResponseConfig {
        enabled: false,
        prevention_enabled: false,
        min_severity: "critical".to_string(),
        channel_capacity: 4,
        allowlist_images: Vec::new(),
        allowlist_paths: Vec::new(),
    })))
}

fn scanner_cfg(sigma: &SigmaFixture, yara: &YaraFixture) -> ScannerConfig {
    ScannerConfig {
        sigma_enabled: true,
        sigma_rules_path: sigma.rules_dir().to_path_buf(),
        sigma_engine: "builtin".to_string(),
        yara_enabled: true,
        yara_rules_path: yara.rules_dir().to_path_buf(),
        yara_allowlist_paths: Vec::new(),
        yara_scan_timeout_ms: 10_000,
        yara_max_file_mb: 64,
        yara_memory_enabled: false,
        yara_memory_queue_capacity: 8,
        yara_memory_delay_ms: 0,
        yara_memory_max_process_mb: 64,
        yara_memory_max_region_mb: 8,
        yara_memory_include_private: true,
        yara_memory_include_image: false,
        yara_memory_include_mapped: false,
    }
}

#[tokio::test]
async fn sigma_reload_swaps_valid_rules_and_allows_empty_rules() {
    let sigma = SigmaFixture::new();
    let platform = host_platform();
    sigma.write_process_rule(platform);
    let yara = YaraFixture::new();
    yara.write_default_rule();
    let ioc = common::IocFixture::new();

    let mut engine = Engine::new_for_platform(platform);
    engine
        .load_rules(sigma.rules_dir())
        .expect("load initial sigma");
    let store = DetectorStore::new(
        Arc::new(engine),
        Arc::new(Scanner::new(yara.rules_dir()).expect("load yara")),
        Arc::new(IocEngine::load(&ioc.config())),
    );

    std::fs::remove_file(sigma.rules_dir().join("process.yml")).expect("remove rule A");
    sigma.write_rule(
        "network.yml",
        &format!(
            r#"title: Reloaded Network
logsource:
  product: {product}
  category: network_connection
detection:
  selection:
    DestinationPort: "443"
  condition: selection
level: high
        "#,
            product = match platform {
                Platform::Windows => "windows",
                Platform::Linux => "linux",
                Platform::MacOS => "macos",
            }
        ),
    );

    let (tx, rx) = mpsc::unbounded_channel();
    let handle = spawn_reload_worker(
        Arc::clone(&store),
        scanner_cfg(&sigma, &yara),
        ioc.config(),
        ReloadConfig {
            enabled: true,
            debounce_ms: 100,
            fallback_poll_interval_ms: 60000,
        },
        "info".to_string(),
        MatchDebugLevel::Off,
        SigmaEngineKind::Builtin,
        None,
        dummy_response_config(),
        rx,
    );
    tx.send(ReloadTarget::Sigma).expect("send reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    let harness = TestNormalizer::new(false);
    let process = harness
        .normalizer
        .normalize(&process_start_event(platform))
        .unwrap();
    let network = harness
        .normalizer
        .normalize(&common::network_connect_event(platform))
        .unwrap();
    assert!(store.sigma().check_event(&network).is_some());
    assert!(store.sigma().check_event(&process).is_none());

    std::fs::remove_file(sigma.rules_dir().join("network.yml")).expect("remove rule B");
    tx.send(ReloadTarget::Sigma).expect("send empty reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(store.sigma().check_event(&network).is_none());
    drop(tx);
    handle.abort();
}

#[tokio::test]
async fn yara_reload_swaps_valid_rules_and_allows_empty_rules() {
    let sigma = SigmaFixture::new();
    let platform = host_platform();
    sigma.write_process_rule(platform);
    let yara = YaraFixture::new();
    yara.write_rule("a.yar", "RuleA", "AAA_RELOAD_MARKER");
    let ioc = common::IocFixture::new();
    let mut engine = Engine::new_for_platform(platform);
    engine.load_rules(sigma.rules_dir()).expect("load sigma");
    let store = DetectorStore::new(
        Arc::new(engine),
        Arc::new(Scanner::new(yara.rules_dir()).expect("load yara A")),
        Arc::new(IocEngine::load(&ioc.config())),
    );

    std::fs::remove_file(yara.rules_dir().join("a.yar")).expect("remove rule A");
    yara.write_rule("b.yar", "RuleB", "BBB_RELOAD_MARKER");
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = spawn_reload_worker(
        Arc::clone(&store),
        scanner_cfg(&sigma, &yara),
        ioc.config(),
        ReloadConfig {
            enabled: true,
            debounce_ms: 100,
            fallback_poll_interval_ms: 60000,
        },
        "info".to_string(),
        MatchDebugLevel::Off,
        SigmaEngineKind::Builtin,
        None,
        dummy_response_config(),
        rx,
    );
    tx.send(ReloadTarget::Yara).expect("send yara reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(
        store
            .yara()
            .scan_bytes(b"BBB_RELOAD_MARKER", MatchDebugLevel::Off)
            .unwrap()
            .len()
            == 1
    );

    std::fs::remove_file(yara.rules_dir().join("b.yar")).expect("remove rule B");
    tx.send(ReloadTarget::Yara).expect("send empty reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(store
        .yara()
        .scan_bytes(b"BBB_RELOAD_MARKER", MatchDebugLevel::Off)
        .unwrap()
        .is_empty());
    drop(tx);
    handle.abort();
}

#[tokio::test]
async fn ioc_reload_swaps_valid_indicators_and_rejects_empty_set() {
    let sigma = SigmaFixture::new();
    let platform = host_platform();
    sigma.write_process_rule(platform);
    let yara = YaraFixture::new();
    yara.write_default_rule();
    let ioc = common::IocFixture::new();
    ioc.write_domains("old.example.test");

    let mut engine = Engine::new_for_platform(platform);
    engine.load_rules(sigma.rules_dir()).expect("load sigma");
    let store = DetectorStore::new(
        Arc::new(engine),
        Arc::new(Scanner::new(yara.rules_dir()).expect("load yara")),
        Arc::new(IocEngine::load(&ioc.config())),
    );

    ioc.write_domains("example.test");
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = spawn_reload_worker(
        Arc::clone(&store),
        scanner_cfg(&sigma, &yara),
        ioc.config(),
        ReloadConfig {
            enabled: true,
            debounce_ms: 100,
            fallback_poll_interval_ms: 60000,
        },
        "info".to_string(),
        MatchDebugLevel::Off,
        SigmaEngineKind::Builtin,
        None,
        dummy_response_config(),
        rx,
    );
    tx.send(ReloadTarget::Ioc).expect("send ioc reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let event = TestNormalizer::new(false)
        .normalizer
        .normalize(&dns_query_event(platform))
        .unwrap();
    assert_eq!(store.ioc().check_event(&event).len(), 1);

    ioc.write_domains("");
    tx.send(ReloadTarget::Ioc).expect("send empty reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(store.ioc().check_event(&event).len(), 1);
    drop(tx);
    handle.abort();
}

#[tokio::test]
async fn test_reload_poller_fallback_polling() {
    use rustinel::config::IocConfig;
    use std::path::PathBuf;
    use std::time::Duration;

    let tempdir = tempfile::tempdir().expect("create tempdir");
    let non_existent_dir = tempdir.path().join("non_existent_sigma_rules");

    let scanner_cfg = ScannerConfig {
        sigma_enabled: true,
        sigma_rules_path: non_existent_dir.clone(),
        sigma_engine: "builtin".to_string(),
        yara_enabled: false,
        yara_rules_path: PathBuf::from(""),
        yara_allowlist_paths: Vec::new(),
        yara_scan_timeout_ms: 10_000,
        yara_max_file_mb: 64,
        yara_memory_enabled: false,
        yara_memory_queue_capacity: 0,
        yara_memory_delay_ms: 0,
        yara_memory_max_process_mb: 0,
        yara_memory_max_region_mb: 0,
        yara_memory_include_private: false,
        yara_memory_include_image: false,
        yara_memory_include_mapped: false,
    };

    let ioc_cfg = IocConfig {
        enabled: false,
        hashes_path: PathBuf::from(""),
        ips_path: PathBuf::from(""),
        domains_path: PathBuf::from(""),
        paths_regex_path: PathBuf::from(""),
        default_severity: "high".to_string(),
        max_file_size_mb: 0,
        hash_allowlist_paths: Vec::new(),
    };

    let reload_cfg = ReloadConfig {
        enabled: true,
        debounce_ms: 10,
        fallback_poll_interval_ms: 100,
    };

    let (reload_tx, mut reload_rx) = mpsc::unbounded_channel();

    // Spawning the poller with a non-existent path will trigger the watcher failure
    // and cause it to fall back to the 100ms polling loop (in test configuration)
    let poller =
        rustinel::reload::spawn_reload_poller(scanner_cfg, ioc_cfg, reload_cfg, None, reload_tx);

    // Give it a moment to initialize and fail watcher setup
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Now, create the directory and add a rules file to trigger a fingerprint change
    std::fs::create_dir_all(&non_existent_dir).expect("create dir");
    std::fs::write(
        non_existent_dir.join("rule.yml"),
        r#"title: Test Rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: "test.exe"
  condition: selection
level: high
"#,
    )
    .expect("write rule");

    // The polling loop (running at 100ms interval in test mode) should pick this up
    // and send a ReloadTarget::Sigma event to the channel.
    let event = tokio::time::timeout(Duration::from_millis(1500), reload_rx.recv())
        .await
        .expect("Timeout waiting for reload event")
        .expect("Channel closed unexpectedly");

    assert_eq!(event, ReloadTarget::Sigma);

    poller.shutdown().await;
}

/// Regression test for a watcher-setup deadlock on deep rule trees.
///
/// notify watches `IN_OPEN`, so walking a tree to register it recursively queues one
/// inotify event per directory. The callback used to block once the wake-up channel
/// filled, parking notify's event-loop thread — the same thread the *next*
/// `Watcher::watch()` call waits on for its acknowledgement. Setup never returned,
/// hot reload never activated, and the process never shut down.
///
/// Reproducing it therefore needs both a tree larger than the channel (100) and a
/// second watch target registered after it; here, the config file's parent.
#[tokio::test]
async fn test_reload_poller_handles_rule_tree_with_many_directories() {
    use rustinel::config::IocConfig;
    use std::path::PathBuf;
    use std::time::Duration;

    // More directories than the wake-up channel can hold (capacity 100).
    const DIR_COUNT: usize = 150;

    let tempdir = tempfile::tempdir().expect("create tempdir");
    let sigma_dir = tempdir.path().join("sigma");
    for i in 0..DIR_COUNT {
        let sub = sigma_dir.join(format!("category_{i:03}"));
        std::fs::create_dir_all(&sub).expect("create rule subdir");
        std::fs::write(sub.join("rule.yml"), sigma_rule_yaml("test.exe")).expect("write rule");
    }

    let config_dir = tempdir.path().join("etc");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    let config_path = config_dir.join("rustinel.toml");
    std::fs::write(&config_path, "").expect("write config");

    let scanner_cfg = ScannerConfig {
        sigma_enabled: true,
        sigma_rules_path: sigma_dir.clone(),
        sigma_engine: "builtin".to_string(),
        yara_enabled: false,
        yara_rules_path: PathBuf::from(""),
        yara_allowlist_paths: Vec::new(),
        yara_scan_timeout_ms: 10_000,
        yara_max_file_mb: 64,
        yara_memory_enabled: false,
        yara_memory_queue_capacity: 0,
        yara_memory_delay_ms: 0,
        yara_memory_max_process_mb: 0,
        yara_memory_max_region_mb: 0,
        yara_memory_include_private: false,
        yara_memory_include_image: false,
        yara_memory_include_mapped: false,
    };

    let ioc_cfg = IocConfig {
        enabled: false,
        hashes_path: PathBuf::from(""),
        ips_path: PathBuf::from(""),
        domains_path: PathBuf::from(""),
        paths_regex_path: PathBuf::from(""),
        default_severity: "high".to_string(),
        max_file_size_mb: 0,
        hash_allowlist_paths: Vec::new(),
    };

    // A poll interval far beyond the test timeout: only a working watcher can
    // produce the reload event below.
    let reload_cfg = ReloadConfig {
        enabled: true,
        debounce_ms: 10,
        fallback_poll_interval_ms: 3_600_000,
    };

    let (reload_tx, mut reload_rx) = mpsc::unbounded_channel();
    let poller = rustinel::reload::spawn_reload_poller(
        scanner_cfg,
        ioc_cfg,
        reload_cfg,
        Some(config_path),
        reload_tx,
    );

    // Let watcher setup finish before touching the tree.
    tokio::time::sleep(Duration::from_millis(500)).await;

    std::fs::write(
        sigma_dir.join("category_000").join("added.yml"),
        sigma_rule_yaml("added.exe"),
    )
    .expect("write rule");

    let event = tokio::time::timeout(Duration::from_secs(10), reload_rx.recv())
        .await
        .expect("watcher setup deadlocked: no reload event")
        .expect("Channel closed unexpectedly");
    assert_eq!(event, ReloadTarget::Sigma);

    tokio::time::timeout(Duration::from_secs(5), poller.shutdown())
        .await
        .expect("poller did not shut down");
}

fn sigma_rule_yaml(image: &str) -> String {
    format!(
        r#"title: Test Rule {image}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: "{image}"
  condition: selection
level: high
"#
    )
}

#[tokio::test]
async fn test_reload_rejects_invalid_rules_but_keeps_previous_rules() {
    let sigma = SigmaFixture::new();
    let platform = host_platform();
    sigma.write_process_rule(platform);
    let yara = YaraFixture::new();
    yara.write_default_rule();
    let ioc = common::IocFixture::new();

    let mut engine = Engine::new_for_platform(platform);
    engine
        .load_rules(sigma.rules_dir())
        .expect("load initial sigma");
    let store = DetectorStore::new(
        Arc::new(engine),
        Arc::new(Scanner::new(yara.rules_dir()).expect("load yara")),
        Arc::new(IocEngine::load(&ioc.config())),
    );

    let (tx, rx) = mpsc::unbounded_channel();
    let handle = spawn_reload_worker(
        Arc::clone(&store),
        scanner_cfg(&sigma, &yara),
        ioc.config(),
        ReloadConfig {
            enabled: true,
            debounce_ms: 100,
            fallback_poll_interval_ms: 60000,
        },
        "info".to_string(),
        MatchDebugLevel::Off,
        SigmaEngineKind::Builtin,
        None,
        dummy_response_config(),
        rx,
    );

    // Delete the original valid Sigma rule file and write a completely invalid rule file
    std::fs::remove_file(sigma.rules_dir().join("process.yml")).expect("remove valid sigma rule");
    sigma.write_rule("invalid_rule.yml", "invalid: yaml: syntax: [error");

    tx.send(ReloadTarget::Sigma).expect("send reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // The reload should have been rejected (keeping the previous rules active in memory).
    // Let's verify that the original process rules (no longer on disk) are still working.
    let proc_event = TestNormalizer::new(false)
        .normalizer
        .normalize(&process_start_event(platform))
        .unwrap();
    assert!(store.sigma().check_event(&proc_event).is_some());

    // Delete the original valid YARA rule file and write an invalid YARA rule
    std::fs::remove_file(yara.rules_dir().join("marker.yar")).expect("remove valid yara rule");
    std::fs::write(
        yara.rules_dir().join("invalid_rule.yar"),
        "rule invalid { syntax_error }",
    )
    .unwrap();
    tx.send(ReloadTarget::Yara).expect("send reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // YARA reload should also be rejected, keeping the default YARA rule (no longer on disk) active
    assert_eq!(
        store
            .yara()
            .scan_bytes(b"RUSTINEL_TEST_MARKER", MatchDebugLevel::Off)
            .unwrap()
            .len(),
        1
    );

    drop(tx);
    handle.abort();
}

#[tokio::test]
async fn test_reload_accepts_partially_invalid_rules() {
    let sigma = SigmaFixture::new();
    let platform = host_platform();
    let yara = YaraFixture::new();
    let ioc = common::IocFixture::new();

    let engine = Engine::new_for_platform(platform);
    // Start with empty rules
    let store = DetectorStore::new(
        Arc::new(engine),
        Arc::new(Scanner::new(yara.rules_dir()).expect("load yara")),
        Arc::new(IocEngine::load(&ioc.config())),
    );

    let (tx, rx) = mpsc::unbounded_channel();
    let handle = spawn_reload_worker(
        Arc::clone(&store),
        scanner_cfg(&sigma, &yara),
        ioc.config(),
        ReloadConfig {
            enabled: true,
            debounce_ms: 100,
            fallback_poll_interval_ms: 60000,
        },
        "info".to_string(),
        MatchDebugLevel::Off,
        SigmaEngineKind::Builtin,
        None,
        dummy_response_config(),
        rx,
    );

    // Write one valid and one invalid Sigma rule file
    sigma.write_process_rule(platform);
    sigma.write_rule("invalid_rule.yml", "invalid: yaml: syntax: [error");

    tx.send(ReloadTarget::Sigma).expect("send reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // The reload should have succeeded (loading the valid rule)
    let proc_event = TestNormalizer::new(false)
        .normalizer
        .normalize(&process_start_event(platform))
        .unwrap();
    assert!(store.sigma().check_event(&proc_event).is_some());

    // Write one valid and one invalid YARA rule file
    yara.write_default_rule();
    std::fs::write(
        yara.rules_dir().join("invalid_rule.yar"),
        "rule invalid { syntax_error }",
    )
    .unwrap();
    tx.send(ReloadTarget::Yara).expect("send reload");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // The reload should have succeeded (loading the valid rule)
    assert_eq!(
        store
            .yara()
            .scan_bytes(b"RUSTINEL_TEST_MARKER", MatchDebugLevel::Off)
            .unwrap()
            .len(),
        1
    );

    drop(tx);
    handle.abort();
}

#[tokio::test]
async fn test_config_reload_swaps_updated_response_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_file_path = dir.path().join("config.toml");

    // Write initial configuration
    std::fs::write(
        &config_file_path,
        r#"
[response]
enabled = false
prevention_enabled = false
min_severity = "high"
"#,
    )
    .unwrap();

    // Verify we can load it initially
    let cfg =
        rustinel::config::AppConfig::from_config_path(Some(config_file_path.clone())).unwrap();
    assert!(!cfg.response.enabled);
    assert!(!cfg.response.prevention_enabled);
    assert_eq!(cfg.response.min_severity, "high");

    let response_config = Arc::new(arc_swap::ArcSwap::from(Arc::new(cfg.response)));

    let sigma = SigmaFixture::new();
    let yara = YaraFixture::new();
    let ioc = common::IocFixture::new();

    let store = DetectorStore::new(
        Arc::new(Engine::new_for_platform(host_platform())),
        Arc::new(Scanner::empty()),
        Arc::new(IocEngine::load(&ioc.config())),
    );

    let (tx, rx) = mpsc::unbounded_channel();
    let handle = spawn_reload_worker(
        Arc::clone(&store),
        scanner_cfg(&sigma, &yara),
        ioc.config(),
        ReloadConfig {
            enabled: true,
            debounce_ms: 100,
            fallback_poll_interval_ms: 60000,
        },
        "info".to_string(),
        MatchDebugLevel::Off,
        SigmaEngineKind::Builtin,
        Some(config_file_path.clone()),
        response_config.clone(),
        rx,
    );

    // Write updated configuration
    std::fs::write(
        &config_file_path,
        r#"
[response]
enabled = true
prevention_enabled = true
min_severity = "low"
"#,
    )
    .unwrap();

    tx.send(ReloadTarget::Config).expect("send reload config");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // Check that response config is swapped atomically with the new values!
    let updated = response_config.load();
    assert!(updated.enabled);
    assert!(updated.prevention_enabled);
    assert_eq!(updated.min_severity, "low");

    drop(tx);
    handle.abort();
}

fn build_critical_process_alert(pid: u32, image: &str) -> rustinel::models::Alert {
    use rustinel::models::*;
    use rustinel::sensor::Platform;
    Alert {
        severity: AlertSeverity::Critical,
        rule_name: "TestCriticalRule".to_string(),
        rule_description: None,
        rule_id: None,
        engine: DetectionEngine::Yara,
        event: NormalizedEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            platform: Platform::Linux,
            provider: "test".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(image.to_string()),
                process_id: Some(pid.to_string()),
                process_start_time: None,
                command_line: None,
                original_file_name: None,
                product: None,
                description: None,
                company: None,
                file_version: None,
                target_image: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                current_directory: None,
                integrity_level: None,
                user: None,
            }),
            process_context: None,
        },
        match_details: None,
    }
}

#[tokio::test]
async fn test_config_reload_decision_disabled_to_terminate() {
    let dir = tempfile::tempdir().unwrap();
    let config_file_path = dir.path().join("config.toml");

    // Start with response disabled
    std::fs::write(
        &config_file_path,
        r#"
[response]
enabled = false
prevention_enabled = false
min_severity = "critical"
"#,
    )
    .unwrap();

    let cfg =
        rustinel::config::AppConfig::from_config_path(Some(config_file_path.clone())).unwrap();
    let response_config = Arc::new(arc_swap::ArcSwap::from(Arc::new(cfg.response)));

    let sigma = SigmaFixture::new();
    let yara = YaraFixture::new();
    let ioc = common::IocFixture::new();

    let store = DetectorStore::new(
        Arc::new(Engine::new_for_platform(host_platform())),
        Arc::new(Scanner::empty()),
        Arc::new(IocEngine::load(&ioc.config())),
    );

    let (tx, rx) = mpsc::unbounded_channel();
    let handle = spawn_reload_worker(
        Arc::clone(&store),
        scanner_cfg(&sigma, &yara),
        ioc.config(),
        ReloadConfig {
            enabled: true,
            debounce_ms: 100,
            fallback_poll_interval_ms: 60000,
        },
        "info".to_string(),
        MatchDebugLevel::Off,
        SigmaEngineKind::Builtin,
        Some(config_file_path.clone()),
        response_config.clone(),
        rx,
    );

    // Build a ResponseEngine sharing the same ArcSwap config
    let (response_engine, response_worker) =
        rustinel::response::ResponseEngine::new(response_config.clone());

    // Build a critical-severity alert with a non-protected PID distinct from this process.
    let test_pid = std::process::id()
        .checked_add(1)
        .filter(|pid| *pid > 4)
        .unwrap_or(5);
    let alert = build_critical_process_alert(test_pid, "/tmp/evil");

    // Before reload: response is disabled
    let decision_before = response_engine.decision_for_alert(&alert);
    assert_eq!(
        decision_before,
        rustinel::response::ResponseDecision::Disabled
    );

    // Write updated config: enable response + prevention
    std::fs::write(
        &config_file_path,
        r#"
[response]
enabled = true
prevention_enabled = true
min_severity = "critical"
"#,
    )
    .unwrap();

    tx.send(ReloadTarget::Config).expect("send reload config");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // After reload: decision should be Terminate
    let decision_after = response_engine.decision_for_alert(&alert);
    assert!(
        matches!(
            decision_after,
            rustinel::response::ResponseDecision::Terminate { pid, .. } if pid == test_pid
        ),
        "expected Terminate, got: {:?}",
        decision_after,
    );

    drop(tx);
    response_worker.abort();
    handle.abort();
}
