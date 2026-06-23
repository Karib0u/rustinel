#[cfg(test)]
mod common;

use std::sync::Arc;

use common::{dns_query_event, process_start_event, SigmaFixture, TestNormalizer, YaraFixture};
use rustinel::{
    config::{ReloadConfig, ScannerConfig},
    engine::Engine,
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

fn scanner_cfg(sigma: &SigmaFixture, yara: &YaraFixture) -> ScannerConfig {
    ScannerConfig {
        sigma_enabled: true,
        sigma_rules_path: sigma.rules_dir().to_path_buf(),
        yara_enabled: true,
        yara_rules_path: yara.rules_dir().to_path_buf(),
        yara_allowlist_paths: Vec::new(),
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
    use rustinel::reload::spawn_reload_poller;
    use std::path::PathBuf;
    use std::time::Duration;

    let tempdir = tempfile::tempdir().expect("create tempdir");
    let non_existent_dir = tempdir.path().join("non_existent_sigma_rules");

    let scanner_cfg = ScannerConfig {
        sigma_enabled: true,
        sigma_rules_path: non_existent_dir.clone(),
        yara_enabled: false,
        yara_rules_path: PathBuf::from(""),
        yara_allowlist_paths: Vec::new(),
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
    let handle = spawn_reload_poller(scanner_cfg, ioc_cfg, reload_cfg, reload_tx);

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

    handle.abort();
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
