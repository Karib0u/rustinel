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
async fn sigma_reload_swaps_valid_rules_and_rejects_empty_rules() {
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
    assert!(store.sigma().check_event(&network).is_some());
    drop(tx);
    handle.abort();
}

#[tokio::test]
async fn yara_reload_swaps_valid_rules_and_rejects_empty_rules() {
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
    assert!(
        store
            .yara()
            .scan_bytes(b"BBB_RELOAD_MARKER", MatchDebugLevel::Off)
            .unwrap()
            .len()
            == 1
    );
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
