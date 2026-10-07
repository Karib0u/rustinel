//! Local rule directories load beside the managed pack and survive pack
//! replacement and failed reloads.

#[cfg(test)]
mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use common::{
    network_connect_event, process_start_event, IocFixture, SigmaFixture, TestNormalizer,
    YaraFixture, TEST_YARA_MARKER,
};
use rustinel::{
    config::{ReloadConfig, ResponseConfig, ScannerConfig},
    engine::{DetectorStore, Engine, SigmaMatchMode},
    ioc::IocEngine,
    models::MatchDebugLevel,
    reload::{spawn_reload_worker, ReloadTarget},
    scanner::Scanner,
    sensor::Platform,
    utils::rule_dirs::RuleDirectoryRole,
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

fn product(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => "windows",
        Platform::Linux => "linux",
        Platform::MacOS => "macos",
    }
}

fn network_rule(platform: Platform, title: &str, id: &str) -> String {
    format!(
        r#"title: {title}
id: {id}
logsource:
  product: {product}
  category: network_connection
detection:
  selection:
    DestinationPort: "443"
  condition: selection
level: high
"#,
        product = product(platform)
    )
}

fn write(dir: &Path, name: &str, content: &str) {
    fs::create_dir_all(dir).expect("create rules dir");
    fs::write(dir.join(name), content).expect("write rule");
}

fn scanner_cfg(
    sigma: &SigmaFixture,
    yara: &YaraFixture,
    sigma_local: &Path,
    yara_local: &Path,
) -> ScannerConfig {
    ScannerConfig {
        sigma_enabled: true,
        sigma_rules_path: sigma.rules_dir().to_path_buf(),
        sigma_local_rules_paths: vec![sigma_local.to_path_buf()],
        sigma_match_mode: SigmaMatchMode::All,
        yara_enabled: true,
        yara_rules_path: yara.rules_dir().to_path_buf(),
        yara_local_rules_paths: vec![yara_local.to_path_buf()],
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

fn response_config() -> Arc<arc_swap::ArcSwap<ResponseConfig>> {
    Arc::new(arc_swap::ArcSwap::from(Arc::new(ResponseConfig {
        enabled: false,
        prevention_enabled: false,
        min_severity: "critical".to_string(),
        channel_capacity: 4,
        allowlist_images: Vec::new(),
        allowlist_paths: Vec::new(),
    })))
}

#[test]
fn sigma_loads_pack_and_local_directories_with_counts() {
    let platform = host_platform();
    let pack = SigmaFixture::new();
    pack.write_process_rule(platform);
    let local = tempfile::tempdir().expect("local dir");
    write(
        &local.path().join("nested"),
        "network.yml",
        &network_rule(platform, "Local Network", "local-network"),
    );

    let mut engine = Engine::new_for_platform(platform);
    engine
        .load_rule_dirs_with_trust(pack.rules_dir(), &[local.path().to_path_buf()], None)
        .expect("load");

    let stats = engine.stats();
    assert_eq!(stats.total_rules, 2);
    assert_eq!(stats.directories.len(), 2);
    assert_eq!(stats.directories[0].role, RuleDirectoryRole::Pack);
    assert_eq!(stats.directories[0].rules, 1);
    assert_eq!(stats.directories[1].role, RuleDirectoryRole::Local);
    assert_eq!(stats.directories[1].files, 1);
    assert_eq!(stats.directories[1].rules, 1);
    assert!(stats.collisions.is_empty());

    let harness = TestNormalizer::new();
    let process = harness
        .normalizer
        .normalize(&process_start_event(platform))
        .unwrap();
    let network = harness
        .normalizer
        .normalize(&network_connect_event(platform))
        .unwrap();
    assert!(!engine.check_event(&process).is_empty());
    assert!(!engine.check_event(&network).is_empty());
}

#[test]
fn sigma_local_rule_replaces_a_pack_rule_with_the_same_id() {
    let platform = host_platform();
    let pack = SigmaFixture::new();
    pack.write_rule(
        "network.yml",
        &network_rule(platform, "Pack Network", "shared-id"),
    );
    let local = tempfile::tempdir().expect("local dir");
    write(
        local.path(),
        "network.yml",
        &network_rule(platform, "Local Network", "shared-id"),
    );

    let mut engine = Engine::new_for_platform(platform).with_sigma_match_mode(SigmaMatchMode::All);
    engine
        .load_rule_dirs_with_trust(pack.rules_dir(), &[local.path().to_path_buf()], None)
        .expect("load");

    let stats = engine.stats();
    assert_eq!(stats.total_rules, 1);
    assert_eq!(stats.collisions.len(), 1);
    let collision = &stats.collisions[0];
    assert_eq!(collision.rule_id, "shared-id");
    assert!(collision
        .overridden
        .starts_with(&pack.rules_dir().display().to_string()));
    assert!(collision
        .winner
        .starts_with(&local.path().display().to_string()));
    assert_eq!(stats.directories[0].rules, 0);
    assert_eq!(stats.directories[1].rules, 1);

    let harness = TestNormalizer::new();
    let network = harness
        .normalizer
        .normalize(&network_connect_event(platform))
        .unwrap();
    let titles = engine
        .check_event(&network)
        .into_iter()
        .map(|alert| alert.rule_name)
        .collect::<Vec<_>>();
    assert_eq!(titles, ["Local Network"]);
}

#[test]
fn yara_loads_pack_and_local_directories_and_local_wins_a_name_collision() {
    let pack = YaraFixture::new();
    pack.write_rule("pack.yar", "PackOnly", "PACK_ONLY_MARKER");
    pack.write_rule("shared.yar", "Shared", "PACK_SHARED_MARKER");
    let local = tempfile::tempdir().expect("local dir");
    write(
        &local.path().join("nested"),
        "local.yar",
        &format!(
            "rule LocalOnly {{ strings: $m = \"{TEST_YARA_MARKER}\" condition: $m }}\n\
             rule Shared {{ strings: $m = \"LOCAL_SHARED_MARKER\" condition: $m }}\n"
        ),
    );

    let scanner =
        Scanner::new_with_dirs_and_trust(pack.rules_dir(), &[local.path().to_path_buf()], None)
            .expect("load");
    assert_eq!(scanner.failed_files(), 0);
    assert_eq!(scanner.directories()[0].rules, 1, "pack Shared is replaced");
    assert_eq!(scanner.directories()[1].rules, 2);
    assert_eq!(scanner.collisions().len(), 1);
    assert_eq!(scanner.collisions()[0].rule_id, "Shared");

    let names = |data: &[u8]| {
        scanner
            .scan_bytes(data, MatchDebugLevel::Off)
            .expect("scan")
            .into_iter()
            .map(|m| m.rule)
            .collect::<Vec<_>>()
    };
    assert_eq!(names(b"PACK_ONLY_MARKER"), ["PackOnly"]);
    assert_eq!(names(TEST_YARA_MARKER.as_bytes()), ["LocalOnly"]);
    assert_eq!(names(b"LOCAL_SHARED_MARKER"), ["Shared"]);
    assert!(names(b"PACK_SHARED_MARKER").is_empty());
}

#[tokio::test]
async fn local_rules_survive_pack_replacement_and_a_rejected_reload_keeps_the_last_rules() {
    let platform = host_platform();
    let sigma = SigmaFixture::new();
    sigma.write_process_rule(platform);
    let yara = YaraFixture::new();
    yara.write_default_rule();
    let ioc = IocFixture::new();
    let local = tempfile::tempdir().expect("local dir");
    let sigma_local = local.path().join("sigma");
    let yara_local = local.path().join("yara");
    write(
        &sigma_local,
        "network.yml",
        &network_rule(platform, "Local Network", "local-network"),
    );
    write(
        &yara_local,
        "local.yar",
        "rule LocalOnly { strings: $m = \"LOCAL_MARKER\" condition: $m }\n",
    );
    let cfg = scanner_cfg(&sigma, &yara, &sigma_local, &yara_local);

    let mut engine = Engine::new_for_platform(platform);
    engine
        .load_rule_dirs_with_trust(&cfg.sigma_rules_path, &cfg.sigma_local_rules_paths, None)
        .expect("load sigma");
    let store = DetectorStore::new(
        Arc::new(engine),
        Arc::new(
            Scanner::new_with_dirs_and_trust(
                &cfg.yara_rules_path,
                &cfg.yara_local_rules_paths,
                None,
            )
            .expect("load yara"),
        ),
        Arc::new(IocEngine::load(&ioc.config())),
    );

    let (tx, rx) = mpsc::unbounded_channel();
    let handle = spawn_reload_worker(
        Arc::clone(&store),
        cfg,
        ioc.config(),
        ReloadConfig {
            enabled: true,
            debounce_ms: 100,
            fallback_poll_interval_ms: 60000,
        },
        MatchDebugLevel::Off,
        None,
        None,
        response_config(),
        None,
        rx,
    );

    let harness = TestNormalizer::new();
    let process = harness
        .normalizer
        .normalize(&process_start_event(platform))
        .unwrap();
    let network = harness
        .normalizer
        .normalize(&network_connect_event(platform))
        .unwrap();

    // Replace the pack the way `rules update` does: the pack directory is
    // swapped for different content while the local directory is untouched.
    fs::remove_file(sigma.rules_dir().join("process.yml")).expect("remove pack rule");
    sigma.write_rule(
        "replacement.yml",
        &network_rule(platform, "Pack Network", "pack-network"),
    );
    tx.send(ReloadTarget::Sigma).expect("send reload");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(store.sigma().check_event(&process).is_empty());
    let titles = store
        .sigma()
        .check_event(&network)
        .into_iter()
        .map(|alert| alert.rule_name)
        .collect::<Vec<_>>();
    assert!(titles.contains(&"Local Network".to_string()), "{titles:?}");
    assert!(titles.contains(&"Pack Network".to_string()), "{titles:?}");

    // A local directory that fails validation rejects the reload and the last
    // working rules stay active.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sigma_local, fs::Permissions::from_mode(0o777)).expect("chmod");
        fs::remove_file(sigma.rules_dir().join("replacement.yml")).expect("remove pack rule");
        sigma.write_process_rule(platform);
        tx.send(ReloadTarget::Sigma).expect("send rejected reload");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            store.sigma().check_event(&process).is_empty(),
            "the pack change must not apply while a local directory is rejected"
        );
        assert!(!store.sigma().check_event(&network).is_empty());
        fs::set_permissions(&sigma_local, fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    drop(tx);
    handle.abort();
}
