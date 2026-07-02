#[cfg(test)]
mod common;

use common::{process_start_event, SigmaFixture, TestNormalizer, YaraFixture};
use rustinel::{
    config::AppConfig,
    engine::{Engine, SigmaEngineKind},
    ioc::IocEngine,
    models::MatchDebugLevel,
    scanner::Scanner,
    sensor::Platform,
};

#[test]
fn configured_paths_and_feature_flags_control_component_loading() {
    let sigma = SigmaFixture::new();
    sigma.write_process_rule(Platform::Linux);
    let yara = YaraFixture::new();
    yara.write_default_rule();
    let ioc = common::IocFixture::new();
    ioc.write_domains(common::TEST_DOMAIN);

    let mut cfg = AppConfig::default();
    cfg.scanner.sigma_rules_path = sigma.rules_dir().to_path_buf();
    cfg.scanner.yara_rules_path = yara.rules_dir().to_path_buf();
    cfg.ioc = ioc.config();
    cfg.response.enabled = true;
    cfg.reload.enabled = false;
    cfg.scanner.yara_memory_enabled = true;

    assert_eq!(cfg.scanner.sigma_rules_path, sigma.rules_dir());
    assert_eq!(cfg.scanner.yara_rules_path, yara.rules_dir());
    assert!(cfg.ioc.enabled);
    assert!(cfg.response.enabled);
    assert!(!cfg.reload.enabled);
    assert!(cfg.scanner.yara_memory_enabled);

    let mut engine = Engine::new_for_platform(Platform::Linux);
    if cfg.scanner.sigma_enabled {
        engine
            .load_rules(&cfg.scanner.sigma_rules_path)
            .expect("load sigma");
    }
    let event = TestNormalizer::new(false)
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .unwrap();
    assert!(engine.check_event(&event).is_some());

    let scanner = cfg
        .scanner
        .yara_enabled
        .then(|| Scanner::new(&cfg.scanner.yara_rules_path).expect("load yara"));
    assert_eq!(scanner.unwrap().compiled_files(), 1);

    let ioc_engine = cfg.ioc.enabled.then(|| IocEngine::load(&cfg.ioc)).unwrap();
    assert_eq!(ioc_engine.stats().domain_exact, 1);
}

#[test]
fn allowlist_propagates_to_empty_module_lists_but_preserves_overrides() {
    let mut cfg = AppConfig::default();
    let global = if cfg!(windows) {
        r"C:\Trusted".to_string()
    } else {
        "/opt/trusted".to_string()
    };
    let response_only = if cfg!(windows) {
        r"C:\ResponseOnly".to_string()
    } else {
        "/response-only".to_string()
    };
    cfg.allowlist.paths = vec![global.clone()];
    cfg.response.allowlist_paths = vec![response_only.clone()];
    cfg.ioc.hash_allowlist_paths = Vec::new();
    cfg.scanner.yara_allowlist_paths = Vec::new();

    let toml = format!(
        r#"
[allowlist]
paths = ["{global}"]

[response]
allowlist_paths = ["{response_only}"]
"#,
        global = global.replace('\\', "\\\\"),
        response_only = response_only.replace('\\', "\\\\")
    );
    let parsed = config::Config::builder()
        .add_source(config::File::from_str(&toml, config::FileFormat::Toml))
        .build()
        .expect("build config")
        .try_deserialize::<serde_json::Value>()
        .expect("deserialize partial config");
    assert!(parsed.get("allowlist").is_some());

    let cfg = {
        let mut c = cfg;
        if c.ioc.hash_allowlist_paths.is_empty() {
            c.ioc.hash_allowlist_paths = c.allowlist.paths.clone();
        }
        if c.scanner.yara_allowlist_paths.is_empty() {
            c.scanner.yara_allowlist_paths = c.allowlist.paths.clone();
        }
        c
    };

    assert_eq!(cfg.response.allowlist_paths, vec![response_only]);
    assert_eq!(cfg.ioc.hash_allowlist_paths, vec![global.clone()]);
    assert_eq!(cfg.scanner.yara_allowlist_paths, vec![global]);
}

#[test]
fn match_debug_configuration_controls_sigma_and_yara_details() {
    let sigma = SigmaFixture::new();
    sigma.write_process_rule(Platform::Linux);
    let event = TestNormalizer::new(false)
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .unwrap();

    let mut off = Engine::new_for_platform_with_logging_level_and_match_debug(
        Platform::Linux,
        "info",
        MatchDebugLevel::Off,
        SigmaEngineKind::Builtin,
    );
    off.load_rules(sigma.rules_dir()).expect("load off rule");
    assert!(off.check_event(&event).unwrap().match_details.is_none());

    let mut full = Engine::new_for_platform_with_logging_level_and_match_debug(
        Platform::Linux,
        "info",
        MatchDebugLevel::Full,
        SigmaEngineKind::Builtin,
    );
    full.load_rules(sigma.rules_dir()).expect("load full rule");
    let details = full.check_event(&event).unwrap().match_details.unwrap();
    assert!(!details.sigma.expect("sigma details").matches.is_empty());

    let yara = YaraFixture::new();
    yara.write_default_rule();
    let scanner = Scanner::new(yara.rules_dir()).expect("load yara");
    let off_matches = scanner
        .scan_bytes(common::TEST_YARA_MARKER.as_bytes(), MatchDebugLevel::Off)
        .unwrap();
    assert!(off_matches[0].strings.is_empty());
    let full_matches = scanner
        .scan_bytes(common::TEST_YARA_MARKER.as_bytes(), MatchDebugLevel::Full)
        .unwrap();
    assert!(!full_matches[0].strings.is_empty());
}
