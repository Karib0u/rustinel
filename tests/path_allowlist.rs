//! Cross-module contracts for existing path allowlist behavior.

mod common;

use std::sync::Arc;

use rustinel::{
    config::AppConfig,
    ioc::IocEngine,
    models::{Alert, AlertSeverity, DetectionEngine, EventFields},
    response::{ResponseDecision, ResponseEngine},
    scanner::{is_path_allowlisted, normalize_allowlist_paths},
    sensor::Platform,
};

async fn check(prefix: &str, path: &str, expected: [bool; 3]) {
    check_paths(vec![prefix.into()], path, expected).await;
}

async fn check_paths(paths: Vec<String>, path: &str, expected: [bool; 3]) {
    let fixture = common::IocFixture::new();
    let mut ioc_cfg = fixture.config();
    ioc_cfg.hash_allowlist_paths = paths.clone();
    let ioc = IocEngine::load(&ioc_cfg);
    let yara_paths = normalize_allowlist_paths(&paths);

    let mut response_cfg = AppConfig::default().response;
    response_cfg.enabled = true;
    response_cfg.prevention_enabled = true;
    response_cfg.min_severity = "low".into();
    response_cfg.allowlist_images.clear();
    response_cfg.allowlist_paths = paths.clone();
    let (response, worker) =
        ResponseEngine::new(Arc::new(arc_swap::ArcSwap::from_pointee(response_cfg)));
    let mut event = common::TestNormalizer::new()
        .normalizer
        .normalize(&common::process_start_event(Platform::Linux))
        .unwrap();
    let EventFields::ProcessCreation(fields) = &mut event.fields else {
        panic!("process fixture");
    };
    fields.image = Some(path.into());
    fields.process_id = Some(u32::MAX.to_string());
    let decision = response.decision_for_alert(&Alert {
        severity: AlertSeverity::Critical,
        rule_name: "allowlist contract".into(),
        rule_description: None,
        rule_id: None,
        sigma_metadata: None,
        engine: DetectionEngine::Sigma,
        event,
        match_details: None,
    });
    assert!(matches!(
        decision,
        ResponseDecision::Allowlisted { .. } | ResponseDecision::Terminate { .. }
    ));
    assert_eq!(
        [
            is_path_allowlisted(path, &yara_paths),
            ioc.is_hash_allowlisted(path),
            matches!(decision, ResponseDecision::Allowlisted { .. }),
        ],
        expected,
        "YARA, IOC, response: paths {paths:?}, path {path:?}",
    );
    drop(response);
    worker.await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn windows_defaults_scan_writable_folders_and_skip_system_binaries() {
    let paths = AppConfig::default().scanner.yara_allowlist_paths;
    check_paths(paths.clone(), r"C:\Windows\Temp\payload.exe", [false; 3]).await;
    check_paths(paths.clone(), r"C:\Windows\Tasks\payload.exe", [false; 3]).await;
    check_paths(
        paths.clone(),
        r"C:\Windows\System32\spool\drivers\color\payload.exe",
        [false; 3],
    )
    .await;
    check_paths(paths, r"C:\Windows\System32\cmd.exe", [true; 3]).await;
}

#[tokio::test]
async fn directory_boundaries_and_raw_ioc_prefixes_remain_distinct() {
    let root = if cfg!(windows) {
        "C:\\trusted"
    } else {
        "/trusted"
    };
    let sep = if cfg!(windows) { '\\' } else { '/' };
    check(root, &format!("{root}{sep}app"), [true, true, true]).await;
    check(root, &format!("{root}-other{sep}app"), [false, true, false]).await;
    check(root, root, [false, true, false]).await;
    check(
        &format!(" {root}{sep} "),
        &format!(" {root}{sep}app "),
        [true, true, true],
    )
    .await;
    check(
        &format!("{root}{sep}"),
        &format!("{root}-other{sep}app"),
        [false, false, false],
    )
    .await;
}

#[tokio::test]
async fn empty_prefixes_preserve_the_existing_ioc_match_all_behavior() {
    check("   ", "/any/path", [false, true, false]).await;
}

#[tokio::test]
async fn case_and_separator_contracts_are_platform_specific() {
    if cfg!(windows) {
        check("C:/TRUSTED", "c:\\trusted\\app.exe", [true, true, true]).await;
        check("c:\\trusted", "C:/TRUSTED/app.exe", [true, true, true]).await;
    } else {
        check("/Trusted", "/trusted/app", [false, false, true]).await;
        check("/Trusted", "/Trusted/app", [true, true, true]).await;
        check("/trusted", "/trusted\\app", [false, true, false]).await;
    }
}

#[tokio::test]
async fn excluded_directory_overrides_each_module_trust_prefix() {
    let (root, excluded, binary) = if cfg!(windows) {
        (
            r"C:\Trusted\",
            r"C:\Trusted\Writable\",
            r"C:\Trusted\System\app.exe",
        )
    } else {
        ("/trusted/", "/trusted/writable/", "/trusted/system/app")
    };
    let paths = vec![root.to_string(), format!("!{excluded}")];
    check_paths(paths.clone(), binary, [true; 3]).await;
    check_paths(paths.clone(), &format!("{excluded}payload"), [false; 3]).await;
    let sibling = format!(
        "{}Other/payload",
        excluded.trim_end_matches(&['/', '\\'][..])
    );
    check_paths(paths, &sibling, [true; 3]).await;
}
