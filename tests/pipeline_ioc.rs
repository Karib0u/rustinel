#[cfg(test)]
mod common;

use common::{
    assert_ecs_field_eq, assert_ecs_field_present, dns_query_event, ecs_json, file_create_event,
    network_connect_event, process_start_event, IocFixture, TestNormalizer, TEST_DESTINATION_IP,
    TEST_DOMAIN, TEST_PID,
};
use rustinel::{
    ioc::{HashCache, IocEngine},
    sensor::Platform,
};

#[test]
fn domain_ioc_matches_exact_and_suffix_dns_events() {
    let fixture = IocFixture::new();
    fixture.write_domains(&format!("{TEST_DOMAIN}; exact\n.example.test; suffix\n"));
    let engine = IocEngine::load(&fixture.config());
    let harness = TestNormalizer::new(false);

    let event = harness
        .normalizer
        .normalize(&dns_query_event(Platform::Linux))
        .expect("dns event should normalize");
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 2);

    let alert = engine.build_alert_for_match(&matches[0], &event);
    let json = ecs_json(&alert);
    assert_ecs_field_eq(&json, "dns.question.name", TEST_DOMAIN);
    assert_ecs_field_eq(&json, "edr.rule.engine", "Ioc");
    assert!(json["rule.name"]
        .as_str()
        .expect("rule name")
        .starts_with("ioc:domain:"));
}

#[test]
fn ip_ioc_matches_network_and_dns_response_ips() {
    let fixture = IocFixture::new();
    fixture.write_ips(&format!(
        "{TEST_DESTINATION_IP}; exact\n198.51.100.0/24; cidr\n"
    ));
    let engine = IocEngine::load(&fixture.config());
    let harness = TestNormalizer::new(true);

    let network = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("network event should normalize");
    assert_eq!(engine.check_event(&network).len(), 2);

    let repeated_network = harness
        .normalizer
        .normalize(&network_connect_event(Platform::Linux))
        .expect("repeated network event should remain available to IOC detection");
    assert_eq!(engine.check_event(&repeated_network).len(), 2);

    let dns = harness
        .normalizer
        .normalize(&dns_query_event(Platform::Linux))
        .expect("dns event should normalize");
    let matches = engine.check_event(&dns);
    assert_eq!(matches.len(), 2);

    let alert = engine.build_alert_for_match(&matches[0], &dns);
    let json = ecs_json(&alert);
    assert_ecs_field_eq(&json, "dns.question.name", TEST_DOMAIN);
    assert_ecs_field_present(&json, "related.ip");
}

#[test]
fn path_regex_ioc_matches_process_and_file_paths() {
    let fixture = IocFixture::new();
    fixture.write_paths_regex(r"(?i)(curl|rustinel-fixture)\.(exe|txt); suspicious path");
    let engine = IocEngine::load(&fixture.config());
    let harness = TestNormalizer::new(false);

    let process = harness
        .normalizer
        .normalize(&process_start_event(Platform::Windows))
        .expect("process event should normalize");
    let process_matches = engine.check_event(&process);
    assert_eq!(process_matches.len(), 1);
    let alert = engine.build_alert_for_match(&process_matches[0], &process);
    assert!(alert
        .rule_description
        .as_deref()
        .expect("description")
        .contains("source:"));
    assert_ecs_field_present(&ecs_json(&alert), "process.executable");

    let file = harness
        .normalizer
        .normalize(&file_create_event(Platform::Linux))
        .expect("file event should normalize");
    let file_matches = engine.check_event(&file);
    assert_eq!(file_matches.len(), 1);
    assert_ecs_field_present(
        &ecs_json(&engine.build_alert_for_match(&file_matches[0], &file)),
        "file.path",
    );
}

#[test]
fn hash_ioc_pipeline_detects_required_hashes_and_respects_limits_and_allowlist() {
    let tempdir = tempfile::tempdir().expect("create hash tempdir");
    let sample = tempdir.path().join("sample.bin");
    std::fs::write(&sample, b"rustinel hash fixture").expect("write sample");

    let mut cache = HashCache::new();
    let requirements = rustinel::ioc::HashRequirements {
        md5: true,
        sha1: true,
        sha256: true,
    };
    let mut buf = [0u8; 8192];
    let hashes = cache
        .get_or_compute(&sample, requirements, &mut buf)
        .expect("compute hashes");

    let fixture = IocFixture::new();
    fixture.write_hashes(&format!(
        "{}; md5\n{}; sha1\n{}; sha256\n",
        hashes.md5.as_deref().unwrap(),
        hashes.sha1.as_deref().unwrap(),
        hashes.sha256.as_deref().unwrap()
    ));
    let mut cfg = fixture.config();
    cfg.max_file_size_mb = 0;
    cfg.hash_allowlist_paths = vec![tempdir.path().display().to_string()];

    let engine = IocEngine::load(&cfg);
    let req = engine.hash_requirements();
    assert!(req.md5 && req.sha1 && req.sha256);
    assert_eq!(engine.max_file_size_bytes(), 0);
    assert!(engine.is_hash_allowlisted(sample.to_str().unwrap()));

    let matches = engine.match_hashes(&hashes);
    assert_eq!(matches.len(), 3);
    let alert = engine.build_alert_for_hash_match(
        &matches[0],
        sample.to_str().unwrap(),
        TEST_PID,
        Platform::Linux,
        "ebpf",
    );
    assert_ecs_field_eq(&ecs_json(&alert), "edr.rule.engine", "Ioc");
}
