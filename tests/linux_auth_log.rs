//! Linux auth journal records through normalization, routing, detection and
//! ECS output, from `journalctl --output=json` lines shaped like the ones
//! captured on Ubuntu 26.04 (OpenSSH 10.2p1, sudo-rs, classic sudo, su).

mod common;

use common::{assert_ecs_field_eq, ecs_json, SigmaFixture, TestNormalizer};
use rustinel::config::AppConfig;
use rustinel::engine::compatibility::{analyze_rules, CompatibilityVerdict};
use rustinel::engine::{Engine, LogSource, LogSourceStatus, SigmaMatchMode};
use rustinel::field_availability::{availability_for_event, missing_always_fields, Availability};
use rustinel::models::{EventCategory, NormalizedEvent};
use rustinel::sensor::auth_log::{decode_record, AuthKind, JournalEntry, Program};
use rustinel::sensor::Platform;
use serde_json::json;

/// 2026-11-20T09:34:12Z, in journald microseconds.
const BASE_US: u64 = 1_795_167_252_000_000;

/// One `journalctl --output=json` line.
fn journal_line(offset_secs: u64, comm: &str, uid: u32, caps: &str, message: &str) -> String {
    json!({
        "__CURSOR": format!("s=15fc2ba76e6547fc8db29565b3577db7;i={:x};b=1e7f3b75a2a14db29c7ba2324a72d3f2;m=1;t=1;x=1", 0x58000 + offset_secs),
        "__REALTIME_TIMESTAMP": (BASE_US + offset_secs * 1_000_000).to_string(),
        "_UID": uid.to_string(),
        "_GID": uid.to_string(),
        "_PID": (5000 + offset_secs).to_string(),
        "_COMM": comm,
        "_EXE": format!("/usr/sbin/{comm}"),
        "_CAP_EFFECTIVE": caps,
        "SYSLOG_IDENTIFIER": comm,
        "SYSLOG_FACILITY": "4",
        "_TRANSPORT": "syslog",
        "MESSAGE": message,
    })
    .to_string()
}

fn normalize(line: &str) -> Option<NormalizedEvent> {
    let entry = JournalEntry::from_json(line).expect("journal record");
    let raw = decode_record(&entry, |_| None).into_event()?;
    TestNormalizer::new().normalizer.normalize(&raw)
}

fn sshd(offset_secs: u64, message: &str) -> NormalizedEvent {
    normalize(&journal_line(
        offset_secs,
        "sshd-session",
        0,
        "1ffffffffff",
        message,
    ))
    .expect("trusted sshd record")
}

/// Every matching rule fires, so a test sees each route, not only the best.
fn engine(fixture: &SigmaFixture) -> Engine {
    let mut engine =
        Engine::new_for_platform(Platform::Linux).with_sigma_match_mode(SigmaMatchMode::All);
    engine.load_rules(fixture.rules_dir()).expect("rules load");
    engine
}

fn fired(engine: &Engine, event: &NormalizedEvent) -> Vec<String> {
    engine
        .check_event(event)
        .into_iter()
        .map(|alert| alert.rule_name)
        .collect()
}

#[test]
fn auth_sshd_and_sudo_logsources_are_active_on_linux_only() {
    let linux = Engine::new_for_platform(Platform::Linux);
    for service in ["auth", "sshd", "sudo"] {
        let classification = linux.classify_logsource(&LogSource {
            product: Some("linux".to_string()),
            service: Some(service.to_string()),
            category: None,
        });
        assert_eq!(
            classification.status,
            LogSourceStatus::Supported,
            "{service}"
        );
        assert_eq!(classification.collector_active, Some(true), "{service}");
    }
    // Still deferred: no collector reads these.
    let cron = linux.classify_logsource(&LogSource {
        product: Some("linux".to_string()),
        service: Some("cron".to_string()),
        category: None,
    });
    assert_eq!(cron.status, LogSourceStatus::Deferred);
}

#[test]
fn a_failed_login_count_correlation_fires_per_source_address() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "ssh_failed.yml",
        r#"title: SSH Failed Login
id: 3e6a9a6f-1f4b-4a43-9a43-0b6f0c3c6a01
logsource:
  product: linux
  service: sshd
detection:
  selection:
    EventID: 2
    Outcome: failure
  condition: selection
level: low
"#,
    );
    fixture.write_rule(
        "ssh_bruteforce.yml",
        r#"title: SSH Brute Force
id: 3e6a9a6f-1f4b-4a43-9a43-0b6f0c3c6a02
correlation:
  type: event_count
  rules:
    - 3e6a9a6f-1f4b-4a43-9a43-0b6f0c3c6a01
  group-by:
    - SourceIp
  timespan: 5m
  condition:
    gte: 5
level: high
"#,
    );
    let engine = engine(&fixture);
    assert!(engine.stats().failed_rules.is_empty());
    assert!(engine.stats().unsupported_rules.is_empty());

    // A spray from 203.0.113.7 interleaved with a slower source and with the
    // other lines sshd writes for the same attempts, which must not count.
    let mut correlations = Vec::new();
    for attempt in 0..5u64 {
        let base = attempt * 10;
        for event in [
            sshd(
                base,
                &format!(
                    "Invalid user admin{attempt} from 203.0.113.7 port {}",
                    40000 + attempt
                ),
            ),
            sshd(
                base + 1,
                "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7",
            ),
            sshd(
                base + 2,
                &format!(
                    "Failed password for invalid user admin{attempt} from 203.0.113.7 port {} ssh2",
                    40000 + attempt
                ),
            ),
            sshd(
                base + 3,
                &format!(
                    "Failed password for root from 198.51.100.4 port {} ssh2",
                    50000 + attempt
                ),
            ),
        ] {
            for name in fired(&engine, &event) {
                if name == "SSH Brute Force" {
                    correlations.push((base, event.get_field("SourceIp").map(str::to_string)));
                }
            }
        }
    }
    // Five attempts from 203.0.113.7 trip the threshold on the fifth; the
    // second source also reaches five, on its own line.
    assert_eq!(
        correlations,
        vec![
            (40, Some("203.0.113.7".to_string())),
            (40, Some("198.51.100.4".to_string())),
        ]
    );
}

#[test]
fn a_correlation_does_not_fire_below_its_threshold() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "ssh_failed.yml",
        "title: SSH Failed Login\nid: 9b0d0c0e-0000-4000-8000-000000000001\nlogsource:\n  product: linux\n  service: sshd\ndetection:\n  selection:\n    EventID: 2\n  condition: selection\n",
    );
    fixture.write_rule(
        "ssh_bruteforce.yml",
        "title: SSH Brute Force\ncorrelation:\n  type: event_count\n  rules:\n    - 9b0d0c0e-0000-4000-8000-000000000001\n  group-by:\n    - SourceIp\n  timespan: 5m\n  condition:\n    gte: 5\n",
    );
    let engine = engine(&fixture);
    for attempt in 0..4u64 {
        let names = fired(
            &engine,
            &sshd(
                attempt,
                &format!("Failed password for root from 192.0.2.9 port {attempt} ssh2"),
            ),
        );
        assert_eq!(names, ["SSH Failed Login"]);
    }
}

#[test]
fn sigmahq_sshd_sudo_and_auth_rules_match_their_records_only() {
    let fixture = SigmaFixture::new();
    // SigmaHQ lnx_sshd_exploit_cve_2023_2283 (keywords over the sshd log).
    fixture.write_rule(
        "libssh.yml",
        "title: libssh CVE-2023-2283\nlogsource:\n  product: linux\n  service: sshd\ndetection:\n  keywords:\n    - 'Failed to generate curve25519 keys'\n  condition: keywords\n",
    );
    // SigmaHQ lnx_sudo_exploit_cve_2019_14287.
    fixture.write_rule(
        "sudo_cve.yml",
        "title: sudo CVE-2019-14287\nlogsource:\n  product: linux\n  service: sudo\ndetection:\n  selection_user:\n    USER:\n      - '#-*'\n      - '#*4294967295'\n  condition: selection_user\n",
    );
    fixture.write_rule(
        "auth_any.yml",
        "title: Any auth failure\nlogsource:\n  product: linux\n  service: auth\ndetection:\n  selection:\n    Outcome: failure\n  condition: selection\n",
    );
    let engine = engine(&fixture);
    assert_eq!(engine.stats().total_rules, 3);

    let libssh = sshd(0, "Failed to generate curve25519 keys");
    assert_eq!(fired(&engine, &libssh), ["libssh CVE-2023-2283"]);

    let sudo_cve = normalize(&journal_line(
        1,
        "sudo",
        1001,
        "1ffffffffff",
        "authtest : unknown user #-1 ; PWD=/home/authtest ; USER=#-1 ;",
    ))
    .unwrap();
    let mut names = fired(&engine, &sudo_cve);
    names.sort();
    assert_eq!(names, ["Any auth failure", "sudo CVE-2019-14287"]);

    // The same keyword in a sudo record is not an sshd record.
    let sudo_echo = normalize(&journal_line(
        2,
        "sudo",
        1001,
        "1ffffffffff",
        "theo : TTY=pts/0 ; PWD=/home/theo ; USER=root ; COMMAND=/usr/bin/echo Failed to generate curve25519 keys",
    ))
    .unwrap();
    assert!(fired(&engine, &sudo_echo).is_empty());

    // su failures answer to `service: auth` but not to sshd or sudo.
    let su = normalize(&journal_line(
        3,
        "su",
        1001,
        "1ffffffffff",
        "FAILED SU (to root) authtest on pts/1",
    ))
    .unwrap();
    assert_eq!(fired(&engine, &su), ["Any auth failure"]);
}

#[test]
fn a_forged_unprivileged_line_never_reaches_a_rule() {
    // `logger -p authpriv.notice -t sshd 'Accepted password for root ...'`
    // as uid 1001: no capabilities.
    let forged = journal_line(
        0,
        "logger",
        1001,
        "0",
        "Accepted password for root from 9.9.9.9 port 22 ssh2",
    );
    assert!(normalize(&forged).is_none());
}

#[test]
fn normalized_records_keep_their_contract_and_survive_a_recording() {
    let cases = [
        (
            sshd(0, "Accepted publickey for theo from 192.168.1.17 port 49625 ssh2: ED25519 SHA256:Vli+Xsf6MmHupHU08x5zsAnoZ8anU1Pjl9EUr8IimNE"),
            AuthKind::SshAccepted,
            Program::Sshd,
        ),
        (
            sshd(1, "pam_unix(sshd:session): session closed for user theo"),
            AuthKind::PamSessionClosed,
            Program::Sshd,
        ),
        (
            sshd(2, "Server listening on 0.0.0.0 port 22."),
            AuthKind::Other,
            Program::Sshd,
        ),
    ];
    for (event, kind, program) in cases {
        assert_eq!(event.category, EventCategory::AuthLog);
        assert_eq!(event.platform, Platform::Linux);
        assert_eq!(event.provider, "journald");
        assert_eq!(event.event_id, kind.event_id());
        assert_eq!(event.opcode, program.code());
        // journald's receive time, not the sender's own clock.
        assert!(
            event.timestamp.starts_with("2026-11-20T09:34:1"),
            "{}",
            event.timestamp
        );
        assert!(
            missing_always_fields(&event).is_empty(),
            "{kind:?}: {:?}",
            missing_always_fields(&event)
        );
        let replay: NormalizedEvent =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&replay.fields).unwrap(),
            serde_json::to_value(&event.fields).unwrap()
        );
        assert_eq!(replay.category, EventCategory::AuthLog);
        assert_eq!(replay.get_field("Message"), event.get_field("Message"));
    }
}

#[test]
fn field_availability_reports_what_each_record_lacks() {
    let closed = sshd(0, "pam_unix(sshd:session): session closed for user theo");
    assert!(matches!(
        availability_for_event(&closed, "SourceIp"),
        Some(Availability::Never(_))
    ));
    let accepted = sshd(
        1,
        "Accepted password for authtest from 127.0.0.1 port 55046 ssh2",
    );
    assert!(matches!(
        availability_for_event(&accepted, "TargetUserName"),
        Some(Availability::Always)
    ));
    assert!(matches!(
        availability_for_event(&accepted, "KeyFingerprint"),
        Some(Availability::Conditional(_))
    ));

    // A rule that needs a remote address on a session-close record can never
    // fire, and doctor says so.
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "close_ip.yml",
        "title: Close from address\nlogsource:\n  product: linux\n  service: sshd\ndetection:\n  selection:\n    EventID: 6\n    SourceIp: 203.0.113.7\n  condition: selection\n",
    );
    let report = analyze_rules(fixture.rules_dir(), Platform::Linux, &AppConfig::default())
        .expect("analyze auth rule");
    assert_eq!(
        report.documents[0].verdict,
        CompatibilityVerdict::CanNeverFire
    );
}

#[test]
fn alerts_carry_ecs_authentication_fields() {
    let fixture = SigmaFixture::new();
    fixture.write_rule(
        "any.yml",
        "title: Any auth\nlogsource:\n  product: linux\n  service: auth\ndetection:\n  selection:\n    Service|exists: true\n  condition: selection\n",
    );
    let engine = engine(&fixture);

    let failed = sshd(
        0,
        "Failed password for invalid user admin from 203.0.113.7 port 40001 ssh2",
    );
    let alert = engine.check_event(&failed).remove(0);
    let ecs = ecs_json(&alert);
    assert_ecs_field_eq(&ecs, "event.category", json!(["authentication"]));
    assert_ecs_field_eq(&ecs, "event.type", json!(["start"]));
    assert_ecs_field_eq(&ecs, "event.action", "ssh-login-failed");
    assert_ecs_field_eq(&ecs, "event.outcome", "failure");
    assert_ecs_field_eq(&ecs, "event.dataset", "edr.auth_log");
    assert_ecs_field_eq(&ecs, "source.ip", "203.0.113.7");
    assert_ecs_field_eq(&ecs, "source.port", 40001);
    assert_ecs_field_eq(&ecs, "user.name", "admin");
    assert_ecs_field_eq(&ecs, "process.pid", 5000);
    assert_eq!(
        ecs["edr.auth_log"]["InvalidUser"],
        json!("true"),
        "the full record rides along"
    );

    // sudo names the person acting, not the account they became.
    let sudo = normalize(&journal_line(
        1,
        "sudo",
        1001,
        "1ffffffffff",
        "authtest :  PWD=/home/authtest ; USER=root ; COMMAND=/usr/bin/true",
    ))
    .unwrap();
    let ecs = ecs_json(&engine.check_event(&sudo).remove(0));
    assert_ecs_field_eq(&ecs, "user.name", "authtest");
    assert_ecs_field_eq(&ecs, "event.outcome", "success");
    assert_ecs_field_eq(&ecs, "event.action", "sudo-command");

    let opened = sshd(
        2,
        "pam_unix(sshd:session): session opened for user theo(uid=1000) by theo(uid=0)",
    );
    let ecs = ecs_json(&engine.check_event(&opened).remove(0));
    assert_ecs_field_eq(&ecs, "event.category", json!(["session"]));
    assert!(ecs.get("event.outcome").is_none());
}
