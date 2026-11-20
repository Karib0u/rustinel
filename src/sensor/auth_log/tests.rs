//! Lines below were captured on Ubuntu 26.04 (OpenSSH 10.2p1, sudo-rs 0.2.13,
//! sudo 1.9 as `sudo.ws`, util-linux su) unless a test says otherwise.

use super::*;

const ROOT: (u32, u64) = (0, 0x1ff_ffff_ffff);
/// sudo and sudo-rs log with the invoker's real UID and every capability.
const SETUID: (u32, u64) = (1001, 0x1ff_ffff_ffff);
const USER: (u32, u64) = (1001, 0);

fn no_users(_: u32) -> Option<String> {
    None
}

/// The lab's accounts.
fn lab_users(uid: u32) -> Option<String> {
    match uid {
        0 => Some("root".into()),
        1001 => Some("authtest".into()),
        1002 => Some("authtest2".into()),
        _ => None,
    }
}

/// A record whose sender exited before journald read `/proc`: only the
/// kernel's `_UID` is left, as captured for classic sudo's refusal.
fn exited(identifier: &str, uid: u32, message: &str) -> JournalEntry {
    JournalEntry {
        comm: None,
        exe: None,
        identifier: Some(identifier.into()),
        uid: Some(uid),
        cap_effective: None,
        ..entry(identifier, ROOT, message)
    }
}

fn entry(comm: &str, sender: (u32, u64), message: &str) -> JournalEntry {
    JournalEntry {
        cursor: "s=15fc2ba76e6547fc8db29565b3577db7;i=5864f;b=1e7f3b75a2a14db29c7ba2324a72d3f2;m=5bf6a13;t=660b1f266f477;x=15987952613ed38c".into(),
        realtime_us: 1_795_167_252_575_351,
        seqnum: Some(362_063),
        message: message.into(),
        comm: Some(comm.into()),
        exe: Some(format!("/usr/bin/{comm}")),
        identifier: Some(comm.into()),
        pid: Some(4523),
        uid: Some(sender.0),
        cap_effective: Some(sender.1),
    }
}

struct Parsed {
    kind: AuthKind,
    program: Program,
    fields: AuthLogFields,
    event: RawEvent,
}

fn decode(comm: &str, sender: (u32, u64), message: &str) -> Parsed {
    let event = decode_record(&entry(comm, sender, message), no_users)
        .into_event()
        .expect("trusted sender");
    let RawPayload::AuthLog(fields) = &event.payload else {
        panic!("expected an auth log payload");
    };
    Parsed {
        kind: AuthKind::from_event_id(event.normalization.event_id).expect("known kind"),
        program: Program::from_code(event.normalization.action_code).expect("known program"),
        fields: fields.clone(),
        event,
    }
}

impl Parsed {
    fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name)
    }
}

#[test]
fn reads_journalctl_json_including_byte_arrays_and_repeated_fields() {
    let line = r#"{"__CURSOR":"s=15fc2ba76e6547fc8db29565b3577db7;i=5864f;b=1e7f3b75a2a14db29c7ba2324a72d3f2;m=5bf6a13;t=660b1f266f477;x=15987952613ed38c","__REALTIME_TIMESTAMP":"1795167252575351","__SEQNUM":"362063","_UID":"0","_PID":"6137","_COMM":"sshd-session","_EXE":"/usr/lib/openssh/sshd-session","SYSLOG_IDENTIFIER":["sshd-session","spoof"],"_CAP_EFFECTIVE":"1ffffffffff","MESSAGE":[73,110,118,97,108,105,100,32,117,115,101,114,32,255,32,102,114,111,109,32,49,46,50,46,51,46,52,32,112,111,114,116,32,53]}"#;
    let entry = JournalEntry::from_json(line).expect("valid record");
    assert_eq!(entry.realtime_us, 1_795_167_252_575_351);
    assert_eq!(entry.seqnum, Some(362_063));
    assert_eq!(entry.uid, Some(0));
    assert_eq!(entry.pid, Some(6137));
    assert_eq!(entry.cap_effective, Some(0x1ff_ffff_ffff));
    assert_eq!(entry.identifier.as_deref(), Some("sshd-session"));
    assert_eq!(entry.message, "Invalid user \u{fffd} from 1.2.3.4 port 5");
    assert_eq!(entry.sender(), SenderTrust::Privileged);

    let decoded = decode_record(&entry, no_users)
        .into_event()
        .expect("trusted");
    assert_eq!(
        decoded.normalization.event_id,
        AuthKind::SshInvalidUser.event_id()
    );
    assert_eq!(decoded.source_seq, Some(362_063));
    assert_eq!(decoded.pid, Some(6137));
}

#[test]
fn rejects_lines_journalctl_did_not_write() {
    for line in ["", "[]", "{", r#"{"MESSAGE":"x"}"#] {
        assert!(JournalEntry::from_json(line).is_err(), "{line}");
    }
    let bad_uid = r#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":"1","_UID":"root"}"#;
    assert_eq!(
        JournalEntry::from_json(bad_uid),
        Err(DecodeError::Invalid("_UID"))
    );
}

#[test]
fn a_forged_line_from_an_unprivileged_sender_is_dropped() {
    // `logger -p authpriv.notice -t sshd 'Accepted password for root ...'`
    // run as an ordinary user: journald records the logger's UID and its
    // empty capability set.
    let mut forged = entry(
        "logger",
        USER,
        "Accepted password for root from 9.9.9.9 port 22 ssh2",
    );
    forged.identifier = Some("sshd".into());
    assert_eq!(forged.sender(), SenderTrust::Unprivileged);
    assert!(matches!(
        decode_record(&forged, no_users),
        Decoded::Untrusted
    ));

    // A process that renames itself sshd is still unprivileged.
    let renamed = entry(
        "sshd",
        USER,
        "Accepted password for root from 9.9.9.9 port 22 ssh2",
    );
    assert!(matches!(
        decode_record(&renamed, no_users),
        Decoded::Untrusted
    ));

    // journald could not read the sender's credentials at all.
    let mut unknown = entry(
        "sshd",
        ROOT,
        "Accepted password for root from 9.9.9.9 port 22 ssh2",
    );
    unknown.uid = None;
    unknown.cap_effective = None;
    assert!(matches!(
        decode_record(&unknown, no_users),
        Decoded::Untrusted
    ));
}

#[test]
fn ssh_password_and_publickey_logins() {
    let password = decode(
        "sshd-session",
        ROOT,
        "Accepted password for authtest from 127.0.0.1 port 55046 ssh2",
    );
    assert_eq!(password.kind, AuthKind::SshAccepted);
    assert_eq!(password.program, Program::Sshd);
    assert_eq!(password.get("Outcome"), Some("success"));
    assert_eq!(password.get("Service"), Some("sshd"));
    assert_eq!(password.get("TargetUserName"), Some("authtest"));
    assert_eq!(password.get("AuthenticationMethod"), Some("password"));
    assert_eq!(password.get("SourceIp"), Some("127.0.0.1"));
    assert_eq!(password.get("SourcePort"), Some("55046"));
    assert_eq!(password.get("KeyFingerprint"), None);
    assert_eq!(password.event.action, SensorAction::Access);
    assert_eq!(password.event.provider, PROVIDER);

    let key = decode(
        "sshd-session",
        ROOT,
        "Accepted publickey for theo from 192.168.1.17 port 49625 ssh2: ED25519 SHA256:Vli+Xsf6MmHupHU08x5zsAnoZ8anU1Pjl9EUr8IimNE",
    );
    assert_eq!(key.kind, AuthKind::SshAccepted);
    assert_eq!(key.get("AuthenticationMethod"), Some("publickey"));
    assert_eq!(key.get("KeyType"), Some("ED25519"));
    assert_eq!(
        key.get("KeyFingerprint"),
        Some("SHA256:Vli+Xsf6MmHupHU08x5zsAnoZ8anU1Pjl9EUr8IimNE")
    );
    assert_eq!(key.get("SourceIp"), Some("192.168.1.17"));
}

#[test]
fn ssh_failures_valid_and_invalid_users_and_ipv6() {
    let failed = decode(
        "sshd-session",
        ROOT,
        "Failed password for authtest from 127.0.0.1 port 55048 ssh2",
    );
    assert_eq!(failed.kind, AuthKind::SshFailed);
    assert_eq!(failed.get("Outcome"), Some("failure"));
    assert_eq!(failed.get("TargetUserName"), Some("authtest"));
    assert_eq!(failed.get("InvalidUser"), None);

    let invalid = decode(
        "sshd-session",
        ROOT,
        "Failed password for invalid user nosuchuser from 127.0.0.1 port 55052 ssh2",
    );
    assert_eq!(invalid.kind, AuthKind::SshFailed);
    assert_eq!(invalid.get("TargetUserName"), Some("nosuchuser"));
    assert_eq!(invalid.get("InvalidUser"), Some("true"));

    let ipv6 = decode(
        "sshd-session",
        ROOT,
        "Failed password for authtest from ::1 port 40778 ssh2",
    );
    assert_eq!(ipv6.get("SourceIp"), Some("::1"));
    assert_eq!(ipv6.get("SourcePort"), Some("40778"));

    let probe = decode(
        "sshd-session",
        ROOT,
        "Invalid user nosuchuser2 from 127.0.0.1 port 55066",
    );
    assert_eq!(probe.kind, AuthKind::SshInvalidUser);
    assert_eq!(probe.get("Outcome"), Some("failure"));
    assert_eq!(probe.get("InvalidUser"), Some("true"));
    assert_eq!(probe.get("TargetUserName"), Some("nosuchuser2"));
}

#[test]
fn an_ssh_user_name_cannot_supply_the_source_address() {
    // `ssh 'evil from 6.6.6.6 port 1 ssh2'@127.0.0.1`: sshd prints the name
    // the client sent, then appends the real peer.
    let decoded = decode(
        "sshd-session",
        ROOT,
        "Invalid user evil from 6.6.6.6 port 1 ssh2 from 127.0.0.1 port 36568",
    );
    assert_eq!(decoded.kind, AuthKind::SshInvalidUser);
    assert_eq!(decoded.get("SourceIp"), Some("127.0.0.1"));
    assert_eq!(decoded.get("SourcePort"), Some("36568"));
    assert_eq!(
        decoded.get("TargetUserName"),
        Some("evil from 6.6.6.6 port 1 ssh2")
    );

    let failed = decode(
        "sshd-session",
        ROOT,
        "Failed password for invalid user x from 6.6.6.6 port 1 ssh2 from 10.0.0.9 port 2222 ssh2",
    );
    assert_eq!(failed.get("SourceIp"), Some("10.0.0.9"));
    assert_eq!(failed.get("SourcePort"), Some("2222"));
}

#[test]
fn a_host_name_never_becomes_a_source_ip() {
    // sshd with `UseDNS yes` prints the reverse name.
    let decoded = decode(
        "sshd",
        ROOT,
        "Failed password for root from attacker.example port 4242 ssh2",
    );
    assert_eq!(decoded.kind, AuthKind::SshFailed);
    assert_eq!(decoded.get("SourceIp"), None);
    assert_eq!(decoded.get("SourceHostname"), Some("attacker.example"));
}

#[test]
fn unclaimed_sshd_lines_keep_their_text_for_keyword_rules() {
    for message in [
        "Connection closed by authenticating user root 127.0.0.1 port 55078 [preauth]",
        "error: kex_exchange_identification: Connection closed by remote host",
        "Server listening on 0.0.0.0 port 22.",
        "Failed to generate curve25519 keys",
        "Accepted bogusmethod for root from 1.2.3.4 port 22 ssh2",
        "pam_unix(sshd:auth): check pass; user unknown",
    ] {
        let decoded = decode("sshd-session", ROOT, message);
        assert_eq!(decoded.kind, AuthKind::Other, "{message}");
        assert_eq!(decoded.program, Program::Sshd);
        assert_eq!(decoded.get("Message"), Some(message));
        assert_eq!(decoded.get("Outcome"), None);
        assert_eq!(decoded.get("Service"), None);
        assert_eq!(decoded.get("SourceIp"), None, "{message}");
    }
}

#[test]
fn pam_authentication_failures() {
    let sshd = decode(
        "sshd-session",
        ROOT,
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=authtest",
    );
    assert_eq!(sshd.kind, AuthKind::PamAuthFailure);
    assert_eq!(sshd.program, Program::Sshd);
    assert_eq!(sshd.get("Outcome"), Some("failure"));
    assert_eq!(sshd.get("Service"), Some("sshd"));
    assert_eq!(sshd.get("TargetUserName"), Some("authtest"));
    assert_eq!(sshd.get("SourceIp"), Some("127.0.0.1"));
    assert_eq!(sshd.get("SubjectUserId"), Some("0"));
    assert_eq!(sshd.get("Terminal"), Some("ssh"));
    assert_eq!(sshd.get("SubjectUserName"), None);

    // An unknown account: pam_unix leaves `user=` out.
    let unknown = decode(
        "sshd-session",
        ROOT,
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1",
    );
    assert_eq!(unknown.get("TargetUserName"), None);
    assert_eq!(unknown.get("SourceIp"), Some("127.0.0.1"));

    // sudo-rs writes nothing else for a wrong password.
    let sudo = decode(
        "sudo",
        SETUID,
        "pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty= ruser=authtest rhost=  user=authtest",
    );
    assert_eq!(sudo.kind, AuthKind::PamAuthFailure);
    assert_eq!(sudo.program, Program::Sudo);
    assert_eq!(sudo.get("Service"), Some("sudo"));
    assert_eq!(sudo.get("SubjectUserName"), Some("authtest"));
    assert_eq!(sudo.get("SubjectUserId"), Some("1001"));
    assert_eq!(sudo.get("TargetUserName"), Some("authtest"));
    assert_eq!(sudo.get("Terminal"), None);
    assert_eq!(sudo.get("SourceIp"), None);

    let su = decode(
        "su",
        SETUID,
        "pam_unix(su:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/1 ruser=authtest rhost=  user=authtest",
    );
    assert_eq!(su.program, Program::Su);
    assert_eq!(su.get("Service"), Some("su"));
    assert_eq!(su.get("Terminal"), Some("/dev/pts/1"));
}

#[test]
fn pam_sessions_open_and_close() {
    let opened = decode(
        "sshd-session",
        ROOT,
        "pam_unix(sshd:session): session opened for user theo(uid=1000) by theo(uid=0)",
    );
    assert_eq!(opened.kind, AuthKind::PamSessionOpened);
    assert_eq!(opened.get("Outcome"), None);
    assert_eq!(opened.get("Service"), Some("sshd"));
    assert_eq!(opened.get("TargetUserName"), Some("theo"));
    assert_eq!(opened.get("TargetUserId"), Some("1000"));
    assert_eq!(opened.get("SubjectUserName"), Some("theo"));
    assert_eq!(opened.get("SubjectUserId"), Some("0"));
    assert_eq!(opened.get("ProcessId"), Some("4523"));

    let sudo = decode(
        "sudo",
        SETUID,
        "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1001)",
    );
    assert_eq!(sudo.kind, AuthKind::PamSessionOpened);
    assert_eq!(sudo.get("TargetUserName"), Some("root"));
    assert_eq!(sudo.get("SubjectUserName"), None);
    assert_eq!(sudo.get("SubjectUserId"), Some("1001"));

    let su_l = decode(
        "su",
        ROOT,
        "pam_unix(su-l:session): session opened for user authtest(uid=1001) by (uid=0)",
    );
    assert_eq!(su_l.get("Service"), Some("su-l"));

    let closed = decode(
        "sshd-session",
        ROOT,
        "pam_unix(sshd:session): session closed for user authtest",
    );
    assert_eq!(closed.kind, AuthKind::PamSessionClosed);
    assert_eq!(closed.get("TargetUserName"), Some("authtest"));
    assert_eq!(closed.get("Outcome"), None);

    // A PAM session line from an unrelated privileged program.
    let cron = decode(
        "cron",
        ROOT,
        "pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
    );
    assert_eq!(cron.kind, AuthKind::PamSessionOpened);
    assert_eq!(cron.program, Program::Other);
    assert_eq!(cron.get("Service"), Some("cron"));
}

#[test]
fn sudo_rs_and_sudo_ws_command_lines() {
    let rs = decode(
        "sudo",
        SETUID,
        "authtest :  PWD=/home/authtest ; USER=root ; COMMAND=/usr/bin/true",
    );
    assert_eq!(rs.kind, AuthKind::SudoCommand);
    assert_eq!(rs.program, Program::Sudo);
    assert_eq!(rs.get("Outcome"), Some("success"));
    assert_eq!(rs.get("Service"), Some("sudo"));
    assert_eq!(rs.get("SubjectUserName"), Some("authtest"));
    assert_eq!(rs.get("TargetUserName"), Some("root"));
    assert_eq!(rs.get("USER"), Some("root"));
    assert_eq!(rs.get("PWD"), Some("/home/authtest"));
    assert_eq!(rs.get("COMMAND"), Some("/usr/bin/true"));
    assert_eq!(rs.get("TTY"), None);

    let ws = decode(
        "sudo.ws",
        SETUID,
        "theo : TTY=pts/0 ; PWD=/home/theo ; USER=root ; COMMAND=/usr/bin/tee /etc/cron.d/hunt-demo",
    );
    // `_COMM` is `sudo.ws` for the classic binary under that name; the
    // identifier it logs under still says sudo.
    assert_eq!(ws.program, Program::Sudo);
    assert_eq!(ws.kind, AuthKind::SudoCommand);
    assert_eq!(ws.get("TTY"), Some("pts/0"));
    assert_eq!(
        ws.get("COMMAND"),
        Some("/usr/bin/tee /etc/cron.d/hunt-demo")
    );

    // A command that legitimately contains ` ; ` keeps all of it.
    let shell = decode(
        "sudo",
        SETUID,
        "theo : TTY=pts/0 ; PWD=/home/theo ; USER=root ; COMMAND=/usr/bin/sh -c a ; b",
    );
    assert_eq!(shell.get("COMMAND"), Some("/usr/bin/sh -c a ; b"));
    assert_eq!(shell.get("USER"), Some("root"));
}

#[test]
fn sudo_refusals() {
    let not_allowed = decode(
        "sudo.ws",
        SETUID,
        "authtest2 : user NOT in sudoers ; PWD=/home/authtest2 ; USER=root ; COMMAND=/usr/bin/true",
    );
    assert_eq!(not_allowed.kind, AuthKind::SudoRefused);
    assert_eq!(not_allowed.get("Outcome"), Some("failure"));
    assert_eq!(not_allowed.get("Reason"), Some("user NOT in sudoers"));
    assert_eq!(not_allowed.get("SubjectUserName"), Some("authtest2"));
    assert_eq!(not_allowed.get("USER"), Some("root"));

    let attempts = decode(
        "sudo.ws",
        SETUID,
        "authtest : 3 incorrect password attempts ; PWD=/home/authtest ; USER=root ; COMMAND=/usr/bin/true",
    );
    assert_eq!(attempts.kind, AuthKind::SudoRefused);
    assert_eq!(
        attempts.get("Reason"),
        Some("3 incorrect password attempts")
    );

    // CVE-2019-14287's `-u#-1`, which SigmaHQ selects as `USER: '#-*'`.
    let cve = decode(
        "sudo.ws",
        SETUID,
        "authtest : unknown user #-1 ; PWD=/home/authtest ; USER=#-1 ;",
    );
    assert_eq!(cve.kind, AuthKind::SudoRefused);
    assert_eq!(cve.get("Reason"), Some("unknown user #-1"));
    assert_eq!(cve.get("USER"), Some("#-1"));
    assert_eq!(cve.get("COMMAND"), None);
}

#[test]
fn a_crafted_sudo_working_directory_cannot_choose_the_target_user() {
    // `cd '/tmp/inj ; USER=evil ; COMMAND=/bin/fake'; sudo echo ' ; USER=evil2'`
    // as logged by sudo-rs and by sudo.ws.
    for (comm, message) in [
        (
            "sudo",
            "authtest :  PWD=/tmp/inj ; USER=evil ; COMMAND=/bin/fake ; USER=root ; COMMAND=/usr/bin/echo  ; USER=evil2",
        ),
        (
            "sudo.ws",
            "authtest : PWD=/tmp/inj ; USER=evil ; COMMAND=/bin/fake ; USER=root ; COMMAND=/usr/bin/echo ' ; USER=evil2'",
        ),
        // Only the command imitates a key.
        (
            "sudo",
            "authtest :  PWD=/home/authtest ; USER=root ; COMMAND=/usr/bin/echo  ; USER=evil2",
        ),
    ] {
        let decoded = decode(comm, SETUID, message);
        assert_eq!(decoded.kind, AuthKind::SudoCommand, "{message}");
        assert_eq!(decoded.get("SubjectUserName"), Some("authtest"));
        for key in ["USER", "TargetUserName", "PWD", "COMMAND", "TTY"] {
            assert_eq!(decoded.get(key), None, "{key} in {message}");
        }
        assert_eq!(decoded.get("Message"), Some(message));
    }
}

#[test]
fn su_switches_and_refusals() {
    let success = decode("su", SETUID, "(to authtest) authtest on pts/0");
    assert_eq!(success.kind, AuthKind::SuSuccess);
    assert_eq!(success.program, Program::Su);
    assert_eq!(success.get("Outcome"), Some("success"));
    assert_eq!(success.get("Service"), Some("su"));
    assert_eq!(success.get("TargetUserName"), Some("authtest"));
    assert_eq!(success.get("SubjectUserName"), Some("authtest"));
    assert_eq!(success.get("Terminal"), Some("pts/0"));

    let root = decode("su", ROOT, "(to authtest) root on none");
    assert_eq!(root.get("SubjectUserName"), Some("root"));
    assert_eq!(root.get("Terminal"), Some("none"));

    let failed = decode("su", SETUID, "FAILED SU (to authtest) authtest on pts/1");
    assert_eq!(failed.kind, AuthKind::SuFailed);
    assert_eq!(failed.get("Outcome"), Some("failure"));
    assert_eq!(failed.get("Terminal"), Some("pts/1"));
}

#[test]
fn other_privileged_writers_are_kept_unparsed() {
    let decoded = decode(
        "systemd-logind",
        ROOT,
        "New session '14' of user 'authtest2' with class 'manager' and type 'unspecified'.",
    );
    assert_eq!(decoded.kind, AuthKind::Other);
    assert_eq!(decoded.program, Program::Other);
    assert_eq!(decoded.get("Program"), Some("systemd-logind"));
    assert_eq!(decoded.get("Image"), Some("/usr/bin/systemd-logind"));

    // A program outside the parsed families cannot be read as sshd.
    let pkexec = decode(
        "pkexec",
        ROOT,
        "Accepted password for root from 1.2.3.4 port 22 ssh2",
    );
    assert_eq!(pkexec.kind, AuthKind::Other);
    assert_eq!(pkexec.get("SourceIp"), None);
}

#[test]
fn a_long_line_is_cut_marked_and_left_unparsed() {
    let user = "u".repeat(MAX_MESSAGE_BYTES);
    let message = format!("Invalid user {user} from 1.2.3.4 port 22");
    let decoded = decode("sshd-session", ROOT, &message);
    assert_eq!(decoded.kind, AuthKind::Other);
    assert_eq!(
        decoded.get("Message").map(str::len),
        Some(MAX_MESSAGE_BYTES)
    );
    assert!(decoded
        .event
        .provenance
        .has("Message", crate::models::Fidelity::Truncated));
    assert_eq!(decoded.get("SourceIp"), None);

    // The cut never splits a character.
    let wide = format!("{}é", "a".repeat(MAX_MESSAGE_BYTES - 1));
    let decoded = decode("sshd-session", ROOT, &wide);
    assert_eq!(
        decoded.get("Message").map(str::len),
        Some(MAX_MESSAGE_BYTES - 1)
    );
}

#[test]
fn cursor_positions() {
    assert_eq!(
        cursor_position(
            "s=15fc2ba76e6547fc8db29565b3577db7;i=5864f;b=1e7f;m=5bf6a13;t=660b;x=1598"
        ),
        Some(("15fc2ba76e6547fc8db29565b3577db7", 0x5864f))
    );
    assert_eq!(cursor_position("garbage"), None);
    assert_eq!(cursor_position("s=short;i=1"), None);
    assert_eq!(
        cursor_position("s=15fc2ba76e6547fc8db29565b3577db7;i=zz"),
        None
    );
}

#[test]
fn numbering_is_stable() {
    // Recordings and rules depend on these numbers; never renumber.
    let ids: Vec<u16> = AuthKind::ALL.iter().map(|kind| kind.event_id()).collect();
    assert_eq!(ids, (0..=10).collect::<Vec<_>>());
    let codes: Vec<u8> = Program::ALL.iter().map(|program| program.code()).collect();
    assert_eq!(codes, vec![0, 1, 2, 3]);
    assert_eq!(Program::Sshd.sigma_service(), Some("sshd"));
    assert_eq!(Program::Sudo.sigma_service(), Some("sudo"));
    assert_eq!(Program::Su.sigma_service(), None);
}

#[test]
fn a_sudo_refusal_from_an_exited_sender_is_kept_when_it_names_its_own_uid() {
    // Captured live: `_UID=1002`, no `_COMM`, `_EXE` or `_CAP_EFFECTIVE`.
    let refusal = exited(
        "sudo",
        1002,
        "authtest2 : user NOT in sudoers ; PWD=/home/authtest2 ; USER=root ; COMMAND=/usr/bin/true",
    );
    assert_eq!(refusal.sender(), SenderTrust::CapabilitiesUnknown(1002));
    let Decoded::AcceptedSameUser(event) = decode_record(&refusal, lab_users) else {
        panic!("a refusal naming its own sender is kept");
    };
    assert_eq!(
        event.normalization.event_id,
        AuthKind::SudoRefused.event_id()
    );
    assert_eq!(event.normalization.action_code, Program::Sudo.code());

    // Without a name for the UID the record cannot be checked.
    assert!(matches!(
        decode_record(&refusal, no_users),
        Decoded::Untrusted
    ));
}

#[test]
fn an_exited_sender_cannot_write_about_another_user_or_as_sshd() {
    // uid 1001 writing a sudo line about authtest2.
    let other_user = exited(
        "sudo",
        1001,
        "authtest2 : user NOT in sudoers ; PWD=/home/authtest2 ; USER=root ; COMMAND=/usr/bin/true",
    );
    assert!(matches!(
        decode_record(&other_user, lab_users),
        Decoded::Untrusted
    ));

    // sshd always logs as root; a non-root sshd record is a forgery.
    let sshd = exited(
        "sshd",
        1001,
        "Accepted password for authtest from 9.9.9.9 port 22 ssh2",
    );
    assert!(matches!(
        decode_record(&sshd, lab_users),
        Decoded::Untrusted
    ));

    // An unparsed or invoker-less line has nothing to check.
    for message in [
        "authtest got root",
        "pam_unix(sudo:session): session closed for user root",
    ] {
        let line = exited("sudo", 1001, message);
        assert!(
            matches!(decode_record(&line, lab_users), Decoded::Untrusted),
            "{message}"
        );
    }

    // The same user's own su failure and PAM lines pass.
    for message in [
        "FAILED SU (to root) authtest on pts/1",
        "pam_unix(su:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/1 ruser=authtest rhost=  user=root",
        "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1001)",
    ] {
        let identifier = if message.contains("sudo") { "sudo" } else { "su" };
        let line = exited(identifier, 1001, message);
        assert!(
            matches!(decode_record(&line, lab_users), Decoded::AcceptedSameUser(_)),
            "{message}"
        );
    }
}

#[test]
fn a_resume_is_checked_against_the_oldest_record() {
    let cursor = |id: &str, seqnum: u64| {
        format!("s={id};i={seqnum:x};b=1e7f3b75a2a14db29c7ba2324a72d3f2;m=1;t=1;x=1")
    };
    let ours = "15fc2ba76e6547fc8db29565b3577db7";
    // The lab journal, never vacuumed, still starts at 1.
    assert_eq!(
        resume_check(&cursor(ours, 0x592e3), &cursor(ours, 1)),
        ResumeCheck::Continuous
    );
    // The record right after the cursor is the oldest: nothing was lost.
    assert_eq!(
        resume_check(&cursor(ours, 100), &cursor(ours, 101)),
        ResumeCheck::Continuous
    );
    assert_eq!(
        resume_check(&cursor(ours, 100), &cursor(ours, 102)),
        ResumeCheck::RetentionPassed {
            saved: 100,
            oldest: 102
        }
    );
    assert_eq!(
        resume_check(
            &cursor(ours, 100),
            &cursor("0123456789abcdef0123456789abcdef", 1)
        ),
        ResumeCheck::ForeignSequence
    );
    assert_eq!(
        resume_check("garbage", &cursor(ours, 1)),
        ResumeCheck::Unknown
    );
}
