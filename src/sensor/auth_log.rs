//! Linux authentication log records from the systemd journal.
//!
//! The journal reader in `sensor::linux::journal` feeds every `auth` and
//! `authpriv` syslog record through [`decode_record`]. This module is the
//! platform-neutral half: the sender trust gate and the bounded parsers that
//! turn sshd, PAM, sudo and su lines into one `auth_log` event.
//!
//! # Trust
//!
//! Any local user can write a syslog line that claims to be sshd:
//! `logger -t sshd 'Accepted password for root from 9.9.9.9 port 22 ssh2'`.
//! `SYSLOG_IDENTIFIER`, `MESSAGE` and `SYSLOG_FACILITY` are all chosen by the
//! sender. A record is only decoded when journald itself attests that the
//! sender was privileged: `_UID` is 0 (sshd, su) or `_CAP_EFFECTIVE` is not
//! empty (sudo and sudo-rs log with the invoker's real UID but hold every
//! capability). `_UID` comes from the kernel's socket credentials and
//! `_CAP_EFFECTIVE` from `/proc/<pid>/status`, never from the client.
//!
//! journald reads `/proc` after the record arrives, so a sender that exits at
//! once loses `_CAP_EFFECTIVE`, `_COMM` and `_EXE`. Classic sudo does exactly
//! that when it refuses a user (`user NOT in sudoers`). Such a record, with a
//! non-zero UID and no capability set, is accepted only from sudo or su and
//! only when the invoker the line names is the sender's own UID: a forger can
//! then write only about themselves, never about another user and never as
//! sshd. See [`SenderTrust`].
//!
//! Privileged programs still echo attacker-chosen text: an SSH user name, the
//! sudo working directory and command. Each parser anchors on the part the
//! program writes itself and leaves a field absent rather than guess when the
//! line is ambiguous. `Message` always keeps the full line.
//!
//! # Event numbering
//!
//! Sigma routes `auth_log` events by `(category, event_id, opcode)` alone, so
//! the opcode carries the program family ([`Program`]) that decides
//! `service: sshd` and `service: sudo`, and the event ID carries what the line
//! asserts ([`AuthKind`]).

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::models::AuthLogFields;
use crate::sensor::{Platform, RawEvent, RawPayload, SensorAction, SensorNormalization};

pub use crate::models::auth_log::{AuthKind, Program, PROVIDER};

/// Longest `Message` kept, in bytes. Longer lines are cut on a character
/// boundary and marked truncated.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// Syslog facilities the reader subscribes to: `auth` (4) and `authpriv` (10).
pub const AUTH_FACILITIES: [u8; 2] = [4, 10];

/// Journal fields one record carries, as `journalctl --output=json` prints
/// them. Unknown fields are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalEntry {
    pub cursor: String,
    /// `__REALTIME_TIMESTAMP`: when journald received the record, in
    /// microseconds. The client's own `_SOURCE_REALTIME_TIMESTAMP` is not used.
    pub realtime_us: u64,
    /// `__SEQNUM`, journald's sequence number, when this systemd prints it.
    pub seqnum: Option<u64>,
    pub message: String,
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub identifier: Option<String>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub cap_effective: Option<u64>,
}

/// Why a journal line could not be read as a record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("journal line is not a JSON object: {0}")]
    Json(String),
    #[error("journal record has no {0}")]
    Missing(&'static str),
    #[error("journal record has an invalid {0}")]
    Invalid(&'static str),
}

impl JournalEntry {
    /// Parse one line of `journalctl --output=json`.
    ///
    /// journalctl prints a field that is not valid UTF-8 as an array of byte
    /// values, and a field repeated within one record as an array of those
    /// values. Both are accepted; a repeated field keeps its first value.
    pub fn from_json(line: &str) -> Result<Self, DecodeError> {
        let value: Value =
            serde_json::from_str(line).map_err(|err| DecodeError::Json(err.to_string()))?;
        let Value::Object(map) = value else {
            return Err(DecodeError::Json("not an object".into()));
        };
        let text = |name: &str| map.get(name).and_then(json_text);
        let cursor = text("__CURSOR").ok_or(DecodeError::Missing("__CURSOR"))?;
        let realtime_us = text("__REALTIME_TIMESTAMP")
            .ok_or(DecodeError::Missing("__REALTIME_TIMESTAMP"))?
            .parse()
            .map_err(|_| DecodeError::Invalid("__REALTIME_TIMESTAMP"))?;
        let number = |name: &'static str| -> Result<Option<u32>, DecodeError> {
            text(name)
                .map(|value| value.parse().map_err(|_| DecodeError::Invalid(name)))
                .transpose()
        };
        Ok(Self {
            cursor,
            realtime_us,
            seqnum: text("__SEQNUM").and_then(|value| value.parse().ok()),
            message: text("MESSAGE").unwrap_or_default(),
            comm: text("_COMM"),
            exe: text("_EXE"),
            identifier: text("SYSLOG_IDENTIFIER"),
            pid: number("_PID")?,
            uid: number("_UID")?,
            cap_effective: text("_CAP_EFFECTIVE")
                .map(|value| {
                    u64::from_str_radix(&value, 16)
                        .map_err(|_| DecodeError::Invalid("_CAP_EFFECTIVE"))
                })
                .transpose()?,
        })
    }

    /// What journald attests about the sender.
    pub fn sender(&self) -> SenderTrust {
        match (self.uid, self.cap_effective) {
            (Some(0), _) => SenderTrust::Privileged,
            (Some(_), Some(caps)) if caps != 0 => SenderTrust::Privileged,
            (Some(uid), None) => SenderTrust::CapabilitiesUnknown(uid),
            _ => SenderTrust::Unprivileged,
        }
    }

    fn timestamp(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_micros(self.realtime_us)
    }
}

fn json_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) if items.iter().all(Value::is_u64) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(Value::as_u64)
                .map(|byte| u8::try_from(byte).ok())
                .collect::<Option<_>>()?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        Value::Array(items) => items.first().and_then(json_text),
        _ => None,
    }
}

/// The sequence number a journal cursor points at, and the ID of the sequence
/// it belongs to: the `s=` and `i=` parts of `s=<id>;i=<hex>;b=...`.
pub fn cursor_position(cursor: &str) -> Option<(&str, u64)> {
    let mut id = None;
    let mut seqnum = None;
    for part in cursor.split(';') {
        if let Some(value) = part.strip_prefix("s=") {
            id = Some(value).filter(|value| {
                value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        } else if let Some(value) = part.strip_prefix("i=") {
            seqnum = u64::from_str_radix(value, 16).ok();
        }
    }
    Some((id?, seqnum?))
}

/// What the oldest record still in the journal says about a saved cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeCheck {
    /// Nothing after the saved cursor has been removed.
    Continuous,
    /// Retention removed records after the saved cursor. How many of them
    /// were auth records is unknown: the facility filter skips numbers.
    RetentionPassed { saved: u64, oldest: u64 },
    /// The journal's sequence is not the cursor's, after a reboot with a
    /// volatile journal or a journal reset.
    ForeignSequence,
    /// One of the cursors could not be read.
    Unknown,
}

/// Compare a saved cursor with the journal's oldest record.
pub fn resume_check(saved: &str, oldest: &str) -> ResumeCheck {
    let (Some((saved_id, saved)), Some((oldest_id, oldest))) =
        (cursor_position(saved), cursor_position(oldest))
    else {
        return ResumeCheck::Unknown;
    };
    if saved_id != oldest_id {
        ResumeCheck::ForeignSequence
    } else if oldest > saved.saturating_add(1) {
        ResumeCheck::RetentionPassed { saved, oldest }
    } else {
        ResumeCheck::Continuous
    }
}

/// What journald attests about a record's sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderTrust {
    /// UID 0, or a non-empty effective capability set.
    Privileged,
    /// A non-zero UID whose capabilities journald could not read, because
    /// the sender exited first.
    CapabilitiesUnknown(u32),
    /// An empty capability set, or no credentials at all.
    Unprivileged,
}

/// How [`decode_record`] judged a record.
#[derive(Debug)]
pub enum Decoded {
    /// Accepted on journald's attestation of a privileged sender.
    Accepted(RawEvent),
    /// Accepted because the sudo or su invoker it names is the sender's own
    /// UID, the only check left when journald lost the capability set.
    AcceptedSameUser(RawEvent),
    /// Dropped: the sender was not shown to be privileged.
    Untrusted,
}

impl Decoded {
    /// The event, however it was accepted.
    pub fn into_event(self) -> Option<RawEvent> {
        match self {
            Self::Accepted(event) | Self::AcceptedSameUser(event) => Some(event),
            Self::Untrusted => None,
        }
    }
}

/// Turn a journal record into an `auth_log` sensor event.
///
/// Every trusted record becomes an event, parsed or not, so keyword rules
/// over `Message` see the whole log. `user_name` resolves a UID to its account
/// name, for records whose sender's capabilities journald could not read.
pub fn decode_record(entry: &JournalEntry, user_name: impl Fn(u32) -> Option<String>) -> Decoded {
    match entry.sender() {
        SenderTrust::Privileged => {
            decode_trusted(entry).map_or(Decoded::Untrusted, Decoded::Accepted)
        }
        SenderTrust::CapabilitiesUnknown(uid) => decode_trusted(entry)
            .filter(|event| names_own_user(event, uid, &user_name))
            .map_or(Decoded::Untrusted, Decoded::AcceptedSameUser),
        SenderTrust::Unprivileged => Decoded::Untrusted,
    }
}

/// Whether a sudo or su record names the sender's own UID as its invoker.
///
/// sudo and su run with the invoker's real UID, which the kernel stamps on
/// the record, and print that user's name. Only records whose invoker field
/// is fixed by that UID qualify: sshd and every other program log as root,
/// and a session-closed line names no invoker at all.
fn names_own_user(event: &RawEvent, uid: u32, user_name: &impl Fn(u32) -> Option<String>) -> bool {
    let RawPayload::AuthLog(fields) = &event.payload else {
        return false;
    };
    if !matches!(
        Program::from_code(event.normalization.action_code),
        Some(Program::Sudo | Program::Su)
    ) {
        return false;
    }
    match AuthKind::from_event_id(event.normalization.event_id) {
        Some(
            AuthKind::SudoCommand
            | AuthKind::SudoRefused
            | AuthKind::SuSuccess
            | AuthKind::SuFailed
            | AuthKind::PamAuthFailure,
        ) => {
            fields.get("SubjectUserName").is_some()
                && fields.get("SubjectUserName") == user_name(uid).as_deref()
        }
        Some(AuthKind::PamSessionOpened) => fields.get("SubjectUserId") == Some(&*uid.to_string()),
        _ => false,
    }
}

fn decode_trusted(entry: &JournalEntry) -> Option<RawEvent> {
    let program = Program::classify(entry.comm.as_deref(), entry.identifier.as_deref());
    let mut fields = AuthLogFields::default();
    let mut provenance = crate::models::Provenance::default();

    let message = entry.message.trim_end_matches(['\n', '\r']);
    let (kept, truncated) = truncate(message, MAX_MESSAGE_BYTES);
    fields.insert("Message", kept);
    if truncated {
        provenance.mark("Message", crate::models::Fidelity::Truncated);
    }
    if let Some(name) = entry.identifier.as_deref().or(entry.comm.as_deref()) {
        fields.insert("Program", name);
    }
    if let Some(exe) = &entry.exe {
        fields.insert("Image", exe);
    }
    if let Some(pid) = entry.pid {
        fields.insert("ProcessId", &pid.to_string());
    }

    // The parsers read the whole line even when `Message` was cut: a parsed
    // field never comes from text the event does not show.
    let kind = if truncated {
        AuthKind::Other
    } else {
        parse_message(program, message, &mut fields)
    };
    if let Some(outcome) = kind.outcome() {
        fields.insert("Outcome", outcome);
    }

    Some(RawEvent {
        process_name: entry.comm.clone(),
        provenance,
        platform: Platform::Linux,
        provider: PROVIDER,
        action: SensorAction::Access,
        normalization: SensorNormalization {
            event_id: kind.event_id(),
            action_code: program.code(),
        },
        pid: entry.pid,
        timestamp: entry.timestamp(),
        source_seq: entry
            .seqnum
            .or_else(|| cursor_position(&entry.cursor).map(|(_, seqnum)| seqnum)),
        process_start_key: None,
        parent_process_start_key: None,
        payload: RawPayload::AuthLog(fields),
    })
}

fn truncate(text: &str, limit: usize) -> (&str, bool) {
    if text.len() <= limit {
        return (text, false);
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

fn parse_message(program: Program, message: &str, fields: &mut AuthLogFields) -> AuthKind {
    // PAM modules log through the calling program, so these lines come from
    // every family.
    if let Some(kind) = parse_pam(message, fields) {
        return kind;
    }
    let parsed = match program {
        Program::Sshd => parse_sshd(message, fields),
        Program::Sudo => parse_sudo(message, fields),
        Program::Su => parse_su(message, fields),
        Program::Other => None,
    };
    let service = match program {
        Program::Sshd => "sshd",
        Program::Sudo => "sudo",
        Program::Su => "su",
        Program::Other => return AuthKind::Other,
    };
    match parsed {
        Some(kind) => {
            fields.insert("Service", service);
            kind
        }
        None => AuthKind::Other,
    }
}

/// Insert source address fields from an address OpenSSH or PAM printed.
///
/// A literal IP lands in `SourceIp`. Anything else, such as a reverse-DNS name
/// with `UseDNS yes`, lands in `SourceHostname`, never in `SourceIp`.
fn insert_source(fields: &mut AuthLogFields, address: &str) {
    if address.is_empty() {
        return;
    }
    match address.parse::<IpAddr>() {
        Ok(ip) => fields.insert("SourceIp", &ip.to_string()),
        Err(_) => fields.insert("SourceHostname", address),
    }
}

/// `<head> from <address> port <port>[ <tail>]`, anchored on the right.
///
/// The user name before `from` is whatever the client sent, so it may itself
/// contain ` from 6.6.6.6 port 1`. Splitting on the last ` from ` keeps the
/// address sshd appended.
fn split_from_port(rest: &str) -> Option<(&str, &str, u16, &str)> {
    let (head, tail) = rest.rsplit_once(" from ")?;
    let (address, after) = tail.split_once(" port ")?;
    let (port, remainder) = after.split_once(' ').unwrap_or((after, ""));
    let port = port.parse().ok()?;
    if address.is_empty() || address.contains(' ') {
        return None;
    }
    Some((head, address, port, remainder))
}

fn parse_sshd(message: &str, fields: &mut AuthLogFields) -> Option<AuthKind> {
    if let Some(rest) = message.strip_prefix("Accepted ") {
        let (method, rest) = rest.split_once(" for ")?;
        let (user, address, port, remainder) = split_from_port(rest)?;
        if !is_ssh_method(method) || user.is_empty() {
            return None;
        }
        fields.insert("AuthenticationMethod", method);
        fields.insert("TargetUserName", user);
        insert_source(fields, address);
        fields.insert("SourcePort", &port.to_string());
        // `ssh2: ED25519 SHA256:...` after a public key or certificate login.
        if let Some(key) = remainder.strip_prefix("ssh2: ") {
            let mut parts = key.split(' ');
            if let (Some(key_type), Some(fingerprint)) = (parts.next(), parts.next()) {
                if fingerprint.starts_with("SHA256:") || fingerprint.starts_with("MD5:") {
                    fields.insert("KeyType", key_type);
                    fields.insert("KeyFingerprint", fingerprint);
                }
            }
        }
        return Some(AuthKind::SshAccepted);
    }
    if let Some(rest) = message.strip_prefix("Failed ") {
        let (method, rest) = rest.split_once(" for ")?;
        let (user, address, port, _) = split_from_port(rest)?;
        if !is_ssh_method(method) {
            return None;
        }
        let (user, invalid) = match user.strip_prefix("invalid user ") {
            Some(user) => (user, true),
            None => (user, false),
        };
        fields.insert("AuthenticationMethod", method);
        fields.insert("TargetUserName", user);
        if invalid {
            fields.insert("InvalidUser", "true");
        }
        insert_source(fields, address);
        fields.insert("SourcePort", &port.to_string());
        return Some(AuthKind::SshFailed);
    }
    if let Some(rest) = message.strip_prefix("Invalid user ") {
        let (user, address, port, _) = split_from_port(rest)?;
        fields.insert("TargetUserName", user);
        fields.insert("InvalidUser", "true");
        insert_source(fields, address);
        fields.insert("SourcePort", &port.to_string());
        return Some(AuthKind::SshInvalidUser);
    }
    None
}

fn is_ssh_method(method: &str) -> bool {
    matches!(
        method,
        "password"
            | "publickey"
            | "keyboard-interactive"
            | "keyboard-interactive/pam"
            | "hostbased"
            | "gssapi-with-mic"
            | "gssapi-keyex"
            | "none"
    )
}

/// `pam_unix(<service>:<group>): <text>`.
fn parse_pam(message: &str, fields: &mut AuthLogFields) -> Option<AuthKind> {
    let rest = message.strip_prefix("pam_unix(")?;
    let (scope, text) = rest.split_once("): ")?;
    let (service, group) = scope.split_once(':')?;
    if service.is_empty() || service.contains(' ') {
        return None;
    }
    let kind = match group {
        "auth" => {
            let rest = text.strip_prefix("authentication failure;")?;
            parse_pam_failure(rest, fields);
            AuthKind::PamAuthFailure
        }
        "session" => {
            if let Some(rest) = text.strip_prefix("session opened for user ") {
                // `<user>(uid=<n>) by <subject>(uid=<m>)`; the subject name
                // may be empty: `by (uid=1001)`.
                let (target, subject) = rest.rsplit_once(" by ")?;
                let (target, target_uid) = split_name_uid(target)?;
                let (subject, subject_uid) = split_name_uid(subject)?;
                fields.insert("TargetUserName", target);
                fields.insert("TargetUserId", target_uid);
                fields.insert("SubjectUserName", subject);
                fields.insert("SubjectUserId", subject_uid);
                AuthKind::PamSessionOpened
            } else {
                let user = text
                    .strip_prefix("session closed for user ")
                    .filter(|user| !user.is_empty())?;
                fields.insert("TargetUserName", user);
                AuthKind::PamSessionClosed
            }
        }
        _ => return None,
    };
    fields.insert("Service", service);
    Some(kind)
}

/// `<name>(uid=<n>)`, where `<name>` may be empty.
fn split_name_uid(text: &str) -> Option<(&str, &str)> {
    let (name, uid) = text.strip_suffix(')')?.rsplit_once("(uid=")?;
    if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((name, uid))
}

/// `logname=<a> uid=<n> euid=<n> tty=<t> ruser=<r> rhost=<h>  user=<u>`.
///
/// pam_unix prints the keys in this fixed order and `user=` only when the
/// account exists. Each key is searched after the previous one, so a value
/// earlier in the line cannot supply a later key.
fn parse_pam_failure(rest: &str, fields: &mut AuthLogFields) {
    const KEYS: [&str; 7] = [
        " logname=",
        " uid=",
        " euid=",
        " tty=",
        " ruser=",
        " rhost=",
        " user=",
    ];
    let mut positions = [None; KEYS.len()];
    let mut from = 0;
    for (index, key) in KEYS.iter().enumerate() {
        if let Some(offset) = rest[from..].find(key) {
            positions[index] = Some(from + offset);
            from += offset + key.len();
        }
    }
    let value = |index: usize| -> Option<&str> {
        let start = positions[index]? + KEYS[index].len();
        let end = positions[index + 1..]
            .iter()
            .flatten()
            .next()
            .copied()
            .unwrap_or(rest.len());
        Some(rest[start..end].trim())
    };
    if let Some(uid) = value(1).filter(|uid| uid.bytes().all(|byte| byte.is_ascii_digit())) {
        fields.insert("SubjectUserId", uid);
    }
    if let Some(tty) = value(3) {
        fields.insert("Terminal", tty);
    }
    if let Some(ruser) = value(4) {
        fields.insert("SubjectUserName", ruser);
    }
    if let Some(rhost) = value(5) {
        insert_source(fields, rhost);
    }
    if let Some(user) = value(6) {
        fields.insert("TargetUserName", user);
    }
}

/// sudo.ws and sudo-rs command log lines.
///
/// `<user> : [TTY=<tty> ; ]PWD=<dir> ; USER=<target> ; [GROUP=.. ; ][ENV=.. ; ]COMMAND=<cmd>`
/// for a command it ran, and the same with `<reason> ; ` before the first key
/// for one it refused. sudo-rs separates the user with two spaces.
///
/// The working directory and the command are the caller's to choose, and
/// sudo does not escape ` ; `, so a directory named `x ; USER=evil` produces
/// two `USER=` keys. When any key appears more than once, the key fields stay
/// absent: `Message` still holds the line, and the invoking user, which
/// comes before any caller-chosen text, is kept.
fn parse_sudo(message: &str, fields: &mut AuthLogFields) -> Option<AuthKind> {
    let (user, rest) = message.split_once(" : ")?;
    if user.is_empty() || user.contains(' ') {
        return None;
    }
    let rest = rest.trim_start();
    fields.insert("SubjectUserName", user);

    let first_key = ["TTY=", "PWD="].iter().any(|key| rest.starts_with(key));
    let (kind, keys) = if first_key {
        (AuthKind::SudoCommand, rest)
    } else {
        let (reason, keys) = rest.split_once(" ; ").unwrap_or((rest, ""));
        fields.insert("Reason", reason.trim());
        (AuthKind::SudoRefused, keys)
    };

    if let Some(found) = sudo_keys(keys) {
        for (key, value) in found {
            fields.insert(key, value);
            if key == "USER" {
                fields.insert("TargetUserName", value);
            }
        }
    }
    Some(kind)
}

const SUDO_KEYS: [&str; 6] = ["TTY", "PWD", "USER", "GROUP", "ENV", "COMMAND"];

/// The `KEY=value` pairs of a sudo line, or `None` when they are ambiguous.
///
/// `COMMAND` is last and takes the rest of the line, because a command such as
/// `sh -c 'a ; b'` legitimately contains ` ; `. A key that appears twice, or a
/// key marker inside the command, means caller-chosen text imitated sudo's
/// own keys, and no reading of the line can be trusted.
fn sudo_keys(keys: &str) -> Option<Vec<(&'static str, &str)>> {
    let mut found: Vec<(&'static str, &str)> = Vec::new();
    let mut rest = keys;
    while !rest.is_empty() {
        let (segment, next) = rest.split_once(" ; ").unwrap_or((rest, ""));
        let Some((name, value)) = segment.split_once('=') else {
            rest = next;
            continue;
        };
        let Some(key) = SUDO_KEYS.iter().copied().find(|key| *key == name) else {
            rest = next;
            continue;
        };
        if found.iter().any(|(seen, _)| *seen == key) {
            return None;
        }
        if key == "COMMAND" {
            let command = &rest["COMMAND=".len()..];
            let imitates_key = SUDO_KEYS
                .iter()
                .any(|key| command.contains(&format!(" ; {key}=")));
            if imitates_key {
                return None;
            }
            found.push((key, command.trim_end_matches(" ;").trim_end()));
            break;
        }
        found.push((key, value.trim_end_matches(" ;").trim_end()));
        rest = next;
    }
    Some(found)
}

/// util-linux su: `(to <target>) <user> on <tty>` for a switch, with a
/// `FAILED SU ` prefix for a refused one.
fn parse_su(message: &str, fields: &mut AuthLogFields) -> Option<AuthKind> {
    let (kind, rest) = match message.strip_prefix("FAILED SU ") {
        Some(rest) => (AuthKind::SuFailed, rest),
        None => (AuthKind::SuSuccess, message),
    };
    let rest = rest.strip_prefix("(to ")?;
    let (target, rest) = rest.split_once(") ")?;
    let (user, tty) = rest.rsplit_once(" on ")?;
    if target.is_empty() || user.is_empty() {
        return None;
    }
    fields.insert("TargetUserName", target);
    fields.insert("SubjectUserName", user);
    fields.insert("Terminal", tty);
    Some(kind)
}

#[cfg(test)]
mod tests;
