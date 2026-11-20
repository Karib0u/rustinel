//! Numbering of Linux auth log events (`auth_log`).
//!
//! Sigma routes `auth_log` events by `(category, event_id, opcode)` alone, so
//! the opcode carries the program family ([`Program`]) that decides
//! `service: sshd` and `service: sudo`, and the event ID carries what the line
//! asserts ([`AuthKind`]). The parsers live in `sensor::auth_log`.

/// The provider name auth log events carry.
pub const PROVIDER: &str = "journald";

/// The program family that wrote a record. Carried in the event opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Program {
    /// Any other privileged writer to the auth facilities: login, cron,
    /// pkexec, systemd-logind and so on.
    Other = 0,
    /// `sshd`, and OpenSSH 9.8+'s `sshd-session` and `sshd-auth`.
    Sshd = 1,
    /// `sudo` (sudo.ws) and sudo-rs.
    Sudo = 2,
    /// util-linux `su`.
    Su = 3,
}

impl Program {
    pub const ALL: [Self; 4] = [Self::Other, Self::Sshd, Self::Sudo, Self::Su];

    pub const fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|program| program.code() == code)
    }

    /// The family as the field availability table names its `source`.
    pub const fn contract_source(self) -> &'static str {
        match self {
            Self::Other => "other privileged auth facility writers",
            Self::Sshd => "sshd",
            Self::Sudo => "sudo",
            Self::Su => "su",
        }
    }

    /// The family a field availability `source` names.
    pub fn from_contract_source(source: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|program| program.contract_source() == source)
    }

    /// The Sigma `service` the family also answers to, besides `auth`.
    pub const fn sigma_service(self) -> Option<&'static str> {
        match self {
            Self::Sshd => Some("sshd"),
            Self::Sudo => Some("sudo"),
            Self::Other | Self::Su => None,
        }
    }

    /// Classify by `_COMM`, then by `SYSLOG_IDENTIFIER`.
    ///
    /// Ubuntu installs classic sudo as `sudo.ws` beside sudo-rs, and it logs
    /// under the identifier `sudo`. Trusting the identifier is sound here only
    /// because `sensor::auth_log::decode_record` has already checked the
    /// sender.
    pub(crate) fn classify(comm: Option<&str>, identifier: Option<&str>) -> Self {
        let family = |name: &str| match name {
            "sshd" | "sshd-session" | "sshd-auth" => Some(Self::Sshd),
            "sudo" | "sudo-rs" | "sudo.ws" => Some(Self::Sudo),
            "su" => Some(Self::Su),
            _ => None,
        };
        comm.and_then(family)
            .or_else(|| identifier.and_then(family))
            .unwrap_or(Self::Other)
    }
}

/// What one record asserts. Carried in the event ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuthKind {
    /// A line from a privileged sender that none of the parsers claims.
    Other = 0,
    /// sshd `Accepted <method> for <user> from <ip> port <port>`.
    SshAccepted = 1,
    /// sshd `Failed <method> for [invalid user ]<user> from <ip> port <port>`.
    SshFailed = 2,
    /// sshd `Invalid user <user> from <ip> port <port>`, once per connection.
    SshInvalidUser = 3,
    /// `pam_unix(<service>:auth): authentication failure; ...`.
    PamAuthFailure = 4,
    /// `pam_unix(<service>:session): session opened for user ...`.
    PamSessionOpened = 5,
    /// `pam_unix(<service>:session): session closed for user ...`.
    PamSessionClosed = 6,
    /// sudo ran a command: `<user> : [TTY=..;] PWD=.. ; USER=.. ; COMMAND=..`.
    SudoCommand = 7,
    /// sudo refused: `<user> : <reason> ; PWD=.. ; USER=.. ; COMMAND=..`.
    SudoRefused = 8,
    /// su switched user: `(to <target>) <user> on <tty>`.
    SuSuccess = 9,
    /// su refused: `FAILED SU (to <target>) <user> on <tty>`.
    SuFailed = 10,
}

impl AuthKind {
    pub const ALL: [Self; 11] = [
        Self::Other,
        Self::SshAccepted,
        Self::SshFailed,
        Self::SshInvalidUser,
        Self::PamAuthFailure,
        Self::PamSessionOpened,
        Self::PamSessionClosed,
        Self::SudoCommand,
        Self::SudoRefused,
        Self::SuSuccess,
        Self::SuFailed,
    ];

    pub const fn event_id(self) -> u16 {
        self as u16
    }

    pub fn from_event_id(event_id: u16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.event_id() == event_id)
    }

    /// `success` or `failure`, for the kinds that report an outcome.
    pub const fn outcome(self) -> Option<&'static str> {
        match self {
            Self::SshAccepted | Self::SudoCommand | Self::SuSuccess => Some("success"),
            Self::SshFailed
            | Self::SshInvalidUser
            | Self::PamAuthFailure
            | Self::SudoRefused
            | Self::SuFailed => Some("failure"),
            Self::Other | Self::PamSessionOpened | Self::PamSessionClosed => None,
        }
    }

    /// The ECS `event.action` for this kind.
    pub const fn ecs_action(self) -> &'static str {
        match self {
            Self::Other => "auth-log",
            Self::SshAccepted => "ssh-login",
            Self::SshFailed => "ssh-login-failed",
            Self::SshInvalidUser => "ssh-invalid-user",
            Self::PamAuthFailure => "pam-authentication-failure",
            Self::PamSessionOpened => "session-opened",
            Self::PamSessionClosed => "session-closed",
            Self::SudoCommand => "sudo-command",
            Self::SudoRefused => "sudo-refused",
            Self::SuSuccess => "su",
            Self::SuFailed => "su-failed",
        }
    }
}
