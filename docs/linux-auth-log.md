# Linux authentication events

On Linux, Rustinel reads the `auth` and `authpriv` syslog facilities from the systemd journal.
That is what `/var/log/auth.log` holds on Debian and Ubuntu and `/var/log/secure` on Red Hat systems: sshd, sudo, su, and every PAM-aware program.
Each record becomes one `auth_log` event.
A line Rustinel can parse also gets the user, source address, method, and result.

Rules select these events with `product: linux` and one of these services:

| Logsource | Records |
| --- | --- |
| `service: auth` | Every record. |
| `service: sshd` | Records written by `sshd`, `sshd-session`, or `sshd-auth`. |
| `service: sudo` | Records written by sudo or sudo-rs. |

The journal source needs systemd-journald.
A host that logs only through rsyslog files has no authentication events, and `doctor` reports the reader as not started.

## Event IDs

`EventID` is what the line reports, not a Windows or Sysmon ID.

| `EventID` | Record | `Outcome` | Key fields |
| --- | --- | --- | --- |
| 0 | Any other line, unparsed | | `Message` |
| 1 | sshd `Accepted <method> for <user> from <ip> port <port>` | `success` | `TargetUserName`, `AuthenticationMethod`, `SourceIp`, `SourcePort`, `KeyType`, `KeyFingerprint` |
| 2 | sshd `Failed <method> for [invalid user ]<user> from ...` | `failure` | `TargetUserName`, `AuthenticationMethod`, `InvalidUser`, `SourceIp`, `SourcePort` |
| 3 | sshd `Invalid user <user> from ...`, once per connection | `failure` | `TargetUserName`, `InvalidUser`, `SourceIp`, `SourcePort` |
| 4 | `pam_unix(<service>:auth): authentication failure` | `failure` | `Service`, `TargetUserName`, `SubjectUserName`, `SubjectUserId`, `Terminal`, `SourceIp` |
| 5 | `pam_unix(<service>:session): session opened` | | `Service`, `TargetUserName`, `TargetUserId`, `SubjectUserName`, `SubjectUserId` |
| 6 | `pam_unix(<service>:session): session closed` | | `Service`, `TargetUserName` |
| 7 | sudo ran a command | `success` | `SubjectUserName`, `TargetUserName`, `USER`, `COMMAND`, `PWD`, `TTY` |
| 8 | sudo refused, with `Reason` such as `user NOT in sudoers` or `3 incorrect password attempts` | `failure` | `SubjectUserName`, `Reason`, `USER`, `COMMAND`, `PWD` |
| 9 | su switched user: `(to <target>) <user> on <tty>` | `success` | `TargetUserName`, `SubjectUserName`, `Terminal` |
| 10 | su refused: `FAILED SU (to <target>) <user> on <tty>` | `failure` | `TargetUserName`, `SubjectUserName`, `Terminal` |

Every event also has `Message` (the full line), `Program`, `ProcessId`, and usually `Image`.
`TargetUserName` is the account being logged into or switched to.
`SubjectUserName` is the user who asked, for sudo and su.
`SourceIp` holds only a literal address.
A host name, as sshd prints with `UseDNS yes`, is in `SourceHostname`.

Which field each record carries, and why one can be absent, is listed in [Field availability](field-availability.md).

### Counting failed logins

One wrong SSH password writes two records: the PAM failure (4) and sshd's own `Failed password` line (2).
Count one of them.
`EventID: 2` counts every password or keyboard-interactive attempt sshd rejected, including those for accounts that do not exist.
`EventID: 3` counts connections that named a nonexistent account, which is the only sshd signal when the server accepts public keys alone.

```yaml
title: SSH failed login
id: 7d3c2f2e-6b1a-4c8e-9f25-0a51d1c2b001
logsource:
  product: linux
  service: sshd
detection:
  selection:
    EventID: 2
  condition: selection
level: low
---
title: SSH brute force from one address
correlation:
  type: event_count
  rules:
    - 7d3c2f2e-6b1a-4c8e-9f25-0a51d1c2b001
  group-by:
    - SourceIp
  timespan: 5m
  condition:
    gte: 10
level: high
```

## Trust

Any local user can write a syslog line that claims to be sshd, for example `logger -t sshd 'Accepted password for root from 9.9.9.9 port 22 ssh2'`.
The program name, message, and facility of a syslog line are all chosen by its sender.
Rustinel only reads a record when journald attests that its sender was privileged: user ID 0, or a non-empty effective capability set.
The journal takes both from the kernel, not from the message.
Both sudo and sudo-rs log with the invoking user's ID and every capability, so they pass.
Records that fail the check are counted as `untrusted` in [telemetry.json](telemetry.md) and dropped.

journald reads the capability set from `/proc` after the record arrives, so a sender that exits at once loses it.
Classic sudo does this when it refuses a user: its `user NOT in sudoers` line can arrive with only the user ID.
A sudo or su record without a capability set is kept when the invoker it names is the sender's own user ID, and counted as `same_user`.
A forger can then only write about their own account, never about another user and never as sshd.

Privileged programs still print text the caller chose:

- An SSH user name can contain ` from 6.6.6.6 port 1`.
  Rustinel reads the address sshd appended at the end of the line, never the first one.
- sudo prints the working directory and command without escaping ` ; `.
  A directory named `x ; USER=root` produces a line with two `USER=` keys.
  When a key appears twice, or the command contains a key, `USER`, `TargetUserName`, `PWD`, `COMMAND`, and `TTY` are left empty.
  `SubjectUserName` and `Message` are kept.

## Sessions and logoff

PAM writes a session-opened line when a login, `su`, or `sudo` starts a session, and a session-closed line when it ends.
The closed line names the user only.
It carries no address and no session number.

Both lines come from the process that opened the session, so `ProcessId` pairs them.
For SSH that is the privileged `sshd-session` process, which also wrote the `Accepted` line.
`ProcessId` is unique only while that process lives, so pair records within one boot and in time order.

Measured on Ubuntu 26.04 with three concurrent SSH sessions for one user:

| How the session ended | Closed line (6) |
| --- | --- |
| The remote command finished | Yes, from the same `ProcessId` as its `Accepted` line |
| The client was killed, so sshd saw the connection drop | Yes, from the same `ProcessId` |
| The `sshd-session` process was killed with `SIGKILL` | No |

A session that ends without PAM writes no closed line: when its sshd process is killed, crashes, or the host loses power.
A closed line therefore proves a logoff, and a missing one proves nothing.
An authentication success is not a logon session either: sudo and su open and close a session around each command.

systemd-logind also writes `New session '<id>' of user '<user>'` and `Removed session <id>.` lines.
They are kept unparsed (0) and carry logind's own session number, which a rule can match through `Message`.

## Resume and loss

The reader saves the journal cursor of the last record it read, under the log directory in `journal/auth.cursor`, and resumes after it when the agent restarts.
A first start begins at the end of the journal and does not replay history.
`rustinel capture` keeps its own cursor in `journal-capture/`.

These are counted in the `linux_journal` section of [telemetry.json](telemetry.md), and `doctor` warns on them:

| Counter | Meaning |
| --- | --- |
| `retention_wraps` | Journal retention removed records after the saved cursor while the agent was down. How many were authentication records is unknown. |
| `resume_failures` | The saved cursor belongs to another journal, such as after a reboot with a volatile journal. What was written in between is unknown. |
| `reader_restarts` | journalctl exited and the reader restarted it from the saved cursor. Nothing is lost unless retention passed the cursor meanwhile. |
| `dropped` | The sensor channel was full and refused an event. |
| `untrusted` | Records whose sender was not shown to be privileged. Expected, such as the unprivileged half of an SSH session or a `logger` line. Not loss. |
| `same_user` | sudo and su records kept on the same-user check above. |
| `checkpoint_errors` | The cursor file could not be read or written. A start without a cursor begins at the end of the journal. |

journald itself rate-limits each service, by default to 10,000 lines in 30 seconds.
Lines it suppresses never reach the journal, and Rustinel cannot count them.

## What is not covered

- **sudo-rs logs no refusal.**
  Ubuntu 26.04's default sudo writes nothing when a user is not in sudoers or names an unknown target user, and only the PAM failure (4) for a wrong password.
  Classic sudo writes a refusal (8) for each of them.
- **OpenSSH 9.8 and later penalise an address after failed logins.**
  While a penalty lasts, sshd drops new connections from that address before authentication, so they write no failure line.
  The penalty itself is logged as `srclimit_penalise: ... activating ipv4 penalty`, which stays unparsed (0).
- **A rejected public key writes no failure line at sshd's default log level.**
  At `LogLevel INFO`, sshd only writes `Connection closed by authenticating user <user> ... [preauth]`, which stays unparsed (0).
  `LogLevel VERBOSE` adds `Failed publickey` lines, which are parsed as 2.
- **Only `pam_unix` lines are parsed.**
  Other PAM modules, such as `pam_sss` or `pam_faillock`, are kept as unparsed lines.
- **Account and credential changes are not parsed.**
  `useradd`, `usermod`, `passwd`, and `chpasswd` lines are in `Message` only.
- **Containers with their own journald are not read.**
- **Lines longer than 8 KiB** are cut, marked truncated, and left unparsed.

## Compared with a PAM eBPF source

Hooking PAM itself with uprobes would report the result of each `pam_authenticate` call regardless of log format, including for programs that log nothing.
It was not chosen.
A uprobe needs the libpam path inside every container and mount namespace, sees nothing from a statically linked program, and gives no source address unless `PAM_RHOST` is read from the PAM handle's private layout.
The outcome lines sshd writes itself, such as `Invalid user` and the authentication method, are not PAM events at all.
The journal gives every field the issue asks for from programs that already record them, and the trust check above closes the forgery path.
