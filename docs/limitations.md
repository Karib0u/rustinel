# Limitations

Rustinel is a transparent, rule-based detection engine. Like any detection
system it has boundaries, and because it is open source we document them in
full rather than hide them.

> **Reading guide.** Items marked **silent risk** are the ones that matter most:
> they make a rule *not fire*, or match the wrong thing, with no error. Check
> these before you rely on a detection.

## Start with these

| Limitation | Area |
| --- | --- |
| Process events carry no hashes (`Hashes` / `Imphash`) | Windows |
| Several modelled process fields are never populated | Windows |
| Rules are silently inert when no collector backs their logsource | Engine |
| Telemetry is dropped under burst load (counted, not prevented) | Pipeline |
| Writes through handles or keys opened before startup are invisible | Windows |
| Security channel events depend on audit policy Rustinel does not set | Windows |
| Image paths are truncated, and truncation is unmarked on process events | Linux |
| `Protocol` is reported as `tcp` on every connection, including UDP | Linux |
| `file_change` is advertised as collected but no sensor emits it | Linux, macOS |

## Windows (ETW and Event Log)

Telemetry comes from ETW plus Windows Event Log subscriptions on the System and
Security channels, rather than a kernel driver. Coverage is the broadest of the
three platforms, but several Sysmon-style fields are unavailable.

- **No process or image-load hashes (silent risk).** There is no
  `Hashes`/`Imphash` on process or image-load events, so the many Sigma rules
  keyed on them can never fire. Hashing exists only in the file/IOC scanner.
- **Some process fields are always empty (silent risk).** `User` and
  `CurrentDirectory` are modelled and exposed to Sigma but never populated by
  the provider, so rules filtering on them cannot match. `Signed` and
  `Signature` on image loads are empty for the same reason.
- **`IntegrityLevel` is on process start only.** It is decoded from the
  `MandatoryLabel` SID that Kernel-Process puts on the start event, and named
  the way Sysmon names it (`System`, `High`, `Medium`). Process *stop* events
  do not carry it, and a mandatory label whose level Windows has not defined is
  reported as the raw `S-1-16-...` SID rather than dropped.
- **Command line is back-filled, and can be lost.** No Kernel-Process event
  carries `CommandLine`; it is obtained by querying the live process. Process
  events are collected on their own ETW session, flushed every 5 ms so they
  reach the sensor while the process is still alive, and the back-fill runs
  before any other decoding work, but a process that exits first still has no
  command line. Measured at 99.9% on 2,000 `cmd /c echo` runs and 4000/4000 on
  a 4,000-process fork tree. Setting `windows.etw_process_flush_interval_ms`
  to `0` drops that to 16.6%.
  When the back-fill loses the race it returns nothing rather than another
  process's command line, but the failure is currently uncounted
  ([#304](https://github.com/Karib0u/rustinel/issues/304)).
- **Registry value data depends on an undocumented request (silent risk).**
  `Details` carries the value data, as Sysmon Event ID 13 defines it, because
  the session asks Kernel-Registry for it with an undocumented filter payload.
  That is not contractual: if a future Windows build stops honouring it,
  `Details` is absent and a warning is logged at startup.
  Binary values render as `Binary Data`, matching Sysmon, so their content is
  not searchable.
- **Registry `TargetObject` is not always a full path (silent risk).** The path
  is composed from the `CreateKey`/`OpenKey` events that named the key, so it is
  a full NT path (`\REGISTRY\MACHINE\...`) only when the parent open was also
  observed, or the parent handle was covered by the startup key rundown below.
  Hive prefixes are never rewritten to `HKLM`/`HKCU`, so `startswith` matches on
  a hive abbreviation miss.
- **File writes through handles opened before startup are invisible (silent
  risk).** Kernel-File identifies targets by kernel pointer, so the sensor learns
  each path from the open that named it. A file already open when the sensor
  starts cannot be attributed, and those events are dropped rather than emitted
  without a path. Long-lived holders such as database files and service logs stay
  unobserved until the handle is closed and reopened, which for some services
  means until reboot. Counted as `unresolved_file_events`.
- **A small share of registry writes is still unattributed (silent risk).**
  Registry keys open before the trace session are named from the kernel handle
  table at startup, which covered 5,908 of 6,644 open keys (88.9%) in 32 ms on a
  measured Windows 11 desktop. The rest belong to protected processes such as
  System, smss, csrss, wininit, services, lsass, and the Defender services, whose
  handles refuse `PROCESS_DUP_HANDLE` even to SYSTEM. Separately, the trace can
  still deliver events for a short-lived key out of order despite disabling
  per-processor buffering. A timestamp-checked, bounded grace index absorbs most
  of that but not all. The measured resolution rate is 98.7% under a mixed
  workload, with short-lived keys accounting for the residue. The `registry`
  section of `telemetry.json` and the `registry_path_resolution` check in
  `rustinel doctor` report the live rate, and the agent log carries the writing
  PID for the first events that fail.
- **Extreme process bursts can still be lost in the kernel.** Both
  ETW sessions use an explicitly sized buffer pool: 256 KB × 64-128 (32 MB
  ceiling) for the main session and 32 KB × 64-512 (16 MB ceiling) for the
  process session. The main pool absorbed a 4,000-process fork tree with no loss,
  while the library defaults lost 12-60%. A host that churns harder can still
  overrun them. The sensor polls ETW's cumulative loss counters and
  warns when they increase; behavioral capture also records the combined count
  as `events.source_lost` and marks the recording incomplete. See
  [Windows ETW session buffers](operations.md#windows-etw-session-buffers).
- **WMI event IDs are not Sysmon's (silent risk).** `Microsoft-Windows-WMI-Activity`
  has no equivalent of Sysmon's `wmi_event` 19/20/21, and numbers its own
  operations in that range. Nothing is remapped and the two colliding IDs are
  dropped, so a `wmi_event` rule selecting on `EventID` never matches rather
  than matching the wrong event. WMI persistence telemetry is not collected.
- **Security channel coverage depends on the host's audit policy (silent
  risk).** Rustinel subscribes to the Security channel and decodes six audit
  event families, but only 4624 (logon) is audited by default. The other five
  need their audit subcategory enabled, and 4656/4663 additionally need a SACL
  on the object being watched. Nothing about this is visible from inside the
  agent: the subscription succeeds, the rules load against an active collector,
  and no event ever arrives. The policy each needs is in
  [Windows audit policy](operations.md#windows-audit-policy); Rustinel never
  changes it.
- **Only six Security event IDs are subscribed to (silent risk).** The
  subscription is scoped in the kernel to 4624, 4656, 4663, 4697, 5136 and 5145.
  A `windows/security` rule selecting on any other `EventID` loads, is counted
  as backed by an active collector, and can never match. The list is
  `SUPPORTED_EVENTS` in `src/sensor/windows/event_log/security.rs`.
- **No injection, driver-load, or named-pipe visibility.** There is no
  equivalent of CreateRemoteThread, ProcessAccess, pipe, or driver-load
  telemetry, so injection-based TTPs leave little trace.
- **PowerShell telemetry depends on host policy.** Only Windows PowerShell 5.1
  is covered; PowerShell 7 (`pwsh`) uses a different provider and is not
  collected. Script block logging (4104) reaches the sensor for suspicious
  blocks even with the policy off, but module logging (4103) does not exist at
  all until Module Logging is enabled on the host, so `ps_module` rules are
  inert on a default install. `ContextInfo` and `Payload` are also written in
  the host's display language, so rules matching English labels do not fire on
  a localized host. See
  [Detection](detection.md#powershell-logsources).
- **`TaskContent` is always empty (silent risk).** Scheduled-task telemetry
  comes from TaskScheduler event 106, which carries only the task name and user
  context. `TaskContent` is modelled and exposed to Sigma but never populated,
  so rules inspecting a task's XML definition cannot match
  ([#296](https://github.com/Karib0u/rustinel/issues/296)).
- **DNS `RecordType` is always empty**, and there is no network data-volume
  telemetry, so exfil-by-volume heuristics are not expressible.

## Linux (eBPF)

The Linux sensor covers process, network, file, and DNS.

- **Image paths are truncated at 127 bytes, with no marker (silent risk).** A
  binary at a long path is reported cut, and nothing distinguishes a truncated
  path from a complete one, so every `Image|endswith` rule fails against it
  silently ([#307](https://github.com/Karib0u/rustinel/issues/307)). `Image`
  normally comes from `/proc/<pid>/exe` and is absolute and symlink-resolved,
  but under burst the raw `execve()` argument is used instead, which is both
  truncated and possibly relative
  ([#308](https://github.com/Karib0u/rustinel/issues/308)).
- **Kernel-captured argv is bounded.** Argv is snapshotted at `execve` entry, so
  a process that exits before the ring is drained still reports its command
  line. Caps are 512 bytes total, 32 arguments, and 127 bytes per argument; past
  any of those the event is flagged truncated and the loader prefers
  `/proc/<pid>/cmdline` while the process lives. A process that rewrites its own
  argv (`setproctitle`) reports what it was launched with.
- **File paths are capped at 511 bytes, and the overflow is marked.** The event
  carries `PathTruncated` naming which side was cut. Since truncation removes
  the end of the path, `|endswith` rules and extension IOCs are what it defeats.
- **File events whose path cannot be placed are dropped (bounded, counted).**
  `openat`, `unlinkat`, and `renameat*` name their target with a directory
  descriptor plus a possibly relative name, and the kernel does not expose the
  resolved path. A process that exits before the drain leaves a name that
  neither `/proc/<pid>/cwd` nor the descriptor index can place, and it is
  dropped rather than reported as though `passwd` were `/etc/passwd`. Counted as
  `unresolved_file_events`.
- **Descriptors opened without `O_DIRECTORY` keep a stale-fd race (silent
  risk).** Directory descriptors are normally indexed when opened, with a kernel
  token that `close`, `dup2`, and `dup3` invalidate. A descriptor with no
  matching token falls back to reading `/proc/<pid>/fd/<dfd>` milliseconds
  later, by which time a process walking a tree may have recycled the number,
  and nothing distinguishes that from the ordinary case. Descriptors with no
  token include those opened before the sensor started, produced by `dup`,
  `pidfd_getfd`, or `SCM_RIGHTS`, inherited across `fork`, or opened with a bare
  `O_RDONLY` (which CPython's `shutil.rmtree` does). Closing the gap costs
  20-29% on read-heavy workloads, so it is not done.
- **`..` is collapsed lexically**, not by walking the filesystem, since the file
  a delete or rename names is usually already gone. That differs from the
  kernel's resolution only when a path component is a symlink.
- **DNS is UDP port 53 only.** DNS-over-TCP, DoH, and DoT are invisible; long
  query names are dropped; answers (`QueryResults`) are not parsed. `RecordType`
  is decoded only for A, NS, CNAME, PTR, TXT, and AAAA. Every other type is
  reported as the literal string `OTHER`, so a rule selecting on any other
  record type cannot match.
- **Network is outbound `connect()` only.** No inbound or `accept()` visibility,
  so every event carries `Initiated: true` and a rule selecting
  `Initiated: 'false'` has nothing to match on Linux — inbound connections are
  absent rather than misreported. Because capture is at syscall entry, failed
  connections are reported as connections, and `SourceIp`/`SourcePort` are not
  yet assigned — they are **reported as absent**, never as `0.0.0.0`/`0`. A
  `/proc/net` lookup fills them in when it provably describes the same
  connection, which under happy-eyeballs it usually does not, so most Linux
  network events carry no source address or port until the two-phase connect
  capture lands ([#301](https://github.com/Karib0u/rustinel/issues/301)). `Protocol` is reported
  as `tcp` on every event even though the hook also captures UDP connects, so
  a rule selecting `Protocol: 'udp'` never matches and one selecting `'tcp'`
  matches UDP traffic ([#300](https://github.com/Karib0u/rustinel/issues/300)). Only
  AF_INET and AF_INET6.
- **No library-load, module-load, or ptrace events.** Sigma rules in those
  categories never match.
- **Kernel requirements.** Linux 5.8+ with BTF and `CAP_BPF` + `CAP_PERFMON` +
  `CAP_NET_ADMIN` (or `CAP_SYS_ADMIN`). Older or BTF-less kernels and many
  restricted containers are unsupported.

## macOS (ESF, experimental)

macOS support is experimental. Active response *is* supported and sends
`SIGKILL` like Linux, but macOS refuses to kill SIP-protected and some system
processes even as root, so a termination can fail where the equivalent Linux one
would succeed.

- **Process and file events only from Endpoint Security.** No image-load,
  script, WMI, service, or task equivalents.
- **Network and DNS attribution is best-effort.** Telemetry comes from
  `/dev/bpf` capture rather than a per-process hook, so connections are matched
  to processes by port (racy), DNS events are not attributed at all, and capture
  binds to a single interface (default `en0`, override with
  `RUSTINEL_BPF_INTERFACE`). A wire capture also cannot say who opened the
  connection, so `Initiated` is left absent and rules selecting on it — either
  value — do not match on macOS.
- **`User` is the real UID, not the effective one (silent risk).** Process,
  exit, and file events report `token.ruid()`. Sigma's `User` is the identity a
  process is operating under, which is the effective UID; the two differ for
  setuid and seteuid processes, so a rule filtering `User: 'root'` does not see
  a privileged process as root
  ([#327](https://github.com/Karib0u/rustinel/issues/327)).
- **Memory scanning is restricted.** YARA memory scanning uses `task_for_pid`,
  which generally needs root plus SIP/AMFI relaxation or an entitlement; when
  denied it silently returns nothing. File scanning is unaffected.

## Detection engine (Sigma)

- **Rules are inert without a backing collector (silent risk).** Rules for a
  product or category the running platform does not collect load successfully
  and never fire. On Linux and macOS a large share of a Windows-oriented ruleset
  is dead weight. **Do not read rule count as coverage.** See
  [Sigma Coverage](coverage.md) for the measured share of SigmaHQ that can fire
  per platform; per-rule diagnostics are tracked by
  [#184](https://github.com/Karib0u/rustinel/issues/184).
- **`file_change` is advertised as collected on Linux and macOS but is not
  (silent risk).** The category is listed among the active logsources on both
  platforms, so its rules are reported as backed by a live collector. Neither
  sensor emits the metadata-change action that `file_change` denotes, so those
  rules can never fire. This is worse than the general case above: the rule is
  not merely inert, it is counted as covered
  ([#293](https://github.com/Karib0u/rustinel/issues/293)).
- **Correlation state resets on Sigma reload.** A reload creates a fresh
  correlation engine, so events in an open window are forgotten. Correlation
  windows also rely on events arriving to trigger cleanup; there is no separate
  eviction task yet. See [Correlation rules](detection.md#correlation-rules).
- **Unsupported modifiers reject the whole rule.** A rule using a modifier
  outside the supported set is dropped at load, not partially matched.
- **Only one detection alert per event.** When several detection rules match,
  the highest-severity one is reported. Correlation alerts are added separately
  when their windows fire.

## Pipeline and operations

- **Telemetry is dropped under load.** Sensor channels are bounded and shed
  events rather than blocking the producer, since blocking an ETW callback or eBPF
  poll loop would lose the events queued behind it in the kernel instead. Under
  burst you get a detection gap, not a slowdown, and Rustinel does not replay
  what it shed. The loss is counted per channel and reported by
  `rustinel doctor`, so a gap can be sized without searching logs.

    What is missing is *backpressure*: no adaptive sampling, no priority
    shedding, no way to slow a producer. Reducing event volume is the only
    mitigation, and channel sizes are fixed at build time apart from
    `response.channel_capacity` and `scanner.yara_memory_queue_capacity`. See
    [Pipeline Telemetry](configuration.md#pipeline-telemetry).

- **Active response is kill-after-the-fact.** The only action is process
  termination, fired after the event is processed, so the process may already have
  done its work or exited. A PID-reuse race is narrowed by identity checks but
  not eliminated. There is no quarantine, file deletion, network isolation, or
  registry rollback.
- **No self-protection or tamper resistance.** A privileged attacker can stop
  the ETW trace, unload eBPF, or kill the agent.
- **Rules catalog trust is release-bound.** `rustinel rules install` trusts
  HTTPS GitHub release assets from `Karib0u/rustinel-rules` and requires the
  released catalog's SHA-256 to match before activation. The catalog is not
  separately signed in this phase, so protect release publishing credentials and
  review release assets before promoting them.

## Detection posture

- **Not a commercial EDR replacement.** ETW instead of a kernel driver is
  simpler and more stable, but without a driver's visibility or enforcement
  points. Rustinel is not designed to detect kernel-mode rootkits,
  vulnerable-driver abuse, or direct telemetry tampering.
- **IOC matching is only as good as its indicators.** Deterministic and fast,
  but it should complement behavioral detection rather than stand alone.
  Encrypted C2 over trusted infrastructure routinely evades it.
- **Memory-only and living-off-the-land activity is hard.** Payloads that never
  touch disk, and abuse of legitimate admin tools, produce little useful
  telemetry. YARA memory scanning helps against packed payloads but is optional
  and privilege-dependent. Note that YARA scans **only executables that run**:
  a payload written to disk and not executed is never scanned.

Rustinel is best suited to detection engineering, rule development and testing,
telemetry collection, SIEM pipeline validation, research, and blue-team labs. It
should not be presented as a full commercial EDR replacement today.

## Planned improvements

Planned work is tracked in
[GitHub Milestones](https://github.com/Karib0u/rustinel/milestones), with the
uncommitted backlog in
[open issues](https://github.com/Karib0u/rustinel/issues). The largest items are
richer process telemetry (hashes, integrity level, token fields), correlation
state preservation across reloads, real backpressure rather than only counting
what was shed, YARA scanning of newly written files, and macOS hardening.
