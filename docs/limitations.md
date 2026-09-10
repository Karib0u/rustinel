# Limitations

Rustinel is a transparent, rule-based detection engine. Like any detection
system it has boundaries, and because it is open source we document them in
full rather than hide them.

> **Reading guide.** Items marked **silent risk** are the ones that matter most:
> they make a rule *not fire*, or match the wrong thing, with no error. Check
> these before you rely on a detection.

## Field availability contract

<!-- BEGIN GENERATED FIELD AVAILABILITY -->
The per-field list below is generated from `FIELD_AVAILABILITY`; edit the Rust
table and run `cargo run --bin generate-field-availability`, not this section.

| Platform | Category | Event / action | Source | Unavailable field | Reason |
| --- | --- | --- | --- | --- | --- |
| linux | `dns_query` | `22 / query` | `socket send tracepoints` | `QueryResults` | the eBPF DNS probe emits outbound queries and does not parse responses |
| linux | `dns_query` | `22 / query` | `socket send tracepoints` | `QueryStatus` | the eBPF DNS probe does not parse response status |
| linux | `file_event` | `create, delete, modify, rename` | `file syscall tracepoints` | `CreationUtcTime` | the eBPF file probes do not read file timestamps |
| linux | `file_event` | `create, delete, modify, rename` | `file syscall tracepoints` | `PreviousCreationUtcTime` | the eBPF file probes do not read file timestamps |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `Company` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `Description` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `FileVersion` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `IntegrityLevel` | Windows integrity levels do not exist on Linux |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `OriginalFileName` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `Product` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `TargetImage` | a process-creation event has no target process |
| macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryResults` | the BPF DNS path emits queries, not responses |
| macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryStatus` | the BPF DNS path emits queries, not responses |
| macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `CreationUtcTime` | ESF file notifications do not carry file timestamps |
| macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `PathTruncated` | ESF paths are not copied through a fixed Rustinel buffer |
| macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `PreviousCreationUtcTime` | ESF file notifications do not carry file timestamps |
| macos | `network_connection` | `3 / connect` | `/dev/bpf` | `Initiated` | a wire capture cannot determine whether the local host initiated the flow |
| macos | `network_connection` | `3 / connect` | `/dev/bpf` | `User` | BPF packets do not carry process user identity |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `CgroupId` | macOS process events do not have a Linux kernel cgroup identifier |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Company` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Description` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `FileVersion` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `ImageSource` | ESF supplies the executable path directly |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `ImageTruncated` | ESF does not use the Linux raw-image buffer |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `IntegrityLevel` | Windows integrity levels do not exist on macOS |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `OriginalFileName` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Product` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `TargetImage` | a process-creation event has no target process |
| windows | `create_remote_thread` | `8` | `none` | `*` | no Rustinel sensor produces remote-thread creation telemetry |
| windows | `dns_query` | `22 / query` | `Microsoft-Windows-DNS-Client` | `RecordType` | the subscribed DNS Client events do not expose the query record type |
| windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `CreationUtcTime` | Kernel-File reports the information class, not the new timestamp |
| windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `PathTruncated` | ETW delivers a complete path or no attributable event |
| windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `PreviousCreationUtcTime` | Kernel-File reports the information class, not the old timestamp |
| windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `SourceFilename` | Kernel-File does not provide the old name on emitted rename events |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Hashes` | loaded images are not hashed by this collector |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Imphash` | loaded images are not hashed by this collector |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Signature` | Kernel-Process image-load events contain no signer identity |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Signed` | Kernel-Process image-load events contain no Authenticode result |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `User` | Kernel-Process image-load events contain no user identity |
| windows | `pipe_created` | `17` | `Microsoft-Windows-Kernel-File` | `*` | named-pipe activity is not carried by Microsoft-Windows-Kernel-File and is not available from ETW |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `CgroupId` | Windows process events do not have a Linux kernel cgroup identifier |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `CurrentDirectory` | Microsoft-Windows-Kernel-Process does not expose the working directory |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `Hashes` | process images are not hashed by this collector |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `Imphash` | process images are not hashed by this collector |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `TargetImage` | a process-creation event has no target process |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `User` | Microsoft-Windows-Kernel-Process does not expose process user identity |
| windows | `service_creation` | `7045 / register` | `Service Control Manager` | `Image` | System event 7045 does not carry a creating process image |
| windows | `service_creation` | `7045 / register` | `Service Control Manager` | `ProcessId` | System event 7045 does not carry process identity |
| windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `Image` | TaskScheduler event 106 does not carry a process image |
| windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `ProcessId` | TaskScheduler event 106 does not carry process identity |
| windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `TaskContent` | TaskScheduler event 106 does not carry the task XML definition |
| windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `User` | TaskScheduler event 106 has UserContext, not a Sysmon User field |
<!-- END GENERATED FIELD AVAILABILITY -->

## Start with these

| Limitation | Area |
| --- | --- |
| Process events carry no hashes (`Hashes` / `Imphash`) | Windows |
| Several modelled process fields are never populated | Windows |
| Rules are inert when no collector backs their logsource (counted, not prevented) | Engine |
| Telemetry is dropped under burst load (counted, not prevented) | Pipeline |
| Writes through handles or keys opened before startup are invisible | Windows |
| Security channel events depend on audit policy Rustinel does not set | Windows |
| Image paths are truncated, and truncation is unmarked on process events | Linux |

## Windows (ETW and Event Log)

Telemetry comes from ETW plus Windows Event Log subscriptions on the System and
Security channels, rather than a kernel driver. Coverage is the broadest of the
three platforms, but several Sysmon-style fields are unavailable.

- **No process or image-load hashes (silent risk).** There is no
  `Hashes`/`Imphash` on process or image-load events, so the many Sigma rules
  keyed on them can never fire. Hashing exists only in the file/IOC scanner.
- **Some process and image-load fields are unavailable (silent risk).** The
  generated [field availability contract](#field-availability-contract) names
  them per event source and records why each one cannot be populated.
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
  means until reboot. The `file_attribution` section of `telemetry.json` and the
  `file_path_attribution` check in `rustinel doctor` report the live resolution
  rate and the handle index's capacity evictions; the agent log samples the
  drops as `unresolved_file_events`. First measurement, on an idle Windows 11
  lab desktop over 45 seconds: 399 of 33,029 file events resolved (1.2%), with
  no index evictions - so on a freshly started agent the gap is wide, and it is
  handles older than the session rather than index pressure that causes it.
  This is scheduled rather than accepted: a classic `FileIo` rundown, which
  enumerates the handles already open when the session starts, is lab-validated
  as a fix costing roughly 100 ms at startup
  ([#428](https://github.com/Karib0u/rustinel/issues/428)).
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
- **A provider that changes its event templates degrades silently (bounded,
  counted).** ETW schemas are per-Windows-build, so a record whose schema cannot
  be located, or whose payload is missing a property this build requires, is
  dropped inside the callback with the channel counters still reporting a
  healthy pipeline. The `etw_decode` section of `telemetry.json` and the
  `etw_decode` check in `rustinel doctor` count these by provider, event ID, and
  event version, and separate them from records the router filtered on purpose.
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
  as backed by an active collector, and can never match. The subscribed event
  IDs and their field allowlists come from `FIELD_AVAILABILITY`.
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
- **Scheduled-task and DNS event fields are source-specific (silent risk).**
  TaskScheduler 106 and DNS Client fields that cannot be populated are listed
  in the generated [field availability contract](#field-availability-contract).
  There is also no network data-volume telemetry, so exfil-by-volume heuristics
  are not expressible.

## Linux (eBPF)

The Linux sensor covers process, network, file, and DNS.

Tracepoint layouts and hook availability are discovered from tracefs at
startup. Kernels that omit a hook retain the other telemetry families; the
resulting per-feature coverage is reported in `telemetry.json` and by
`rustinel doctor`. An object whose event ABI does not match the loader is
rejected before any program attaches.

- **The raw image path is capped at 255 bytes.** `Image`
  comes from the raw `execve()` argument. When its suffix does not fit,
  `ImageTruncated` and `edr.process.image_truncated` mark the path as incomplete
  ([#307](https://github.com/Karib0u/rustinel/issues/307)). The raw argument may
  also be relative
  ([#308](https://github.com/Karib0u/rustinel/issues/308)).
- **Kernel-captured argv is bounded.** Argv is snapshotted at `execve` entry, so
  a process that exits before the ring is drained still reports its command
  line. Caps are 512 bytes total, 32 arguments, and 127 bytes per argument; past
  any of those the event is flagged truncated. A process that rewrites its own
  argv (`setproctitle`) reports what it was launched with.
- **`CLONE_PARENT` parent attribution is derived.** Stable eBPF helpers expose
  the creating task but not its real parent. For `CLONE_PARENT`,
  `ParentProcessId` therefore names the creator TGID and carries `Derived`
  provenance. Ordinary fork, vfork, clone, and clone3 process creation records
  the creator TGID at `sched_process_fork`. Thread creation is excluded.
- **Processes that predate the sensor may have no parent identity.** The fork
  relationship does not exist for tasks already running at startup. A bounded
  startup inventory supplies metadata only after kernel `start_boottime` matches
  the inventoried `/proc` start ticks. Fork parents remain absent when unobserved;
  later procfs reparenting is not substituted for the original relationship.
- **File paths are capped at 511 bytes, and the overflow is marked.** The event
  carries `PathTruncated` naming which side was cut. Since truncation removes
  the end of the path, `|endswith` rules and extension IOCs are what it defeats.
- **File events whose path cannot be placed are dropped (bounded, counted).**
  The `*at` file syscalls name their target with a directory descriptor plus a
  possibly relative name, and the kernel does not expose the resolved path. A
  process that exits before the drain leaves a name that
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
- **Network fidelity depends on the socket fexit capability.** With runtime BTF
  and all three probes attached, connect and accept events carry the bound
  source address, source port, and TCP/UDP protocol as measured fields. Accepted
  connections carry `Initiated: false`, with the peer as source and the local
  listener as destination. Offsets and the accept prototype come
  from the running kernel, including `sk_protocol`; no compiled layout is used.
  If BTF, a required member, or an attachment is unavailable, the entire network
  tier falls back to outbound connect syscalls. `SourceIp`, `SourcePort`, and
  `Protocol` are absent in that tier, and inbound connections are invisible.
  `linux_ebpf_network_tuple_capability` reports the degradation in doctor.
  **Silent risk:** rules requiring those fields or inbound visibility cannot
  match while the fallback is active. The sensor still requires Linux 5.8+
  because its event transport uses ring buffers, even though fexit was added
  in 5.5. Only AF_INET and AF_INET6 are captured; IPv4 loopback and IPv6 `::1`
  are filtered in the kernel. Unknown IP protocols remain unnamed.
  Refused, unreachable, and timed-out connects are dropped. `EINPROGRESS` and
  `EINTR` are reported as attempts underway; later failures are not retracted.
  No per-event `/proc/net` scan or descriptor-to-socket cache is used.
- **Kernel identity fields depend on runtime BTF.** `User` uses the effective
  UID. Missing BTF or an unsupported member disables only the affected fields,
  with `linux_task_<field>` doctor warnings; an unknown effective UID stays
  absent. Rules requiring those fields cannot match while they are unavailable.
  No build-kernel offsets are used as fallback.
- **No library-load, module-load, or ptrace events.** Sigma rules in those
  categories never match.
- **Kernel requirements.** Linux 5.8+ with `CAP_BPF` + `CAP_PERFMON` +
  `CAP_NET_ADMIN` (or `CAP_SYS_ADMIN`). Older kernels and many
  restricted containers are unsupported. BTF is needed for kernel process
  identity fields and startup inventory reconciliation.

## macOS (ESF, experimental)

macOS support is experimental. Active response *is* supported and sends
`SIGKILL` like Linux, but macOS refuses to kill SIP-protected and some system
processes even as root, so a termination can fail where the equivalent Linux one
would succeed.

- **Process and file events only from Endpoint Security.** No image-load,
  script, WMI, service, or task equivalents.
- **Network and DNS attribution is best-effort.** Telemetry comes from
  `/dev/bpf` capture rather than a per-process hook, so connections are matched
  to processes by port (racy) against a socket inventory rebuilt at most every
  250 ms — so a connection whose socket opens and closes inside that window can
  go unattributed — DNS events are not attributed at all, and capture
  binds to a single interface (default `en0`, override with
  `RUSTINEL_BPF_INTERFACE`). A wire capture also cannot say who opened the
  connection, so `Initiated` is left absent and rules selecting on it — either
  value — do not match on macOS.
- **Parent enrichment depends on observed identities (silent risk).** An exec
  whose parent was not observed by the sensor, or whose identity was evicted,
  has no `ParentImage` or `ParentCommandLine`. PID-only fallback is omitted
  when multiple process lifetimes are known for that PID. The bounded process
  cache retains exited parents briefly; after expiry, their image is absent.
- **Memory scanning is restricted.** YARA memory scanning uses `task_for_pid`,
  which generally needs root plus SIP/AMFI relaxation or an entitlement; when
  denied it silently returns nothing. File scanning is unaffected.

## Detection engine (Sigma)

- **Rules are inert without a backing collector (silent risk).** Rules for a
  product or category the running platform does not collect load successfully
  and never fire. On Linux and macOS a large share of a Windows-oriented ruleset
  is dead weight. **Do not read rule count as coverage.** The count is now
  reported rather than silent: rule loading logs how many rules have no backing
  collector, grouped by the missing telemetry category, and `rustinel doctor`
  repeats it as the `sigma_rules_inert` check. Rules whose logsource names
  another product are skipped at load instead, and counted separately. See
  [Sigma Coverage](coverage.md) for the measured share of SigmaHQ that can fire
  per platform; per-rule diagnostics are tracked by
  [#184](https://github.com/Karib0u/rustinel/issues/184).
- **`file_change` has no collector on Linux or macOS.** Neither the eBPF nor
  the ESF sensor emits the metadata-change action that `file_change` denotes
  (Sysmon Event ID 2), so its rules cannot fire on those platforms. They still
  load, and are reported as having no backing collector rather than counted as
  covered ([#293](https://github.com/Karib0u/rustinel/issues/293)); the
  telemetry itself is tracked by
  [#146](https://github.com/Karib0u/rustinel/issues/146).
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
