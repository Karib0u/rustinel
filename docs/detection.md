# Detection

Rustinel runs three detector paths over the same normalized events:

| Detector | Input | Execution | Alert behavior |
| --- | --- | --- | --- |
| Sigma | Every normalized event | Inline | At most one detection alert plus correlation alerts, see [Match Selection](#match-selection) |
| YARA | Process-start executable path | Background worker | One alert per matching rule |
| IOC domains / IPs / paths | Every normalized event | Inline | Zero or more alerts per event |
| IOC hashes | Process-start executable path | Background worker | Zero or more alerts per file |

All hits are written as ECS NDJSON and can feed the optional response engine.

## Sigma

### The engine

Sigma matching is provided by the [RSigma](https://crates.io/crates/rsigma-eval)
libraries — `rsigma-parser` for rule parsing, `rsigma-eval` for matching. There
is no second backend and nothing to select: every build and every release binary
uses it.

Rustinel owns everything around it — event normalization, logsource
classification and routing, ECS output, hot reload, and the IOC and YARA
detectors — and hands RSigma only the detection logic.

### Supported document types

| Sigma document | Status |
| --- | --- |
| Detection rules | Evaluated |
| Collection actions `global`, `reset`, `repeat` | Expanded at load |
| `N of` quantifiers such as `2 of selection*` | Evaluated |
| Array-scope quantifiers `field[any]` / `field[all]` ([SEP #212](https://github.com/SigmaHQ/sigma-specification/issues/212)) | Evaluated |
| `expand` modifier and `%placeholder%` expansion | Evaluated |
| `sigma-version` aware evaluation ([SEP #213](https://github.com/SigmaHQ/sigma-specification/issues/213)) | Evaluated |
| Correlation rules (`event_count`, `value_count`, `temporal`, …) | Evaluated with event-time windows |
| Filter rules | Applied to their referenced detection rules |

Correlation and filter documents load as part of the same collection as the
detection rules they reference. A reference to a rule excluded for the active
platform is dropped with its source path, identity, and reason, rather than
making the rest of the collection fail to load. `rustinel doctor` reports those
dropped documents.

### Correlation rules

RSigma evaluates correlation rules after the stateless detection pass. Rustinel
loads all detection, correlation, and filter documents into one collection, so
a correlation can reference a rule in another file or logsource family. Filters
are applied before the collection is compiled.

For each event, Rustinel evaluates detection rules under the concrete logsources
that can produce that event. It removes duplicate matches caused by overlapping
aliases, then sends every remaining detection to one synchronized correlation
engine. The alert list contains the best detection match, if any, followed by
every correlation that fired for the event.

Correlation windows use `NormalizedEvent.timestamp`, parsed as RFC3339. A
correlation alert keeps its own rule name, ID, and severity. Its group key,
aggregate, and window length appear in `match_details.correlation`. Correlation
state is in memory, so a Sigma hot reload starts new windows.

### Rule loading and classification

- Rules load recursively from `scanner.sigma_rules_path`.
- Multi-document YAML is supported; the `global`, `reset`, and `repeat`
  collection actions expand into the rules that follow.
- Rules are classified at load time by normalized `product`, `service`, and
  `category`. `product` mismatches and unknown logsource shapes are skipped.
- Known but inactive collectors still load for compatibility, but those rules
  **never fire**, because no sensor emits their telemetry. Do not read rule
  count as coverage; see [Sigma Coverage](coverage.md) for how much of the
  public corpus can actually fire, and on what it is blocked.

### Match selection

Rustinel emits at most one detection alert per event. When several detection
rules match, the winner is chosen by this policy:

1. Highest normalized severity wins (`critical` > `high` > `medium` > `low`;
   missing or unknown levels normalize to `low`).
2. On a tie, a rule with an `id` beats one without.
3. Then the smallest rule `id`, then the smallest `title`.

A broad low-severity rule therefore cannot shadow a specific critical one, and
the detection result never depends on rule load order. Correlation alerts are
added separately when their windows fire.

### Supported logsource families

| Family | Windows | Linux | macOS | Notes |
| --- | --- | --- | --- | --- |
| `process_creation` | Yes | Yes | Yes | Sysmon-style process events |
| `network_connection` | Yes | Yes | Yes | Generic `service: connection`, `category: network` also supported; macOS attribution is best-effort |
| `file_event` | Yes | Yes | Yes | Base file family |
| `file_create` | Yes | Yes | Yes | Derived from file event ID / opcode |
| `file_delete` | Yes | Yes | Yes | Derived from file event ID / opcode |
| `file_change` | Yes | No | No | Timestomping only, see below. Not emitted on Linux or macOS ([#146](https://github.com/Karib0u/rustinel/issues/146)) |
| `file_rename` | Yes | Yes | Yes | Derived from file event ID / opcode |
| `dns_query` | Yes | Yes | Yes | Generic `category: dns` and `service: dns`, `category: network` also supported |
| `registry_event` / `registry_*` | Yes | No | No | Windows only |
| `image_load` | Yes | No | No | Windows only |
| `ps_script` | Yes | No | No | Windows only |
| `ps_module` | Yes | No | No | Windows only, requires Module Logging policy, see below |
| `wmi_event` | Yes | No | No | Windows only, see below |
| `service_creation` | Yes | No | No | Windows only |
| `task_creation` | Yes | No | No | Windows only |

The Windows Security channel is a family of its own. Rules for it carry no
`category` — `product: windows`, `service: security`, and an `EventID`
selection — so they are routed by channel rather than by category:

| Event ID | Event | Key fields |
| --- | --- | --- |
| 4624 | An account was successfully logged on | `LogonType`, `AuthenticationPackageName`, `LogonProcessName`, `TargetUserName`, `WorkstationName`, `IpAddress` |
| 4656 | A handle to an object was requested | `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4663 | An attempt was made to access an object | `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4697 | A service was installed in the system | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` |
| 5136 | A directory service object was modified | `ObjectDN`, `ObjectClass`, `AttributeLDAPDisplayName`, `AttributeValue`, `OperationType` |
| 5145 | A network share object was checked | `ShareName`, `ShareLocalPath`, `RelativeTargetName`, `AccessMask`, `AccessList`, `IpAddress` |

Every one of them also carries the `Subject*` identity block
(`SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`).
An event ID outside this list is not subscribed to, so a rule selecting on one
loads and never matches. The authoritative list is `SUPPORTED_EVENTS` in
`src/sensor/windows/event_log/security.rs`.

Values are kept exactly as Windows renders them, because that is what rules for
this channel are written against: `SubjectLogonId` matches `0x3e4`, not `996`,
and `AccessList` matches the raw `%%4417` access-right codes. `ProcessId` is
likewise the channel's own hex.

Five of the six need audit policy that is off by default — see
[Windows audit policy](operations.md#windows-audit-policy).

macOS telemetry has two sources: Endpoint Security for process and file events
(`provider: esf`), and `/dev/bpf` capture for network and DNS (`provider: bpf`).
Its coverage mirrors Linux.

#### File event numbering

Every sensor routes file telemetry through one shared table, so the same logical
action carries the same identifiers on all three platforms:

| Action | Meaning | `event_id` | `action_code` | Categories |
| --- | --- | --- | --- | --- |
| Create | File created | 11 | 64 | `file_event`, `file_create` |
| Set | Timestamps or attributes changed | 2 | 2 | `file_event`, `file_change` |
| Modify | Content written or truncated | 65 | 65 | `file_event` |
| Delete | File deleted | 23 | 70 | `file_delete` |
| Rename | File renamed or hard-linked | 71 | 71 | `file_event`, `file_rename` |

Identifiers are Sysmon-compatible where Sysmon has an equivalent (2, 11, 23).
Sysmon has no modify or rename event, so those reuse the action code. A delete
is deliberately not a member of `file_event`.

Two things rule authors need to know:

- **`file_change` means timestomping, not "was written".** It corresponds to
  Sysmon Event ID 2, and rules published in it are written against timestamp
  manipulation. Ordinary writes are reported under `file_event` instead. On
  Windows, `CreationUtcTime` and `PreviousCreationUtcTime` stay empty because
  the provider reports which information class was set but never the values, so a
  `file_change` rule keyed on those fields cannot fire, one keyed on
  `TargetFilename` and `Image` can.
- **File events whose path cannot be resolved are dropped, not emitted bare.**
  On both Windows and Linux the kernel names the target by handle or descriptor
  rather than by path, and the path has to be reconstructed. When that fails the
  event is discarded, because a `TargetFilename` of `passwd` would match rules
  written for `/etc/passwd`. The drops are counted and logged as
  `unresolved_file_events`, so the size of the gap is observable. See
  [Limitations](limitations.md) for which handles and descriptors this affects.

**`PathTruncated` marks incomplete paths.** The Linux sensor captures at most
511 bytes per path; longer paths are cut and the event names which side was
truncated (`target`, `source`, or `source,target`), surfacing in ECS as
`edr.file.path_truncated`. Truncation removes the *end* of the path (exactly
what `|endswith` rules and extension IOCs match on), so a marked event that
matched nothing has not been cleared. The field never participates in keyword
search.

#### WMI event numbering

Windows WMI telemetry comes from `Microsoft-Windows-WMI-Activity`, whose event
IDs are its own and are **not** remapped onto Sysmon's. Sysmon's `wmi_event` IDs
19, 20, and 21 mean filter, consumer, and filter-to-consumer binding; the native
provider numbers unrelated operations in the same range, so the two colliding
IDs are dropped rather than passed through
([#291](https://github.com/Karib0u/rustinel/issues/291)).

For rule authors: `wmi_event` rules selecting on `EventID` do not match. Rules
matching `Operation`, `Query`, `EventNamespace`, `Image`, `User`, or
`DestinationHostname` do. WMI *persistence* telemetry is not collected at all.

#### PowerShell logsources

Both PowerShell families come from one provider,
`Microsoft-Windows-PowerShell`, split by event ID:

| Family | Event | Fields | Host policy required |
| --- | --- | --- | --- |
| `ps_script` | 4104 | `ScriptBlockText`, `ScriptBlockId`, `Path` | Script Block Logging, except for blocks Windows flags as suspicious |
| `ps_module` | 4103 | `ContextInfo`, `Payload` | Module Logging, always |

Module logging is **off by default**, and unlike script block logging it has no
automatic path: with the policy disabled, PowerShell writes no 4103 at all, so
`ps_module` rules see nothing however the session is configured. Enable **Turn
on Module Logging** under *Windows Components > Windows PowerShell* in Group
Policy, with module names set to `*`, or set the equivalent registry values:

```powershell
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path "$key\ModuleNames" -Force | Out-Null
New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force
```

For rule authors: `ContextInfo` and `Payload` are free-form provider text, not
parsed fields. `ContextInfo` is a newline-separated `name = value` block (host
application, command name, user, shell ID) and `Payload` is the
parameter-binding transcript. Windows writes **both in the host's display
language**, so a rule that matches a label (`Host Application =`) rather than a
value only fires on an English host. PowerShell 7 uses a different provider and
is not collected.

### Field model

Sigma evaluates the shared `NormalizedEvent` model using Sysmon-style field
names.

- **Process:** `Image`, `CommandLine`, `User`, `ProcessId`, `ParentImage`,
  `ParentCommandLine`
- **Network:** `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`,
  `DestinationHostname`, `Protocol`, `Initiated`
- **File:** `TargetFilename`, `Image`, `ProcessId`, `User`, plus
  `SourceFilename` on a rename and `PathTruncated`
- **DNS:** Sysmon-style `QueryName` / `QueryResults` / `RecordType`, or the
  generic aliases `query`, `answer`, `record_type`
 - **Service (Windows 7045):** `Provider_Name`, `ServiceName`, `ImagePath`,
   `ServiceType`, `StartType`, `AccountName`, `User`. `ServiceFileName` is the
   same value as `ImagePath`; SigmaHQ's service rules use `ImagePath`, so both
   names resolve. `Image` and `ProcessId` stay empty: the 7045 record names no
   installing process.

 - **PE version resources (Windows only):** `OriginalFileName`, `Product`,
   `Description`, `Company`, and `FileVersion` are read from the image's own
   version resource on process creation and image load. They are absent on Linux
  and macOS, and on any image whose file is unreadable when the event is
   decoded (deleted, locked, or unversioned).
- **PowerShell:** `ScriptBlockText`, `ScriptBlockId`, `Path` on `ps_script`;
  `ContextInfo`, `Payload` on `ps_module`

`Initiated` is Sysmon's connection direction, written in rules as the string
`'true'` or `'false'`. Windows reports it from the ETW operation: `true` for a
connect, `false` for an accept. Linux hooks only `connect()`, so it is always
`true` there. macOS captures packets off the wire, which does not say who opened
the connection, so the field is absent and neither value matches. An absent
field never matches an equality selection, so a sensor that cannot tell the
direction stays silent rather than answering wrongly.

Per-platform process notes:

- **Linux:** `CommandLine` comes from argv snapshotted in eBPF at `execve` entry,
  so it survives processes that exit before enrichment; it is bounded at 512
  bytes, 32 arguments, and 127 bytes per argument. `Image` resolves from
  `/proc/<pid>/exe`, which is absolute and symlink-resolved, but short-lived
  processes fall back to the raw `execve()` argument, which may be relative and
  is capped at 127 bytes. `ParentImage`, `ParentProcessId`, `ParentCommandLine`, and
  `CurrentDirectory` are enriched from `/proc` and may be absent.
- **macOS:** ESF exec events carry `CommandLine`, `ParentImage`,
  `ParentProcessId`, and `CurrentDirectory` natively. `ParentCommandLine` is not
  provided, and `IntegrityLevel` is a Windows field with no macOS equivalent.
- **Windows:** `IntegrityLevel` is decoded from the mandatory-label SID on the
  process start event and spelled the way Sysmon spells it (`System`, `High`,
  `Medium`), so it is absent on process stop events. Several other modelled
  fields are never populated. See
  [Limitations](limitations.md#windows-etw-and-event-log).

**`Provider_Name` is not `event.provider`.** `Provider_Name` is the Windows
provider that wrote the record — `Service Control Manager` for event 7045 — and
comes from the Event Log subscription. `NormalizedEvent.provider`, surfaced as
ECS `event.provider`, names the Rustinel sensor that collected it (`etw`,
`windows_event_log`, `ebpf`, `esf`, `bpf`). Only Event-Log-sourced events carry
`Provider_Name`; ETW-sourced events do not. In SigmaHQ, the field is almost
entirely a `system` and `application` channel concern, so that gap costs three
rules.

DNS field availability:

| Field | Windows ETW | Linux eBPF | macOS bpf |
| --- | --- | --- | --- |
| `QueryName` | Yes | Yes | Yes |
| `QueryResults` | Yes | No | No |
| `QueryStatus` | Yes | No | No |
| `RecordType` | No | Yes | Yes |
| `Image` | Yes | Yes | No |
| `ProcessId` | Yes | Yes | No |

DNS capture is **plaintext port 53 only** on Linux and macOS: DNS-over-HTTPS,
DNS-over-TLS, and cached resolver answers that send no packet are invisible, and
response answers are not parsed. macOS capture is packet-based rather than
per-process, so its DNS events are not attributed to a process at all.

After a Sigma hit, non-process alerts are enriched with `process_context` from
the process cache where available.

### Supported modifiers

| Modifier | Meaning |
| --- | --- |
| `contains` | Substring match |
| `startswith` | Prefix match |
| `endswith` | Suffix match |
| `all` | All values must match |
| `cased` | Case-sensitive match |
| `re` | Regular expression |
| `i`, `m`, `s` | Regex flags |
| `windash` | Windows dash normalization |
| `fieldref` | Compare against another field |
| `exists` | Field presence or null check |
| `cidr` | IP range matching |
| `base64`, `base64offset` | Base64-encoded match, with and without offset variations |
| `wide`, `utf16`, `utf16le`, `utf16be` | UTF-16 transformations |
| `lt`, `gt`, `le`, `lte`, `ge`, `gte` | Numeric comparison |
| `neq` | Value must differ |
| `expand` | `%placeholder%` expansion |
| `minute`, `hour`, `day`, `week`, `month`, `year` | Timestamp part comparison |

Wildcards `*` and `?` are supported in string patterns. A rule using a modifier
outside this set fails to parse; it is reported in the load summary and by
`rustinel doctor` rather than partially matched.

### Match debug

`alerts.match_debug` controls how much match metadata is attached:

- `off`: no detection `match_details`; correlation alerts still include their
  aggregation details
- `summary`: the matched selections and the matched field or keyword
  descriptors, without the matched values
- `full`: the matched values as well

For YARA alerts, `summary` adds the matched rule name, tags, and namespace, and
`full` adds matched string IDs, offsets, and snippets. Long metadata is
truncated to keep alerts bounded.

### Severity

| Sigma rule level | Alert severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| anything else | Low |

## YARA

YARA scanning runs on Windows, Linux, and macOS.

- Rules compile recursively from `.yar` and `.yara` files under
  `scanner.yara_rules_path`.
- **Only process-start events queue a scan**, so a file written but never executed
  is not scanned.
- Trusted path prefixes are skipped before queueing and re-checked in the worker.
- Results are cached by file identity, 10,000 entries with a 6-hour TTL.
- Each matching rule emits its own `critical` alert.
- On Windows, raw ETW paths are normalized before scanning.

### Memory scanning

Optional and off by default (`scanner.yara_memory_enabled = false`). When
enabled, process identities from process-start events are queued to a bounded
worker, which waits `yara_memory_delay_ms` (default 750 ms) to let packers
finish unpacking, then reads a limited amount of process memory and scans it.

Before reading, the worker revalidates the queued PID against the process image
and any available start-time and command-line metadata, skipping the scan if the
identity changed or cannot be queried. Platforms without identity query support
fail closed.

By default only private readable regions are scanned; image-backed and mapped
regions are excluded to limit overhead and false positives. Hits carry
`provider: yara-memory` to distinguish them from file hits. Memory scanning
honours the same allowlist as file YARA, and a full queue drops jobs rather than
blocking the sensor path.

macOS additionally depends on `task_for_pid` access, which is heavily
restricted. See [Limitations](limitations.md#macos-esf-experimental).

## IOC

The IOC engine hot reloads indicator files and splits work between inline checks
and a background hash worker.

| Indicator | Source file | Checked against | Path |
| --- | --- | --- | --- |
| Hashes | `ioc/hashes.txt` | Process-start executable | Background worker |
| IPs / CIDRs | `ioc/ips.txt` | Network source and destination IPs, plus IPs parsed from DNS answers | Inline |
| Domains | `ioc/domains.txt` | DNS `QueryName`, network and WMI `DestinationHostname` | Inline |
| Path regexes | `ioc/paths_regex.txt` | `Image`, `TargetImage`, `TargetFilename`, `ImageLoaded`, PowerShell `Path`, `ServiceFileName` | Inline |

Hashing runs only when at least one hash IOC is loaded, only from process-start
events, and only after trusted-path and `ioc.max_file_size_mb` checks. Results
are cached like YARA's. Inline matching can emit several alerts from one event.

Domain matching works on all three platforms through `QueryName`. Matching on
DNS *answer* IPs requires `QueryResults` and is therefore Windows-only.

### File format

- `#` and `//` begin comments; empty lines are ignored; `;comment` suffixes are optional.
- Hashes are auto-detected by length as MD5, SHA1, or SHA256.
- Domains without a leading `.` are exact matches; with a leading `.` (or `*.`)
  they match the suffix and all subdomains.
- Path regexes compile case-insensitive.

```text
203.0.113.1;C2 endpoint
.example.org;Suspicious zone
^/tmp/evil(/.*)?$;Linux staging path
```

Severity comes from `ioc.default_severity`, defaulting to `high` for unknown
values.

## Overall severity mapping

| Detector | Behavior |
| --- | --- |
| Sigma | The rule `level`; anything outside critical/high/medium becomes Low |
| YARA | Always Critical |
| IOC | `ioc.default_severity` |

## Replay

`rustinel replay` evaluates a recording against the detectors offline, calling
the same detector service the live pipeline calls, so a replayed event is
evaluated by exactly the code that would have seen it live.

| Detector path | In replay |
| --- | --- |
| Sigma | Evaluated, routed by the platform in the manifest |
| IOC domains / IPs / paths | Evaluated |
| YARA and IOC hashes | Skipped and reported as skipped: a recording holds events, not files |
| Active response | Never invoked, whatever the configuration says |
| Deduplication | Off, so every match is reported |
| Hot reload | Off, so a finite replay is reproducible |

This is the detection-development loop: capture a behavior once, then iterate on
rules without re-running the sample. See the
[CLI reference](cli.md#replay) for the command,
[Output Format](output.md#replay-results) for the result formats, and
[Development](development.md#replay-regression-fixture) for the checked-in
regression fixture.
