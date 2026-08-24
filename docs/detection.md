# Detection

Rustinel has three detector paths:

- Sigma for behavioral rules on normalized events
- YARA for executable scans on process-start events
- IOC for inline indicators plus background file hashing

All detection hits are written as ECS NDJSON alerts. The same alerts can also feed the optional response engine.

## Runtime Flow

| Detector | Input | Execution path | Alert behavior |
| --- | --- | --- | --- |
| Sigma | Every normalized event | Inline in the shared `EventDetectors` service | At most one Sigma alert per event, see [Match Selection](#match-selection) |
| YARA | Process-start executable path | Background worker via `YaraEventHandler` | One alert per matching YARA rule |
| IOC domains / IPs / paths | Every normalized event | Inline in the shared `EventDetectors` service | Zero or more alerts per event |
| IOC hashes | Process-start executable path | Background worker | Zero or more alerts per file |

## Sigma

### Detection Engine

Rustinel ships two interchangeable Sigma matchers, selectable at runtime:

- Built-in (default): Rustinel's own matcher with an `evalexpr` condition evaluator. Always available.
- RSigma: the `rsigma-parser` and `rsigma-eval` libraries. Available only in binaries built with the `rsigma-engine` Cargo feature, which the official release binaries include.

Both backends reuse Rustinel's normalization, logsource classification, ECS alert output, hot reload, and IOC and YARA paths, so switching between them changes only the Sigma matching internals.

The RSigma engine is an opt-in, experimental backend. It is a newer detection path that may differ in behavior from the built-in matcher (see [Engine Conformance](#engine-conformance) for the known differences). The built-in matcher remains the default and the supported path; the official release binaries include RSigma so you can try it without rebuilding.

Select the engine with the `run` flag or the config file, with the flag taking precedence:

```sh
rustinel run --sigma-engine rsigma   # or: --sigma-engine builtin (default)
```

```toml
[scanner]
sigma_engine = "rsigma"  # or "builtin" (default)
```

The `EDR__SCANNER__SIGMA_ENGINE` environment variable works as well. Requesting `rsigma` from a binary built without the `rsigma-engine` feature fails fast at startup with a clear message rather than silently falling back. To compile the engine into your own build:

```sh
cargo build --release --features rsigma-engine
```

### Engine Conformance

The built-in engine implements the stateless subset of the Sigma specification that covers typical field-matching rules. The RSigma parser and evaluator cover a broader stateless surface. Rustinel does not currently integrate stateful correlation evaluation or filter application into its RSigma runtime. Each parsed correlation or filter document is therefore reported as unsupported with its source path, identity, and reason, and the counts are included in startup and reload summaries. Stateful correlation support remains tracked by [issue #143](https://github.com/Karib0u/rustinel/issues/143).

Both backends agree on the common surface: the modifiers listed under [Supported Modifiers](#supported-modifiers), wildcards, keyword search, list-as-OR and map-as-AND selections, and `1 of` and `all of` conditions.

The built-in engine does not implement the following. RSigma provides broader stateless support, while stateful correlation and filter documents are reported as unsupported. Run rulesets that rely on the stateless RSigma features under `--sigma-engine rsigma`:

| Sigma feature | Built-in runtime | RSigma runtime |
| --- | --- | --- |
| `N of` condition quantifiers such as `2 of selection*` | No (only `1 of` and `all of`) | Yes |
| Array-scope quantifiers `field[any]` and `field[all]`, and element-scope blocks ([SEP #212](https://github.com/SigmaHQ/sigma-specification/issues/212)) | No | Yes |
| Correlations (`event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, `value_median`) | No | No, reported unsupported |
| Filter rules | No | No, reported unsupported |
| Collection actions `reset` and `repeat` (`global` is supported by both) | No | Yes for stateless rule documents |
| `expand` modifier and `%placeholder%` expansion | No | Yes |
| `sigma-version` aware evaluation ([SEP #213](https://github.com/SigmaHQ/sigma-specification/issues/213)) | No | Yes |
| Full rule-object metadata (status, date, author, references, falsepositives, related, fields, custom attributes) | Dropped | Preserved |

On an unsupported construct the built-in engine may skip the rule at load, fail to match, or mis-evaluate a complex condition. The RSigma runtime reports parsed correlation and filter documents as unsupported rather than evaluating them. Rulesets that rely on stateful features should wait for the integration tracked by issue #143.

Array matching and `sigma-version` are proposed Sigma Enhancement Proposals ([SEP #212](https://github.com/SigmaHQ/sigma-specification/issues/212) and [SEP #213](https://github.com/SigmaHQ/sigma-specification/issues/213)) targeting the next major Sigma release; RSigma is their reference implementation and supports them ahead of standardization.

### Rule Loading and Classification

- Rules load recursively from `scanner.sigma_rules_path`.
- Multi-document YAML is supported. Ordinary documents load as separate rules,
  and `action: global` documents expand shared metadata into following rules.
- Rules are classified at load time by normalized `product`, `service`, and `category`.
- `product` mismatches are skipped.
- Known Linux service families that are not implemented yet are marked as deferred instead of unknown.
- Unknown logsource shapes are skipped.
- Known but inactive collectors can still load for compatibility, but they will not match until the sensor emits that telemetry family.

### Match Selection

Rustinel emits at most one Sigma alert per event. When several rules match the
same event, both backends apply the same selection policy:

1. The highest normalized severity wins: `critical` > `high` > `medium` > `low`.
   Rules without a `level`, or with a level outside that set, normalize to `low`.
2. On equal severity, a rule carrying an `id` wins over one without.
3. Then the lexicographically smallest rule `id` wins, and finally the smallest
   `title`.

A broad low-severity rule therefore cannot shadow a more specific critical rule.
The tie-breaker never consults rule load order or directory traversal order, so
the emitted alert is the same whichever order the ruleset was loaded in.

Selecting the best match means every candidate rule for the event's logsources
is evaluated rather than stopping at the first hit. Reporting every matching
rule instead of one is tracked separately by
[issue #195](https://github.com/Karib0u/rustinel/issues/195).

### Supported Logsource Families

| Family | Windows ETW | Linux eBPF | macOS ESF/bpf | Notes |
| --- | --- | --- | --- | --- |
| `process_creation` | Yes | Yes | Yes | Sysmon-style process events |
| `network_connection` | Yes | Yes | Yes | Generic `service: connection`, `category: network` is also supported; macOS connections are best-effort process-attributed |
| `file_event` | Yes | Yes | Yes | Base file family |
| `file_create` | Yes | Yes | Yes | Derived from file event ID / opcode (ESF event type on macOS) |
| `file_delete` | Yes | Yes | Yes | Derived from file event ID / opcode (ESF event type on macOS) |
| `file_change` | Yes | No | No | Timestamp or attribute changes only — see [File Event Numbering](#file-event-numbering). Not populated on Linux or macOS, whose sensors do not yet report metadata changes ([#146](https://github.com/Karib0u/rustinel/issues/146)) |
| `file_rename` | Yes | Yes | Yes | Derived from file event ID / opcode (ESF event type on macOS) |
| `dns_query` | Yes | Yes | Yes | Generic `category: dns` and `service: dns`, `category: network` are also supported |
| `registry_event` / `registry_*` | Yes | No | No | Windows only |
| `image_load` | Yes | No | No | Windows only |
| `ps_script` | Yes | No | No | Windows only |
| `wmi_event` | Yes | No | No | Windows only |
| `service_creation` | Yes | No | No | Windows only |
| `task_creation` | Yes | No | No | Windows only |

macOS telemetry comes from two sources: Endpoint Security (ESF) for process and file events (`provider: esf`), and `/dev/bpf` packet capture for network and DNS (`provider: bpf`). Its coverage mirrors Linux; the Windows-only families above are not collected on macOS.

#### File Event Numbering

Every sensor routes its native file telemetry through one shared table, so the
same logical action carries the same identifiers — and therefore lands in the
same categories — on all three platforms:

| Action | Meaning | `event_id` | `action_code` | Categories |
| --- | --- | --- | --- | --- |
| Create | File created | 11 | 64 | `file_event`, `file_create` |
| Set | Timestamps or attributes changed | 2 | 2 | `file_event`, `file_change` |
| Modify | Content written or truncated | 65 | 65 | `file_event` |
| Delete | File deleted | 23 | 70 | `file_delete` |
| Rename | File renamed or hard-linked | 71 | 71 | `file_event`, `file_rename` |

The identifiers are Sysmon-compatible where Sysmon has an equivalent event
(2 = FileCreateTime, 11 = FileCreate, 23 = FileDelete). Sysmon has no
file-modify or file-rename event, so those reuse the action code as the
`event_id`. A delete is deliberately not a member of `file_event`.

**`file_change` means timestomping, not "was written".** The category
corresponds to Sysmon Event ID 2, *file creation time changed*. Rules published
in it are written against timestamp manipulation, so routing ordinary writes
there would make any rule that keys only on `TargetFilename` — which is most of
them — fire on routine file activity. Writes are reported under the base
`file_event` family instead.

On Windows this is derived from Kernel-File `SetInformation` (event ID 17): an
information class of `FileBasicInformation` is reported as `Set`, while
`FileAllocationInformation` and `FileEndOfFileInformation` are truncation and
are reported as `Modify`. One caveat for rule authors: the provider reports
*which* information class was set but never the values written, so
`CreationUtcTime` and `PreviousCreationUtcTime` stay empty. A `file_change`
rule that matches on those fields will not fire; one that matches on
`TargetFilename` and `Image` will.

**File events that cannot be resolved to a path are dropped.** Kernel-File
identifies the target of a write or a metadata change by kernel pointer rather
than by name, so the path is recovered from the earlier event that named the
handle. When that lookup misses — most often because the handle was already open
before the sensor started — the event is dropped rather than emitted without a
`TargetFilename`, since a file event with no path cannot match a rule. This is a
bounded, deliberate drop of a low-value event class, and it is counted: the
running total is logged as `unresolved_file_events`, so the size of the gap is
observable even though the events are not. See
[Limitations](limitations.md#windows-etw).

### Field Model

- Sigma evaluates the shared `NormalizedEvent` model with Sysmon-style field names.
- Shared process fields include `Image`, `CommandLine`, `User`, `ProcessId`, `ParentImage`, and `ParentCommandLine`.
- Shared network fields include `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`, and `DestinationHostname`.
- Shared file fields include `TargetFilename`, `Image`, `ProcessId`, and `User`.
- DNS rules can use either Sysmon-style names such as `QueryName` and `QueryResults` or the generic aliases `query`, `answer`, and `record_type`.

Per-platform process field notes:

- On Linux, the kernel exec event carries `Image`, `ProcessId`, `User`, and `CommandLine`; `ParentImage`, `ParentProcessId`, `ParentCommandLine`, and `CurrentDirectory` are enriched from `/proc/<pid>` and may be absent for very short-lived processes.
- On Linux, `CommandLine` comes from argv snapshotted in eBPF at `execve`/`execveat` entry, so it survives processes that exit before enrichment. The capture is bounded at 512 bytes, 32 arguments, and 127 bytes per argument; when a command line exceeds any of those the event is flagged truncated and the loader prefers `/proc/<pid>/cmdline` when that is still readable.
- `Image` is resolved from `/proc/<pid>/exe`, so it is absolute and symlink-resolved even when the binary was launched with a relative path (`./payload`). Short-lived processes that exit before enrichment fall back to the raw `execve()` argument, which may be relative and is capped at 128 bytes.
- On macOS, ESF exec events carry `CommandLine` (argv), `ParentImage`, `ParentProcessId`, and `CurrentDirectory` natively. `ParentCommandLine` is **not** provided by ESF exec events, and `IntegrityLevel` / `LogonId` / `LogonGuid` are Windows-only.

DNS field availability differs by platform:

| Field | Windows ETW | Linux eBPF | macOS bpf |
| --- | --- | --- | --- |
| `QueryName` | Yes | Yes | Yes |
| `QueryResults` | Yes | No | No |
| `QueryStatus` | Yes | No | No |
| `RecordType` | Yes | Yes | Yes |
| `Image` | Yes | Yes | No |
| `ProcessId` | Yes | Yes | No |

On Linux, `QueryName` is extracted in userspace from the bounded raw DNS payload emitted by the eBPF `sendto`, `sendmsg`, or `sendmmsg` paths. Each message uses the first iovec, capped at 256 bytes, and each `sendmmsg` call is capped at four messages. This covers outbound plaintext DNS queries observed on port 53. It does not cover DNS-over-HTTPS, DNS-over-TLS, cached resolver answers that do not send a packet, or DNS response answers. `QueryResults` and `QueryStatus` remain Windows-only today.

On macOS, `QueryName` and `RecordType` are parsed from `/dev/bpf` packet capture of outbound port-53 traffic, so the same plaintext-only limitations apply. Because capture is packet-based rather than per-process, macOS DNS events are **not** attributed to a process; `Image` and `ProcessId` are empty. Likewise, macOS `network_connection` events do not populate `DestinationHostname`, and their process attribution is best-effort. See [Limitations](limitations.md#macos-network-and-dns-attribution).

After a Sigma hit, Rustinel enriches non-process alerts with `process_context` from the process cache when that context is available.

### Supported Modifiers

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
| `base64` | Base64-encoded match |
| `base64offset` | Base64 match with offset variations |
| `wide`, `utf16`, `utf16le`, `utf16be` | UTF-16 transformations |
| `lt`, `gt`, `le`, `lte`, `ge`, `gte` | Numeric comparison |

Wildcard `*` and `?` matching is also supported for string patterns.

### Match Debug

`alerts.match_debug` controls how much match metadata is attached to Sigma alerts:

- `off`: no `match_details`
- `summary`: adds a short summary, the rule condition, selection results, and matched field or keyword descriptors without the matched field values
- `full`: adds the matched field values as well

Rustinel truncates long match metadata to keep alerts bounded.

### Severity

| Sigma Rule Level | Alert Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| anything else | Low |

## YARA

YARA scanning runs on all supported platforms (Windows, Linux, and macOS).

### Behavior

- Rules compile recursively from `.yar` and `.yara` files in `scanner.yara_rules_path` and all subdirectories.
- Only process-start events queue YARA scans.
- On Windows, raw ETW paths are normalized before scanning so the worker can open the file.
- Trusted path prefixes are skipped before queueing and checked again in the worker.
- Results are cached by file identity with a 10,000-entry cap and a 6-hour TTL.
- Each matching YARA rule emits its own alert.

### Match Debug

`alerts.match_debug` also affects YARA alerts:

- `off`: no `match_details`
- `summary`: includes the matched rule name and structured rule metadata such as tags and namespace
- `full`: also includes matched string IDs, offsets, and snippets

### Severity

Every YARA match is emitted as a `critical` alert.

### YARA memory scanning

YARA memory scanning is optional and disabled by default (`scanner.yara_memory_enabled = false`).

When enabled, Rustinel queues process identities from process-start events to a bounded background worker. The worker waits a configurable delay (`yara_memory_delay_ms`, default 750 ms) to allow packers or loaders to finish unpacking, then reads a limited amount of selected process memory and scans it with the active YARA ruleset.

Before reading memory, the worker revalidates the queued PID against the process image and any available start-time and command-line metadata. If the process identity changed or cannot be queried, the worker skips the scan and logs the reason. Platforms without process identity query support fail closed.

Default behavior scans private readable memory only and avoids mapped or image-backed regions to reduce overhead and false positives. Each matching YARA rule emits its own `critical` alert. The alert `provider` field is set to `yara-memory` to distinguish memory hits from file hits (`etw`, `ebpf`, or `esf`).

Memory scanning follows the same allowlist as file YARA: process paths allowlisted via `scanner.yara_allowlist_paths` are not queued for memory scanning either.

The worker uses `try_send` so a full queue drops jobs rather than blocking the sensor event path.

On macOS, memory scanning additionally depends on `task_for_pid` access, which is heavily restricted (it generally requires root plus SIP/AMFI relaxation or a specific entitlement); when access is denied, memory scanning simply yields nothing. File YARA scanning is unaffected. See [Limitations](limitations.md#macos-memory-scanning).

## IOC

The IOC engine hot reloads indicator files and splits work between inline event checks and a background hash worker.

### Indicator Types

| Indicator Type | Source File | Checked Against | Execution Path |
| --- | --- | --- | --- |
| Hashes | `rules/current/ioc/hashes.txt` | Process-start executable path | Background worker |
| IPs / CIDRs | `rules/current/ioc/ips.txt` | Network source and destination IPs, plus IPs parsed from DNS answers | Inline |
| Domains | `rules/current/ioc/domains.txt` | DNS `QueryName`, network `DestinationHostname`, WMI `DestinationHostname` | Inline |
| Path regexes | `rules/current/ioc/paths_regex.txt` | `ProcessCreation.Image`, `ProcessCreation.TargetImage`, `FileEvent.TargetFilename`, `ImageLoad.ImageLoaded`, `PowerShellScript.Path`, `ServiceCreation.ServiceFileName` | Inline |

### Runtime Notes

- Hashing only runs when at least one hash IOC is loaded.
- Hashing is triggered from process-start events.
- Trusted path prefixes and `ioc.max_file_size_mb` are enforced before hashing.
- Hash results are cached by file identity with a 10,000-entry cap and a 6-hour TTL.
- Inline IOC matching can emit multiple alerts from a single event.

Domain IOC matching works on Windows DNS events and on Linux and macOS outbound DNS query events through `QueryName`. IOC matching on DNS answer IPs still depends on `QueryResults`, so it is effectively Windows-only today.

### IOC File Format

- Lines beginning with `#` or `//` are comments.
- Empty lines are ignored.
- `;comment` suffixes are optional.
- Hashes are auto-detected by length as MD5, SHA1, or SHA256.
- Domain entries without a leading `.` are exact matches.
- Domain entries with a leading `.` match the suffix and all subdomains.
- Domain entries with a leading `*.` are normalized to suffix matching.
- Path regexes are compiled case-insensitive.

Example:

```text
203.0.113.1;C2 endpoint
.example.org;Suspicious zone
^/tmp/evil(/.*)?$;Linux staging path
```

### Severity

`ioc.default_severity` maps IOC alerts to `critical`, `high`, `medium`, or `low`. Unknown values fall back to `high`.

## Overall Severity Mapping

| Detector | Severity Behavior |
| --- | --- |
| Sigma | Uses the rule `level` with `critical`, `high`, and `medium` mapped explicitly; everything else becomes Low |
| YARA | Every match is Critical |
| IOC | Uses `ioc.default_severity` |

## Replay

`rustinel replay` runs the event-based detectors over a recording instead of over
a live sensor stream. It calls the same `EventDetectors` service the live
pipeline calls, so there is no second matching implementation to drift: a
replayed event is evaluated by exactly the code that would have seen it live.

What differs is only what a recording can support, and what a lab must not do:

| Detector path | Replay |
| --- | --- |
| Sigma | Evaluated, routed by the platform recorded in the manifest |
| IOC domains / IPs / paths | Evaluated |
| YARA | Skipped and reported as skipped: the file behind the event is not in the recording |
| IOC hashes | Skipped, for the same reason |
| Active response | Never invoked, whatever the configuration says |
| Deduplication | Off, so every match is reported |
| Hot reload | Off, so a finite replay is reproducible |

See the [CLI reference](cli.md#replay) for the command and
[Output Format](output.md#replay-results) for the result formats.

### Replay Regression Workflow

The repository carries a golden fixture so that a change to normalization,
serialization, or matching cannot quietly stop a rule from firing:

```text
tests/fixtures/replay/
+-- windows-powershell-fixture.ps1     benign behavior generator
+-- windows-powershell.ndjson          the recording
+-- windows-powershell.manifest.json   its manifest
+-- sigma/                             the rules the recording must fire
```

`tests/replay_fixture.rs` replays the recording against those rules on every
platform in ordinary CI, with no sensors and no privileges, and asserts that both
rules fire in the recorded order. The recording is a Windows capture, so it also
proves that a recording replays away from the platform that produced it.

To develop a rule against your own behavior:

```bash
# On a lab endpoint, with the sample ready to run in another window
sudo rustinel capture --output /tmp/lab/run-42.ndjson
# ... run the sample, then Ctrl-C ...

# Anywhere, as often as the rules change
rustinel replay /tmp/lab/run-42.ndjson --config /tmp/candidate.toml
```

To regenerate the checked-in fixture recording:

1. On a Windows lab endpoint, start `rustinel capture --output windows-powershell.ndjson`.
2. Run `windows-powershell-fixture.ps1`, then stop the capture with Ctrl-C.
3. Confirm the manifest reads `"status": "complete"`.
4. Copy both files into `tests/fixtures/replay/`, replacing the previous pair.
   Never edit a recording by hand: the manifest checksum is verified on every
   replay, and an edited payload is rejected.
5. Run `cargo test --test replay_fixture`.
