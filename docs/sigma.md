# Sigma support

What the Sigma engine accepts, and which logsources and fields each platform provides.
Fields a platform never fills are listed in [Field availability](field-availability.md).

## Documents

| Sigma feature | Supported |
| --- | --- |
| Detection rules | Yes |
| Multi-document YAML with `global`, `reset`, `repeat` | Yes |
| `N of` quantifiers such as `2 of selection*` | Yes |
| `field[any]` / `field[all]` ([SEP #212](https://github.com/SigmaHQ/sigma-specification/issues/212)) | Yes |
| `%placeholder%` expansion with `expand` | Yes |
| `sigma-version` aware evaluation ([SEP #213](https://github.com/SigmaHQ/sigma-specification/issues/213)) | Yes |
| Correlation rules (`event_count`, `value_count`, `temporal`, ...) | Yes, windows use event time |
| Filter rules | Yes |

Rules are loaded recursively from `scanner.sigma_rules_path` and from every directory in `scanner.sigma_local_rules_paths`.
A correlation or filter can reference a rule in another file.
A filter must name its target rules by id, name, or title under `filter.rules`.
A filter with `rules: any`, an empty list, or no `rules` key is not loaded, because it would suppress matches for every rule in the tree; `rustinel doctor` reports it under `sigma_rules_unsupported`, and `rustinel sigma doctor` as `untargeted_filter`.
Each loaded filter is logged with its targets.
A reference to a rule that does not apply to this platform is dropped and reported by `rustinel doctor`.

## Compatibility diagnostics

Run the focused compatibility report before deploying a rules pack:

```bash
rustinel sigma doctor --platform windows
rustinel sigma doctor --platform linux --json
rustinel sigma doctor --platform macos --rules ./candidate/sigma
```

The platform defaults to the current host.
The rules directory defaults to `scanner.sigma_rules_path`.
`--rules` makes it possible to inspect a candidate pack without changing configuration.
The current field view is `sysmon`; the field view is included in JSON so future views can be distinguished without guessing from the platform.

Every detection, correlation, and filter document receives one verdict:

| Verdict | Meaning |
| --- | --- |
| `can-fire` | The document parses, compiles, routes to an active collector, and has a condition that an emitted event shape can satisfy. It can carry caveats, see below. |
| `degraded` | The document can evaluate, but at least one referenced field is conditional, unavailable on some branch, derived, best-effort, truncated, or stale, and that field has not been measured as reliable. |
| `can-never-fire` | Parsing, compilation, routing, collector configuration, field availability, or a missing dependency prevents the document from evaluating successfully. |

A field measured as reliably populated downgrades its reasons to caveats.
A caveat keeps the reason in the report with `severity: "caveat"` but does not degrade the document.
Today that covers `process_creation` on three platforms: `CommandLine`, `Image`, `ParentImage`, and `ParentProcessId` on Windows, `CommandLine`, `Image`, `ParentImage`, and `ParentCommandLine` on Linux, and `CommandLine` and `Image` on macOS.
The macOS `ParentImage` stays a limitation, because it is only present when the parent's exec was observed or the parent was already running when the sensor started.
Every other field stays strict until it has been measured.
`summary.can_fire_with_caveats` counts the `can-fire` documents that carry at least one caveat.

Field availability comes from the same [field availability](field-availability.md) contract the sensors follow.
The analysis follows the condition structure.
An unavailable selection behind `or` does not make an available alternative inert, and negating an unavailable selection can still produce a true condition.
Exact `EventID` selections are checked against individual event shapes, including the optional Windows Filtering Platform collector.

Correlation and filter entries list their referenced documents.
A missing reference is `missing_reference`; an existing dependency that cannot fire is `dependency_unavailable`.
A filter without explicit targets is `untargeted_filter` and can never fire.
Temporal correlations require every dependency.
Count and aggregation correlations can remain degraded when another dependency still contributes events.
A filter with several explicit targets remains usable when at least one target is compatible.

### JSON contract

`--json` emits `schema_version: 1`, the selected `platform` and `field_view`, aggregate verdict and reason counts, and a deterministic `documents` array.
Each document includes source path, kind, identity, verdict, logsource, referenced fields, dependencies, and stable reason codes.
A reason carries `severity: "caveat"` when it does not weigh on the verdict, and omits `severity` otherwise.
Source paths are relative to the inspected rules directory.

The schema version changes only for an incompatible rename, removal, type change, or semantic change.
New optional fields, new reason codes, and new document kinds are additive and keep the current schema version.
Consumers must ignore unknown object fields and reason codes.
Array order is stable for a given ruleset, but consumers should identify documents by source, kind, and id or title rather than by array position.

Stable reason codes in schema version 1 are:

`parse_error`, `compile_error`, `product_mismatch`, `deferred_logsource`, `unknown_logsource`, `inactive_collector`, `collector_disabled`, `no_platform_telemetry`, `unavailable_field`, `conditional_field`, `derived_field`, `best_effort_field`, `truncated_field`, `stale_field`, `missing_reference`, `dependency_unavailable`, and `untargeted_filter`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every document is `can-fire`, with or without caveats. |
| `1` | At least one document is `degraded` or `can-never-fire` for a coverage reason. |
| `2` | Configuration, parsing, or compilation prevented a reliable report. |

## Logsources

| Logsource | Windows | Linux | macOS |
| --- | :---: | :---: | :---: |
| `process_creation` | ✓ | ✓ | ✓ |
| `network_connection` (also `category: network`) | ✓ | ✓ | ✓ |
| `dns_query` (also `category: dns`, `service: dns`) | ✓ | ✓ | ✓ |
| `file_event`, `file_create`, `file_delete`, `file_rename` | ✓ | ✓ | ✓ |
| `file_change` | ✓ | | |
| `registry_event`, `registry_*` | ✓ | | |
| `image_load` | ✓ | | |
| `driver_load` | ✓ | | |
| `ps_script` | ✓ | | |
| `ps_module` | ✓ | | |
| `ps_classic_start` (also `service: powershell-classic`) | ✓ | | |
| `wmi_event` | ✓ | | |
| `service: wmi` | ✓ | | |
| `service_creation` | ✓ | | |
| `task_creation` | ✓ | | |
| `service: security` | ✓ | | |
| `service: windefend` | ✓ | | |
| `category: antivirus` (no product) | ✓ | | |
| `service: auditd` | | ✓ | |

A rule whose `product` does not match the platform is skipped.
A rule for a logsource the platform does not collect loads but never fires.
On Linux and macOS, `service: sysmon` selects the Sysmon-compatible field view over native telemetry; it does not claim that Sysmon collected the event.

`ps_module`, `ps_script`, and most `service: security` rules also need host logging to be enabled, see [Windows host logging](windows-logging.md).

### Linux auditd rules

Rustinel does not read auditd.
It renders its own eBPF exec and file telemetry through an `auditd` field view, so `service: auditd` rules need no audit daemon, no audit rules, and no extra privileges.
The view is a projection of what the sensor measured, not an audit log.

An exec stands for the `SYSCALL`, `EXECVE`, and `PATH` records auditd would write.
A file create, modify, delete, or rename stands for `SYSCALL` and `PATH`.

| Field | Source |
| --- | --- |
| `type` | The record types of the event. A rule value matches when it equals any of them. |
| `SYSCALL` | `execve` or `execveat` on an exec, taken from the argv snapshot at syscall entry. |
| `a0` to `a7` | The captured argv entries of an `EXECVE` record, with their boundaries kept. |
| `exe` | The executable path of the process. |
| `comm` | The short task name. |
| `euid` | The effective user ID. |
| `name` | The executed path, or the file path of a file event. A rename carries its source and target. |
| `nametype` | `CREATE`, `DELETE`, or `NORMAL` for a file event. A rename carries `DELETE` and `CREATE`. |

`a0` to `a7` are argv entries, never raw syscall arguments, and are never split out of `CommandLine`.

`key` and `unit` are not mapped.
An audit key is a label an operator configures on an audit rule, so the view never invents one.
A rule that selects on `key`, on `unit`, or on a syscall other than `execve` and `execveat` loads, and `rustinel sigma doctor` reports it as `can_never_fire` instead of leaving it silently inert.

File telemetry sees successful create, delete, rename, and write-intent operations.
It does not see read-only opens, so `PATH` rules for read access can miss.

## Fields

The default `sysmon` field view follows Sysmon names.
Rustinel maps those names to canonical event accessors after collection, so sensors do not depend on a rule vocabulary.

| Events | Fields |
| --- | --- |
| Process | `Image`, `CommandLine`, `ProcessId`, `ParentImage`, `ParentCommandLine`, `ParentProcessId`, `User`, `CurrentDirectory`, `IntegrityLevel` |
| Process, Windows only | `OriginalFileName`, `Product`, `Description`, `Company`, `FileVersion`, `Hashes`, `Imphash` |
| Image load, Windows only | `ImageLoaded`, `Image`, `ProcessId`, `OriginalFileName`, `Product`, `Description`, `Company`, `FileVersion`, `Hashes`, `Imphash`, `Signed`, `Signature`, `SignatureStatus` |
| Process, Linux only | `ImageTruncated`, `CgroupId`, `CgroupPath`, `ContainerId`, `ContainerRuntime` |
| Process, macOS only | `PreExecImage`, `Script`, `Signed`, `SignatureStatus`, `SigningId`, `TeamId`, `CdHash`, `CodeSigningFlags`, `IsPlatformBinary` |
| Network | `DestinationIp`, `DestinationPort`, `DestinationHostname`, `SourceIp`, `SourcePort`, `Protocol`, `Initiated` |
| File | `TargetFilename`, `SourceFilename` (rename), `Image`, `ProcessId`, `User`, `PathTruncated` |
| DNS | `QueryName`, `QueryResults`, `RecordType`, or the aliases `query`, `answer`, `record_type` |
| DNS, derived | `QueryRegisteredDomain`, `QueryLabelCount`, `QueryLongestLabel`, `QueryNameLength` |
| Service (7045) | `ServiceName`, `ImagePath` (also `ServiceFileName`), `ServiceType`, `StartType`, `AccountName`, `Provider_Name` |
| Defender Operational | `Provider_Name` and the native fields for each event ID, including `Old Value`, `New Value`, `Feature Name`, `Threat Name`, and `Path`. Rule aliases such as `OldValue`, `NewValue`, `Feature_Name`, and `ThreatName` are also available. Detections (1116 and 1117) also carry `Signature` (the threat name) and `Filename` (the first `file:_` resource of `Path`, without the prefix), which is what SigmaHQ's `category: antivirus` rules select on. |
| Application channel | `Provider_Name`, `Level`, `Data`; Application Error 1000 also has `AppName`, `AppVersion`, `ModuleName`, `ExceptionCode` when present |
| PowerShell | `ScriptBlockText`, `ScriptBlockId`, `Path` (`ps_script`); `ContextInfo`, `Payload` (`ps_module`); `Data` (`ps_classic_start`) |
| WMI Operational | `EventNamespace`, `Query`, `User`, `ProcessId`, `PossibleCause`; 5857 has `ProviderName`, `ProviderPath`, `HostProcess`, and `Code`; 5861 also has `FilterName`, `ConsumerClass`, `ConsumerName`, `ConsumerText`, and `Destination` |

Things that differ from Sysmon:

- **Derived DNS fields** are read-only values computed from `QueryName` when a rule reads them, so they never appear in recordings or alerts.
  `QueryRegisteredDomain` is the public suffix plus one label, so `a.b.example.co.uk` gives `example.co.uk`; it is absent for a bare suffix such as `co.uk` and for names under an unlisted suffix such as `.local`.
  It keeps the letter case of `QueryName`, and group keys compare case-sensitively, so resolvers that randomize case split a group.
  `QueryLabelCount`, `QueryLongestLabel`, and `QueryNameLength` are numbers: labels, the longest label in bytes, and the whole name in bytes, none of them counting a trailing root dot.
  Use them to find tunnelling and generated domains, for example a `value_count` correlation on `QueryName` with `group-by: QueryRegisteredDomain`.
  The suffix data is the Mozilla Public Suffix List, including its private section such as `github.io`.
  It is compiled into the binary by the `psl` crate, so it only changes with a Rustinel release; Dependabot proposes each `psl` update.
  Linux drops names its DNS parser rejects, such as a label over 63 bytes, and a name cut off by the capture (`QueryTruncated` is `true`) carries no derived field.
- **`Initiated`** is `'true'` for outgoing and `'false'` for accepted connections, on Windows and Linux.
  On Linux, accepted connections and `SourceIp`, `SourcePort`, and `Protocol` need kernel BTF; without it only outgoing connections are seen. macOS cannot tell the direction, so the field is absent there and matches neither value.
- **Linux `Image`** is the path passed to `execve()`.
  It may be relative, and is cut at 255 bytes, in which case `ImageTruncated` is `true`.
- **Linux `CommandLine`** is cut at 512 bytes, 32 arguments, or 127 bytes per argument.
- **Linux file paths** are cut at 511 bytes.
  `PathTruncated` names the side that was cut (`target`, `source`, or both).
  Cutting removes the end of the path, which is what `|endswith` matches.
- **Linux container fields** come from the process cgroup, checked against the kernel's cgroup ID.
  `ContainerId` is the full ID, and `ContainerRuntime` is `docker`, `containerd`, `cri-o`, `podman`, or `lxc`.
  Namespace membership alone does not identify a container: `nsenter` without a cgroup change keeps the caller's cgroup attribution.
  A host process has `CgroupPath` and no `ContainerId`.
  An event without `CgroupPath` is unresolved, not a host process, so select host processes with `CgroupPath|exists: true` and exclude `ContainerId|exists: true`.
- **`ParentImage` and `ParentCommandLine`** on Linux and macOS come from Rustinel's process cache.
  They are absent when Rustinel never saw the parent or has evicted it.
- **`Hashes` and `Imphash`** are computed by Rustinel from the image file, not by the kernel, and rules on them run in a [deferred pass](detection.md#deferred-pass).
  `Hashes` lists only the algorithms loaded rules name, in Sysmon's order.
- **`Signed`, `Signature`, and `SignatureStatus`** on Windows image loads are verified by Rustinel from the file, also in the [deferred pass](detection.md#deferred-pass).
  They are absent when verification did not finish.
- **`Provider_Name`** is the Windows provider that wrote an Event Log record, such as `Service Control Manager`.
  It is not the ECS `event.provider`.
- **Application `Message`** is unavailable.
  `Data` contains the raw XML values separated by newlines, and `Level` is numeric.
- **Security events** keep Windows' formatting: `SubjectLogonId` is `0x3e4`, not `996`, and `AccessList` holds `%%4417`-style codes.
- **PowerShell `ContextInfo` and `Payload`** are free text in the host's display language.
- **Classic PowerShell `Data`** is the raw event 400 engine-start description from the `Windows PowerShell` channel.

## Windows Security events

Rules with `service: security` match on `EventID`.
The collected IDs and their key fields are listed in [Windows Security events](windows-security-events.md).

## File event IDs

The same action has the same IDs on every platform:

| Action | `EventID` | Logsources |
| --- | --- | --- |
| Create | 11 | `file_event`, `file_create` |
| Modify | 65 | `file_event` |
| Rename | 71 | `file_event`, `file_rename` |
| Delete | 23 | `file_delete` |
| Timestamps or attributes changed | 2 | `file_event`, `file_change` |

`file_change` means timestamp tampering, as in Sysmon event 2, not "the file was written".
It exists only on Windows, and `CreationUtcTime` is never filled, so match on `TargetFilename` and `Image` instead.

## WMI event IDs

WMI events come from `Microsoft-Windows-WMI-Activity`, which numbers events differently from Sysmon's 19, 20, and 21.
A `wmi_event` rule that selects on `EventID` never matches.
Rules on `Operation`, `Query`, `EventNamespace`, `Image`, `User`, or `DestinationHostname` work.
Operational events 5857 through 5861 route under `product: windows, service: wmi` without a `category`.
Event 5861 reports a permanent filter-to-consumer binding.
`ConsumerText` and `Destination` contain its consumer definition, including `CommandLineTemplate` or script content when supplied by WMI.
`PossibleCause` holds the full binding detail, while `ConsumerClass`, `ConsumerName`, and `FilterName` identify its parts.
The sensor sees new bindings.
It does not enumerate bindings already present before it starts.

## Modifiers

| Modifier | Meaning |
| --- | --- |
| `contains`, `startswith`, `endswith` | Substring, prefix, suffix |
| `all` | All values must match |
| `cased` | Case-sensitive |
| `re`, with `i`, `m`, `s` (or `ignorecase`, `multiline`, `dotall`) | Regular expression and flags |
| `windash` | Also match `-`, `/`, and similar dashes |
| `fieldref` | Compare with another field |
| `exists` | Field is present |
| `cidr` | IP range |
| `base64`, `base64offset` | Base64-encoded value |
| `wide`, `utf16`, `utf16le`, `utf16be` | UTF-16 encodings |
| `lt`, `lte`, `gt`, `gte`, `neq` | Numeric comparison and not-equal |
| `expand` | `%placeholder%` expansion |
| `minute`, `hour`, `day`, `week`, `month`, `year` | Part of a timestamp |

Wildcards `*` and `?` work in values.
A rule with any other modifier fails to load and is reported by `rustinel doctor`.
