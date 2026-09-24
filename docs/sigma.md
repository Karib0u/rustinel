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

Rules are loaded recursively from `scanner.sigma_rules_path`.
A correlation or filter can reference a rule in another file.
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
| `can-fire` | The document parses, compiles, routes to an active collector, and has a condition that an emitted event shape can satisfy. |
| `degraded` | The document can evaluate, but at least one referenced field is conditional, unavailable on some branch, derived, best-effort, truncated, or stale. |
| `can-never-fire` | Parsing, compilation, routing, collector configuration, field availability, or a missing dependency prevents the document from evaluating successfully. |

Field availability is read from the same [`FIELD_AVAILABILITY`](field-availability.md) contract used by event access.
The analysis follows the condition structure.
An unavailable selection behind `or` does not make an available alternative inert, and negating an unavailable selection can still produce a true condition.
Exact `EventID` selections are checked against individual event shapes, including the optional Windows Filtering Platform collector.

Correlation and filter entries list their referenced documents.
A missing reference is `missing_reference`; an existing dependency that cannot fire is `dependency_unavailable`.
Temporal correlations require every dependency.
Count and aggregation correlations can remain degraded when another dependency still contributes events.
A filter with several explicit targets remains usable when at least one target is compatible.

### JSON contract

`--json` emits `schema_version: 1`, the selected `platform` and `field_view`, aggregate verdict and reason counts, and a deterministic `documents` array.
Each document includes source path, kind, identity, verdict, logsource, referenced fields, dependencies, and stable reason codes.
Source paths are relative to the inspected rules directory.

The schema version changes only for an incompatible rename, removal, type change, or semantic change.
New optional fields, new reason codes, and new document kinds are additive and keep the current schema version.
Consumers must ignore unknown object fields and reason codes.
Array order is stable for a given ruleset, but consumers should identify documents by source, kind, and id or title rather than by array position.

Stable reason codes in schema version 1 are:

`parse_error`, `compile_error`, `product_mismatch`, `deferred_logsource`, `unknown_logsource`, `inactive_collector`, `collector_disabled`, `no_platform_telemetry`, `unavailable_field`, `conditional_field`, `derived_field`, `best_effort_field`, `truncated_field`, `stale_field`, `missing_reference`, and `dependency_unavailable`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every document is `can-fire`. |
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
| `ps_script` | ✓ | | |
| `ps_module` | ✓ | | |
| `ps_classic_start` (also `service: powershell-classic`) | ✓ | | |
| `wmi_event` | ✓ | | |
| `service_creation` | ✓ | | |
| `task_creation` | ✓ | | |
| `service: security` | ✓ | | |

A rule whose `product` does not match the platform is skipped.
A rule for a logsource the platform does not collect loads but never fires.
On Linux and macOS, `service: sysmon` selects the Sysmon-compatible field view over native telemetry; it does not claim that Sysmon collected the event.

`ps_module`, `ps_script`, and most `service: security` rules also need host logging to be enabled, see [Windows host logging](windows-logging.md).

## Fields

The default `sysmon` field view follows Sysmon names.
Rustinel maps those names to canonical event accessors after collection, so sensors do not depend on a rule vocabulary.

| Events | Fields |
| --- | --- |
| Process | `Image`, `CommandLine`, `ProcessId`, `ParentImage`, `ParentCommandLine`, `ParentProcessId`, `User`, `CurrentDirectory`, `IntegrityLevel` |
| Process, Windows only | `OriginalFileName`, `Product`, `Description`, `Company`, `FileVersion`, `Hashes`, `Imphash` |
| Image load, Windows only | `ImageLoaded`, `Image`, `ProcessId`, `OriginalFileName`, `Product`, `Description`, `Company`, `FileVersion`, `Hashes`, `Imphash` |
| Process, Linux only | `ImageTruncated`, `CgroupId`, `CgroupPath`, `ContainerId`, `ContainerRuntime` |
| Process, macOS only | `PreExecImage`, `Script`, `Signed`, `SignatureStatus`, `SigningId`, `TeamId`, `CdHash`, `CodeSigningFlags`, `IsPlatformBinary` |
| Network | `DestinationIp`, `DestinationPort`, `DestinationHostname`, `SourceIp`, `SourcePort`, `Protocol`, `Initiated` |
| File | `TargetFilename`, `SourceFilename` (rename), `Image`, `ProcessId`, `User`, `PathTruncated` |
| DNS | `QueryName`, `QueryResults`, `RecordType`, or the aliases `query`, `answer`, `record_type` |
| Service (7045) | `ServiceName`, `ImagePath` (also `ServiceFileName`), `ServiceType`, `StartType`, `AccountName`, `Provider_Name` |
| Application channel | `Provider_Name`, `Level`, `Data`; Application Error 1000 also has `AppName`, `AppVersion`, `ModuleName`, `ExceptionCode` when present |
| PowerShell | `ScriptBlockText`, `ScriptBlockId`, `Path` (`ps_script`); `ContextInfo`, `Payload` (`ps_module`); `Data` (`ps_classic_start`) |

Things that differ from Sysmon:

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
- **`Provider_Name`** is the Windows provider that wrote an Event Log record, such as `Service Control Manager`.
  It is not the ECS `event.provider`.
- **Application `Message`** is unavailable. `Data` contains the raw XML values separated by newlines, and `Level` is numeric.
- **Security events** keep Windows' formatting: `SubjectLogonId` is `0x3e4`, not `996`, and `AccessList` holds `%%4417`-style codes.
- **PowerShell `ContextInfo` and `Payload`** are free text in the host's display language.
- **Classic PowerShell `Data`** is the raw event 400 engine-start description from the `Windows PowerShell` channel.

## Windows Security events

Rules with `service: security` match on `EventID`.
Only these IDs are collected; a rule for any other ID loads but never matches.

| Event ID | Event | Key fields |
| --- | --- | --- |
| 1102 | Security log cleared | `Provider_Name` (`Microsoft-Windows-Eventlog`) |
| 4624 | Logon | `LogonType`, `AuthenticationPackageName`, `LogonProcessName`, `TargetUserName`, `WorkstationName`, `IpAddress` |
| 4625 | Logon failed | `Status`, `SubStatus`, `FailureReason`, `LogonType`, `TargetUserName`, `WorkstationName`, `IpAddress` |
| 4648 | Logon with explicit credentials | `TargetUserName`, `TargetServerName`, `TargetInfo`, `ProcessName`, `IpAddress` |
| 4656 | Handle requested | `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4657 | Registry value modified | `ObjectName`, `ObjectValueName`, `OperationType`, `OldValue`, `NewValue`, `ProcessName` |
| 4663 | Object accessed | `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4697 | Service installed | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` |
| 4698, 4699, 4700, 4701 | Scheduled task created, deleted, enabled, disabled | `TaskName`, `TaskContent` |
| 4702 | Scheduled task updated | `TaskName`, `TaskContentNew` |
| 4719 | Audit policy changed | `SubcategoryGuid`, `AuditPolicyChanges` |
| 4720, 4738 | User account created, changed | `TargetUserName`, `SamAccountName`, `OldUacValue`, `NewUacValue`, `AllowedToDelegateTo`, `SidHistory` |
| 4722, 4724, 4726 | User account enabled, password reset, deleted | `TargetUserName`, `TargetSid` |
| 4728, 4732, 4756 | Member added to a global, local, universal group | `MemberName`, `MemberSid`, `TargetUserName`, `TargetSid` |
| 4741, 4743 | Computer account created, deleted | `TargetUserName`, `SamAccountName`, `DnsHostName`, `ServicePrincipalNames` |
| 4765, 4766 | SID history added, addition failed | `SourceUserName`, `TargetUserName`, `SidList` |
| 4771 | Kerberos pre-authentication failed | `TargetUserName`, `ServiceName`, `Status`, `PreAuthType`, `IpAddress` |
| 4776 | Credentials validated | `PackageName`, `TargetUserName`, `Workstation`, `Status` |
| 4781 | Account renamed | `OldTargetUserName`, `NewTargetUserName` |
| 4794 | DSRM administrator password set | `Workstation`, `Status` |
| 4817 | Object auditing settings changed | `ObjectType`, `ObjectName`, `OldSd`, `NewSd` |
| 5136 | Directory object changed | `ObjectDN`, `ObjectClass`, `AttributeLDAPDisplayName`, `AttributeValue`, `OperationType` |
| 5145 | Share access checked | `ShareName`, `ShareLocalPath`, `RelativeTargetName`, `AccessMask`, `AccessList`, `IpAddress` |
| 5152 ⁱ | Packet dropped | `Application`, `Direction`, `SourceAddress`, `DestAddress`, `DestPort`, `FilterName` |
| 5156 ⁱ, 5157 ⁱ | Connection allowed, blocked | `Application`, `Direction`, `SourceAddress`, `SourcePort`, `DestAddress`, `DestPort`, `LayerRTID` |
| 5447 | Filtering platform filter changed | `FilterName`, `ChangeType`, `LayerName`, `ProviderName` |
| 6416 | Device recognized | `DeviceId`, `DeviceDescription`, `ClassName` |

ⁱ Only with `windows.security_filtering_platform_connections = true`, see [Windows host logging](windows-logging.md#filtering-platform-connections).

Every event except 4771, 4776, and the filtering platform events also carries `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, and `SubjectLogonId`.
The connection events name the process `ProcessID` or `ProcessId`, depending on the Windows build: write rules against `Application` instead.
The complete field list for each ID is in [`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).
Domain controller authentication and directory access events, such as 4662, 4768, and 4769, are not collected yet.

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
WMI persistence events are not collected.

## Modifiers

| Modifier | Meaning |
| --- | --- |
| `contains`, `startswith`, `endswith` | Substring, prefix, suffix |
| `all` | All values must match |
| `cased` | Case-sensitive |
| `re`, with `i`, `m`, `s` | Regular expression and flags |
| `windash` | Also match `-`, `/`, and similar dashes |
| `fieldref` | Compare with another field |
| `exists` | Field is present |
| `cidr` | IP range |
| `base64`, `base64offset` | Base64-encoded value |
| `wide`, `utf16`, `utf16le`, `utf16be` | UTF-16 encodings |
| `lt`, `lte`, `le`, `gt`, `gte`, `ge`, `neq` | Numeric comparison and not-equal |
| `expand` | `%placeholder%` expansion |
| `minute`, `hour`, `day`, `week`, `month`, `year` | Part of a timestamp |

Wildcards `*` and `?` work in values.
A rule with any other modifier fails to load and is reported by `rustinel doctor`.
