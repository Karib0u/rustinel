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
| `wmi_event` | ✓ | | |
| `service_creation` | ✓ | | |
| `task_creation` | ✓ | | |
| `service: security` | ✓ | | |

A rule whose `product` does not match the platform is skipped.
A rule for a logsource the platform does not collect loads but never fires.

`ps_module`, `ps_script`, and most `service: security` rules also need host logging to be enabled, see [Windows host logging](windows-logging.md).

## Fields

Field names follow Sysmon.

| Events | Fields |
| --- | --- |
| Process | `Image`, `CommandLine`, `ProcessId`, `ParentImage`, `ParentCommandLine`, `ParentProcessId`, `User`, `CurrentDirectory`, `IntegrityLevel` |
| Process, Windows only | `OriginalFileName`, `Product`, `Description`, `Company`, `FileVersion` |
| Process, Linux only | `ImageTruncated` |
| Process, macOS only | `PreExecImage`, `Script`, `Signed`, `SignatureStatus`, `SigningId`, `TeamId`, `CdHash`, `CodeSigningFlags`, `IsPlatformBinary` |
| Network | `DestinationIp`, `DestinationPort`, `DestinationHostname`, `SourceIp`, `SourcePort`, `Protocol`, `Initiated` |
| File | `TargetFilename`, `SourceFilename` (rename), `Image`, `ProcessId`, `User`, `PathTruncated` |
| DNS | `QueryName`, `QueryResults`, `RecordType`, or the aliases `query`, `answer`, `record_type` |
| Service (7045) | `ServiceName`, `ImagePath` (also `ServiceFileName`), `ServiceType`, `StartType`, `AccountName`, `Provider_Name` |
| PowerShell | `ScriptBlockText`, `ScriptBlockId`, `Path` (`ps_script`); `ContextInfo`, `Payload` (`ps_module`) |

Things that differ from Sysmon:

- **`Initiated`** is `'true'` for outgoing and `'false'` for accepted connections, on Windows and Linux.
  On Linux, accepted connections and `SourceIp`, `SourcePort`, and `Protocol` need kernel BTF; without it only outgoing connections are seen. macOS cannot tell the direction, so the field is absent there and matches neither value.
- **Linux `Image`** is the path passed to `execve()`.
  It may be relative, and is cut at 255 bytes, in which case `ImageTruncated` is `true`.
- **Linux `CommandLine`** is cut at 512 bytes, 32 arguments, or 127 bytes per argument.
- **Linux file paths** are cut at 511 bytes.
  `PathTruncated` names the side that was cut (`target`, `source`, or both).
  Cutting removes the end of the path, which is what `|endswith` matches.
- **`ParentImage` and `ParentCommandLine`** on Linux and macOS come from Rustinel's process cache.
  They are absent when Rustinel never saw the parent or has evicted it.
- **`Provider_Name`** is the Windows provider that wrote an Event Log record, such as `Service Control Manager`.
  It is not the ECS `event.provider`.
- **Security events** keep Windows' formatting: `SubjectLogonId` is `0x3e4`, not `996`, and `AccessList` holds `%%4417`-style codes.
- **PowerShell `ContextInfo` and `Payload`** are free text in the host's display language.

## Windows Security events

Rules with `service: security` match on `EventID`.
Only these IDs are collected; a rule for any other ID loads but never matches.

| Event ID | Event | Key fields |
| --- | --- | --- |
| 4624 | Logon | `LogonType`, `AuthenticationPackageName`, `LogonProcessName`, `TargetUserName`, `WorkstationName`, `IpAddress` |
| 4656 | Handle requested | `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4663 | Object accessed | `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4697 | Service installed | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` |
| 5136 | Directory object changed | `ObjectDN`, `ObjectClass`, `AttributeLDAPDisplayName`, `AttributeValue`, `OperationType` |
| 5145 | Share access checked | `ShareName`, `ShareLocalPath`, `RelativeTargetName`, `AccessMask`, `AccessList`, `IpAddress` |

All of them also carry `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, and `SubjectLogonId`.

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
