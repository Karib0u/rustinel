# Platform coverage

## What each platform collects

| Telemetry | Windows | Linux | macOS |
| --- | :---: | :---: | :---: |
| Process start and exit | ✓ | ✓ | ✓ |
| Cross-process thread starts | ✓ | | |
| Network connections | ✓ | ✓ | ✓ ¹ |
| File create, modify, rename, delete | ✓ | ✓ | ✓ |
| DNS queries | ✓ | ✓ ² | ✓ ² |
| DNS answers | ✓ | ✓ ² | |
| Registry | ✓ | | |
| Image (DLL) load | ✓ ⁴ | | |
| PowerShell script blocks and modules | ✓ ³ | | |
| WMI activity | ✓ | | |
| Service installs, scheduled tasks | ✓ | | |
| Security audit events | ✓ ³ | | |
| Microsoft Defender Operational events | ✓ | | |
| Application channel events | ✓ | | |
| Authentication: sshd, sudo, su, PAM | ✓ ³ | ✓ ⁵ | |
| Driver loads | ✓ | | |

1. Captured from the network and matched to a process on a best-effort basis.
2. Plain DNS on port 53 only.
   DNS over HTTPS or TLS is not visible.
3. Needs host policy, see [Windows host logging](windows-logging.md).
4. Image-load rules receive live DLL loads.
   This is a dense event stream, so enabling a broad rule corpus can increase CPU and memory use during DLL-heavy workloads.
5. Read from the systemd journal, see [Linux authentication events](linux-auth-log.md).
   Hosts without journald have none.

macOS support is experimental.
Detailed gaps are in [Limitations](limitations.md).

## Telemetry that is missing

A blank cell in the table above is one of three things.

| Gap | Status | Platform | Why |
| --- | --- | --- | --- |
| Named pipes (`pipe_created`) | Unavailable without a driver | Windows | Kernel-File ETW records no pipe name or creator for a pipe exchange. |
| Process tampering | Unavailable without a driver | Windows | The only source is the Threat Intelligence provider, which is closed to a process that is not a protected process light. |
| Process access | Planned | Windows | Kernel-Audit-API-Calls gives the access, but not the true `GrantedAccess`, see [Limitations](limitations.md#windows). |
| File reads of sensitive paths | Planned | Windows, Linux | Bounded to sensitive paths, not every read. |
| Alternate data streams | Planned | Windows | Stream names come from ETW, but contents and hashes need a bounded read. |
| Raw device reads | Planned | Windows | Raw reads of physical drives. |

Anything else not in the table is not collected today and has no decision recorded.

## Not in scope

These are deliberate boundaries, not gaps to close.

- **Other platforms.**
  Rustinel runs on Windows, Linux, and macOS hosts.
  ESXi and other hypervisors, network and edge devices, and mobile devices are not platforms.
- **Per-host correlation.**
  Correlation state lives in one agent.
  Correlating across hosts belongs to the SIEM that receives the alerts.
- **Inventory and exposure.**
  Rustinel collects no software inventory and no vulnerability exposure data.
- **Blocking.**
  Linux (BPF LSM) and macOS (Endpoint Security AUTH events) could block an action before it happens.
  Rustinel does not use them: detection stays passive by decision, see [Security model](security.md#scope).

## SigmaHQ rules

CI loads every rule from SigmaHQ commit `c04ad420` (3,793 rules) and checks the result against a pinned baseline.
Rules that load against a collector on each platform:

| Platform | Rules |
| --- | ---: |
| Windows | 2,753 |
| Linux | 237 |
| macOS | 86 |

The rest are skipped: they target another platform, a cloud or network product, or a Linux log service Rustinel does not read, such as `cron` or `syslog`.

### Windows cross-process thread rules

All 15 pinned `create_remote_thread` rules load.
`rustinel sigma doctor --platform windows` reports 13 as `degraded` and two as `can-never-fire`.
Every field listed below is conditional unless marked unavailable.

| Rule | Verdict | Detection fields |
| --- | --- | --- |
| CACTUSTORCH Remote Thread Creation | Degraded | `SourceImage`, `TargetImage`, `StartModule` (null selection) |
| Potential CobaltStrike Process Injection | Degraded | `StartAddress` |
| Remote Thread Created In KeePass.EXE | Degraded | `TargetImage` |
| CreateRemoteThread API and LoadLibrary | Can never fire | `StartModule`, `StartFunction` (unavailable) |
| Potential Bumblebee Remote Thread Creation | Degraded | `SourceImage`, `TargetImage` |
| Remote Thread Creation In Mstsc.Exe From Suspicious Location | Degraded | `SourceImage`, `TargetImage` |
| Remote Thread Creation Via PowerShell | Degraded | `SourceImage`, `SourceParentImage` |
| Potential Credential Dumping Attempt Via PowerShell Remote Thread | Degraded | `SourceImage`, `TargetImage` |
| Remote Thread Creation Via PowerShell In Uncommon Target | Degraded | `SourceImage`, `TargetImage` |
| Password Dumper Remote Thread in LSASS | Can never fire | `TargetImage`, `StartModule` (requires an empty string) |
| Rare Remote Thread Creation By Uncommon Source Image | Degraded | `SourceImage`, `TargetImage` |
| Remote Thread Created In Shell Application | Degraded | `SourceImage`, `TargetImage` |
| Remote Thread Creation By Uncommon Source Image | Degraded | `SourceImage`, `SourceCommandLine`, `SourceParentImage`, `TargetImage`, `TargetParentProcessId` |
| Remote Thread Creation In Uncommon Target Image | Degraded | `SourceImage`, `TargetImage`, `StartFunction` (unavailable for exclusions) |
| Remote Thread Creation Ttdinject.exe Proxy | Degraded | `SourceImage` |

A null selection on `StartModule` matches when the field is absent, including when startup or eviction gaps leave a mapped address unresolved.
The empty-string selection cannot match because resolved module paths are nonempty and unresolved paths are omitted.

## Rules that load but never fire

A rule can load without error and still never fire, in two ways:

- **No collector.**
  The platform does not collect the rule's logsource.
  `rustinel doctor` counts these rules as `sigma_rules_inert`.
- **A field is never filled.**
  The rule needs a field listed in [Field availability](field-availability.md).

`rustinel sigma doctor --platform <platform>` gives a verdict for each rule, taking `or` branches and negation into account, see [Compatibility diagnostics](sigma.md#compatibility-diagnostics).

!!! note "Rule count is not coverage"
    A 3,000-rule pack on Linux does not give 3,000 detections: most SigmaHQ rules are written for Windows.
    Judge a pack by what its rules reference.

## Field availability

<!-- BEGIN GENERATED FIELD AVAILABILITY -->
Generated from `FIELD_AVAILABILITY`.
These count fields, not rules: a rule that references a `Never` field inside an `or` branch can still fire.

| View | Platform | Always | Conditional | Never |
| --- | --- | ---: | ---: | ---: |
| `sysmon` | windows | 222 | 1163 | 67 |
| `sysmon` | linux | 129 | 148 | 47 |
| `sysmon` | macos | 27 | 28 | 28 |
| `auditd` | linux | 15 | 23 | 47 |

The complete machine-readable baseline is [`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).
<!-- END GENERATED FIELD AVAILABILITY -->
