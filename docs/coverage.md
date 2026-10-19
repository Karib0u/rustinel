# Platform coverage

## What each platform collects

| Telemetry | Windows | Linux | macOS |
| --- | :---: | :---: | :---: |
| Process start and exit | ✓ | ✓ | ✓ |
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
| Driver loads | ✓ | | |

1. Captured from the network and matched to a process on a best-effort basis.
2. Plain DNS on port 53 only.
   DNS over HTTPS or TLS is not visible.
3. Needs host policy, see [Windows host logging](windows-logging.md).
4. Image-load rules receive live DLL loads.
   This is a dense event stream, so enabling a broad rule corpus can increase CPU and memory use during DLL-heavy workloads.

macOS support is experimental.
Detailed gaps are in [Limitations](limitations.md).

## Telemetry that is missing

A blank cell in the table above is one of three things.

| Gap | Status | Platform | Why |
| --- | --- | --- | --- |
| Named pipes (`pipe_created`) | Unavailable without a driver | Windows | Kernel-File ETW records no pipe name or creator for a pipe exchange. |
| Process tampering | Unavailable without a driver | Windows | The only source is the Threat Intelligence provider, which is closed to a process that is not a protected process light. |
| Process access | Planned | Windows | Kernel-Audit-API-Calls gives the access, but not the true `GrantedAccess`, see [Limitations](limitations.md#windows). |
| Remote threads | Planned | Windows | Thread starts give the source and target process, with field gaps for rules that need module or function names. |
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

CI loads every rule from SigmaHQ commit `da9bb07` (3,783 rules) and checks the result against a pinned baseline.
Rules that load against a collector on each platform:

| Platform | Rules |
| --- | ---: |
| Windows | 2,709 |
| Linux | 178 |
| macOS | 86 |

The rest are skipped: they target another platform, a cloud or network product, or a Linux log service Rustinel does not read, such as `auditd`.

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
| `sysmon` | windows | 217 | 1139 | 65 |
| `sysmon` | linux | 19 | 51 | 15 |
| `sysmon` | macos | 27 | 28 | 28 |
| `auditd` | linux | 15 | 23 | 47 |

The complete machine-readable baseline is [`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).
<!-- END GENERATED FIELD AVAILABILITY -->
