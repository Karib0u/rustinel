# Platform coverage

## What each platform collects

| Telemetry | Windows | Linux | macOS |
| --- | :---: | :---: | :---: |
| Process start and exit | ✓ | ✓ | ✓ |
| Network connections | ✓ | ✓ | ✓ ¹ |
| File create, modify, rename, delete | ✓ | ✓ | ✓ |
| DNS queries | ✓ | ✓ ² | ✓ ² |
| DNS answers | ✓ | | |
| Registry | ✓ | | |
| Image (DLL) load | ✓ | | |
| PowerShell script blocks and modules | ✓ ³ | | |
| WMI activity | ✓ | | |
| Service installs, scheduled tasks | ✓ | | |
| Security audit events | ✓ ³ | | |
| Remote threads, process access, named pipes, drivers | | | |

1. Captured from the network and matched to a process on a best-effort basis.
2. Plain DNS on port 53 only.
   DNS over HTTPS or TLS is not visible.
3. Needs host policy, see [Windows host logging](windows-logging.md).

macOS support is experimental.
Detailed gaps are in [Limitations](limitations.md).

## SigmaHQ rules

CI loads every rule from SigmaHQ commit `da9bb07` (3,783 rules) and checks the result against a pinned baseline.
Rules that load against a collector on each platform:

| Platform | Rules |
| --- | ---: |
| Windows | 2,649 |
| Linux | 178 |
| macOS | 86 |

The rest are skipped: they target another platform, a cloud or network product, or a Linux log service Rustinel does not read, such as `auditd`.

A rule that loads can still reference a field the platform never fills.
Such a rule never fires.
Those fields are listed in [Field availability](field-availability.md), and `rustinel doctor` reports loaded rules with no collector as `sigma_rules_inert`.

!!! note "Rule count is not coverage"
    A 3,000-rule pack on Linux does not give 3,000 detections: most SigmaHQ rules are written for Windows.
    Judge a pack by what its rules reference.

## Field availability

<!-- BEGIN GENERATED FIELD AVAILABILITY -->
Generated from `FIELD_AVAILABILITY`.
These count fields, not rules: a rule that references a `Never` field inside an `or` branch can still fire.

| Platform | Always | Conditional | Never |
| --- | ---: | ---: | ---: |
| windows | 19 | 189 | 41 |
| linux | 19 | 40 | 17 |
| macos | 27 | 24 | 26 |

The complete machine-readable baseline is [`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).
<!-- END GENERATED FIELD AVAILABILITY -->
