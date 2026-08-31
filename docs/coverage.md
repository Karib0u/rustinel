# Sigma Coverage

How much of the public SigmaHQ corpus can actually fire on Rustinel today,
measured rather than estimated.

> **"Can fire" is not "will detect."** It means every field the rule references
> is populated by a real sensor, so the rule is capable of matching. Whether it
> matches your adversary is a separate question.

## Headline

Measured against SigmaHQ `da9bb07` (2026-08-19, 3,783 rules) on Rustinel
`4d391a6`:

| Platform | Rules | Can fire | Blocked: no collector | Blocked: unavailable field |
| --- | --- | --- | --- | --- |
| Windows | 2,875 | **2,138 (74.4%)** | 448 (15.6%) | 289 (10.1%) |
| Linux | 248 | **177 (71.4%)** | 65 (26.2%) | 6 (2.4%) |
| macOS | 75 | **74 (98.7%)** | 0 | 1 (1.3%) |

The other 585 corpus rules target cloud, network, and appliance sources (Azure,
AWS, Okta, Zeek, M365…). Rustinel is an endpoint sensor and does not claim them.

No rule matches on substituted or wrong data on any platform, and **no rule in
the public corpus uses Sigma correlation**, so the lack of stateful correlation
(see [Limitations](limitations.md#detection-engine-sigma)) costs nothing against
SigmaHQ, though it still matters for custom rules.

## What blocks the rest

### Windows: missing collectors (448 rules)

Dominated by two Event Log channels and a few Sysmon categories:

| Rules | Blocked on |
| --- | --- |
| 177 | `security` channel |
| 32 | `application` channel |
| 34 | `ps_module` (PowerShell event 4103) |
| 29 | `process_access` |
| 20 | `pipe_created` |
| 17 | `windefend` |
| 15 | `create_remote_thread` |

**Since this measurement**, two of these rows have moved. The table itself is
left as measured; the next full run will absorb both.

- The 34 `ps_module` rules are no longer blocked. Event 4103 is collected from
  the PowerShell provider
  ([#322](https://github.com/Karib0u/rustinel/issues/322)), and all 34 reference
  only `ContextInfo` and `Payload`, which the decoder populates — so they move
  to "can fire" (Windows 2,172 / 75.5%, blocked-on-collector 414 / 14.4%) once
  the host has Module Logging enabled. See
  [Detection](detection.md#powershell-logsources).
- The `security` row predates the Security channel collector
  ([#315](https://github.com/Karib0u/rustinel/issues/315)), which covers six
  audit event families in that channel. It has not been re-measured, and what
  the collector delivers depends on the host's
  [audit policy](operations.md#windows-audit-policy), so treat 177 as an upper
  bound on what is still blocked rather than a current count.

### Windows: unavailable fields (289 rules)

The field is modelled but no sensor populates it:

| Rules | Field |
| --- | --- |
| 72 | `Provider_Name` |
| 51 | `Initiated` (since fixed, see below) |
| 47 | `Hashes` |
| 39 | `ImagePath` |
| 29 | `IntegrityLevel` (fixed after this measurement) |
| 27 | `User` |
| 21 | `Company` |
| 15 | `Signed` |
| 11 | `CurrentDirectory` |

These are the fields listed as permanently empty in
[Limitations](limitations.md#windows-etw-and-event-log). A rule referencing any
of them loads successfully and never matches.

`IntegrityLevel` is populated on Windows process creation since
[#294](https://github.com/Karib0u/rustinel/issues/294), which lands after the
run above. The 29 rules it blocks are no longer blocked on it, but the headline
totals are left as measured rather than adjusted by hand; they are re-measured
against the corpus each release.

`Initiated` is the exception: it is now populated on Windows, `true` for a
connect and `false` for an accept. The table is left as measured because the
whole snapshot was taken before that change and re-deriving one row against a
different corpus would make the totals inconsistent; the next measurement is
what moves the headline.

`Company` is no longer one of them: it is now read from the PE version
resource, alongside `FileVersion`
([#303](https://github.com/Karib0u/rustinel/issues/303)). The table above
predates that change and still counts its 21 rules as blocked.

### Linux: one source dominates

**54 of the 65 blocked Linux rules are `auditd`**, and nothing else reaches 4.
Those rules use raw auditd fields (`type`, `a0`-`a4`, `exe`, `syscall`), which
is a different field model rather than more eBPF telemetry. Everything else
(module load, ptrace, `accept()`, TCP DNS) unlocks **zero** corpus rules.

### macOS

74 of 75 rules can fire; the one exception is blocked on `OriginalFileName`. The
corpus is small enough that this says as much about SigmaHQ's macOS coverage as
about Rustinel's.

## Two things this changes

**Rule count is not coverage.** Loading a 3,000-rule pack on Linux does not
give you 3,000 detections. Most of it is Windows-oriented and inert. Judge a
pack by what its rules reference, not by its size.

**A blocked rule fails silently.** It loads, sees events, and never matches, with
no error. That is why the field tables above matter more than the headline
percentage. Per-rule diagnostics are tracked by
[#184](https://github.com/Karib0u/rustinel/issues/184).

## Provenance

These figures are a point-in-time measurement, derived by running Rustinel's own
logsource-classification and field-resolution logic over every rule in the
corpus, with field availability read from the decoders rather than from
documentation. They move whenever a collector, a field mapping, or the corpus
changes, so treat the commit and corpus above as part of the number.
