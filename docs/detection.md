# Detection

Rustinel runs three engines over the same events.

| Engine | Checks | When | Alerts per event |
| --- | --- | --- | --- |
| Sigma | Every event | Inline | At most one, plus correlation alerts |
| IOC (IP, domain, path) | Every event | Inline | One per matching indicator |
| IOC (hash) | Executable of each new process | Background | One per matching hash |
| YARA | Executable of each new process, and optionally its memory | Background | One per matching rule |

## Sigma

Sigma rules are evaluated by the [RSigma](https://crates.io/crates/rsigma-eval) engine.
Detection, correlation, and filter rules are supported.
What logsources, fields, and modifiers work is in [Sigma support](sigma.md).

A rule for a logsource the platform does not collect still loads but never fires.
Rustinel counts these rules and `rustinel doctor` reports them as `sigma_rules_inert`.

**One alert per event.**
When several rules match the same event, Rustinel keeps one:

1. the highest severity (`critical`, `high`, `medium`, then `low`; a missing or unknown level counts as `low`),
2. then a rule with an `id` over one without,
3. then the smallest `id`, then the smallest `title`.

Correlation alerts are added on top when their window completes.
Correlation state lives in memory, so a Sigma reload starts new windows.

## YARA

YARA scans the executable of every new process, skipping trusted paths.
Results are cached per file, so an unchanged executable is scanned once.
Files that are written but never run are not scanned.

Memory scanning is off by default (`scanner.yara_memory_enabled`).
When on, Rustinel waits `yara_memory_delay_ms` after the process starts, then scans its private memory.
Memory hits carry `event.provider: yara-memory`.

## IOC

| Indicator | Matched against |
| --- | --- |
| Hashes | Executables of new processes (MD5, SHA1, or SHA256) |
| IPs and CIDRs | Source and destination IPs, and IPs in DNS answers |
| Domains | DNS queries and destination host names |
| Path regexes | `Image`, `TargetImage`, `TargetFilename`, `ImageLoaded`, PowerShell `Path`, `ServiceFileName` |

Only Windows DNS events carry answers, so IP matching on DNS answers is Windows-only.
The file format is in [Write and test rules](rule-development.md#add-indicators).

## Severity

| Engine | Alert severity |
| --- | --- |
| Sigma | The rule's `level`. Anything other than `critical`, `high`, or `medium` becomes `low` |
| YARA | Always `critical` |
| IOC | `ioc.default_severity` |

## Deduplication

Identical alerts within `dedup.window_secs` (60 by default) are collapsed.
Two alerts are identical when they share the engine, rule, process executable, parent executable, and user.

- The first alert is written immediately.
- At the end of the window, one rollup alert is written with `event.count` set to the number of repeats that were suppressed.

Five identical alerts produce two lines: the first alert, and a rollup with `event.count: 4`.
To count real occurrences, sum `event.count` and count lines without it as 1.
Turn deduplication off with `dedup.enabled = false`.

## Match details

`alerts.match_debug` adds detail about why an alert fired:

| Value | Adds |
| --- | --- |
| `off` | Nothing (correlation alerts still show their aggregation) |
| `summary` | The matched selections and fields, or the YARA rule, tags, and namespace |
| `full` | Also the matched values, or the YARA string IDs, offsets, and snippets |
