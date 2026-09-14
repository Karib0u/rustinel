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

1. the highest severity (`critical`, `high`, `medium`, `low`, then `informational`; a missing or unknown level counts as `low`),
2. then a rule with an `id` over one without,
3. then the smallest `id`, then the smallest `title`.

Correlation alerts are added on top when their window completes.
Correlation state lives in memory, so a Sigma reload starts new windows.

## YARA

YARA scans the executable of every new process, skipping trusted paths.
Results are cached per file, so an unchanged executable is scanned once.
Files that are written but never run are not scanned.
The shared artifact resolver supplies YARA and IOC hashing from one identity-validated file read.
Its queue and per-artifact deadline are bounded; a saturated or expired job skips the scan and records the unavailable enrichment in telemetry.
YARA results carry the active rule generation, so a successful rule reload invalidates YARA results without discarding immutable hash or PE metadata entries.

### Asynchronous enrichment and admission

Every event enters Sigma, correlation, and capture exactly once, in the order Rustinel ingested it (`ingest_seq`).
A recording therefore replays in the order live detection evaluated it.
Only enrichment that fills fields Sigma can match may delay that admission.
Today that is Windows PE metadata (`OriginalFileName`, `Product`, `Description`, `Company`, `FileVersion`) on process starts and image loads.
It may hold an event for at most 100 ms from the event's arrival; events behind it wait in order, so no event is delayed longer than that.
When PE metadata is not ready in time, the event is admitted without it and `artifact_resolver` counts the miss; the metadata is still cached for the next start of the same image.
YARA file scanning and hash indicators never delay admission, because they raise their own alerts instead of feeding Sigma.
Enrichment that cannot fit the budget, such as future hash or signature fields, must be evaluated by a separate deferred pass rather than by holding events.

Memory scanning is off by default (`scanner.yara_memory_enabled`).
When on, Rustinel waits `yara_memory_delay_ms` after the process starts, then scans its private memory.
Every YARA alert carries `edr.yara.scan_source: file` or `edr.yara.scan_source: process_memory`, including when match debug is off.
`event.provider` continues to identify the sensor that observed the process start.

## IOC

Each event is read once for the domains, IPs, and paths it carries, and every indicator of a kind is matched against all of them.

| Indicator | Matched against |
| --- | --- |
| Hashes | Executables of new processes (MD5, SHA1, or SHA256) |
| IPs and CIDRs | `DestinationIp`, `SourceIp`, DNS `QueryResults`, and IPs in text fields |
| Domains | `QueryName`, `DestinationHostname`, host names in DNS `QueryResults`, and host names in text fields |
| Path regexes | `Image`, `ParentImage`, `TargetImage`, `TargetFilename`, rename `SourceFilename`, `ImageLoaded`, PowerShell `Path`, `ServiceFileName`, and paths in text fields |

The text fields are `CommandLine`, registry `Details`, PowerShell `ScriptBlockText`, WMI `Query`, and `ServiceFileName`.
In them, a URL yields its host, `host:port` and `user@host` yield the host, and an absolute path yields the path.
`ServiceFileName` yields hosts and IPs only, because the whole value is already matched as a path.
Only Windows DNS events carry answers, so matching DNS answers is Windows-only.

### Command-line paths

A path operand in `CommandLine` is matched in absolute form.
`chmod +x malware` run from `/tmp` is matched as `/tmp/malware`, exactly like `chmod +x /tmp/malware`.
The alert still reports `CommandLine` exactly as it was run, and Sigma rules never see the resolved form.

- Relative operands are joined to the process start's `CurrentDirectory`, then `.` and `..` are folded without reading the file system, so a symlink before a `..` is not followed.
- The directory is the one the sensor recorded when the process started. A process that changes directory before it opens the file is still resolved against its starting directory, and replay resolves against the recorded directory, never the replaying host's.
- When the event has no `CurrentDirectory`, or it is not absolute, relative operands are not matched. Absolute operands still are.
- Today only macOS process starts carry `CurrentDirectory` (Endpoint Security reports it at exec). Windows Kernel-Process never reports it, and Linux exec events do not yet capture it, so on those platforms only absolute operands are matched.
- The program itself, flags (`-x`, `--flag`, and `/flag` on Windows), `chmod` modes, numbers, globs, variables, shell operators, and `user:group` or `host:port` forms are never treated as paths. A flag's attached value, as in `--output=payload`, is.
- Shape alone cannot tell a file operand from a subcommand, so `git status` run from `/tmp` also yields `/tmp/status`. Anchor path regexes to the file they describe rather than to a whole directory.
- Text fields other than `CommandLine` have no working directory, so only their absolute paths are matched.

The file format is in [Write and test rules](rule-development.md#add-indicators).

## Severity

| Engine | Alert severity |
| --- | --- |
| Sigma | The rule's `level`: `informational`, `low`, `medium`, `high`, or `critical`. A missing or invalid level falls back to `low` |
| YARA | Always `critical` |
| IOC | `ioc.default_severity` |

An informational Sigma alert has `event.severity: 1` and `edr.rule.severity: Informational`; low remains `25` and `Low`.
Active response accepts `low` as its least severe threshold, so informational alerts are always reported but never terminate a process.
An unrecognized Sigma level does not silently become a valid low level: rule loading logs a warning and `rustinel doctor` reports the parser diagnostic under `sigma_rules_parse`.
The rule continues to load with the explicit low fallback.

## Sigma metadata in alerts

Rustinel preserves this bounded, operator-facing subset of Sigma metadata from rule loading through alert construction and NDJSON serialization:

| Sigma metadata | Alert field |
| --- | --- |
| `level` | `edr.sigma.level` (the original valid level, before normalization) |
| `status` | `edr.sigma.status` |
| `author` | ECS `rule.author` |
| `references` | ECS `rule.reference` |
| `tags` | ECS `tags` |
| `attack.<tactic>` tags | ECS `threat.framework` and `threat.tactic.*` |
| `attack.tNNNN` tags | ECS `threat.technique.*` |
| `attack.tNNNN.NNN` tags | Parent `threat.technique.*` plus `threat.technique.subtechnique.*` |

Only canonical lowercase Sigma ATT&CK tags are mapped into `threat.*` fields; tactic names use underscores, such as `attack.initial_access`.
Other tags are still preserved in ECS `tags` but do not create ATT&CK fields.

Metadata is available regardless of `alerts.match_debug`; that setting only controls match evidence.
To keep one rule from producing unbounded alerts, Rustinel includes at most 64 tags (256 UTF-8 bytes each), 32 references (2,048 bytes each), and 512 bytes of author text.
`edr.sigma.metadata_truncated: true` marks an alert where a limit was applied.
Arbitrary Sigma custom attributes are not copied into alerts.

## Deduplication

Identical alerts within `dedup.window_secs` (60 by default) are collapsed.
Two alerts are identical when they share the engine, rule, scan source, process executable, parent executable, user, and bounded Sigma metadata.
The scan source applies to YARA alerts, so a file hit and a process-memory hit are never collapsed together.

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
