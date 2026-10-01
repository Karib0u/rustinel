# Detection

Rustinel runs three engines over the same events.

| Engine | Checks | When | Alerts |
| --- | --- | --- | --- |
| Sigma | Every event | Inline, except rules on `Hashes` or `Imphash`, see [Deferred pass](#deferred-pass) | The best match per event, or every match in `all` mode, plus correlations |
| IOC (IP, domain, path) | Every event | Inline | One per matching indicator |
| IOC (hash) | Executables of new processes, and qualifying written files | Background | One per matching hash |
| YARA | Executables of new processes, qualifying written files, Linux memfd memory, and optionally other process memory | Background | One per matching rule |

Background checks never delay Sigma.
When one cannot run in time, it is skipped and counted under `artifact_resolver` in `rustinel doctor`.
How the pipeline orders and bounds this work is in [Internals](architecture.md#event-path).

## Sigma

Sigma rules are evaluated by the [RSigma](https://crates.io/crates/rsigma-eval) engine.
Detection, correlation, and filter rules are supported.
What logsources, fields, and modifiers work is in [Sigma support](sigma.md).
A rule for a logsource the platform does not collect loads but never fires, see [Platform coverage](coverage.md).

### Which matches become alerts

`scanner.sigma_match_mode` decides:

| Value | Behavior |
| --- | --- |
| `best` | Default. One alert per event, from the best-ranked matching rule |
| `all` | One alert per matching rule, in rank order. Overlapping rules can multiply alert volume |

Rules rank by:

1. the highest severity (`critical`, `high`, `medium`, `low`, then `informational`),
2. then a rule with an `id` over one without,
3. then the smallest `id`, then the smallest `title`.

Correlation rules see every matching rule in both modes, and their alerts are added when a window completes.
Correlation state lives in memory, so a Sigma reload starts new windows.

### Deferred pass

Windows `Hashes` and `Imphash` are computed from the image file after the event, which takes longer than inline evaluation allows.
Rules that select on either field run in a separate pass, once per event, as soon as the fields are ready or 2 seconds after the event, whichever comes first.

- Only what loaded rules need is computed: `Hashes|contains: 'SHA256=...'` computes SHA256 alone.
- `Hashes` follows Sysmon: `SHA1=...,MD5=...,SHA256=...,IMPHASH=...`, uppercase hex.
  `Imphash` is lowercase and matches pefile, YARA, and VirusTotal.
  A file that is not a PE, or imports nothing, has no imphash.
- The file is read as it is when hashed, so an image replaced right after it starts is hashed as the replacement.
  Both fields are marked `derived`.
- When the fields are not ready in time, or the image is unreadable or larger than 128 MB, the rules still run once without them.
  `rustinel doctor` counts these under `artifact_resolver`.
- One event can raise one alert inline and one from the deferred pass.
  Deferred alerts reach correlation up to 2 seconds late, so a correlation window shorter than that can miss them.
- Recordings do not carry these fields, so replay cannot reproduce a match that needed them.

## YARA

YARA scans the executable of every new process and qualifying files written to disk, skipping [trusted paths](configuration.md#default-trusted-paths).
A written file is scanned 250 ms after the write when it is non-empty and has a supported executable, script, archive, or document extension or file signature.
Results are cached per file, so unchanged content is scanned once, and a rule reload invalidates the cache.

Scanning the memory of all new processes is off by default (`scanner.yara_memory_enabled`).
Linux memfd executions always queue a memory scan when YARA is enabled, including their memfd image mappings.
Rustinel waits `yara_memory_delay_ms` after a process starts before scanning memory.
Every YARA alert carries `edr.yara.scan_source`: `file` or `process_memory`.

## IOC

Every indicator of a kind is matched against every value of that kind the event carries.

| Indicator | Matched against |
| --- | --- |
| Hashes | Executables of new processes and qualifying written files (MD5, SHA1, or SHA256) |
| IPs and CIDRs | `DestinationIp`, `SourceIp`, DNS `QueryResults`, and IPs in text fields |
| Domains | `QueryName`, `DestinationHostname`, host names in DNS `QueryResults`, and host names in text fields |
| Path regexes | `Image`, `ParentImage`, `TargetImage`, `TargetFilename`, rename `SourceFilename`, `ImageLoaded`, PowerShell `Path`, `ServiceFileName`, and paths in text fields |

The text fields are `CommandLine`, registry `Details`, PowerShell `ScriptBlockText`, WMI `Query`, and `ServiceFileName`.
In them, a URL, `host:port`, or `user@host` yields its host, and an absolute path yields the path.
DNS events on macOS carry no answers, so DNS answer matching does not apply there.

The file format is in [Write rules](rule-development.md#add-indicators).

### Command-line paths

A relative path in `CommandLine` is joined to the process's `CurrentDirectory` before matching, so `chmod +x malware` run from `/tmp` matches `/tmp/malware`.
The alert still shows the command line as it was run, and Sigma never sees the joined form.

- `.` and `..` are folded as text, without following symlinks.
- Without a `CurrentDirectory`, only absolute paths are matched.
  Windows never reports it, and on Linux a process that exits immediately can lack it.
- Flags, modes, numbers, globs, variables, and `host:port` forms are not paths.
  A flag's attached value, as in `--output=payload`, is.
- Shape alone cannot tell a file from a subcommand: `git status` run from `/tmp` also yields `/tmp/status`.
  Anchor path regexes to the file, not to a whole folder.

## Severity

| Engine | Alert severity |
| --- | --- |
| Sigma | The rule's `level`: `informational`, `low`, `medium`, `high`, or `critical`. A missing or invalid level becomes `low`, and `rustinel doctor` reports the invalid one under `sigma_rules_parse` |
| YARA | First valid metadata value from `severity`, `level`, then `score`; defaults to `high` |
| IOC | `ioc.default_severity` |

Informational alerts are written but never trigger [active response](active-response.md).

YARA `severity` and `level` accept `informational` (or `info`), `low`, `medium`, `high`, and `critical`, ignoring case and surrounding whitespace.
Unknown values and unsupported types are skipped, so a valid lower-priority key can still apply.
`score` accepts an integer or an integer string from 0 to 100:

| YARA score | Alert severity |
| --- | --- |
| 0 | `informational` |
| 1 to 39 | `low` |
| 40 to 59 | `medium` |
| 60 to 79 | `high` |
| 80 to 100 | `critical` |

Severity applies to file and process-memory scans, including when match debugging is off.

## Sigma metadata in alerts

| Sigma metadata | Alert field |
| --- | --- |
| `level` | `edr.sigma.level`, as written in the rule |
| `status` | `edr.sigma.status` |
| `author` | `rule.author` |
| `references` | `rule.reference` |
| `tags` | `tags` |
| `attack.<tactic>` tags | `threat.framework` and `threat.tactic.*` |
| `attack.tNNNN` tags | `threat.technique.*` |
| `attack.tNNNN.NNN` tags | Parent `threat.technique.*` plus `threat.technique.subtechnique.*` |

Only lowercase ATT&CK tags with underscores, such as `attack.initial_access`, fill `threat.*`.
An alert keeps at most 64 tags, 32 references, and 512 bytes of author text, and sets `edr.sigma.metadata_truncated: true` when it cuts any.
Custom rule attributes are not copied.

## Deduplication

Identical alerts within `dedup.window_secs` (60 by default) are collapsed.
Alerts are identical when they share the engine, rule, YARA scan source, process and parent executable, user, and Sigma metadata.

- The first alert is written immediately.
- When the window ends, one rollup alert carries `event.count`, the number of repeats suppressed.

Five identical alerts produce two lines: the first, and a rollup with `event.count: 4`.
To count real occurrences, sum `event.count` and count lines without it as 1.
Turn it off with `dedup.enabled = false`.

## Match details

`alerts.match_debug` adds why an alert fired:

| Value | Adds |
| --- | --- |
| `off` | Nothing (correlation alerts still show their aggregation) |
| `summary` | The matched selections and fields, or the YARA rule, tags, and namespace |
| `full` | Also the matched values, or the YARA string IDs, offsets, and snippets |
