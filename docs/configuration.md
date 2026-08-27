# Configuration

This is the reference for every configuration option, where configuration is
read from, and how paths resolve.

## Where Configuration Comes From

Values are resolved highest priority first:

1. CLI flags, where supported
2. `EDR__` environment variables
3. The selected configuration file
4. Built-in defaults

The configuration **file** is selected highest priority first:

1. `--config <PATH>`
2. `RUSTINEL_CONFIG`
3. The managed platform path
4. `config.toml` beside the executable
5. `config.toml` in the current working directory

`rustinel doctor` prints which file was selected and where its paths resolved.

### Path resolution

**Relative paths resolve from the directory containing the selected
configuration file**, not from the working directory. A portable archive in
`/opt/rustinel` can therefore write `rules/current/sigma` and have it resolve to
`/opt/rustinel/rules/current/sigma` regardless of where the binary was launched.

This is the single most common source of "Rustinel is looking in the wrong
place". Windows services start in `C:\Windows\System32` and Linux service
managers may start anywhere, so **use absolute paths in production**.

### Managed layouts

| Platform | Config | Rules | Logs and alerts | Recordings |
| --- | --- | --- | --- | --- |
| Windows | `C:\ProgramData\Rustinel\config.toml` | `C:\ProgramData\Rustinel\rules` | `C:\ProgramData\Rustinel\logs` | `C:\ProgramData\Rustinel\captures` |
| Linux | `/etc/rustinel/config.toml` | `/var/lib/rustinel/rules` | `/var/log/rustinel` | `/var/lib/rustinel/captures` |
| macOS | `/Library/Application Support/Rustinel/config.toml` | `/Library/Application Support/Rustinel/rules` | `/Library/Logs/Rustinel` | `/Library/Application Support/Rustinel/captures` |

On Unix, Rustinel restricts configured log, alert, and recording directories to
mode `0700` and their files to `0600`, so other local users cannot read
operational context, alert details, or recorded behavior. Windows uses the
owning account's configured ACLs.

## Example `config.toml`

```toml
[scanner]
sigma_enabled = true
sigma_rules_path = "rules/current/sigma"
sigma_engine = "builtin"
yara_enabled = true
yara_rules_path = "rules/current/yara"

# Per-scan guards. 0 disables the guard.
# yara_scan_timeout_ms = 10000
# yara_max_file_mb = 64

# Memory scanning is off by default.
# yara_memory_enabled = false
# yara_memory_delay_ms = 750
# yara_memory_max_process_mb = 64
# yara_memory_max_region_mb = 8

[reload]
enabled = true
debounce_ms = 2000

[logging]
level = "info"
directory = "logs"
filename = "rustinel.log"
console_output = false

[alerts]
directory = "logs"
filename = "alerts.json"
match_debug = "off"

[dedup]
enabled = true
window_secs = 60
max_entries = 10000

[capture]
directory = "captures"

[telemetry]
enabled = true
snapshot_interval_secs = 30

[response]
enabled = false
prevention_enabled = false
min_severity = "critical"
channel_capacity = 128
allowlist_images = []

[process]
max_entries = 65536

[network]
aggregation_enabled = true
aggregation_max_entries = 20000
aggregation_window_secs = 60
aggregation_interval_buffer_size = 50

[ioc]
enabled = true
hashes_path = "rules/current/ioc/hashes.txt"
ips_path = "rules/current/ioc/ips.txt"
domains_path = "rules/current/ioc/domains.txt"
paths_regex_path = "rules/current/ioc/paths_regex.txt"
default_severity = "high"
max_file_size_mb = 50
```

Use Windows path prefixes on Windows and Unix prefixes elsewhere. For a
service-owned deployment, replace every relative path with an absolute one:

```toml
[scanner]
sigma_rules_path = "C:\\Rustinel\\rules\\sigma"
yara_rules_path = "C:\\Rustinel\\rules\\yara"

[logging]
directory = "C:\\Rustinel\\logs"

[alerts]
directory = "C:\\Rustinel\\logs"
```

## Options

### Scanner

| Option | Default | Description |
| --- | --- | --- |
| `sigma_enabled` | `true` | Enable Sigma rule evaluation |
| `sigma_rules_path` | `rules/current/sigma` | Sigma rules directory, loaded recursively |
| `sigma_engine` | `builtin` | Sigma matching backend: `builtin` or `rsigma` (needs the `rsigma-engine` build feature) |
| `yara_enabled` | `true` | Enable YARA scanning |
| `yara_rules_path` | `rules/current/yara` | YARA rules directory, loaded recursively |
| `yara_allowlist_paths` | inherits `allowlist.paths` | Prefix paths skipped by YARA queueing and scanning |
| `yara_scan_timeout_ms` | `10000` | Per-scan timeout for file and memory scans; `0` disables |
| `yara_max_file_mb` | `64` | Files larger than this are reported oversized instead of scanned; `0` disables |
| `yara_memory_enabled` | `false` | Enable YARA memory scanning (requires `yara_enabled`) |
| `yara_memory_queue_capacity` | `64` | Maximum pending memory scan jobs before new ones drop |
| `yara_memory_delay_ms` | `750` | Delay after process start before reading memory |
| `yara_memory_max_process_mb` | `64` | Stop reading a process after this many MB |
| `yara_memory_max_region_mb` | `8` | Clamp each region read to this many MB |
| `yara_memory_include_private` | `true` | Scan private (anonymous) regions |
| `yara_memory_include_image` | `false` | Scan image-backed regions (loaded executables/DLLs) |
| `yara_memory_include_mapped` | `false` | Scan file-mapped regions |

### Reload

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Watch Sigma, YARA, and IOC files, plus the active config file, and reload on change |
| `debounce_ms` | `2000` | Coalescing window used to group rapid writes into one reload |
| `fallback_poll_interval_ms` | `60000` | Polling interval used only when the filesystem watcher cannot start |

What reloads and what does not:

- **Sigma, YARA, and IOC files reload live.** Both rule directories are watched
  recursively, matching how they are loaded.
- **Only the `[response]` section of the config file hot-swaps**: enablement,
  prevention mode, minimum severity, and allowlists. Every other section,
  including `response.channel_capacity`, takes effect at startup only.
- **A rejected reload keeps the previous set live.** Empty Sigma and YARA
  rulesets are accepted (effectively disabling those detections) when no rule
  files exist at all, but a ruleset whose files fail to compile is rejected
  wholesale. Empty IOC sets are always rejected.
- If the filesystem watcher cannot start, the agent falls back to a 60-second
  polling cycle and logs a warning.

### Global allowlist

| Option | Default | Description |
| --- | --- | --- |
| `paths` | platform-specific | Shared trusted path prefixes |

`response.allowlist_paths`, `ioc.hash_allowlist_paths`, and
`scanner.yara_allowlist_paths` each inherit this list while they are empty, and
override it entirely once set.

#### Default trusted paths

=== "Windows"

    `C:\Windows\` · `C:\Program Files\` · `C:\Program Files (x86)\`

=== "Linux"

    `/usr/bin/` · `/usr/sbin/` · `/usr/lib/` · `/usr/lib64/` · `/usr/libexec/` ·
    `/bin/` · `/sbin/` · `/lib/` · `/lib64/`

=== "macOS"

    `/usr/bin/` · `/usr/sbin/` · `/usr/libexec/` · `/bin/` · `/sbin/` ·
    `/System/`

`/Applications` is deliberately **not** allowlisted: it holds user-installed
software and is a common location for macOS malware.

### Logging

| Option | Default | Description |
| --- | --- | --- |
| `level` | `info` | `trace`, `debug`, `info`, `warn`, or `error` |
| `filter` | `null` | Optional `tracing_subscriber` filter expression; overrides `level` when valid |
| `directory` | `logs` | Operational log directory |
| `filename` | `rustinel.log` | Operational log filename, rotated daily |
| `console_output` | `false` | Console mirroring when the runtime does not override it. Interactive `rustinel run` enables console output regardless; use `--no-console` to suppress. On Windows, colored output needs [Windows Terminal](https://aka.ms/terminal) |

### Alerts

| Option | Default | Description |
| --- | --- | --- |
| `directory` | `logs` | Alert directory |
| `filename` | `alerts.json` | ECS NDJSON filename, rotated daily |
| `match_debug` | `off` | `off`, `summary`, or `full` match metadata, see [Detection](detection.md#match-debug) |

### Deduplication

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable alert deduplication |
| `window_secs` | `60` | Fixed window length, measured from the first occurrence; repeats do not extend it |
| `max_entries` | `10000` | Maximum distinct alert keys tracked at once |

Identical repeated alerts are collapsed into one rollup per window. The **first
occurrence always emits immediately**, so novel alerts carry no added latency,
and the rollup is written at window close carrying `event.count`, the number of
*suppressed repeats*. A burst of 5 identical alerts therefore produces 2 lines:
the live alert (no `event.count`, implicitly 1) and a rollup with
`event.count = 4`. Summing `event.count` across lines, counting a missing field
as 1, yields the true volume.

The dedup key is
`(engine, rule_name, process.executable, process.parent.executable, user.name)`.
Set `enabled = false` where every individual alert matters. Dedup metrics are
logged every 5 minutes while dedup is active and once at shutdown:

```text
dedup: suppressed_total=1420 aggregated_rollup_alerts=38 pending_keys=0
```

### Capture

| Option | Default | Description |
| --- | --- | --- |
| `directory` | `captures` | Parent directory for recordings, unless `capture --output` overrides it |

Recordings are written only by `rustinel capture`; an ordinary `run` never
touches this directory. They are more revealing than alerts and should be
handled accordingly. See
[Behavioral Recordings](output.md#behavioral-recordings).

### Pipeline telemetry

Every channel between a sensor and the detectors is bounded and sheds load
rather than blocking, so a burst produces a **detection gap rather than a
slowdown**. Rustinel therefore counts, per channel: events accepted, events
dropped because the channel was full, events dropped because the consumer had
already stopped, and the deepest queue depth reached. The counters are always
on; this section controls only whether they are published outside the process.

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Write the counter snapshot that `rustinel doctor` reads |
| `snapshot_interval_secs` | `30` | Refresh interval; a snapshot is also written at shutdown |

The snapshot is `telemetry.json` inside `logging.directory`, rewritten in place
and holding only counts, never endpoint detail. The counted channels:

| Channel | What a drop costs |
| --- | --- |
| `sensor_events` | Raw events never reached the detectors, the widest gap |
| `yara_file_scan` | Files were never YARA scanned |
| `yara_memory_scan` | Processes were never memory scanned |
| `ioc_hash` | Process images were never hashed for IOC matching |
| `active_response` | Response actions were never executed |
| `capture_writer` | Events never reached a `rustinel capture` recording |

Read them with `rustinel doctor`, whose `pipeline_telemetry` check passes when
nothing was dropped and warns with per-channel totals when something was;
`--json` carries the raw numbers under `telemetry`. Setting `enabled = false`
leaves drop totals visible only in the operational log, and `doctor` reports
that reduced visibility as a warning.

### Active response

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enable the response engine |
| `prevention_enabled` | `false` | If `false`, actions are logged but not executed |
| `min_severity` | `critical` | Minimum severity to act on |
| `channel_capacity` | `128` | Queue size for response work |
| `allowlist_images` | `[]` | Image basenames or full paths to skip |
| `allowlist_paths` | inherits `allowlist.paths` | Module-specific trusted prefixes |

See [Active Response](active-response.md) for platform behavior and safe testing.

### Process cache

| Option | Default | Description |
| --- | --- | --- |
| `max_entries` | `65536` | Maximum process metadata records retained; oldest are evicted when exit events are missed |

### Network

| Option | Default | Description |
| --- | --- | --- |
| `aggregation_enabled` | `true` | Track repeated-connection metrics without suppressing events |
| `aggregation_max_entries` | `20000` | Maximum unique connections tracked |
| `aggregation_window_secs` | `60` | Start a new aggregate period after this many seconds; `0` starts one per event |
| `aggregation_interval_buffer_size` | `50` | Timing intervals retained per aggregated connection |

Aggregation is **observational only**. Every normalized network event is still
forwarded to Sigma and IOC evaluation, so this creates no detection blind spot;
it only bounds how long counts, timestamps, and intervals are combined.

### IOC

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable IOC detection |
| `hashes_path` | `rules/current/ioc/hashes.txt` | Hash IOC file |
| `ips_path` | `rules/current/ioc/ips.txt` | IP and CIDR IOC file |
| `domains_path` | `rules/current/ioc/domains.txt` | Domain IOC file |
| `paths_regex_path` | `rules/current/ioc/paths_regex.txt` | Path regex IOC file |
| `default_severity` | `high` | Severity assigned to IOC alerts |
| `max_file_size_mb` | `50` | Skip hashing files larger than this |
| `hash_allowlist_paths` | inherits `allowlist.paths` | Prefix paths skipped during hashing |

## Environment Variables

The prefix is `EDR__`; nested keys use double underscores. Values are parsed as
TOML, so lists are JSON-style arrays.

=== "Bash"

    ```bash
    export EDR__LOGGING__LEVEL=debug
    export EDR__SCANNER__SIGMA_RULES_PATH=/opt/rustinel/rules/current/sigma
    export EDR__ALLOWLIST__PATHS='["/usr/bin/","/usr/sbin/"]'
    sudo /opt/rustinel/rustinel run
    ```

=== "PowerShell"

    ```powershell
    $env:EDR__LOGGING__LEVEL="debug"
    $env:EDR__SCANNER__SIGMA_RULES_PATH="C:\\Rustinel\\rules\\sigma"
    $env:EDR__ALLOWLIST__PATHS='["C:\\Windows\\","C:\\Program Files\\"]'
    .\rustinel.exe run
    ```

Interactive `run` also accepts `--log-level` and `--no-console` as one-off
overrides. For repeatable deployments, prefer `config.toml` and `EDR__`
variables. See the [CLI Reference](cli.md) for every flag.
