# Configuration

Rustinel loads configuration from these sources, highest priority first:

1. CLI flags where supported
2. Environment variables using the `EDR__` prefix
3. `config.toml` in the current working directory
4. `config.toml` in the directory containing the executable
5. Built-in defaults

## Configuration File

Place `config.toml` in the directory you launch Rustinel from, alongside the
`rustinel` executable, or use absolute paths throughout. When both a working-directory
and an executable-directory config exist, the working-directory file takes precedence
on conflicting keys.

Production note:

- Windows services often run with `C:\Windows\System32` as the working directory.
  Because the executable directory is also searched, you can keep `config.toml` next
  to `rustinel.exe` (for example in `C:\Rustinel`) without copying it into `System32`.
- Linux service managers can also start in a directory that is not your install root.
- For production, prefer absolute paths for rules, logs, and alerts.

## Example `config.toml`

```toml
[scanner]
sigma_enabled = true
sigma_rules_path = "rules/sigma"
yara_enabled = true
yara_rules_path = "rules/yara"

# Memory scanning is off by default.
# yara_memory_enabled = false
# yara_memory_delay_ms = 750
# yara_memory_max_process_mb = 64
# yara_memory_max_region_mb = 8
# yara_memory_include_private = true
# yara_memory_include_image = false
# yara_memory_include_mapped = false

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

[response]
enabled = false
prevention_enabled = false
min_severity = "critical"
channel_capacity = 128
allowlist_images = []

[network]
aggregation_enabled = true
aggregation_max_entries = 20000
aggregation_interval_buffer_size = 50

[ioc]
enabled = true
hashes_path = "rules/ioc/hashes.txt"
ips_path = "rules/ioc/ips.txt"
domains_path = "rules/ioc/domains.txt"
paths_regex_path = "rules/ioc/paths_regex.txt"
default_severity = "high"
max_file_size_mb = 50
```

Use Windows path prefixes on Windows and Unix path prefixes on Linux.

## Platform-Aware Defaults

### Shared Defaults

| Option | Default |
| --- | --- |
| `scanner.sigma_enabled` | `true` |
| `scanner.sigma_rules_path` | `rules/sigma` |
| `scanner.yara_enabled` | `true` |
| `scanner.yara_rules_path` | `rules/yara` |
| `reload.enabled` | `true` |
| `reload.debounce_ms` | `2000` |
| `logging.level` | `info` |
| `logging.directory` | `logs` |
| `logging.filename` | `rustinel.log` |
| `logging.console_output` | `false` |
| `alerts.directory` | `logs` |
| `alerts.filename` | `alerts.json` |
| `alerts.match_debug` | `off` |
| `dedup.enabled` | `true` |
| `dedup.window_secs` | `60` |
| `dedup.max_entries` | `10000` |
| `response.enabled` | `false` |
| `response.prevention_enabled` | `false` |
| `response.min_severity` | `critical` |
| `ioc.enabled` | `true` |
| `ioc.default_severity` | `high` |
| `ioc.max_file_size_mb` | `50` |

### Default Trusted Paths

These defaults feed `allowlist.paths`, which then propagate to active response, YARA allowlists, and IOC hash allowlists unless a module-specific override is set.

#### Windows

- `C:\Windows\`
- `C:\Program Files\`
- `C:\Program Files (x86)\`

#### Linux

- `/usr/bin/`
- `/usr/sbin/`
- `/usr/lib/`
- `/usr/lib64/`
- `/usr/libexec/`
- `/bin/`
- `/sbin/`
- `/lib/`
- `/lib64/`

#### macOS

- `/usr/bin/`
- `/usr/sbin/`
- `/usr/libexec/`
- `/bin/`
- `/sbin/`
- `/System/`

`/Applications` is intentionally **not** allowlisted: it holds user-installed software and is a common location for macOS malware, so allowlisting it would blind scanning and response there.

## Options

### Scanner

| Option | Default | Description |
| --- | --- | --- |
| `sigma_enabled` | `true` | Enable Sigma rule evaluation |
| `sigma_rules_path` | `rules/sigma` | Sigma rules directory |
| `yara_enabled` | `true` | Enable YARA scanning |
| `yara_rules_path` | `rules/yara` | YARA rules directory |
| `yara_allowlist_paths` | inherits `allowlist.paths` | Prefix paths skipped by YARA queueing and scanning |
| `yara_memory_enabled` | `false` | Enable YARA memory scanning (requires `yara_enabled = true`) |
| `yara_memory_queue_capacity` | `64` | Maximum pending memory scan jobs before new ones are dropped |
| `yara_memory_delay_ms` | `750` | Milliseconds to wait after process start before reading memory |
| `yara_memory_max_process_mb` | `64` | Stop reading a process once this many MB have been accumulated |
| `yara_memory_max_region_mb` | `8` | Clamp each region read to this many MB |
| `yara_memory_include_private` | `true` | Scan private (anonymous) memory regions |
| `yara_memory_include_image` | `false` | Scan image-backed regions (loaded executables/DLLs) |
| `yara_memory_include_mapped` | `false` | Scan file-mapped regions |

### Reload

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable local file-based hot reload for Sigma, YARA, and IOC files |
| `debounce_ms` | `2000` | Debounce window before rebuilding detectors |

Reload notes:

- Poll cadence is `max(reload.debounce_ms, 2000ms)`.
- Empty rebuild results are rejected to keep the last good detector set live.

### Global Allowlist

| Option | Default | Description |
| --- | --- | --- |
| `paths` | platform-specific | Shared trusted path prefixes |

Propagation behavior:

- If `response.allowlist_paths` is empty, it inherits `allowlist.paths`.
- If `ioc.hash_allowlist_paths` is empty, it inherits `allowlist.paths`.
- If `scanner.yara_allowlist_paths` is empty, it inherits `allowlist.paths`.

### Logging

| Option | Default | Description |
| --- | --- | --- |
| `level` | `info` | Base log level: `trace`, `debug`, `info`, `warn`, `error` |
| `filter` | `null` | Optional `tracing_subscriber` filter expression; overrides `level` when valid |
| `directory` | `logs` | Operational log directory |
| `filename` | `rustinel.log` | Operational log filename with daily rotation |
| `console_output` | `false` | Default console mirroring when the runtime does not override console behavior. Interactive `rustinel run` enables console output by default; use `rustinel run --no-console` to suppress it. On Windows, colored output requires [Windows Terminal](https://aka.ms/terminal) — other terminals (cmd.exe, PowerShell host) will display plain text automatically. |

### Alerts

| Option | Default | Description |
| --- | --- | --- |
| `directory` | `logs` | Alert directory |
| `filename` | `alerts.json` | ECS NDJSON filename with daily rotation |
| `match_debug` | `off` | `off`, `summary`, or `full` match metadata in alerts |

### Deduplication

Alert deduplication collapses repeated identical alerts within a sliding window into a single rollup alert. The **first occurrence always emits immediately** — there is no added detection latency for novel alerts. Only repeats of the same alert within the window are suppressed.

A rollup alert is written at window close carrying `event.count` with the total number of occurrences (including the first).

The dedup key is `(engine, rule_name, process.executable, process.parent.executable, user.name)`.

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable alert deduplication |
| `window_secs` | `60` | Window length in seconds; identical alerts within this window are aggregated |
| `max_entries` | `10000` | Maximum distinct alert keys tracked simultaneously (memory cap) |

Set `enabled = false` for high-fidelity environments where every individual alert event matters.

**Dedup metrics** are written to the operational log at shutdown:

```
dedup: suppressed_total=1420 aggregated_rollup_alerts=38 pending_keys=0
```

### Active Response

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enable the response engine |
| `prevention_enabled` | `false` | If `false`, actions are logged but not executed |
| `min_severity` | `critical` | Minimum severity to act on |
| `channel_capacity` | `128` | Queue size for response work |
| `allowlist_images` | `[]` | Image basenames or full paths to skip |
| `allowlist_paths` | inherits `allowlist.paths` | Module-specific trusted prefixes |

See [Active Response](active-response.md) for platform behavior and safe testing.

### Network

| Option | Default | Description |
| --- | --- | --- |
| `aggregation_enabled` | `true` | Enable repeated-connection suppression |
| `aggregation_max_entries` | `20000` | Maximum unique connections tracked |
| `aggregation_interval_buffer_size` | `50` | Timing intervals retained per aggregated connection |

### IOC

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable IOC detection |
| `hashes_path` | `rules/ioc/hashes.txt` | Hash IOC file |
| `ips_path` | `rules/ioc/ips.txt` | IP and CIDR IOC file |
| `domains_path` | `rules/ioc/domains.txt` | Domain IOC file |
| `paths_regex_path` | `rules/ioc/paths_regex.txt` | Path regex IOC file |
| `default_severity` | `high` | Severity assigned to IOC alerts |
| `max_file_size_mb` | `50` | Skip hashing files larger than this limit |
| `hash_allowlist_paths` | inherits `allowlist.paths` | Prefix paths skipped during hashing |

## Environment Variables

The environment prefix is `EDR__`. Nested keys use double underscores.

### PowerShell

```powershell
$env:EDR__LOGGING__LEVEL="debug"
$env:EDR__SCANNER__SIGMA_RULES_PATH="C:\\Rustinel\\rules\\sigma"
$env:EDR__ALLOWLIST__PATHS='["C:\\Windows\\","C:\\Program Files\\"]'
.\rustinel.exe run
```

### Bash

```bash
export EDR__LOGGING__LEVEL=debug
export EDR__SCANNER__SIGMA_RULES_PATH=/opt/rustinel/rules/sigma
export EDR__ALLOWLIST__PATHS='["/usr/bin/","/usr/sbin/"]'
sudo /opt/rustinel/rustinel run
```

## CLI Overrides

Interactive `run` accepts CLI overrides for log level and console output. For repeatable cross-platform deployments, prefer `config.toml` and `EDR__...` environment variables.

```powershell
rustinel run --log-level debug
rustinel run --no-console
```

## Practical Examples

### Windows Service-Friendly Paths

```toml
[scanner]
sigma_rules_path = "C:\\Rustinel\\rules\\sigma"
yara_rules_path = "C:\\Rustinel\\rules\\yara"

[logging]
directory = "C:\\Rustinel\\logs"

[alerts]
directory = "C:\\Rustinel\\logs"
```

### Linux Install Layout

```toml
[scanner]
sigma_rules_path = "/opt/rustinel/rules/sigma"
yara_rules_path = "/opt/rustinel/rules/yara"

[logging]
directory = "/opt/rustinel/logs"

[alerts]
directory = "/opt/rustinel/logs"
```
