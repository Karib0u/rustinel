# Configuration

Rustinel reads one TOML file.
Every option has a default, so the file only needs what you change.

```toml
[scanner]
sigma_rules_path = "/opt/rules/sigma"

[logging]
level = "debug"

[response]
enabled = true
```

## Which file is used

The first match wins:

1. `--config <PATH>`
2. `RUSTINEL_CONFIG`
3. The managed config written by `rustinel setup`, see [managed paths](operations.md#managed-paths)
4. `config.toml` next to the binary
5. `config.toml` in the working directory

Relative paths in the file resolve from the file's folder, not from the working directory.
`rustinel doctor` shows which file was used and where each path resolved.

## Environment variables

Any option can be overridden with `EDR__<SECTION>__<KEY>`.
Values are parsed as TOML, so lists use brackets:

=== "Bash"

    ```bash
    export EDR__LOGGING__LEVEL=debug
    export EDR__ALLOWLIST__PATHS='["/usr/bin/","/usr/sbin/"]'
    ```

=== "PowerShell"

    ```powershell
    $env:EDR__LOGGING__LEVEL = "debug"
    $env:EDR__ALLOWLIST__PATHS = '["C:\\Windows\\","C:\\Program Files\\"]'
    ```

Priority, highest first: CLI flags, `EDR__` variables, the config file, defaults.

## What reloads

- Sigma, YARA, and IOC files reload when they change.
- In the config file, only `[response]` reloads, except `channel_capacity`.
  Every other change needs a restart.
- A reload with a rule that fails to compile, or an empty IOC set, is rejected and the previous rules stay active.

## Options

<!-- BEGIN GENERATED CONFIG REFERENCE -->
This section is generated from `src/config/reference.rs`. Edit that file and run `cargo run --bin generate-docs`.

### `[scanner]`

Sigma and YARA rules, YARA scan limits, and optional memory scanning.

| Option | Default | Description |
| --- | --- | --- |
| `sigma_enabled` | `true` | Evaluate Sigma rules. |
| `sigma_rules_path` | `"rules/current/sigma"` | Sigma rules directory, loaded recursively. |
| `yara_enabled` | `true` | Scan executables with YARA when they start. |
| `yara_rules_path` | `"rules/current/yara"` | Directory of `.yar` and `.yara` files, loaded recursively. |
| `yara_allowlist_paths` | inherits `allowlist.paths` | Path prefixes YARA never scans. Replaces `allowlist.paths` for YARA once set. |
| `yara_scan_timeout_ms` | `10000` | Time limit for one file scan, or for all memory reads of one process. `0` disables it. |
| `yara_max_file_mb` | `64` | Larger files are reported as oversized instead of scanned. `0` disables the limit. |
| `yara_memory_enabled` | `false` | Also scan the memory of new processes. Needs `yara_enabled`. |
| `yara_memory_queue_capacity` | `64` | Pending memory scans. New scans are dropped when it is full. |
| `yara_memory_delay_ms` | `750` | Wait after process start before reading memory, so packed code can unpack. |
| `yara_memory_max_process_mb` | `64` | Stop reading a process after this many MB. |
| `yara_memory_max_region_mb` | `8` | Most memory read from one region at a time, in MB. |
| `yara_memory_include_private` | `true` | Scan private (anonymous) memory. |
| `yara_memory_include_image` | `false` | Scan memory backed by executables and libraries. |
| `yara_memory_include_mapped` | `false` | Scan memory-mapped files. |

### `[allowlist]`

Trusted path prefixes shared by YARA, IOC hashing, and active response.

| Option | Default | Description |
| --- | --- | --- |
| `paths` | OS directories, see below | Trusted path prefixes. Each module uses this list until its own allowlist is set. |

### `[reload]`

Hot reload of rules, indicators, and the `[response]` section.

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Reload rules, indicators, and the `[response]` section when their files change. |
| `debounce_ms` | `2000` | Wait this long after the last change before reloading. |
| `fallback_poll_interval_ms` | `60000` | Poll interval, used only when the file watcher cannot start. |

### `[logging]`

The operational log.

| Option | Default | Description |
| --- | --- | --- |
| `level` | `"info"` | `trace`, `debug`, `info`, `warn`, or `error`. |
| `filter` | unset | A `tracing` filter expression. Overrides `level` when valid. |
| `directory` | `"logs"` | Operational log directory. |
| `filename` | `"rustinel.log"` | Operational log file name. Rotated daily with a date suffix. |
| `console_output` | `false` | Mirror the log to the console. `rustinel run` enables the console anyway; pass `--no-console` to turn it off. |

### `[alerts]`

The ECS NDJSON alert file.

| Option | Default | Description |
| --- | --- | --- |
| `directory` | `"logs"` | Alert directory. |
| `filename` | `"alerts.json"` | Alert file name. Rotated daily with a date suffix. |
| `match_debug` | `"off"` | Match detail added to alerts: `off`, `summary` (what matched), or `full` (also the matched values). |

### `[dedup]`

Collapsing of repeated identical alerts.

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Collapse identical alerts within a window. |
| `window_secs` | `60` | Window length, counted from the first alert. Repeats do not extend it. |
| `max_entries` | `10000` | Distinct alerts tracked at once. |

### `[response]`

Optional process termination. Off by default.

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Turn on the response engine. |
| `prevention_enabled` | `false` | Kill processes. When `false`, actions are only logged. |
| `min_severity` | `"critical"` | Lowest alert severity that triggers a response: `low`, `medium`, `high`, or `critical`. |
| `channel_capacity` | `128` | Pending response actions. New ones are dropped when it is full. Read at startup only. |
| `allowlist_images` | `[]` | Executable names or full paths that are never killed. |
| `allowlist_paths` | inherits `allowlist.paths` | Path prefixes that are never killed. Replaces `allowlist.paths` for response once set. |

### `[ioc]`

Indicator files for hashes, IPs, domains, and path patterns.

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Match indicator files. |
| `hashes_path` | `"rules/current/ioc/hashes.txt"` | MD5, SHA1, or SHA256 hashes, one per line. |
| `ips_path` | `"rules/current/ioc/ips.txt"` | IP addresses and CIDR ranges. |
| `domains_path` | `"rules/current/ioc/domains.txt"` | Domains. A leading `.` or `*.` also matches subdomains. |
| `paths_regex_path` | `"rules/current/ioc/paths_regex.txt"` | Path regular expressions, matched case-insensitively. |
| `default_severity` | `"high"` | Severity of IOC alerts: `low`, `medium`, `high`, or `critical`. |
| `max_file_size_mb` | `50` | Larger executables are not hashed. |
| `hash_allowlist_paths` | inherits `allowlist.paths` | Path prefixes that are never hashed. Replaces `allowlist.paths` for hashing once set. |

### `[process]`

The process cache used for parent and context enrichment.

| Option | Default | Description |
| --- | --- | --- |
| `max_entries` | `65536` | Process records kept. The oldest are evicted first. |

### `[capture]`

Recordings written by `rustinel capture`.

| Option | Default | Description |
| --- | --- | --- |
| `directory` | `"captures"` | Where `rustinel capture` writes recordings when `--output` is not given. |

### `[telemetry]`

The `telemetry.json` loss counters that `rustinel doctor` reads.

| Option | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Write `telemetry.json` to the log directory. |
| `snapshot_interval_secs` | `30` | How often `telemetry.json` is rewritten. It is also written at shutdown. |

### `[windows]`

ETW delivery. Read on every platform so one file can serve a mixed fleet, used only on Windows.

| Option | Default | Description |
| --- | --- | --- |
| `etw_flush_interval_ms` | `20` | How often the main ETW session hands over partly filled buffers. Lower is faster alerting. `0` falls back to the 1 second ETW timer. Values below 20 are raised to 20. |
| `etw_process_flush_interval_ms` | `5` | The same for the process session. Keep it at 10 or below: the command line is read from the live process, so slower values lose it for short-lived processes, and `0` loses most of them. |
<!-- END GENERATED CONFIG REFERENCE -->

## Default trusted paths

`allowlist.paths` defaults to the OS folders:

=== "Windows"

    `C:\Windows\`, `C:\Program Files\`, `C:\Program Files (x86)\`

=== "Linux"

    `/usr/bin/`, `/usr/sbin/`, `/usr/lib/`, `/usr/lib64/`, `/usr/libexec/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`

=== "macOS"

    `/usr/bin/`, `/usr/sbin/`, `/usr/libexec/`, `/bin/`, `/sbin/`, `/System/`

    `/Applications` is not trusted: it holds user-installed software.

Paths are prefixes and are not resolved, so symlinks are not followed.
Matching ignores case on Windows, and for active response on every platform.

## File permissions

On Linux and macOS, Rustinel makes its log, alert, and recording folders readable by their owner only (`0700`) and their files `0600`.

## Unknown options

Unknown sections and keys are ignored, so a config file written for an older release keeps loading.
