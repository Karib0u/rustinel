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
- A reload whose files another account can change is rejected as a whole and the previous rules stay active, see [Input trust](security.md#input-trust).

## Options

<!-- BEGIN GENERATED CONFIG REFERENCE -->
This section is generated from `src/config/reference.rs`. Edit that file and run `cargo run --bin generate-docs`.

### `[security]`

Optional access for an unprivileged integration agent.

| Option | Default | Description |
| --- | --- | --- |
| `integration_group` | `unset` | Group or account allowed to edit the config and read logs. On Unix it must match the config file's group; on Windows it must be the only non-administrator granted write. File-only, restart required. See [integration access](security.md#integration-access). |
| `integration_rules_directory` | `unset` | Optional absolute administrator-owned directory in which the integration may manage rules and IOC files. Requires integration_group; file-only, restart required. |

### `[scanner]`

Sigma and YARA rules, YARA scan limits, and optional memory scanning.

| Option | Default | Description |
| --- | --- | --- |
| `sigma_enabled` | `true` | Evaluate Sigma rules. |
| `sigma_rules_path` | `"rules/current/sigma"` | Sigma rules directory, loaded recursively. |
| `sigma_local_rules_paths` | `[]` | Extra Sigma directories, loaded recursively after the managed pack. `rules install` and `rules update` never touch them, and a local rule wins over a pack rule with the same `id`. |
| `sigma_match_mode` | `"best"` | `best` emits the highest-severity detection per pass; `all` emits every matching detection rule. |
| `yara_enabled` | `true` | Scan new process executables and qualifying files written to disk with YARA. |
| `yara_rules_path` | `"rules/current/yara"` | Directory of `.yar` and `.yara` files, loaded recursively. |
| `yara_local_rules_paths` | `[]` | Extra YARA directories, compiled after the managed pack. `rules install` and `rules update` never touch them, and a local rule wins over a pack rule with the same name. |
| `yara_allowlist_paths` | inherits `allowlist.paths` | Path prefixes YARA never scans. Replaces `allowlist.paths` for YARA once set. |
| `yara_scan_timeout_ms` | `10000` | Time limit for one file scan, or for all memory reads of one process. `0` disables it. |
| `yara_max_file_mb` | `64` | Larger files are reported as oversized instead of scanned. `0` disables the limit. |
| `yara_memory_enabled` | `false` | Scan the memory of all new processes. Needs `yara_enabled`. Linux memfd executions are memory scanned even when this is disabled. |
| `yara_memory_queue_capacity` | `64` | Pending memory scans. New scans are dropped when it is full. |
| `yara_memory_delay_ms` | `750` | Wait after process start before reading memory, so packed code can unpack. |
| `yara_memory_max_process_mb` | `64` | Stop reading a process after this many MB. |
| `yara_memory_max_region_mb` | `8` | Most memory read from one region at a time, in MB. |
| `yara_memory_include_private` | `true` | Scan private (anonymous) memory. On Linux, includes unnamed anonymous mappings, `[heap]`, and `[stack]`; other bracket-named mappings such as `[vdso]`, `[vvar]`, and `[vsyscall]` are excluded. On macOS, the dyld shared cache counts as library memory and is scanned under the image and mapped options instead. On Windows, committed `MEM_PRIVATE` regions are scanned. |
| `yara_memory_include_image` | `false` | Scan memory backed by executables and libraries. Linux memfd executions include memfd image mappings even when this is disabled. |
| `yara_memory_include_mapped` | `false` | Scan memory-mapped files. On Windows, a committed region is scanned when its base protection is readable (read-only, read-write, write-copy, execute-read, execute-read-write, or execute-write-copy), whatever modifier bits such as `PAGE_NOCACHE` or `PAGE_WRITECOMBINE` accompany it. `PAGE_GUARD`, `PAGE_NOACCESS`, and execute-only regions are never read, and reserved and free regions are not scanned. At debug level the `scanner` target logs one region summary per process, separating `excluded_protection` and `excluded_kind` (never read) from `read_failed` (eligible but the read failed). |

### `[allowlist]`

Trusted path prefixes shared by YARA, IOC hashing, and active response.

| Option | Default | Description |
| --- | --- | --- |
| `paths` | OS directories, see below | Trusted path prefixes. Each module uses this list until its own allowlist is set. |
| `excluded_paths` | Windows writable folders, see below; empty elsewhere | Directory prefixes never trusted by YARA, IOC hashing, or active response, even with module-specific allowlists. |

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

The ECS NDJSON alert file, and optional webhook destinations.

| Option | Default | Description |
| --- | --- | --- |
| `directory` | `"logs"` | Alert directory. |
| `filename` | `"alerts.json"` | Alert file name. Rotated daily with a date suffix. |
| `match_debug` | `"off"` | Match detail added to alerts: `off`, `summary` (what matched), or `full` (also the matched values). |
| `webhook` | none | HTTP endpoints that also receive every alert, as `[[alerts.webhook]]` tables. See [webhook destinations](#webhook-destinations). |

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
| `max_file_size_mb` | `50` | Larger files are not hashed. |
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
| `security_filtering_platform_connections` | `false` | Read Security events 5156, 5157, and 5152: one per allowed connection, blocked connection, and dropped packet. Off by default because they are the highest-volume Security events. The host must also audit them, see [Windows host logging](windows-logging.md#filtering-platform-connections). |
<!-- END GENERATED CONFIG REFERENCE -->

## Webhook destinations

Each `[[alerts.webhook]]` table adds one HTTP endpoint that receives every alert.
The request format, retries, and a receiver example are in [Webhooks](output.md#webhooks).

```toml
[[alerts.webhook]]
name = "collector"
url = "https://collector.example/rustinel"
headers = { Authorization = "Bearer <token>" }
secret = "<shared secret>"

[[alerts.webhook]]
url = "https://automation.example/hooks/alerts"
```

| Option | Default | Description |
| --- | --- | --- |
| `url` | required | `http` or `https` endpoint. |
| `name` | host and port of `url` | Label in logs, `telemetry.json`, and `rustinel doctor`. Must be unique. |
| `headers` | none | Headers added to every request. `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, and `X-Rustinel-*` are rejected. |
| `secret` | unset | Key for the `X-Rustinel-Signature` HMAC-SHA256 header. |
| `timeout_ms` | `5000` | Time limit for one attempt, connecting included. |
| `tls_verify` | `true` | Verify the server certificate. Set `false` only for lab endpoints. |
| `ca_file` | unset | PEM file of extra CA certificates to trust, in addition to the system roots. |
| `queue_capacity` | `1024` | Alerts waiting for this destination. New alerts are dropped for it when it is full. |
| `max_attempts` | `5` | Attempts per alert, the first included. At most 20. |
| `retry_initial_ms` | `500` | Delay before the first retry. Doubles on each further retry. |
| `retry_max_ms` | `30000` | Longest delay between two attempts. |
| `max_payload_bytes` | `1048576` | Alerts with larger JSON are not sent to this destination. |

A malformed URL, header, or CA file stops the agent at startup, and `rustinel doctor` reports it.
Header values, `secret`, and the URL path are treated as credentials: they are never logged, so keep the config file readable only by the agent.
`[[alerts.webhook]]` cannot be set with `EDR__` variables.

## Default trusted paths

`allowlist.paths` defaults to the OS folders:

=== "Windows"

    `C:\Windows\System32\`, `C:\Windows\SysWOW64\`, `C:\Windows\WinSxS\`, `C:\Program Files\`, `C:\Program Files (x86)\`

    `allowlist.excluded_paths` defaults to `C:\Windows\Temp\`, `C:\Windows\Tasks\`, `C:\Windows\Tracing\`, `C:\Windows\System32\Tasks\`, and `C:\Windows\System32\spool\drivers\color\`.
    Exclusions take precedence over shared and module-specific trusted paths.
    Set `excluded_paths = [...]` under `[allowlist]` to replace the defaults.

=== "Linux"

    `/usr/bin/`, `/usr/sbin/`, `/usr/lib/`, `/usr/lib64/`, `/usr/libexec/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`

=== "macOS"

    `/usr/bin/`, `/usr/sbin/`, `/usr/libexec/`, `/bin/`, `/sbin/`, `/System/`

    `/Applications` is not trusted: it holds user-installed software.

Paths are prefixes and are not resolved, so symlinks are not followed.
Matching ignores case on Windows, and for active response on every platform.
Excluded paths use directory boundaries, including for IOC hashing.

## File permissions

Rustinel refuses a config file or rule folder that another account can change, and writes its logs readable by their owner only.
See [Input trust](security.md#input-trust).

## Unknown options

An unknown section or option, in the file or in an `EDR__` variable, stops startup.
The error names the key and suggests a valid one, and `rustinel doctor` reports the same error.
