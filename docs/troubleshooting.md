# Troubleshooting

Use this page when Rustinel starts but does not behave the way you expect, or when it fails before first telemetry.

## Start Here

Before changing config or rules, check these first:

- Read the current operational log: `logs/rustinel.log.<date>`
- Run in the foreground with a higher log level:
  - Windows: `.\rustinel.exe run --log-level debug`
  - Linux: `sudo ./rustinel run --log-level debug`
  - macOS: `sudo ./rustinel run --log-level debug`
- Trigger a known bundled demo rule:
  - Windows: `whoami /all`
  - Linux: `whoami`
  - macOS: `whoami`
- Confirm you are using the expected working directory and rule paths

## Quick Symptom Guide

| Symptom | Common causes |
| --- | --- |
| Startup fails immediately | bad config, wrong working directory, missing privileges, unsupported Linux eBPF environment |
| Agent runs but no alerts appear | detector disabled, rules not loaded, testing unsupported telemetry, allowlists, aggregation |
| Rule edits are ignored | hot reload disabled, wrong rule path, YARA file placed in a subdirectory, reload rejected |
| Active response does not kill | dry-run mode, severity below threshold, allowlist hit, missing PID or image |
| Alerts are missing details | `alerts.match_debug = "off"` |
| Logs mention dropped events or full queues | sensor backpressure, YARA/IOC/response queues saturated |

## Startup Failures

### `Failed to load configuration`

This usually means one of these:

- `config.toml` is not in the current working directory or next to the executable
- the TOML syntax is invalid
- an `EDR__...` environment override has the wrong shape or type
- a relative path assumes a different working directory than the one Rustinel is using

What to do:

- verify where you launched Rustinel from
- prefer absolute paths for production deployments
- temporarily move to the install directory and start again
- remove recent environment overrides and retry

See [Configuration](configuration.md).

### Windows says Administrator privileges are required

Windows ETW collection requires an elevated process.

What to do:

- start Rustinel from an elevated PowerShell
- if running as a service, confirm the service account has the required privileges

Typical symptom in logs:

```text
This application requires Administrator privileges
Please run as Administrator to access ETW providers
```

### Linux `eBPF sensor failed to start`

The most common causes are:

- kernel older than 5.8
- BTF is not available
- missing root or required eBPF capabilities
- `tracefs` or `debugfs` is not mounted
- invalid `RUSTINEL_EBPF_OBJECT` override path
- incompatible or stale eBPF object

What to do:

- confirm the host meets the Linux requirements from [Getting Started](getting-started.md)
- if the error contains `tracefs not found`, mount the tracing filesystems and retry:

```bash
mount -t tracefs tracefs /sys/kernel/tracing
mount -t debugfs debugfs /sys/kernel/debug
```

- some minimal Linux environments, including some WSL 2 distros, may start without these filesystems mounted
- retry without `RUSTINEL_EBPF_OBJECT` if you were using an override
- if you are iterating on the eBPF program, rebuild the object and retry
- check the operational log for the exact Aya or loader error

Typical symptom in logs:

```text
eBPF object load failed — ensure BTF is available and kernel is 5.8+
```

### Linux source build fails on the first build

If `ebpf/rustinel-ebpf.o` is missing, the build falls back to compiling the eBPF crate. That first build needs:

- nightly Rust
- `rust-src`
- `bpf-linker`

See [Getting Started](getting-started.md) and [Development](development.md).

### macOS `Endpoint Security client init failed`

Creating the Endpoint Security client failed at startup. The result code at the
end of the error tells you exactly which requirement is missing:

| Result code | Cause | Fix |
| --- | --- | --- |
| `NotPrivileged` | Not running as root. | Re-run with `sudo`. |
| `NotPermitted` | Running as root with the entitlement, but macOS has not granted the client Endpoint Security access (TCC). | For an interactive `sudo` run from a terminal, grant **Full Disk Access to that terminal app** (Terminal/iTerm/…) and reopen it — macOS attributes the permission to the terminal, so Rustinel itself will not appear in the list. For a background LaunchDaemon, grant `Rustinel.app` directly (or use an MDM PPPC profile). |
| `NotEntitled` | The binary is not signed with `com.apple.developer.endpoint-security.client`, or its provisioning profile does not authorize the entitlement. | Run a signed `Rustinel.app` from a release, or repackage with `scripts/macos/package-app.sh` (see [Development](development.md)). |

On a fresh machine the first run typically reports `NotPermitted`: signing and
notarization are correct, and the only thing left is the one-time Full Disk
Access approval that macOS requires for every Endpoint Security client.

To inspect the bundle:

- check the signature and entitlements: `codesign --display --entitlements - Rustinel.app`
- decode the embedded profile: `security cms -D -i Rustinel.app/Contents/embedded.provisionprofile`

Typical symptom in logs:

```text
macOS Endpoint Security sensor failed to start: Endpoint Security client init failed: es_new_client failed: NotPermitted: macOS has not granted Endpoint Security access. Grant Rustinel.app Full Disk Access ...
```

### macOS network or DNS events are missing

Network and DNS telemetry on macOS comes from `/dev/bpf` capture, which is a
separate, best-effort source. If it cannot start, the agent logs a warning and
continues with Endpoint Security (process and file) only.

Check these first:

- access to the `/dev/bpf*` device nodes requires root
- capture binds to one interface (default `en0`); set `RUSTINEL_BPF_INTERFACE` to match your active interface
- DNS visibility requires plaintext DNS on port 53; DNS-over-HTTPS and DNS-over-TLS are not visible
- network connection events are attributed to a process on a best-effort basis and may be unattributed

Typical symptom in logs:

```text
macOS network/DNS sensor unavailable: ...; continuing with Endpoint Security only
```

## Agent Runs But No Alerts

### The process starts cleanly, but `alerts.json` stays empty

Check these in order:

1. Trigger the bundled `whoami` Sigma rule first.
2. Confirm the operational log shows rules loaded successfully.
3. Confirm the relevant detector is enabled:
   - `scanner.sigma_enabled`
   - `scanner.yara_enabled`
   - `ioc.enabled`
4. Confirm the rule paths point to the directories and files you expect.
5. Confirm you are testing telemetry that exists on the current platform.

See [Detection](detection.md).

### The detector is enabled, but my test never matches

The most common reasons are:

- the rule depends on fields that the platform does not emit
- the event family does not exist on that platform yet
- the event was skipped by an allowlist
- the event was suppressed by network aggregation

Examples:

- registry, image load, PowerShell, WMI, service, and task detections are Windows-only today
- Linux DNS events populate `QueryName` for outbound plaintext DNS queries, but not `QueryResults`
- repeated network connections may be suppressed when aggregation is enabled

### Linux DNS or IOC domain rules do not match

Linux DNS query-name extraction is available, but it has narrower coverage than Windows DNS ETW.

Linux eBPF DNS events can populate:

- `QueryName`
- `RecordType`
- `Image`
- `ProcessId`

Linux eBPF DNS events do not currently populate:

- `QueryResults`
- `QueryStatus`

If a DNS or domain IOC rule does not match, check these first:

- the lookup must send plaintext DNS on port 53; DNS-over-HTTPS and DNS-over-TLS are not visible to the DNS parser
- cached resolver answers may not send a DNS packet
- the rule should match `QueryName` or the generic `query` alias, not `QueryResults`
- DNS answer IP IOC matching requires `QueryResults`, so it is effectively Windows-only today

Sigma DNS rules that depend on queried domain names and IOC domain matching can work on Linux when the query is visible to the eBPF `sendto` path.

See [Detection](detection.md).

### YARA did not scan the process I expected

Check these first:

- YARA only runs on process-start events
- the executable path may be under an allowlisted prefix
- YARA may be disabled
- the YARA rule file may be outside the configured top-level directory
- the queue may have been full and the job dropped

Typical symptom in logs:

```text
YARA queue full; dropping scan job
```

### YARA memory scan produces no alerts

Check these first:

- `scanner.yara_memory_enabled` must be `true` and `scanner.yara_enabled` must also be `true`
- the process path may be allowlisted via `scanner.yara_allowlist_paths`
- the memory scan queue may have been full and the job dropped (look for `YARA memory queue full; dropping scan job`)
- the process may have exited before the scan ran (the worker waits `yara_memory_delay_ms` first)
- per-region or per-process byte caps may have prevented reading the region containing the match
- insufficient privileges may prevent reading process memory (see below)

#### Linux memory scanning privileges

On Linux, reading `/proc/<pid>/mem` typically requires root or the `CAP_SYS_PTRACE` capability. You may also need to set a permissive ptrace scope:

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

Without adequate privileges, region reads will fail silently (logged at `trace`).

#### Windows memory scanning privileges

On Windows, `OpenProcess` with `PROCESS_VM_READ` may fail for:

- protected processes (`PROTECTED_PROCESS_LIGHT` or `PROTECTED_PROCESS`)
- system processes with elevated integrity levels
- some anti-tamper or security software

These failures are logged at `trace` and do not affect other detection paths.

#### macOS memory scanning privileges

On macOS, reading another process's memory uses `task_for_pid`, which is
heavily restricted. It generally requires root and SIP/AMFI relaxation or a
specific entitlement, and is denied for many system and protected processes.
When access is denied the scan returns nothing, logged at `trace`.

### IOC hash matching did not fire

Hash matching is more selective than inline IOC checks.

It only runs when:

- at least one hash IOC is loaded
- a process-start event queued the executable path
- the file path is not allowlisted
- the file size is below `ioc.max_file_size_mb`

## Hot Reload Problems

### My rule edits are ignored

Check these first:

- `reload.enabled` must be `true`
- the file must be under the configured detector path
- Sigma reloads recursively, but YARA only loads top-level files
- a failed reload keeps the previous detector set live

Typical reload failure messages:

```text
Sigma reload failed; keeping previous engine
YARA reload failed; keeping previous scanner
Rejected IOC reload: indicator set is empty
```

### I changed a file but nothing reloaded

Remember:

- reload polling is local file based
- the poll cadence is effectively `max(reload.debounce_ms, 2000ms)`
- empty rebuild results are rejected on purpose

If in doubt, make a tiny valid change to a known-good file and watch the operational log.

## Active Response Problems

### I see alerts, but no process is killed

Active response only executes when all of the following are true:

- `response.enabled = true`
- `response.prevention_enabled = true`
- alert severity is at or above `response.min_severity`
- the target has a valid PID
- the target image is known
- the PID is not protected
- the target is not Rustinel itself
- the image or path is not allowlisted

If `prevention_enabled = false`, the response engine logs what it would have done instead of killing the process.

See [Active Response](active-response.md).

### Active response says the target was skipped

That is usually expected and safety-related.

The response engine skips:

- protected low system PIDs
- Rustinel itself
- allowlisted images and paths
- alerts without a usable PID or image path

## Dropped Events And Full Queues

### I see “dropping event” or “queue full” in logs

These messages mean the agent is under backpressure somewhere in the pipeline.

Common log lines include:

```text
Sensor event channel full; dropping ETW event
eBPF sensor: event channel full, dropping event
bpf sensor: event channel full, dropping event
YARA queue full; dropping scan job
IOC hash queue full; dropping job
Active response queue full, dropping task
```

What to do:

- reduce event volume during testing
- narrow overly broad rules
- widen trusted-path exclusions where appropriate
- avoid scanning large trusted software trees unnecessarily
- watch system load while reproducing the issue

If the problem is persistent, capture the relevant log excerpt before tuning.

## Logging And Output Problems

### I have no operational logs

Check these first:

- `logging.directory` points to a writable location
- the current working directory is what you expect
- the service or supervisor account can write there

Rustinel may fall back to a temp directory if file logging cannot be initialized. If that also fails, it falls back to a sink writer and you may lose file-based operational logs.

### Alerts are missing match details

That is controlled by `alerts.match_debug`.

Use:

- `off` for no match metadata
- `summary` for compact details
- `full` for more verbose match information

See [Detection](detection.md) and [Output Format](output.md).

### I see operational logs but alert writes fail

Check:

- `alerts.directory` is writable
- the filesystem is not full
- the process has permission to create or rotate files there

Typical symptom in logs:

```text
Failed to write ECS alert
```

## Windows ETW Restart Behavior

### Why did the Windows agent exit after the ETW sensor failed?

That is intentional.

If the ETW sensor thread dies unexpectedly, Rustinel forces the process to exit so the Windows Service Manager or another supervisor can restart it. This avoids leaving a process that appears healthy but is no longer collecting telemetry.

Typical symptom in logs:

```text
CRITICAL: ETW sensor thread died unexpectedly
Forcing process exit to trigger restart
```

## Before Opening An Issue

Collect these first:

- platform and version
- Rustinel version or commit
- exact start command
- relevant config snippets
- relevant operational log excerpt
- whether the bundled `whoami` demo rule works
- on Linux: kernel version, BTF availability, and whether an eBPF override object was used
- on macOS: macOS version, whether running as root, and whether the build is signed/notarized or SIP/AMFI is relaxed

If the problem is rule-related, include the minimal rule and the event type you expected it to match.
