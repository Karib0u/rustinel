# CLI Reference

## Usage

```text
rustinel [COMMAND] [OPTIONS]
```

Running `rustinel` without a subcommand is equivalent to `rustinel run`.

## Global Options

Accepted by every subcommand.

| Option | Description |
| --- | --- |
| `--config <PATH>` | Load configuration from an explicit file path. Highest configuration-file precedence. |
| `--log-level <LEVEL>` | Log-level override: `error`, `warn`, `info`, `debug`, or `trace`. For production and automation, prefer `config.toml` or `EDR__LOGGING__LEVEL`. |
| `--version` | Print the version and exit. |
| `--help` | Print usage and exit. |

## Commands

### `run`

Run Rustinel in the foreground.

```text
rustinel run [--config <PATH>] [--no-console] [--console] [--log-level <LEVEL>]
```

Examples:

```powershell
rustinel run
rustinel run --config C:\ProgramData\Rustinel\config.toml
rustinel run --no-console
rustinel run --log-level debug
```

```bash
sudo ./rustinel run
sudo ./rustinel run --config /etc/rustinel/config.toml
```

Notes:

- `rustinel run` enables console output by default on every platform.
- At the default `info` level, the console shows startup milestones, detections,
  actionable warnings and errors, and the final pipeline summary. The
  operational log keeps the detailed stream.
- Use `--log-level debug` or `--log-level trace` when the detailed console
  stream is needed for troubleshooting.
- `--config <PATH>` selects the config file and overrides `RUSTINEL_CONFIG`, managed platform paths, executable-directory config, and current-directory config.
- `--no-console` suppresses console output, for example when redirecting logs.
- `--console` is kept as a compatibility alias and has the same effect as the default.
- Linux foreground execution is the normal runtime model unless you wrap the binary in a service manager.

### `capture`

Record endpoint behavior to a file that can be replayed against detectors later.

```text
rustinel capture [--config <PATH>] [--output <PATH>] [--log-level <LEVEL>]
```

Capture is passive. It starts the same sensors as `run` and records every
normalized event, but evaluates no rules, writes no alerts, and never invokes
active response. Rustinel does not launch the activity being observed: start
capture first, run the sample yourself, then press Ctrl-C.

```powershell
# In a disposable VM
rustinel capture
# ... run the sample, script, or Atomic test in another window ...
# Ctrl-C
```

```bash
sudo ./rustinel capture --output /tmp/lab/run-42.ndjson
```

Behavior:

- Requires the same privileges as `run`, and fails with the same preflight errors.
- Without `--output`, the recording is written to
  `<capture.directory>/rustinel-capture-<UTC timestamp>.ndjson`, creating the
  directory if needed. `--output` overrides that path entirely.
- Each recording has a manifest sidecar next to it, named after the recording
  with a `.manifest.json` extension.
- Ctrl-C drains queued events and finalizes the manifest as `complete`. A
  capture that is killed, or that lost events, stays `incomplete` and is
  rejected by `rustinel replay`.
- Progress and final counts go to stderr. Event payloads are never printed.
- Recordings can be replayed on any platform: a Windows recording replays on
  Linux and vice versa.

Recordings contain full command lines, file paths, network destinations, and
user names for all observed activity, so handle them as sensitive artifacts.
See [Output Format](output.md#behavioral-recordings) for the stream and manifest
layout.

### `replay`

Evaluate a recording against the detectors, offline.

```text
rustinel replay <RECORDING> [--config <PATH>] [--output <PATH>] [--log-level <LEVEL>]
```

Replay is the detection-development loop: capture a behavior once, then edit
rules or configuration and evaluate the same event stream as often as you like,
without re-running the sample and without an endpoint.

```bash
# The default: a console alert list
rustinel replay /tmp/lab/run-42.ndjson

# Compare a candidate rule set against the same behavior
rustinel replay /tmp/lab/run-42.ndjson --config /tmp/candidate.toml

# Machine-readable results
rustinel replay /tmp/lab/run-42.ndjson --output /tmp/lab/run-42.alerts.ndjson
```

Behavior:

- Needs no sensors, no elevated privileges, and no particular platform. A
  Windows recording replays on Linux or macOS and the other way round; Sigma
  logsource routing follows the platform recorded in the manifest, not the host.
- Uses the current configured detector set. `--config <PATH>` selects a different
  configuration, which is how two rule sets are compared over one recording.
- Loads detectors once. Hot reload is off, so a finite replay is reproducible.
- Processes events sequentially in recorded order, at full speed, with no
  wall-clock delays. Recorded timestamps are preserved in the alerts.
- Evaluates Sigma and the inline IOC checks (IP, domain, path). YARA and hash
  IOC checks are skipped, and said to be skipped, because a recording holds
  events rather than the files behind them.
- Never invokes active response, whatever `response.enabled` says, and never
  deduplicates: every detector match is reported.
- Writes a console alert list by default. `--output <PATH>` writes ECS NDJSON
  instead, owner-only, with an `edr.replay` object on every alert. Replay refuses
  to write into the configured alert directory.
- Rejects recordings that are incomplete, corrupted, missing their manifest, or
  written with a capture schema this build does not understand, and exits
  non-zero with the reason.

Two replays of one recording against one configuration produce identical output,
so a change in results is a change in detection. See
[Development](development.md#replay-regression-fixture) for the regression
fixture and [Output Format](output.md#replay-results) for the result formats.

### `doctor`

Run read-only preflight and health checks without starting the agent.

```text
rustinel doctor [--config <PATH>] [--json]
```

Examples:

```bash
rustinel doctor
rustinel doctor --json
sudo rustinel doctor --config /etc/rustinel/config.toml
```

Doctor reports `pass`, `warn`, or `fail` for configuration discovery and parsing,
resolved paths, writable log and alert directories, installed rules pack state,
pack compatibility and checksum metadata, Sigma, YARA, and IOC parsing, Sigma
rules left inert by a missing collector, native
service state, active-response safety, platform telemetry prerequisites, and
pipeline drop counters.

The `sigma_rules_inert` check reports how many loaded Sigma rules have no
backing collector on this platform - they parse, they count toward the rule
total, and they can never fire - grouped by the telemetry category that is
missing. The same summary is logged once at rule load. Rule count is not
coverage; see [Sigma Coverage](coverage.md) and
[Limitations](limitations.md#detection-engine-sigma).

The `pipeline_telemetry` check reports how much telemetry the agent shed under
load, per channel, from the snapshot the running agent writes - so a detection
gap can be sized without searching the operational log. `--json` carries the
raw per-channel counters under `telemetry`. On Windows, three further checks
cover the gaps the channel counters cannot show, because they happen before any
channel sees the event: `registry_path_resolution` and `file_path_attribution`
report the share of registry writes and file events that reached the detectors
with a path, and `etw_decode` reports records that failed to decode at all,
named by provider and event version. See
[Pipeline Telemetry](configuration.md#pipeline-telemetry).

Exit codes are intended for automation:

| Code | Meaning |
| --- | --- |
| `0` | All checks passed. |
| `1` | One or more warnings were found. |
| `2` | One or more failures were found. |

### `rules`

Discover and install released rules packs.

```text
rustinel rules list [--catalog-url <URL>] [--rules-dir <PATH>]
rustinel rules install <PACK> [--catalog-url <URL>] [--rules-dir <PATH>]
```

Examples:

```bash
rustinel rules list
sudo rustinel rules install linux-essential
```

The default catalog is the latest released `index.json` from
`Karib0u/rustinel-rules`. `rules list` filters packs to the current platform and
marks the active pack from `rules/state.json`. `rules install` downloads the pack
artifact into `rules/staging`, verifies its SHA-256 checksum, rejects unsafe ZIP
paths, validates `pack.yml`, then atomically replaces `rules/current`.

Managed active rules layout:

```text
rules/
+-- current/
|   +-- pack.yml
|   +-- sigma/
|   +-- yara/
|   +-- ioc/
+-- staging/
+-- state.json
```

### `setup`

Install Rustinel into the managed platform layout, install a rules pack,
register the native service, optionally start it, and run health checks.

```text
rustinel setup [--pack <essential|advanced>] [--yes] [--no-start] [--force]
               [--catalog-url <URL>]
```

Examples:

```powershell
rustinel setup --yes
rustinel setup --pack advanced --no-start
```

```bash
sudo rustinel setup --yes
sudo rustinel setup --pack advanced --no-start
```

Behavior:

- `setup` creates the managed configuration, rules, log, alert, and binary directories before writing files.
- `--pack` chooses the Essential or Advanced rules pack. Without `--pack`, interactive terminals prompt for a pack and non-interactive runs use Essential.
- `--yes` accepts defaults and skips the prompt.
- `--no-start` registers the native service without starting it.
- `--force` replaces an existing managed configuration. Without `--force`, existing configuration is preserved and validated before setup continues.
- `--catalog-url` overrides the rules catalog index, the same as on `rules`.
- The current executable is copied to the managed service binary path before service registration. On macOS, setup copies the complete signed `Rustinel.app` bundle so its signature, entitlements, and provisioning profile remain intact.
- Rules pack downloads use the same catalog validation, SHA-256 verification, ZIP safety checks, and atomic activation as `rules install`.
- If a rules download or validation fails, setup preserves existing active rules and continues only when an existing active pack is valid.
- If service installation or startup fails, setup leaves configuration and rules in place and prints the exact recovery command.
- The final summary prints configuration, rules, logs, alerts, service binary, active pack, and service status.

### `service`

Manage native service installation and lifecycle.

```text
rustinel service <install|uninstall|start|stop|restart|status>
```

Examples:

```powershell
rustinel service install
rustinel service start
rustinel service status
rustinel service restart
rustinel service stop
rustinel service uninstall
```

```bash
sudo rustinel service install
sudo rustinel service start
rustinel service status
sudo rustinel service restart
sudo rustinel service stop
sudo rustinel service uninstall
```

Status output is normalized across platforms:

```text
not-installed
stopped
starting
running
failed
unknown
```

Managed paths:

| Platform | Native manager | Binary | Configuration |
| --- | --- | --- | --- |
| Windows | Service Control Manager | `C:\Program Files\Rustinel\rustinel.exe` | `C:\ProgramData\Rustinel\config.toml` |
| Linux | systemd | `/opt/rustinel/rustinel` | `/etc/rustinel/config.toml` |
| macOS | launchd | `/usr/local/var/rustinel/Rustinel.app/Contents/MacOS/rustinel` | `/Library/Application Support/Rustinel/config.toml` |

`service install` validates that the managed binary and configuration file
already exist. It registers the native service definition only; it does not
download rules, copy a temporary executable, or overwrite user configuration.
`service uninstall` unregisters the native service and preserves configuration,
rules, logs, and state.

## Environment Variables

`RUSTINEL_CONFIG` selects the configuration file, below `--config` in
precedence. Every configuration key is also settable through an `EDR__`
variable. See [Configuration](configuration.md#environment-variables).

Two development-only variables exist: `RUSTINEL_EBPF_OBJECT` points the Linux
loader at a specific `.o` instead of the embedded object, and
`RUSTINEL_BPF_INTERFACE` selects the macOS capture interface. Both are covered
in [Development](development.md).

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Error |

Check the operational log if startup or runtime initialization fails.
