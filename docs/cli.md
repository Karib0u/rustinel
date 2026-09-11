# CLI

```text
rustinel [COMMAND] [OPTIONS]
```

With no command, `rustinel` runs the agent in the foreground, like `rustinel run`.
Commands that read telemetry (`run`, `capture`, `doctor` for some checks) need Administrator on Windows and root on Linux and macOS.

<!-- BEGIN GENERATED CLI REFERENCE -->
This section is generated from the clap definitions in `src/cli/mod.rs`. Edit those and run `cargo run --bin generate-docs`.

## Global options

Accepted by every command.

| Option | Description |
| --- | --- |
| `--config <PATH>` | Configuration file to load. Overrides RUSTINEL_CONFIG and every discovered config.toml. |
| `--log-level <LEVEL>` | Log level for this run: error, warn, info, debug, or trace. |
| `--help` | Print help. |
| `--version` | Print the version. |

## `rustinel update`

Update the binary from the latest GitHub Release.

Downloads the archive for this OS and architecture, verifies its SHA-256 checksum, and replaces the running executable. Configuration, rules, logs, and captures are kept. Restart Rustinel afterwards: a running service is not restarted for you.

```text
rustinel update
```

## `rustinel setup`

Install Rustinel into the managed platform layout.

Writes the managed configuration, installs a rules pack, copies this executable (the whole signed Rustinel.app on macOS), makes it available as the `rustinel` command, registers the native service, starts it, and runs the doctor checks. An existing configuration is kept unless `--force` is given.

```text
rustinel setup [--pack <PACK>] [--yes] [--no-start] [--force] [--catalog-url <URL>]
```

| Option | Description |
| --- | --- |
| `--pack <PACK>` | Rules pack to install. Interactive runs prompt when omitted; other runs use essential. One of `essential`, `advanced`. |
| `--yes` | Accept defaults and do not prompt. |
| `--no-start` | Register the service but do not start it. |
| `--force` | Replace existing managed configuration. |
| `--catalog-url <URL>` | Rules catalog index URL. Default: `https://github.com/Karib0u/rustinel-rules/releases/latest/download/index.json`. |

## `rustinel run`

Run in the foreground with console output.

```text
rustinel run [--console] [--no-console]
```

| Option | Description |
| --- | --- |
| `--console` | Compatibility alias; console output is enabled by default. |
| `--no-console` | Disable console output. |

## `rustinel capture`

Record endpoint behavior to a replayable file without evaluating detections.

Capture is passive: start it first, then run the sample, script, or test you want to record, and press Ctrl-C when the session is complete.

```text
rustinel capture [--output <PATH>]
```

| Option | Description |
| --- | --- |
| `--output <PATH>` | Recording path. Defaults to &lt;capture.directory&gt;/rustinel-capture-&lt;UTC timestamp&gt;.ndjson. |

## `rustinel replay`

Evaluate a recording against the detectors, offline.

Replay needs no sensors, no privileges, and no particular platform: a recording made on one endpoint can be replayed anywhere, as often as the rules being developed against it change.

```text
rustinel replay <RECORDING> [--output <PATH>]
```

| Option | Description |
| --- | --- |
| `<RECORDING>` | Recording to replay, as written by `rustinel capture`. Its manifest sidecar must sit next to it. |
| `--output <PATH>` | Write ECS NDJSON alerts here instead of a console alert list. |

## `rustinel doctor`

Check configuration, paths, and runtime prerequisites.

Read-only; it does not start the agent. Exits 0 when every check passes, 1 when at least one check warns, and 2 when at least one fails.

```text
rustinel doctor [--json]
```

| Option | Description |
| --- | --- |
| `--json` | Emit structured JSON output. |

## `rustinel service`

Manage the native service (SCM on Windows, systemd on Linux, launchd on macOS).

### `rustinel service install`

Register the native service. The managed binary and configuration must already exist.

```text
rustinel service install
```

### `rustinel service uninstall`

Unregister the native service. Configuration, rules, and logs are kept.

```text
rustinel service uninstall
```

### `rustinel service start`

Start the service.

```text
rustinel service start
```

### `rustinel service stop`

Stop the service.

```text
rustinel service stop
```

### `rustinel service restart`

Stop and start the service.

```text
rustinel service restart
```

### `rustinel service status`

Print not-installed, stopped, starting, running, failed, or unknown.

```text
rustinel service status
```

## `rustinel rules`

Discover, install, and update released rules packs.

### `rustinel rules list`

List rules packs available for this platform.

```text
rustinel rules list [--catalog-url <URL>] [--rules-dir <PATH>]
```

| Option | Description |
| --- | --- |
| `--catalog-url <URL>` | Rules catalog index URL. Default: `https://github.com/Karib0u/rustinel-rules/releases/latest/download/index.json`. |
| `--rules-dir <PATH>` | Rules root directory, containing current, staging, and state.json. |

### `rustinel rules update`

Update the active pack to the newest compatible release.

Installs only a strictly newer version compatible with this platform and Rustinel version. Restart Rustinel afterwards: a whole-pack replacement is not hot reloaded. Local edits under `rules/current` are replaced.

```text
rustinel rules update [--catalog-url <URL>] [--rules-dir <PATH>]
```

| Option | Description |
| --- | --- |
| `--catalog-url <URL>` | Rules catalog index URL. Default: `https://github.com/Karib0u/rustinel-rules/releases/latest/download/index.json`. |
| `--rules-dir <PATH>` | Rules root directory, containing current, staging, and state.json. |

### `rustinel rules install`

Install a rules pack and make it active.

Downloads the pack, verifies its SHA-256 checksum, validates it, then atomically replaces `rules/current`. A failure keeps the previous pack.

```text
rustinel rules install <PACK> [--catalog-url <URL>] [--rules-dir <PATH>]
```

| Option | Description |
| --- | --- |
| `<PACK>` | Pack ID from `rustinel rules list`. |
| `--catalog-url <URL>` | Rules catalog index URL. Default: `https://github.com/Karib0u/rustinel-rules/releases/latest/download/index.json`. |
| `--rules-dir <PATH>` | Rules root directory, containing current, staging, and state.json. |

<!-- END GENERATED CLI REFERENCE -->

## Exit codes

| Command | Code | Meaning |
| --- | --- | --- |
| `doctor` | `0`, `1`, `2` | All checks passed, a warning, a failure |
| every other command | `0`, `1` | Success, error |

## Environment variables

| Variable | Effect |
| --- | --- |
| `RUSTINEL_CONFIG` | Config file to load, unless `--config` is given |
| `EDR__<SECTION>__<KEY>` | Overrides one config option, see [Configuration](configuration.md#environment-variables) |
| `RUSTINEL_BPF_INTERFACE` | macOS: comma-separated interfaces to capture instead of all active ones |
| `RUSTINEL_EBPF_OBJECT` | Linux, development only: load this eBPF object instead of the embedded one |
