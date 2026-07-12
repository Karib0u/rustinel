# FAQ

This page answers the questions that come up most often when running, deploying, or tuning Rustinel.

## General

### What does Rustinel do?

Rustinel is a cross-platform endpoint detection engine. It collects telemetry from ETW on Windows, eBPF on Linux, and Endpoint Security plus `/dev/bpf` on macOS, normalizes events into a shared model, evaluates Sigma, YARA, and IOC detections, writes ECS NDJSON alerts, and can optionally terminate offending processes on Windows and Linux only; macOS is detection-only today.

See [Architecture](architecture.md) and [Detection](detection.md) for the detailed runtime flow.

### Which platforms are supported?

- Windows 10/11 and Server 2016+
- Linux with kernel 5.8+, BTF, and the required eBPF privileges
- macOS 11+ (experimental) using Endpoint Security plus `/dev/bpf` capture

Current telemetry coverage is broadest on Windows, which includes process, image load, network, file, registry, DNS, PowerShell, WMI, service, and task telemetry. Linux and macOS currently cover process, network, file, and DNS. macOS support remains experimental while signed release packaging is validated across supported versions.

### Do I need Administrator or root?

Yes.

- Windows ETW collection requires Administrator privileges.
- Linux eBPF collection requires root or equivalent capabilities such as `CAP_BPF`, `CAP_PERFMON`, and `CAP_NET_ADMIN`, or `CAP_SYS_ADMIN` on supported setups.
- macOS Endpoint Security collection requires root, Full Disk Access, and a signed app bundle whose embedded provisioning profile authorizes `com.apple.developer.endpoint-security.client`.

## Running and Deployment

### What happens if I run `rustinel` without a subcommand?

It behaves the same as `rustinel run`.

See [CLI Reference](cli.md).

### Can I run Rustinel as a native service?

Yes. `rustinel setup` installs the managed layout and registers the native
service on Windows, Linux, and macOS. The `rustinel service` commands manage its
lifecycle through the Windows Service Control Manager, systemd, or launchd.

See [Operations and Upgrade Guide](operations.md) for managed paths, service
behavior, and upgrades.

### Why does Rustinel look in the wrong directory for rules or logs?

Relative paths in `config.toml` resolve from the directory containing the
selected configuration file. Check which configuration file Rustinel selected,
then verify its relative paths from that directory. Use `rustinel doctor` to
inspect the resolved configuration and paths.

For production deployments, managed layouts and absolute paths remain the
clearest choices.

See [Configuration](configuration.md).

### Where does Rustinel read configuration from?

Configuration values use CLI flags first, then `EDR__...` environment
variables, the selected configuration file, and built-in defaults. The file is
selected from `--config`, `RUSTINEL_CONFIG`, the managed platform path, the
executable directory, or the current working directory, in that order.

See [Configuration](configuration.md).

### Can I override the embedded eBPF object during Linux development?

Yes. Set `RUSTINEL_EBPF_OBJECT` to an absolute path to a compiled `.o` file.

Example:

```bash
sudo env RUSTINEL_EBPF_OBJECT=/opt/rustinel/ebpf/rustinel-ebpf.o ./rustinel run
```

See [CLI Reference](cli.md).

## Alerts, Logs, and Validation

### Where do logs and alerts go?

By default:

- Operational logs: `logs/rustinel.log.<date>`
- Alerts: `logs/alerts.json.<date>`

Both paths are configurable.

See [Output Format](output.md) and [Configuration](configuration.md).

### How do I quickly validate that Rustinel is working?

Use the bundled demo Sigma rules:

- Windows: run `whoami`
- Linux: run `whoami`
- macOS: run `whoami`

Then confirm:

- startup messages exist in the operational log
- the corresponding alert exists in `alerts.json.<date>`

See [Getting Started](getting-started.md).

### Why do I see startup logs but no alerts?

Run `rustinel doctor`, trigger the bundled `whoami` rule, and follow the ordered
checks in [Troubleshooting](troubleshooting.md#agent-runs-but-no-alerts).

## Detection Behavior

### Can I disable Sigma, YARA, or IOC independently?

Yes.

- `scanner.sigma_enabled`
- `scanner.yara_enabled`
- `ioc.enabled`

See [Configuration](configuration.md).

### Does hot reload require a restart?

No. If `reload.enabled = true`, Rustinel watches Sigma, YARA, and IOC directories/files for changes and reloads them automatically (falling back to a 60-second polling check if the watcher setup fails).

A restart is still useful when you change deployment layout, supervisor configuration, privileges, or the binary itself.

### What exactly hot reloads?

Sigma, YARA, and configured IOC files reload automatically. Sigma is recursive;
YARA reads only the top-level configured directory. Invalid reloads keep the
last valid detector active. See
[Troubleshooting](troubleshooting.md#hot-reload-problems) for failure behavior.

### Do Sigma and YARA load subdirectories the same way?

No.

- Sigma rules are loaded recursively.
- YARA rules are compiled from top-level `.yar` and `.yara` files in the configured directory.

See [Detection](detection.md).

### Why are my Linux DNS or domain-based detections not matching?

Linux captures visible plaintext DNS queries but not every resolver path or DNS
response. See the focused checks in
[Troubleshooting](troubleshooting.md#linux-dns-or-ioc-domain-rules-do-not-match).

### Why did YARA not scan a process I expected?

See the ordered checks in
[Troubleshooting](troubleshooting.md#yara-did-not-scan-the-process-i-expected).

### How are severities assigned?

- Sigma uses the rule `level`
- YARA always emits `critical`
- IOC uses `ioc.default_severity`

Active response applies `response.min_severity` after those mappings.

See [Detection](detection.md) and [Active Response](active-response.md).

### What does `alerts.match_debug` do?

It controls how much match metadata is attached to alerts.

- `off`: no match details
- `summary`: short structured match information
- `full`: more detailed match data, including matched values or YARA string details where supported

See [Detection](detection.md) and [Output Format](output.md).

## Active Response and Allowlists

### Why didn't active response kill the process?

See the ordered checks in
[Troubleshooting](troubleshooting.md#i-see-alerts-but-no-process-is-killed) and
the safety model in [Active Response](active-response.md).

### Are allowlists shared across modules?

Yes, by default.

`allowlist.paths` is the shared trusted-prefix list. If module-specific path allowlists are empty, they inherit from it:

- `response.allowlist_paths`
- `scanner.yara_allowlist_paths`
- `ioc.hash_allowlist_paths`

See [Configuration](configuration.md).

### Can I test active response safely?

Yes. Start with dry-run mode:

```toml
[response]
enabled = true
prevention_enabled = false
```

Then trigger a known benign bundled rule such as:

- `whoami` on Windows
- `whoami` on Linux

After you confirm the log output looks correct, enable prevention mode.

See [Active Response](active-response.md).

## Data Export

### Does Rustinel ship alerts directly to a SIEM?

Not by itself. Rustinel writes ECS NDJSON alert files and operational logs. A log shipper such as Filebeat can forward them.

See [Output Format](output.md).
