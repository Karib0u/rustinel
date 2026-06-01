# FAQ

This page answers the questions that come up most often when running, deploying, or tuning Rustinel.

## General

### What does Rustinel do?

Rustinel is a cross-platform EDR agent. It collects telemetry from ETW on Windows and eBPF on Linux, normalizes events into a shared model, evaluates Sigma, YARA, and IOC detections, writes ECS NDJSON alerts, and can optionally terminate offending processes.

See [Architecture](architecture.md) and [Detection](detection.md) for the detailed runtime flow.

### Which platforms are supported?

- Windows 10/11 and Server 2016+
- Linux with kernel 5.8+, BTF, and the required eBPF privileges

Current telemetry coverage is broader on Windows than Linux. Windows includes process, image load, network, file, registry, DNS, PowerShell, WMI, service, and task telemetry. Linux currently covers process, network, file, and DNS.

### Do I need Administrator or root?

Yes.

- Windows ETW collection requires Administrator privileges.
- Linux eBPF collection requires root or equivalent capabilities such as `CAP_BPF` or `CAP_SYS_ADMIN`, depending on your setup.

## Running And Deployment

### What happens if I run `rustinel` without a subcommand?

It behaves the same as `rustinel run`.

See [CLI Reference](cli.md).

### Can I run Rustinel as a Windows service?

Yes. Windows supports built-in service commands:

- `rustinel service install`
- `rustinel service start`
- `rustinel service stop`
- `rustinel service uninstall`

The installed service points at the current executable path, so moving the binary to a new directory requires reinstalling the service.

See [Operations and Upgrade Guide](operations.md).

### Can I run Rustinel as a Linux service?

Yes, but Rustinel does not include built-in Linux service-management commands. Run it under `systemd` or another supervisor.

See [Operations and Upgrade Guide](operations.md) for the example `systemd` unit.

### Why does Rustinel look in the wrong directory for rules or logs?

Because relative paths resolve from the current working directory.

That matters especially for:

- Windows services, which often start in `C:\Windows\System32`
- Linux supervisors, which may start outside your install directory

For production deployments, use absolute paths for `config.toml`, rules, logs, and alerts.

See [Configuration](configuration.md).

### Where does Rustinel read configuration from?

Configuration precedence is:

1. CLI flags where supported
2. `EDR__...` environment variables
3. `config.toml` in the current working directory
4. `config.toml` in the directory containing the executable
5. Built-in defaults

This means you can keep `config.toml` next to the `rustinel` executable even when
the working directory differs (such as `C:\Windows\System32` for a Windows service).

See [Configuration](configuration.md).

### Can I override the embedded eBPF object during Linux development?

Yes. Set `RUSTINEL_EBPF_OBJECT` to an absolute path to a compiled `.o` file.

Example:

```bash
sudo env RUSTINEL_EBPF_OBJECT=/opt/rustinel/ebpf/rustinel-ebpf.o ./rustinel run
```

See [CLI Reference](cli.md).

## Alerts, Logs, And Validation

### Where do logs and alerts go?

By default:

- Operational logs: `logs/rustinel.log.<date>`
- Alerts: `logs/alerts.json.<date>`

Both paths are configurable.

See [Output Format](output.md) and [Configuration](configuration.md).

### How do I quickly validate that Rustinel is working?

Use the bundled demo Sigma rules:

- Windows: run `whoami /all`
- Linux: run `whoami`

Then confirm:

- startup messages exist in the operational log
- the corresponding alert exists in `alerts.json.<date>`

See [Getting Started](getting-started.md).

### Why do I see startup logs but no alerts?

The most common reasons are:

- the agent is running from a directory that does not contain the expected `config.toml` or rule paths
- the relevant detector is disabled in config
- the rule files were not loaded from the path you expected
- the event source you are testing is not covered on that platform
- the event was suppressed by network aggregation or skipped by an allowlist

The operational log is the first place to check because it records sensor startup, rule loading, reload activity, warnings, and response decisions.

## Detection Behavior

### Can I disable Sigma, YARA, or IOC independently?

Yes.

- `scanner.sigma_enabled`
- `scanner.yara_enabled`
- `ioc.enabled`

See [Configuration](configuration.md).

### Does hot reload require a restart?

No. If `reload.enabled = true`, Rustinel polls Sigma, YARA, and IOC files and reloads them automatically.

A restart is still useful when you change deployment layout, supervisor configuration, privileges, or the binary itself.

### What exactly hot reloads?

- Sigma rule files under `scanner.sigma_rules_path`
- top-level YARA rule files under `scanner.yara_rules_path`
- IOC files configured in `ioc.hashes_path`, `ioc.ips_path`, `ioc.domains_path`, and `ioc.paths_regex_path`

If a rebuild produces an empty detector set, Rustinel keeps the last known good one instead of swapping in an empty configuration.

### Do Sigma and YARA load subdirectories the same way?

No.

- Sigma rules are loaded recursively.
- YARA rules are compiled from top-level `.yar` and `.yara` files in the configured directory.

See [Detection](detection.md).

### Why are my Linux DNS or domain-based detections not matching?

Linux DNS coverage is still narrower than Windows, but outbound query names are supported.

The eBPF DNS path observes userspace `sendto` calls for plaintext DNS traffic and parses the queried domain name in userspace. Linux DNS events can populate:

- `QueryName`
- `RecordType`
- `Image`
- `ProcessId`

Linux DNS events do not currently populate `QueryResults` or `QueryStatus`. That means:

- Sigma DNS rules that depend on `QueryName` can match on Linux
- IOC domain matching from DNS `QueryName` works on Linux
- IOC IP matching from DNS answers is effectively Windows-only right now

Linux DNS query-name extraction covers outbound plaintext DNS queries observed on port 53. It does not cover DNS-over-HTTPS, DNS-over-TLS, cached resolver answers that do not send a packet, or response-answer parsing.

See [Detection](detection.md).

### Why did YARA not scan a process I expected?

The common causes are:

- the event was not a process-start event
- the executable path was under an allowlisted prefix
- YARA is disabled
- the rule file was not loaded from the configured directory
- the queue was full and the job was dropped

See [Detection](detection.md) and [Configuration](configuration.md).

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

## Active Response And Allowlists

### Why didn’t active response kill the process?

Active response only acts when all of the following are true:

- `response.enabled = true`
- the alert severity is at or above `response.min_severity`
- the process has a usable PID and image path
- the PID is not protected
- the target is not Rustinel itself
- the image or path is not allowlisted
- `prevention_enabled = true`

If `prevention_enabled = false`, Rustinel logs what it would have done without terminating the process.

See [Active Response](active-response.md).

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

- `whoami /all` on Windows
- `whoami` on Linux

After you confirm the log output looks correct, enable prevention mode.

See [Active Response](active-response.md).

## Data Export

### Does Rustinel ship alerts directly to a SIEM?

Not by itself. Rustinel writes ECS NDJSON alert files and operational logs. A log shipper such as Filebeat can forward them.

See [Output Format](output.md).
