# Troubleshooting

## Start here

Commands on this page use `rustinel`, which [setup](operations.md#the-rustinel-command) puts on your `PATH`.
From a release folder, use `./rustinel` or `.\rustinel.exe` instead.

1. Run `rustinel doctor` (with `sudo` or as Administrator) and fix `FAIL` results first.
   Each check is explained in [Doctor checks](doctor.md).
2. Read the operational log, `logs/rustinel.log.<date>`.
3. Run in the foreground with more detail: `rustinel run --log-level debug`.
4. Trigger the demo rule with `whoami` to confirm the pipeline works.

## Rustinel does not start

### Windows exits with no output

`$LASTEXITCODE` is `-1073741515`: the Visual C++ runtime is missing.
Install it and retry:

```powershell
Invoke-WebRequest https://aka.ms/vc14/vc_redist.x64.exe -OutFile "$env:TEMP\vc_redist.x64.exe"
Start-Process "$env:TEMP\vc_redist.x64.exe" -ArgumentList "/install", "/quiet", "/norestart" -Wait -Verb RunAs
```

### "requires Administrator privileges"

Start PowerShell with *Run as administrator*.

### "Failed to load configuration"

- No config file was found, see [Which file is used](configuration.md#which-file-is-used).
- The TOML is invalid, or an `EDR__` variable has the wrong type.
  Unset recent variables and retry.

`rustinel doctor` shows which file it tried and where paths resolved.

### Linux: "eBPF sensor failed to start"

- Check the kernel is 5.8 or later and that you run as root.
- If the error mentions `tracefs`, mount it:

    ```bash
    sudo mount -t tracefs tracefs /sys/kernel/tracing
    ```

- If you set `RUSTINEL_EBPF_OBJECT`, unset it.
- If the error mentions an ABI mismatch, the eBPF object and the binary come from different builds.
  Rebuild both, see [Development](development.md).

### macOS: "Endpoint Security client init failed"

The error ends with `NotPrivileged`, `NotPermitted`, or `NotEntitled`.
See [macOS permissions](macos-permissions.md#start-up-errors).

## No alerts

1. Trigger `whoami`.
   If the demo rule does not fire, the problem is the pipeline, not your rule.
2. Check the log says rules loaded, and `doctor` shows no parse errors.
3. Check the engine is on: `scanner.sigma_enabled`, `scanner.yara_enabled`, `ioc.enabled`.
4. Check the rule folders are the ones you edited: `doctor` prints them.
5. Check the platform collects what the rule needs, see below.

## A rule never matches

- **The platform does not collect the logsource or field.**
  Check [Sigma support](sigma.md) and [Field availability](field-availability.md).
  `doctor` counts rules with no collector as `sigma_rules_inert`.
- **The host does not produce the event.**
  Security audit events and PowerShell module logging need host policy, see [Windows host logging](windows-logging.md).
- **A trusted path skipped it.**
  YARA, hashing, and response ignore `allowlist.paths`.
- **Registry rules use `HKLM` or `HKCU`.**
  Rustinel reports `\REGISTRY\MACHINE\...` paths.
- **DNS rules match answers.**
  Only Windows fills `QueryResults`.
  Linux and macOS see plain DNS queries on port 53, not DNS over HTTPS or TLS, and not lookups answered from a local cache.
- **The event was dropped.**
  Check `pipeline_telemetry`, and on Windows `registry_path_resolution` and `file_path_attribution`.

## YARA did not scan a file

- YARA scans executables when they start.
  A file that never runs is not scanned.
- The path is under a trusted prefix (`scanner.yara_allowlist_paths`).
- The file is larger than `scanner.yara_max_file_mb`, or the scan hit `scanner.yara_scan_timeout_ms`.
- The queue was full: the log says `YARA queue full; dropping scan job`.

For memory scans, also check that `scanner.yara_memory_enabled` is `true` and that the process did not exit before `yara_memory_delay_ms`.
Reading another process's memory can be refused: protected processes on Windows, missing `CAP_SYS_PTRACE` or a strict `ptrace_scope` on Linux, and most processes on macOS.
Refusals are logged at `trace` level.

## A hash indicator did not fire

Hashes are checked only when at least one hash is loaded, for executables of new processes, outside trusted paths, and below `ioc.max_file_size_mb`.

## Rule edits are ignored

- `reload.enabled` must be `true`, and the file must be under the configured rule folder.
- A rule that fails to compile rejects the whole reload.
  The log says `Rejected Sigma reload` or `Rejected YARA reload`, and the previous rules stay active.
- An empty IOC set is rejected on purpose.
- Replacing a whole pack needs a restart, see [Manage rule packs](rule-packs.md#why-a-restart-is-needed).

## Active response did not kill

All of these must hold: `response.enabled` and `response.prevention_enabled` are `true`, the alert severity is at least `response.min_severity`, the PID and executable path are known, and the process is not allowlisted, a low system PID, or Rustinel itself.
`Active response skipped` log lines give the reason.
See [Use active response](active-response.md).

## "queue full" or "dropping" in the log

Rustinel is shedding events under load.
Each queue logs its running total at most once a minute:

```text
Pipeline channel full; shedding telemetry channel="sensor_events" capacity=32768 dropped_total=1204
```

See [Telemetry loss](telemetry-loss.md) for what each queue costs and how to reduce load.

## The Windows agent exited after an ETW error

This is on purpose.
If the ETW sensor thread dies, Rustinel exits so the service manager restarts it, instead of running without telemetry:

```text
CRITICAL: ETW sensor thread died unexpectedly
```

## No operational log, or alerts fail to write

- `logging.directory` and `alerts.directory` must be writable by the account running Rustinel, and the disk must not be full.
- If the log folder cannot be used, Rustinel falls back to a temporary folder, or to no file log at all.

## macOS: no network or DNS events

Packet capture needs root.
If it cannot start, the log says `macOS network/DNS sensor unavailable` and process and file events continue.
Check the `macos_bpf_interface_<name>` results in `doctor`.

## Reporting a bug

Include:

- OS and version, and the Rustinel version (`rustinel --version`)
- the exact command, and relevant parts of `config.toml`
- the output of `rustinel doctor --json`
- the relevant log lines
- whether the `whoami` demo rule fires
- for a rule problem, the smallest rule that shows it and the event you expected it to match

[Open an issue](https://github.com/Karib0u/rustinel/issues).
