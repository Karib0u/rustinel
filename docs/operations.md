# Operations and Upgrade Guide

How to lay out a persistent installation, run it under the platform's service
manager, and upgrade it safely.

For the commands themselves (`setup`, `service`, `rules`, `doctor`), see the
[CLI Reference](cli.md). For configuration precedence and path resolution, see
[Configuration](configuration.md). For Linux container deployment and its host
access requirements, see [Docker](docker.md).

## Managed Setup

For a persistent endpoint installation, use `setup`:

```bash
sudo rustinel setup --yes
```

It prepares the managed layout, writes a managed configuration when none exists,
downloads and verifies a rules pack, copies the executable to the service binary
path, registers the native service, starts it, and runs health checks. Existing
configuration is preserved unless `--force` is given. Use `--pack advanced` for
the larger pack, or `--no-start` to register without starting.

On macOS, `setup` copies the complete signed `Rustinel.app` bundle. Do not
replace only `Contents/MacOS/rustinel`, which invalidates the signing context
Endpoint Security requires.

Managed paths per platform are listed in
[Configuration](configuration.md#managed-layouts).

## Portable Directory Layout

If you are not using the managed layout, keep the binary, config, rules, and
logs together and point `config.toml` at absolute paths:

=== "Windows"

    ```text
    C:\Rustinel\
    ├── rustinel.exe
    ├── config.toml
    ├── rules\{sigma,yara,ioc}\
    └── logs\
    ```

=== "Linux"

    ```text
    /opt/rustinel/
    ├── rustinel
    ├── config.toml
    ├── rules/{sigma,yara,ioc}/
    └── logs/
    ```

=== "macOS"

    ```text
    /usr/local/var/rustinel/
    ├── Rustinel.app/
    ├── rustinel -> Rustinel.app/Contents/MacOS/rustinel
    ├── config.toml
    ├── rules/{sigma,yara,ioc}/
    └── logs/
    ```

macOS release archives contain a signed and notarized daemon bundle
(`Rustinel.app`) plus a `rustinel` symlink into it. The bundled
`com.rustinel.agent.plist` LaunchDaemon expects the
`/usr/local/var/rustinel` layout.

## Installers And Archives

The install scripts accept a target directory and a published version:

=== "Linux and macOS"

    ```bash
    scripts/install/install.sh --dir /opt/rustinel --version 1.2.0
    ```

=== "Windows"

    ```powershell
    .\scripts\install\install.ps1 -InstallDir C:\Rustinel -Version 1.2.0
    ```

They download published binaries only; they never install Rust or build from
source. Manual packages for Windows x86_64, Linux x86_64 and arm64, and macOS
Intel and Apple Silicon are on
[GitHub Releases](https://github.com/Karib0u/rustinel/releases). Each archive
carries the binary, `config.toml`, demo rules, install scripts, examples, and an
empty `logs/` directory.

## Rules In Production

Install a released pack with `rustinel rules install <PACK>`; packs activate
atomically under the managed rules directory. Local edits to active Sigma, YARA,
and IOC files are picked up by hot reload. See
[Configuration](configuration.md#reload) for what reloads and what does not.

After editing a rule, check the operational log for a successful reload and
trigger a known event. A rejected reload leaves the last valid rules live. Run
`rustinel doctor` to validate the on-disk configuration and rules.

## Service Runtime Models

`rustinel service install` registers the platform's native service and is the
supported path on all three platforms. The sections below cover what that
service actually runs, for operators who need to supervise it themselves.

### Linux

The binary is an ordinary foreground process; `systemd` wraps it. `service
install` writes this unit to `/etc/systemd/system/rustinel.service`, reloads
`systemd`, and enables it:

```ini
[Unit]
Description=Rustinel endpoint detection agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/rustinel/rustinel run --config /etc/rustinel/config.toml --no-console
WorkingDirectory=/opt/rustinel
Restart=on-failure
RestartSec=5s
User=root

[Install]
WantedBy=multi-user.target
```

### macOS

macOS support is experimental, though active response works there like it does
elsewhere. `service install` writes and bootstraps
`/Library/LaunchDaemons/com.rustinel.agent.plist`, expecting the managed bundle
at `/usr/local/var/rustinel/Rustinel.app`.

The bundle must be signed with the
`com.apple.developer.endpoint-security.client` entitlement, contain the
authorizing provisioning profile, and hold Full Disk Access, granted to
`Rustinel.app` itself for a LaunchDaemon, or provisioned by an MDM PPPC profile.
See [Development](development.md) for signing and notarization.

### Windows

The Service Control Manager runs the managed binary directly. Note that Windows
services start with `C:\Windows\System32` as the working directory, which is why
managed installs use an absolute managed config path.

## Monitoring Telemetry Loss

Sensor channels are bounded and shed events under burst load, which produces a
detection gap rather than a slowdown. Rustinel counts what it sheds, so the gap
is measurable:

```bash
rustinel doctor --json | jq '.telemetry.channels[] | select(.dropped > 0)'
```

Treat a growing `sensor_events` count as a coverage problem rather than a
performance one: those events never reached any detector. Counts are cumulative
per agent run. See
[Pipeline Telemetry](configuration.md#pipeline-telemetry) for the per-channel
meaning and [Troubleshooting](troubleshooting.md#dropped-events-and-full-queues)
for what to do about it.

### Windows ETW session buffers

Those counters see only Rustinel's own queues. On Windows there is an earlier
place events can be lost: the kernel's buffer pool for the `rustinel-etw-trace`
session. If the pool fills before the sensor drains it, the kernel discards
events and the sensor never sees them.

Rustinel sets the pool explicitly rather than inheriting library defaults:

| Setting | Value | Default it replaces |
| --- | --- | --- |
| Buffer size | 256 KB | 32 KB |
| Minimum buffers | 64 (16 MB committed at start) | 2 |
| Maximum buffers | 128 (32 MB ceiling) | 24 (768 KB) |
| Flush timer | 1 s | 1 s |
| Forced partial-buffer handoff | 100 ms | disabled |

The forced handoff controls quiet-host delivery latency without changing the
buffer pool. Configure it with `windows.etw_flush_interval_ms`; `0` disables it.
Rustinel pauses requests while its sensor queue is at least half full, when
queueing controls latency instead.

The buffers are non-paged pool: 16 MB is committed for the life of the agent and
grows to at most 32 MB under load. Read the live values back with:

```powershell
Get-EtwTraceSession -Name rustinel-etw-trace
```

`logman query -ets` shows the same session but localizes its output, so prefer
the cmdlet in scripts.

This sizing absorbed a 4,000-process fork tree with no loss on a Windows 11 lab
VM, where the library defaults lost 12-60% of process starts across identical
runs ([#312](https://github.com/Karib0u/rustinel/pull/312)). It is a fixed
configuration, not an adaptive one: a host that churns processes harder than
that can still overrun a 32 MB pool, and kernel-side loss is not counted
anywhere yet ([#305](https://github.com/Karib0u/rustinel/issues/305)). Treat a
recorded event count as an upper bound on what happened.

## Upgrades

### Windows: replace the binary in place

```powershell
Set-Location C:\Rustinel
.\rustinel.exe service stop
Copy-Item C:\Staging\rustinel.exe .\rustinel.exe -Force
.\rustinel.exe service start
```

### Windows: move to a new install directory

```powershell
Set-Location C:\OldRustinel
.\rustinel.exe service stop
.\rustinel.exe service uninstall

New-Item -ItemType Directory -Path D:\Rustinel -Force | Out-Null
Copy-Item C:\Staging\rustinel.exe D:\Rustinel\rustinel.exe -Force
Copy-Item C:\Staging\config.toml D:\Rustinel\config.toml -Force
Copy-Item C:\Staging\rules D:\Rustinel\rules -Recurse -Force

Set-Location D:\Rustinel
.\rustinel.exe service install
.\rustinel.exe service start
```

### Linux: replace the binary and restart

```bash
sudo install -m 0755 ./rustinel /opt/rustinel/rustinel
sudo systemctl restart rustinel
```

### Safe upgrade checklist

1. Back up `config.toml` and any custom rules.
2. Keep log and alert directories outside ephemeral build directories.
3. Replace the binary.
4. Restart the process or service.
5. Confirm new startup logs in `rustinel.log.<date>`.
6. Trigger the bundled `whoami` rule.
7. Run `rustinel doctor` and confirm `pipeline_telemetry` reports no new drops.
