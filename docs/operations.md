# Operations and Upgrade Guide

This guide covers install layout, service behavior, and practical upgrade examples.

## Recommended Directory Layout

### Windows

```text
C:\Rustinel\
├── rustinel.exe
├── config.toml
├── rules\
│   ├── sigma\
│   ├── yara\
│   └── ioc\
└── logs\
```

### Linux

```text
/opt/rustinel/
├── rustinel
├── config.toml
├── rules/
│   ├── sigma/
│   ├── yara/
│   └── ioc/
└── logs/
```

### macOS

```text
/usr/local/var/rustinel/
├── Rustinel.app/
├── rustinel -> Rustinel.app/Contents/MacOS/rustinel
├── config.toml
├── rules/
│   ├── sigma/
│   ├── yara/
│   └── ioc/
└── logs/
```

macOS support is experimental. Release archives contain a signed and notarized
app-like daemon bundle (`Rustinel.app`) plus a `rustinel` symlink into it. The
bundled `com.rustinel.agent.plist` LaunchDaemon expects this
`/usr/local/var/rustinel` layout. See [Getting Started](getting-started.md) for
Full Disk Access setup and [Development](development.md) for signing details.

Use absolute paths in `config.toml` once you move beyond the default repo layout.

## Managed Setup

For a persistent endpoint installation, use the managed setup command:

```powershell
rustinel setup --yes
```

```bash
sudo rustinel setup --yes
```

`setup` prepares the managed layout, writes a managed configuration when needed,
downloads and verifies the selected rules pack, copies the current executable to
the service binary path, registers the native service, starts it unless
`--no-start` is supplied, runs health checks, and prints the final paths and
service status. Existing managed configuration is preserved unless `--force` is
supplied.

On macOS, `setup` copies the complete signed `Rustinel.app` bundle into the
managed layout. Do not replace only `Contents/MacOS/rustinel`: doing so can
invalidate the signing context required by Endpoint Security.

Pack selection:

```bash
sudo rustinel setup --pack essential
sudo rustinel setup --pack advanced --no-start
```

Without `--pack`, an interactive terminal prompts for Essential or Advanced.
Non-interactive setup defaults to Essential. If rules download or verification
fails, setup preserves existing active rules and continues only when the active
pack is valid.

## Installer And Archive Options

The install scripts accept a target directory and published version:

=== "Linux and macOS"

    ```bash
    scripts/install/install.sh --dir /opt/rustinel --version 1.2.0
    ```

=== "Windows"

    ```powershell
    .\scripts\install\install.ps1 -InstallDir C:\Rustinel -Version 1.2.0
    ```

The scripts download published binaries only. They do not install Rust or build
from source. Manual packages are available from
[GitHub Releases](https://github.com/Karib0u/rustinel/releases) for Windows
x86_64, Linux x86_64 and arm64, and macOS Intel and Apple Silicon. Each archive
contains the binary, `config.toml`, demo rules, install scripts, examples, and
an empty `logs/` directory.

## Rules And Hot Reload

Install a released pack with `rustinel rules install <PACK>`. Managed packs are
activated atomically under the platform rules directory. Local edits to active
Sigma, YARA, IOC files, and the configuration file are watched when `reload.enabled = true` (the
default), with rapid changes grouped by `reload.debounce_ms`. Config file changes hot-swap the active response settings (`[response]` section); other config sections require a restart.

After editing a rule, check the operational log for a successful reload and
trigger a known event. A rejected reload leaves the last valid in-memory rules
active. Run `rustinel doctor` to validate the on-disk configuration and rules.

## Working Directory Rules

- Configuration files are selected from `--config`, `RUSTINEL_CONFIG`, the
  managed platform path, the executable directory, and the current working
  directory, in that order.
- Relative paths resolve from the directory containing the selected
  configuration file.
- `rustinel doctor` reports the selected configuration and resolved paths.
- Use the managed platform configuration path for native services.
- Prefer absolute paths for custom service layouts and supervisors.

## Native Service Lifecycle

Rustinel includes built-in native service management commands on Windows,
Linux, and macOS:

```powershell
.\rustinel.exe service install
.\rustinel.exe service start
.\rustinel.exe service status
.\rustinel.exe service restart
.\rustinel.exe service stop
.\rustinel.exe service uninstall
```

```bash
sudo rustinel service install
sudo rustinel service start
rustinel service status
sudo rustinel service restart
sudo rustinel service stop
sudo rustinel service uninstall
```

Important behavior:

- `service install` registers the native service definition with managed paths.
- The managed binary and managed configuration file must already exist.
- `service install` does not download rules, copy a temporary executable, or overwrite user configuration.
- `service uninstall` stops and unregisters the native service while preserving configuration, rules, logs, and state.
- `service status` prints one normalized value: `not-installed`, `stopped`, `starting`, `running`, `failed`, or `unknown`.
- Service mode uses the managed config file path and can still be adjusted with `EDR__...` environment variables.

Managed service paths:

| Platform | Native manager | Binary | Configuration |
| --- | --- | --- | --- |
| Windows | Service Control Manager | `C:\Program Files\Rustinel\rustinel.exe` | `C:\ProgramData\Rustinel\config.toml` |
| Linux | systemd | `/opt/rustinel/rustinel` | `/etc/rustinel/config.toml` |
| macOS | launchd | `/usr/local/var/rustinel/Rustinel.app/Contents/MacOS/rustinel` | `/Library/Application Support/Rustinel/config.toml` |

## Linux Runtime Model

The binary itself remains the same foreground application. Service management
wraps it with `systemd`:

```bash
sudo /opt/rustinel/rustinel run
```

### Example systemd Unit

Save as `/etc/systemd/system/rustinel.service`:

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

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable rustinel
sudo systemctl start rustinel
sudo systemctl status rustinel
```

The built-in `service install` command writes this unit to
`/etc/systemd/system/rustinel.service`, reloads `systemd`, and enables the unit.

## macOS Runtime Model

macOS support is experimental and detection-only today. Active response is not
supported on macOS. You can still run it in the foreground as root:

```bash
sudo /usr/local/var/rustinel/rustinel run
```

For background execution, `service install` writes and bootstraps
`/Library/LaunchDaemons/com.rustinel.agent.plist` as a `launchd`
LaunchDaemon. It expects the managed app bundle at
`/usr/local/var/rustinel/Rustinel.app` and the managed configuration file at
`/Library/Application Support/Rustinel/config.toml`.

The app bundle must be signed with the
`com.apple.developer.endpoint-security.client` entitlement, contain the
authorizing provisioning profile, and have Full Disk Access (a LaunchDaemon needs
it granted to `Rustinel.app`, or provisioned via an MDM PPPC profile). See
[Development](development.md) for signing and notarization details.

## Upgrade Examples

### Windows: Replace Binary In Place

If the service already points to the final directory:

```powershell
Set-Location C:\Rustinel
.\rustinel.exe service stop
Copy-Item C:\Staging\rustinel.exe .\rustinel.exe -Force
.\rustinel.exe service start
```

### Windows: Move To A New Install Directory

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

### Linux: Rebuild From Source And Restart

Example with `systemd` as the supervisor:

```bash
cd /opt/src/rustinel
git pull
cargo build --release
sudo install -m 0755 ./target/release/rustinel /opt/rustinel/rustinel
sudo systemctl restart rustinel
```

### Linux: Release Binary Upgrade

```bash
sudo install -m 0755 ./rustinel /opt/rustinel/rustinel
sudo systemctl restart rustinel
```

### Linux: eBPF-Only Iteration

When you only changed `ebpf/`, rebuild the object and run with the override path:

```bash
cd /opt/src/rustinel/ebpf
cargo +nightly build --release --bin rustinel-ebpf
cp target/bpfel-unknown-none/release/rustinel-ebpf rustinel-ebpf.o

cd /opt/src/rustinel
sudo env RUSTINEL_EBPF_OBJECT=$PWD/ebpf/rustinel-ebpf.o ./target/release/rustinel run
```

This is useful for development because it avoids rebuilding the full userspace binary after every eBPF-only change.

## Monitoring Telemetry Loss

Sensor channels are bounded and shed events under burst load, which produces a
detection gap rather than a slowdown. Rustinel counts what it sheds, so the gap
is measurable:

```bash
rustinel doctor
```

The `pipeline_telemetry` check reports the per-channel drop totals, and
`rustinel doctor --json` exposes them under `telemetry` for a monitoring agent
to collect:

```bash
rustinel doctor --json | jq '.telemetry.channels[] | select(.dropped > 0)'
```

Treat a growing `sensor_events` drop count as a coverage problem, not a
performance one: those events never reached any detector. Counts are cumulative
for an agent run and reset when it restarts. See
[Pipeline Telemetry](configuration.md#pipeline-telemetry) and
[Dropped Events And Full Queues](troubleshooting.md#dropped-events-and-full-queues).

### Windows ETW Session Buffers

Those counters see only Rustinel's own queues. On Windows there is a second,
earlier place events can be lost: the kernel's buffer pool for the
`rustinel-etw-trace` session. If the pool fills before the sensor drains it,
the kernel discards events and the sensor never sees them at all.

Rustinel sets the pool explicitly rather than taking the library defaults:

| Setting | Value | Default it replaces |
| --- | --- | --- |
| Buffer size | 256 KB | 32 KB |
| Minimum buffers | 64 (16 MB committed at start) | kernel-chosen, 2 |
| Maximum buffers | 128 (32 MB ceiling) | kernel-chosen, 24 (768 KB) |
| Flush timer | 1 s | 1 s |

The buffers are non-paged pool: 16 MB is committed for the life of the agent
and the pool grows to at most 32 MB under load. Read the live values back with:

```powershell
Get-EtwTraceSession -Name rustinel-etw-trace
```

`logman query -ets` shows the same session, but its output is localized, so
prefer the cmdlet in scripts.

**What the values were chosen against.** A two-level fork tree on a Windows 11
lab VM (6 vCPU, 8 GB), 40 parent processes each spawning 100 short-lived
children. Ground truth is the number of children that actually ran — each one
creates a uniquely named file — compared against the process-creation events in
a `rustinel capture` recording of the same run:

| Session sizing | Children ran | Start events delivered | Lost |
| --- | --- | --- | --- |
| 32 KB x 2-24 (defaults) | 4,000 | 1,584 | 60.4% |
| 32 KB x 2-24 (defaults) | 4,000 | 2,178 | 45.6% |
| 32 KB x 2-24 (defaults) | 3,604 | 1,652 | 54.2% |
| 32 KB x 2-24 (defaults) | 4,000 | 3,514 | 12.2% |
| 32 KB x 2-24 (defaults), 50 x 100 | 5,000 | 4,159 | 16.8% |
| 256 KB x 64-128 | 4,000 | 4,000 | 0% |
| 256 KB x 64-128 | 4,000 | 4,000 | 0% |
| 256 KB x 64-128 | 4,000 | 4,000 | 0% |
| 256 KB x 64-128, 50 x 100 | 5,000 | 5,000 | 0% |

The spread in the default rows is the point as much as the magnitude: identical
runs lost between 12% and 60% depending on how tightly the burst landed, so a
single favourable measurement on default sizing proves nothing. A heavier tree
(60 x 150) exhausted the lab VM's memory before it exhausted the buffer pool,
so it bounds the *host*, not the sizing.

This is a fixed configuration, not an adaptive one. A host that sustains far
more process churn than the lab VM can still overrun a 32 MB pool; kernel-side
loss of that kind is not yet counted anywhere, so treat a recorded event count
as an upper bound on what happened.

## Safe Upgrade Checklist

1. Back up `config.toml` and your custom `rules/`.
2. Keep log and alert directories outside ephemeral build directories.
3. Replace the binary.
4. Restart the process or service.
5. Confirm new startup logs in `rustinel.log.<date>`.
6. Trigger a known benign rule such as the bundled `whoami` Sigma rule.
7. Run `rustinel doctor` and confirm `pipeline_telemetry` reports no new drops.
