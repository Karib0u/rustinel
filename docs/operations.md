# Operations and Upgrade Guide

How to lay out a persistent installation, run it under the platform's service
manager, and upgrade it safely.

For the commands themselves (`setup`, `service`, `rules`, `doctor`), see the
[CLI Reference](cli.md). For configuration precedence and path resolution, see
[Configuration](configuration.md).

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

## Windows Audit Policy

Rustinel subscribes to the Security channel, but Windows only writes to it what
the host's audit policy tells it to. Every event below is subscribed to and
decoded; the ones whose policy is off simply never occur, so the rules that
need them load and stay silent. **Enabling this policy is the operator's
decision, not Rustinel's** — the agent never changes it.

| Event | Subcategory | Subcategory GUID | On by default |
| --- | --- | --- | --- |
| 4624 logon | Logon | `{0CCE9215-…}` | Yes |
| 4697 service installed | Security System Extension | `{0CCE9211-…}` | No |
| 4656 handle requested | File System, Registry, Kernel Object, SAM | `{0CCE921D-…}`, `{0CCE921E-…}`, `{0CCE921F-…}`, `{0CCE9220-…}` | No |
| 4663 object access | File System, Registry, Kernel Object | `{0CCE921D-…}`, `{0CCE921E-…}`, `{0CCE921F-…}` | No |
| 5145 network share object checked | Detailed File Share | `{0CCE9244-…}` | No |
| 5136 directory service object modified | Directory Service Changes | `{0CCE923C-…}` | No (domain controllers) |

All GUIDs end in `-69AE-11D9-BED3-505054503030`.

Turn a subcategory on with `auditpol`, from an elevated prompt:

```bat
auditpol /set /subcategory:"Security System Extension" /success:enable
```

```bat
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```

Check what is currently enabled:

```bat
auditpol /get /category:*
```

**`auditpol` takes the *localized* subcategory name.** On a non-English Windows
the commands above fail with *the parameter is incorrect*; use the GUID, which
is the same on every locale:

```bat
auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable
```

`auditpol /list /subcategory:* /v` prints the local names next to their GUIDs.
Before changing policy on a host you do not own, take a copy you can put back:

```bat
auditpol /backup /file:C:\auditpol-before.csv
```

Two caveats worth knowing before turning these on:

- **4656 and 4663 additionally need a SACL on the object.** The subcategory only
  enables the *mechanism*; nothing is logged until an audit entry is placed on
  the file, key, or object of interest (its **Properties → Security → Advanced →
  Auditing** tab). Enabling the subcategory alone produces no events.
- **Detailed File Share and Kernel Object auditing are high volume.** 5145 fires
  once per share access check. On a file server this can dominate the Security
  channel. Enable it deliberately, and size the channel accordingly
  (`wevtutil sl Security /ms:<bytes>`).

Group Policy configures the same settings at
*Computer Configuration → Windows Settings → Security Settings → Advanced Audit
Policy Configuration*.

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
place events can be lost: the kernel's buffer pool for Rustinel's ETW sessions.
If a pool fills before the sensor drains it, the kernel discards events and the
sensor never sees them.

Rustinel runs **two** real-time sessions, because process events and everything
else want opposite buffer sizing:

| Session | Providers | Why |
| --- | --- | --- |
| `rustinel-etw-trace` | File, Registry, Network, DNS, PowerShell, WMI, Task Scheduler | Burst headroom - these are the high-volume providers |
| `rustinel-etw-process` | Kernel-Process | Latency - `CommandLine` is read from the live process, which must still exist |

Both set the pool explicitly rather than inheriting library defaults:

| Setting | `rustinel-etw-trace` | `rustinel-etw-process` | Default it replaces |
| --- | --- | --- | --- |
| Buffer size | 256 KB | 32 KB | 32 KB |
| Minimum buffers | 64 (16 MB committed) | 64 (2 MB committed) | 2 |
| Maximum buffers | 128 (32 MB ceiling) | 512 (16 MB ceiling) | 24 (768 KB) |
| Flush timer | 1 s | 1 s | 1 s |
| Forced partial-buffer handoff | 20 ms | 5 ms | disabled |

A buffer is handed to the consumer when it fills, or when a flush is forced.
Neither buffer size on its own gets a low-volume stream out quickly - a session
carrying only process events does not fill a buffer of *any* size fast enough to
beat a process that lives 20 ms, which is why the split had to come with a
faster forced handoff (below). What the split buys is that the faster handoff is
affordable: it applies to a small session rather than to the 256 KB pool sized
to absorb bursts, where flushing 200 times a second would hand over mostly empty
buffers and give back what
[#312](https://github.com/Karib0u/rustinel/pull/312) bought. The process session
keeps the 32 KB buffer and raises the buffer *count* instead, so it has burst
headroom without committing 32 MB to it.

The forced handoff controls quiet-host delivery latency without changing the
buffer pools, and runs on both sessions - each from its own option,
`windows.etw_flush_interval_ms` and `windows.etw_process_flush_interval_ms`.
Rustinel pauses requests while its sensor queue is at least half full, when
queueing controls latency instead.

The process session defaults to 5 ms rather than the main session's 20 ms,
because what sets it is how long a short-lived process lives, not a latency
preference. Over 2,000 `cmd /c echo` runs on the lab VM:

| Process-session handoff | Command lines captured |
| --- | --- |
| 20 ms (the main session's interval) | 61.5% |
| 10 ms | 99.9% |
| 5 ms | 99.85% |
| 1 ms | 99.8% |
| `0` (disabled - falls back to ETW's 1 s timer) | 16.6% |

Agent CPU was indistinguishable across the 1-20 ms range. Note that `0` is much
worse than a slow interval, not equivalent to one: it returns the session to
ETW's one-second timer. Treat it as giving up short-lived command lines
deliberately. The main session's `etw_flush_interval_ms` is a separate option
precisely so that setting *it* to `0` does not do this - measured that way,
command-line capture stayed at 100%. A process that exits before
the back-fill can still have no `CommandLine` even at 5 ms; the race is
structural, and only its width is under Rustinel's control. Rustinel narrows it
on the decode side too: the back-fill runs as soon as the PID is parsed, ahead
of PE version-resource parsing and every path conversion, so no avoidable work
sits between the event arriving and the live-process read.

The buffers are non-paged pool: 18 MB is committed for the life of the agent
across both sessions and grows to at most 48 MB under load. Read the live values
back with:

```powershell
Get-EtwTraceSession -Name rustinel-etw-trace
Get-EtwTraceSession -Name rustinel-etw-process
```

`logman query -ets` shows the same sessions but localizes its output, so prefer
the cmdlet in scripts.

This sizing absorbed a 4,000-process fork tree with no loss on a Windows 11 lab
VM, where the library defaults lost 12-60% of process starts across identical
runs ([#312](https://github.com/Karib0u/rustinel/pull/312)). Re-measured on the
same fork tree after the session split, with the pre-#312 configuration rebuilt
on current code for comparison:

| Configuration | Kernel loss | Command lines |
| --- | --- | --- |
| Pre-#312 (one 32 KB session, no handoff) | 51.4% | 1877 / 4000 |
| 1.4.0 (one 256 KB session, 20 ms) | 0% | 3878 / 4000 |
| Split sessions, 5 ms process handoff | 0% | 4000 / 4000 |

It is a fixed configuration, not an adaptive one: a host that churns processes
harder than that can still overrun either pool. Rustinel polls each session's
cumulative `EventsLost` counter once per second and emits a rate-limited warning
when it increases. Behavioral recordings also store the combined value as
`events.source_lost` and are marked incomplete when it is non-zero.

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
