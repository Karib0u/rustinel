# Getting Started

This guide gets Rustinel installed, running, and producing its first alert.

## Install From A Release

Use the install scripts when you want a published binary, bundled demo rules,
`config.toml`, and the default `logs/` layout.

### Windows

Run from an elevated PowerShell:

```powershell
Invoke-WebRequest https://rustinel.io/install.ps1 -OutFile install-rustinel.ps1
powershell -ExecutionPolicy Bypass -File .\install-rustinel.ps1 -Run
```

Official Windows binaries use the MSVC runtime. Install the current x64
[Microsoft Visual C++ Redistributable](https://aka.ms/vc14/vc_redist.x64.exe)
if Rustinel exits before printing output. Exit code `-1073741515`
(`0xC0000135`) normally means a required runtime DLL is missing:

```powershell
Invoke-WebRequest https://aka.ms/vc14/vc_redist.x64.exe -OutFile "$env:TEMP\vc_redist.x64.exe"
Start-Process "$env:TEMP\vc_redist.x64.exe" -ArgumentList "/install", "/quiet", "/norestart" -Wait -Verb RunAs
```

### Linux

```bash
curl -fsSL https://rustinel.io/install.sh | sh -s -- --run
```

To inspect the script first:

```bash
curl -fsSLO https://rustinel.io/install.sh
less install.sh
sh install.sh --run
```

### macOS

macOS support is experimental. Install without `--run` so you can grant the
required Full Disk Access approval before the first real start:

```bash
curl -fsSL https://rustinel.io/install.sh | sh
cd rustinel
```

If the first run exits with `NotPermitted`, grant Full Disk Access and run it
again. For an interactive `sudo` run from Terminal, iTerm, Ghostty, or another
terminal, grant Full Disk Access to that terminal app, then fully quit and
reopen it. For a background LaunchDaemon, grant Full Disk Access to
`Rustinel.app` directly or deploy a PPPC profile.

Install macOS packages in a stable location. macOS does not retain the approval
reliably for an app launched from a temporary path such as `/tmp`.

After approval, start Rustinel:

```bash
sudo ./rustinel run
```

## Verify The Demo Rule

Keep Rustinel running, then execute:

```bash
whoami
```

Confirm that an alert was written:

=== "Windows"

    ```powershell
    Get-Content .\logs\alerts.json.*
    ```

=== "Linux"

    ```bash
    cat logs/alerts.json.*
    ```

=== "macOS"

    ```bash
    cat logs/alerts.json.*
    ```

Bundled demo rules:

| Platform | Rule |
| --- | --- |
| Windows | `rules/sigma/windows_whoami.yml` |
| Linux | `rules/sigma/linux_whoami.yml` |
| macOS | `rules/sigma/macos_whoami.yml` |

Installed release packs become active under `rules/current`.

## Other Install Methods

The scripts only download published release binaries. For version selection,
custom installation directories, manual archives, and upgrade procedures, see
[Operations and Upgrade Guide](operations.md).

To run the Linux sensor as a container instead, see [Docker](docker.md).

## Keep Rustinel Running

After the portable test succeeds, install the managed layout and native service:

=== "Windows"

    ```powershell
    rustinel setup --yes
    rustinel service status
    rustinel doctor
    ```

=== "Linux"

    ```bash
    sudo rustinel setup --yes
    rustinel service status
    rustinel doctor
    ```

=== "macOS"

    Grant Full Disk Access to `Rustinel.app` before starting the LaunchDaemon.

    ```bash
    sudo ./rustinel setup --yes
    ./rustinel service status
    ./rustinel doctor
    ```

`setup` installs an Essential rules pack by default, registers the platform's
native service, starts it, and runs health checks. Use `--pack advanced` to
select the larger pack or `--no-start` to register without starting.

## Minimum Requirements

| Platform | Requirements |
| --- | --- |
| Windows | Windows 10/11 or Server 2016+, x64 Visual C++ Redistributable, Administrator privileges for telemetry and service management |
| Linux | Kernel 5.8+ with BTF, root or eBPF capabilities such as `CAP_BPF`, `CAP_PERFMON`, and `CAP_NET_ADMIN`, or `CAP_SYS_ADMIN`, `tracefs`, and `debugfs` |
| macOS | macOS 11+, root, signed Endpoint Security client, Full Disk Access, and `/dev/bpf*` access for network and DNS capture |

Source builds require Rust 1.92 and platform build tools. See
[Development](development.md) for build, signing, eBPF, and test instructions.

## Next Steps

- [Configuration](configuration.md): move rule paths, logs, and allowlists out of the default layout.
- [Docker](docker.md): run the Linux sensor from the Alpine container image.
- [SIEM Demos](siem-demos.md): ship first alerts to Elastic or Splunk.
- [Operations and Upgrade Guide](operations.md): install layouts, services, and upgrades.
- [CLI Reference](cli.md): service commands and runtime examples.
- [Development](development.md): build and test from source.
- [Limitations](limitations.md): current platform and detection gaps.
