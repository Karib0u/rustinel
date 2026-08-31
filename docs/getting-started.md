# Getting Started

Install Rustinel, run it, and see your first alert.

## Install

=== "Windows"

    From an elevated PowerShell:

    ```powershell
    Invoke-WebRequest https://rustinel.io/install.ps1 -OutFile install-rustinel.ps1
    powershell -ExecutionPolicy Bypass -File .\install-rustinel.ps1 -Run
    ```

    Official binaries use the MSVC runtime. If Rustinel exits immediately with
    no output and `$LASTEXITCODE` is `-1073741515`, install the x64
    [Visual C++ Redistributable](https://aka.ms/vc14/vc_redist.x64.exe). See
    [Troubleshooting](troubleshooting.md#windows-exits-without-printing-output).

=== "Linux"

    ```bash
    curl -fsSL https://rustinel.io/install.sh | sh -s -- --run
    ```

    To inspect the script first:

    ```bash
    curl -fsSLO https://rustinel.io/install.sh
    less install.sh
    sh install.sh --run
    ```

=== "macOS"

    macOS support is experimental. Install **without** `--run` so you can grant
    Full Disk Access before the first real start:

    ```bash
    curl -fsSL https://rustinel.io/install.sh | sh
    cd rustinel
    sudo ./rustinel run
    ```

    If the first run exits with `NotPermitted`, macOS has not yet granted
    Endpoint Security access. For an interactive `sudo` run, grant Full Disk
    Access to **your terminal app** (Terminal, iTerm, Ghostty…), then fully quit
    and reopen it. macOS attributes the permission to the terminal, so Rustinel
    itself never appears in the list. For a background LaunchDaemon, grant
    `Rustinel.app` directly or deploy a PPPC profile.

    Install into a stable location: macOS does not reliably retain approval for
    an app launched from a temporary path such as `/tmp`.

The install scripts only download published release binaries. For version
selection, custom directories, and manual archives, see
[Operations](operations.md#installers-and-archives).

## Verify

With Rustinel running, in another window:

```bash
whoami
```

Then confirm an alert was written:

=== "Linux and macOS"

    ```bash
    cat logs/alerts.json.*
    ```

=== "Windows"

    ```powershell
    Get-Content .\logs\alerts.json.*
    ```

That fires a bundled demo rule: `rules/sigma/{windows,linux,macos}_whoami.yml`.
Installed release packs become active under `rules/current` instead.

If nothing appears, run `rustinel doctor` and follow
[Troubleshooting](troubleshooting.md#agent-runs-but-no-alerts).

## Keep It Running

Once the portable test works, install the managed layout and native service:

=== "Linux"

    ```bash
    sudo rustinel setup --yes
    rustinel service status
    rustinel doctor
    ```

=== "Windows"

    ```powershell
    rustinel setup --yes
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

`setup` installs an Essential rules pack, registers the platform's native
service, starts it, and runs health checks. Use `--pack advanced` for the larger
pack or `--no-start` to register without starting. See
[Operations](operations.md) for the managed layout and upgrades.

## Minimum Requirements

| Platform | Requirements |
| --- | --- |
| Windows | Windows 10/11 or Server 2016+, x64 Visual C++ Redistributable, Administrator |
| Linux | Kernel 5.8+ with BTF; root, or `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN` (or `CAP_SYS_ADMIN`); `tracefs` and `debugfs` mounted |
| macOS | macOS 11+, root, signed Endpoint Security client, Full Disk Access, and `/dev/bpf*` access for network and DNS |

Source builds need Rust 1.92 and platform build tools. See
[Development](development.md).

## Install With Nix

Rustinel ships a flake that packages the **prebuilt musl binary** from GitHub
releases (not a source build), for `x86_64-linux` and `aarch64-linux`:

```bash
nix run github:Karib0u/rustinel -- --version
nix build github:Karib0u/rustinel#rustinel
```

An overlay (`rustinel.overlays.default`) exposes `pkgs.rustinel` for NixOS or
Home Manager. Three things to know:

- A checkout or `nix build` gives you the **last published release**, not your
  working tree.
- There is **no NixOS module**. Wire up the systemd unit yourself, or use
  `nix shell .#rustinel` with `rustinel setup` / `rustinel service`.
- Rules ship read-only in the Nix store. To use `rustinel rules install`, point
  the config at a writable location: write `/etc/rustinel/config.toml` (the
  wrapper defers to it when present) or set `RUSTINEL_CONFIG`.

## Next Steps

- [Configuration](configuration.md): move rules, logs, and allowlists out of the default layout
- [SIEM Demos](siem-demos.md): ship alerts to Elastic or Splunk
- [Detection](detection.md): write and debug rules
- [CLI Reference](cli.md): every command and flag
- [Limitations](limitations.md): what will not fire, and why
