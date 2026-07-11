# Getting Started

This guide gets Rustinel installed, running, and producing its first alert.

## Install From A Release

Use the install scripts when you want a published binary, bundled demo rules,
`config.toml`, and the default `logs/` layout.

### Windows

Run from an elevated PowerShell:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.ps1 -OutFile install-rustinel.ps1
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
curl -fsSL https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh | sh -s -- --run
```

To inspect the script first:

```bash
curl -fsSLO https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh
less install.sh
sh install.sh --run
```

### macOS

macOS support is experimental. Install without `--run` so you can grant the
required Full Disk Access approval before the first real start:

```bash
curl -fsSL https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh | sh
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

## Install Options

Install to a specific directory:

```bash
scripts/install/install.sh --dir /opt/rustinel
```

```powershell
.\scripts\install\install.ps1 -InstallDir C:\Rustinel
```

Install a specific version:

```bash
scripts/install/install.sh --version 1.0.2
```

```powershell
.\scripts\install\install.ps1 -Version 1.0.2
```

The install scripts only download published release binaries. They do not
install Rust, Cargo, or build from source. If no release asset exists for your
OS or architecture, the script exits before changing the install directory.

## Manual Package Install

Download the package for your platform from
[GitHub Releases](https://github.com/Karib0u/rustinel/releases).

| Platform | Package |
| --- | --- |
| Windows x86_64 | `rustinel-<version>-x86_64-pc-windows-msvc.zip` |
| Linux x86_64 | `rustinel-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `rustinel-<version>-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple Silicon | `rustinel-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `rustinel-<version>-x86_64-apple-darwin.tar.gz` |

Release packages already include `config.toml`, bundled demo rules, install
scripts, examples, and an empty `logs/` directory.

### Windows

1. Extract the zip archive.
2. Open an elevated PowerShell in the extracted directory.
3. Run:

```powershell
.\rustinel.exe run
```

### Linux

```bash
tar xzf rustinel-<version>-x86_64-unknown-linux-musl.tar.gz
cd rustinel-<version>-x86_64-unknown-linux-musl
sudo ./rustinel run
```

If startup fails with `tracefs not found`, see
[Troubleshooting](troubleshooting.md#linux-ebpf-sensor-failed-to-start).

### macOS

```bash
tar xzf rustinel-<version>-aarch64-apple-darwin.tar.gz
cd rustinel-<version>-aarch64-apple-darwin
sudo ./rustinel run
```

If startup exits with `NotPermitted`, grant Full Disk Access as described in the
macOS install notes above. If it exits with `NotPrivileged`, re-run with `sudo`.
See [Troubleshooting](troubleshooting.md#macos-endpoint-security-client-init-failed)
for the macOS result-code table.

Network and DNS capture also needs access to `/dev/bpf*`. If packet capture
cannot start, Rustinel continues with Endpoint Security process and file telemetry.

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

Building from source also requires Rust 1.92+. Windows needs Visual Studio Build
Tools, Linux eBPF rebuilds need nightly Rust plus `rust-src` and `bpf-linker`,
and macOS needs the Xcode Command Line Tools.

## Build From Source

Use this path if you want to build the binary yourself instead of using a
published release.

### Windows

```powershell
git clone https://github.com/Karib0u/rustinel.git
cd rustinel
cargo build --release
.\target\release\rustinel.exe run
```

### Linux

```bash
git clone https://github.com/Karib0u/rustinel.git
cd rustinel
cargo build --release
sudo ./target/release/rustinel run
```

On Linux, `build.rs` embeds `ebpf/rustinel-ebpf.o` when it already exists. If it
does not exist, the build falls back to compiling the eBPF crate with nightly
Rust.

### macOS

```bash
git clone https://github.com/Karib0u/rustinel.git
cd rustinel
cargo build --release

scripts/macos/package-app.sh \
  --binary target/release/rustinel \
  --output target/release/Rustinel.app \
  --profile "$HOME/Downloads/rustinel.provisionprofile" \
  --identity "Developer ID Application: Example (TEAMID)"

sudo ./target/release/Rustinel.app/Contents/MacOS/rustinel run
```

The profile must belong to the explicit App ID approved for Endpoint Security
and authorize `com.apple.developer.endpoint-security.client`. The packaging
script derives the bundle identifier from that profile. Grant the resulting app
bundle Full Disk Access before starting it. See [Development](development.md)
for maintainer release-signing details and ad-hoc lab builds.

## Optional Checks

### YARA Demo

Keep Rustinel running, build the demo binary, and run it:

```bash
rustc ./examples/yara_demo.rs -o ./examples/yara_demo
./examples/yara_demo
```

On Windows:

```powershell
rustc .\examples\yara_demo.rs -o .\examples\yara_demo.exe
.\examples\yara_demo.exe
```

Confirm that an alert references `ExampleMarkerString` in
`logs/alerts.json.<date>`.

### Hot Reload

Keep Rustinel running, edit a Sigma, YARA, or IOC file, and wait a few seconds.
The operational log should report a reload event.

Windows example:

```powershell
$rule = Get-ChildItem rules\current\sigma -Filter *.yml | Select-Object -First 1
Add-Content $rule.FullName "`n# hot reload smoke test"
```

Linux example:

```bash
rule=$(find rules/current/sigma -name '*.yml' -print -quit)
printf '\n# hot reload smoke test\n' >> "$rule"
```

## Next Steps

- [Configuration](configuration.md): move rule paths, logs, and allowlists out of the default layout.
- [SIEM Demos](siem-demos.md): ship first alerts to Elastic or Splunk.
- [Operations and Upgrade Guide](operations.md): install layouts, services, and upgrades.
- [CLI Reference](cli.md): service commands and runtime examples.
- [Limitations](limitations.md): current platform and detection gaps.
