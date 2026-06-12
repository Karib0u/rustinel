# Getting Started

This guide gets Rustinel to first telemetry and first alert on supported
platforms.

## Fastest Path

Use the install scripts when you want a release binary, bundled demo rules, and
the default `logs/` layout without choosing an asset by hand.

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh | sh -s -- --run
```

If you prefer to inspect the script first:

```bash
curl -fsSLO https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.sh
less install.sh
sh install.sh --run
```

### Windows

Run from an elevated PowerShell:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/Karib0u/rustinel/main/scripts/install/install.ps1 -OutFile install-rustinel.ps1
powershell -ExecutionPolicy Bypass -File .\install-rustinel.ps1 -Run
```

After the agent starts, trigger the bundled rule:

=== "Linux"

    ```bash
    whoami
    cat logs/alerts.json.*
    ```

=== "Windows"

    ```powershell
    whoami /all
    Get-Content .\logs\alerts.json.*
    ```

Install script options:

```bash
scripts/install/install.sh --dir /opt/rustinel
```

```powershell
.\scripts\install\install.ps1 -InstallDir C:\Rustinel
```

macOS support is experimental. Use the macOS release archive when it is present
on the release page, or follow the source build path below.

The install scripts only install published release binaries. They do not install
Rust, Cargo, or build Rustinel from source. If no release asset exists for your
OS or architecture, the script exits before changing the install directory.

## Minimum Requirements

### Windows

- Windows 10/11 or Server 2016+
- Administrator privileges
- Rust 1.92+ and Visual Studio Build Tools if building from source

### Linux

- Linux kernel 5.8+ with BTF
- Root, or eBPF capabilities such as `CAP_BPF` or `CAP_SYS_ADMIN`
- `tracefs` available at `/sys/kernel/tracing` and `debugfs` available at `/sys/kernel/debug`
- Rust 1.92+ if building from source
- If `ebpf/rustinel-ebpf.o` is missing, nightly Rust, `rust-src`, and `bpf-linker` are also required for the first build

### macOS

- macOS 11+
- Root and Full Disk Access for the signed Endpoint Security client
- Access to the `/dev/bpf*` device nodes for network and DNS capture
- Rust 1.92+ and the Xcode Command Line Tools if building from source

macOS support remains experimental while release packaging and runtime behavior
are validated across supported versions.

## Quick Start

Download the package for your platform from [GitHub Releases](https://github.com/Karib0u/rustinel/releases). The release archives already include `config.toml`, the bundled demo rules, and an empty `logs/` directory.

### Windows

1. Download `rustinel-<version>-x86_64-pc-windows-msvc.zip`.
2. Extract it.
3. Open an elevated PowerShell in the extracted directory.
4. Run `.\rustinel.exe run`.

### Linux

Choose the archive that matches your target system:

- `rustinel-<version>-x86_64-unknown-linux-musl.tar.gz`
- `rustinel-<version>-aarch64-unknown-linux-musl.tar.gz`

Then extract and run it:

```bash
tar xzf rustinel-<version>-x86_64-unknown-linux-musl.tar.gz
cd rustinel-<version>-x86_64-unknown-linux-musl
sudo ./rustinel run
```

If startup fails with `tracefs not found`, mount the tracing filesystems and retry:

```bash
mount -t tracefs tracefs /sys/kernel/tracing
mount -t debugfs debugfs /sys/kernel/debug
```

Some minimal Linux environments, including some WSL 2 distros, may start without these filesystems mounted.

### macOS

Choose the archive that matches your Mac:

- `rustinel-<version>-aarch64-apple-darwin.tar.gz`
- `rustinel-<version>-x86_64-apple-darwin.tar.gz`

Then extract and run it as root:

```bash
tar xzf rustinel-<version>-aarch64-apple-darwin.tar.gz
cd rustinel-<version>-aarch64-apple-darwin
sudo ./rustinel run
```

If startup fails with `NotPrivileged`, the Endpoint Security client could not be
created. Confirm that the app is signed, its embedded provisioning profile
authorizes Endpoint Security, it has Full Disk Access, and it is running as
root. Network and DNS capture additionally needs access to the `/dev/bpf*`
device nodes; the agent continues with Endpoint Security only if capture cannot
start.

## Compile From Source

Use this path if you want to build the binary yourself instead of using a published release.

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

The profile must belong to the explicit App ID approved for the project and
authorize `com.apple.developer.endpoint-security.client`. The packaging script
derives the bundle identifier from that profile. Grant the resulting app bundle
Full Disk Access before starting it. See [Development](development.md) for
profile validation, ad-hoc lab builds, and release secrets.

Notes:

- Running `rustinel` with no subcommand is equivalent to `rustinel run`.
- On Linux, `build.rs` embeds `ebpf/rustinel-ebpf.o` when it already exists. If it does not exist, the build falls back to compiling the eBPF crate with nightly Rust.
- If startup fails with `tracefs not found`, mount the tracing filesystems and retry:

```bash
mount -t tracefs tracefs /sys/kernel/tracing
mount -t debugfs debugfs /sys/kernel/debug
```

Some minimal Linux environments, including some WSL 2 distros, may start without these filesystems mounted.

## Verify First Alert

### Windows Sigma Demo

1. Keep Rustinel running.
2. Execute:

```powershell
whoami /all
```

3. Confirm an alert was written to `logs\alerts.json.<date>`.

The bundled rule is `rules/sigma/windows_whoami.yml`.

### Linux Sigma Demo

1. Keep Rustinel running.
2. Execute:

```bash
whoami
```

3. Confirm an alert was written to `logs/alerts.json.<date>`.

The bundled rule is `rules/sigma/linux_whoami.yml`.

### macOS Sigma Demo

1. Keep Rustinel running.
2. Execute:

```bash
whoami
```

3. Confirm an alert was written to `logs/alerts.json.<date>`.

The bundled rule is `rules/sigma/macos_whoami.yml`.

### Cross-Platform YARA Demo

1. Keep Rustinel running.
2. Build the demo binary:

```bash
rustc ./examples/yara_demo.rs -o ./examples/yara_demo
```

On Windows:

```powershell
rustc .\examples\yara_demo.rs -o .\examples\yara_demo.exe
```

3. Run the demo binary.
4. Confirm an alert references `ExampleMarkerString` in `logs/alerts.json.<date>`.

## Verify Hot Reload

1. Keep Rustinel running.
2. Edit a Sigma, YARA, or IOC file.
3. Wait a few seconds.
4. Confirm the operational log reports a reload event.

Example on Windows:

```powershell
Add-Content rules\sigma\windows_whoami.yml "`n# hot reload smoke test"
```

Example on Linux:

```bash
printf '\n# hot reload smoke test\n' >> rules/sigma/linux_whoami.yml
```

## Next Steps

- Use [Configuration](configuration.md) to move rule paths, logs, and allowlists out of the default repo layout.
- Use [SIEM Demos](siem-demos.md) to ship first alerts to Elastic or Splunk.
- Use [Operations and Upgrade Guide](operations.md) for installation layout and update workflows.
- Use [CLI Reference](cli.md) for service commands and runtime examples.
