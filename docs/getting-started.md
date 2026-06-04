# Getting Started

This guide gets Rustinel to first telemetry and first alert on both supported platforms.

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
- Root, plus the `com.apple.developer.endpoint-security.client` entitlement on signed and notarized builds, or SIP/AMFI relaxed for local testing
- Access to the `/dev/bpf*` device nodes for network and DNS capture
- Rust 1.92+ and the Xcode Command Line Tools if building from source

macOS support is experimental while the project waits for the required Endpoint Security Framework entitlement.

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
created. Run as root with a signed, entitled build, or relax SIP/AMFI on a test
machine. Network and DNS capture additionally needs access to the `/dev/bpf*`
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
codesign --force --sign - \
  --entitlements packaging/macos/rustinel.entitlements \
  target/release/rustinel
sudo ./target/release/rustinel run
```

Ad-hoc signing with the entitlement only takes effect when SIP/AMFI is relaxed.
See the [Development](development.md) guide for signing and notarization details.

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
- Use [Operations and Upgrade Guide](operations.md) for installation layout and update workflows.
- Use [CLI Reference](cli.md) for service commands and runtime examples.
