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
├── Rustinel.app/
├── rustinel -> Rustinel.app/Contents/MacOS/rustinel
├── config.toml
├── rules/
│   ├── sigma/
│   ├── yara/
│   └── ioc/
└── logs/
```

### macOS

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

macOS support is experimental. Release archives contain a signed and notarized
app-like daemon bundle with the Endpoint Security provisioning profile. See
[Getting Started](getting-started.md) and [Development](development.md).

Use absolute paths in `config.toml` once you move beyond the default repo layout.

## Working Directory Rules

- `config.toml` is loaded from the current working directory, falling back to the
  directory containing the executable (the working-directory copy wins on conflicts).
- Relative rule and log paths resolve from the current working directory.
- Windows services often start in `C:\Windows\System32`; keep `config.toml` next to
  `rustinel.exe` (it will still be found) and use absolute paths for rules and logs.
- Linux supervisors should also use absolute paths for predictable upgrades and restarts.

## Windows Service Lifecycle

Rustinel includes built-in Windows service management commands:

```powershell
.\rustinel.exe service install
.\rustinel.exe service start
.\rustinel.exe service stop
.\rustinel.exe service uninstall
```

Important behavior:

- `service install` registers the current executable path with the Service Control Manager.
- Replacing the binary in the same directory is fine.
- Moving the binary to a new directory requires `service uninstall` followed by `service install`.
- Service mode does not consume interactive CLI flags; configure it with `config.toml` and `EDR__...` environment variables.

## Linux Runtime Model

Rustinel does not currently ship Linux service-management commands. Common deployment patterns are:

- Run it directly in a root shell for testing
- Wrap it in `systemd`
- Run it under another process supervisor

The binary itself is the same foreground application in all cases:

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
ExecStart=/opt/rustinel/rustinel run
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

Because `config.toml` is loaded from `WorkingDirectory`, use absolute paths for all rules and log directories in that file when running under `systemd`.

## macOS Runtime Model

macOS support is experimental and detection-only (no active response). Rustinel does not ship macOS service-management commands; run it in the foreground as root, or wrap it in a `launchd` job for background execution:

```bash
sudo /opt/rustinel/Rustinel.app/Contents/MacOS/rustinel run
```

The app bundle must be signed with the
`com.apple.developer.endpoint-security.client` entitlement, contain the
authorizing provisioning profile, and have Full Disk Access. See
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

## Safe Upgrade Checklist

1. Back up `config.toml` and your custom `rules/`.
2. Keep log and alert directories outside ephemeral build directories.
3. Replace the binary.
4. Restart the process or service.
5. Confirm new startup logs in `rustinel.log.<date>`.
6. Trigger a known benign rule such as the bundled `whoami` Sigma rule.
