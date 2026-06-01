# CLI Reference

## Usage

```text
rustinel [COMMAND] [OPTIONS]
```

Running `rustinel` without a subcommand is equivalent to `rustinel run`.

## Global Option

| Option | Description |
| --- | --- |
| `--log-level <LEVEL>` | Interactive log-level override. For production and cross-platform automation, prefer `config.toml` or `EDR__LOGGING__LEVEL`. |

## Commands

### `run`

Run Rustinel in the foreground.

```text
rustinel run [--no-console] [--console] [--log-level <LEVEL>]
```

Examples:

```powershell
rustinel run
rustinel run --no-console
rustinel run --log-level debug
```

```bash
sudo ./rustinel run
```

Notes:

- `rustinel run` enables console output by default on every platform.
- `--no-console` suppresses console output, for example when redirecting logs.
- `--console` is kept as a compatibility alias and has the same effect as the default.
- Linux foreground execution is the normal runtime model unless you wrap the binary in a service manager.

### `service`

Manage Windows service installation and lifecycle.

```text
rustinel service <install|uninstall|start|stop>
```

Examples:

```powershell
rustinel service install
rustinel service start
rustinel service stop
rustinel service uninstall
```

Platform note:

- Service commands are supported on Windows only.
- On Linux, use `systemd` or another process supervisor if you need background execution.

## Environment Variables

Common examples:

### PowerShell

```powershell
$env:EDR__LOGGING__LEVEL="debug"
$env:EDR__SCANNER__SIGMA_ENABLED="true"
rustinel run
```

### Bash

```bash
export EDR__LOGGING__LEVEL=debug
export EDR__SCANNER__SIGMA_ENABLED=true
sudo ./rustinel run
```

## Linux eBPF Override

For Linux development, `RUSTINEL_EBPF_OBJECT` points the loader at a specific `.o` file instead of the embedded object:

```bash
sudo env RUSTINEL_EBPF_OBJECT=/opt/rustinel/ebpf/rustinel-ebpf.o ./rustinel run
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Error |

Check the operational log if startup or runtime initialization fails.
