# CLI Reference

## Usage

```text
rustinel [COMMAND] [OPTIONS]
```

Running `rustinel` without a subcommand is equivalent to `rustinel run`.

## Global Option

| Option | Description |
| --- | --- |
| `--config <PATH>` | Load configuration from an explicit file path. This has the highest configuration file precedence. |
| `--log-level <LEVEL>` | Interactive log-level override. For production and cross-platform automation, prefer `config.toml` or `EDR__LOGGING__LEVEL`. |

## Commands

### `run`

Run Rustinel in the foreground.

```text
rustinel run [--config <PATH>] [--no-console] [--console] [--log-level <LEVEL>] [--sigma-engine <ENGINE>]
```

Examples:

```powershell
rustinel run
rustinel run --config C:\ProgramData\Rustinel\config.toml
rustinel run --no-console
rustinel run --log-level debug
```

```bash
sudo ./rustinel run
sudo ./rustinel run --config /etc/rustinel/config.toml
```

Notes:

- `rustinel run` enables console output by default on every platform.
- `--config <PATH>` selects the config file and overrides `RUSTINEL_CONFIG`, managed platform paths, executable-directory config, and current-directory config.
- `--no-console` suppresses console output, for example when redirecting logs.
- `--console` is kept as a compatibility alias and has the same effect as the default.
- `--sigma-engine <builtin|rsigma>` selects the Sigma matching backend, overriding `scanner.sigma_engine`. `rsigma` requires a build with the `rsigma-engine` feature (included in the official release binaries). See [Detection](detection.md#detection-engine).
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
$env:RUSTINEL_CONFIG="C:\ProgramData\Rustinel\config.toml"
rustinel run
```

### Bash

```bash
export EDR__LOGGING__LEVEL=debug
export EDR__SCANNER__SIGMA_ENABLED=true
export RUSTINEL_CONFIG=/etc/rustinel/config.toml
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
