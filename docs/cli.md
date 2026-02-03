# CLI Reference

## Usage

```
rustinel [COMMAND]
```

## Global Options

These flags apply to `run` only.

- `--log-level <LEVEL>` - Override logging level for this run (`trace`, `debug`, `info`, `warn`, `error`)

## Commands

### run

Run in console mode with visible output.

```bash
rustinel run [OPTIONS]
```

**Options:**
- `--console` - Force console output regardless of config

**Examples:**
```bash
# Basic run
rustinel run

# With forced console output
rustinel run --console

# Override log level
rustinel run --log-level debug
```

### service

Manage Windows service installation and lifecycle.

```bash
rustinel service <SUBCOMMAND>
```

**Subcommands:**

| Command | Description |
|---------|-------------|
| `install` | Register as Windows service (auto-start enabled) |
| `uninstall` | Remove service registration |
| `start` | Start the service |
| `stop` | Stop the service |

**Examples:**
```bash
# Full service lifecycle
rustinel service install
rustinel service start
rustinel service stop
rustinel service uninstall
```

## Default Behavior

Running `rustinel` without arguments is equivalent to `rustinel run`.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (check logs for details) |

## Requirements

- Must run as Administrator
- For service commands, requires elevated command prompt

## Environment Variables

Configuration can be overridden via environment:

```bash
# Set before running
set EDR__LOGGING__LEVEL=debug
set EDR__SCANNER__SIGMA_ENABLED=true
rustinel run
```

See [Configuration](configuration.md) for all available options.
