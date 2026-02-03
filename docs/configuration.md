# Configuration

Rustinel loads configuration from four sources (in order of precedence):

1. CLI flags (highest, run mode only)
2. Environment variables
3. `config.toml` file
4. Built-in defaults (lowest)

## Configuration File

Create `config.toml` in the same directory as the executable:

```toml
[scanner]
sigma_enabled = true
sigma_rules_path = "rules/sigma"
yara_enabled = true
yara_rules_path = "rules/yara"

[logging]
level = "info"
directory = "logs"
filename = "rustinel.log"
console_output = true

[alerts]
directory = "logs"
filename = "alerts.json"

[network]
aggregation_enabled = true
aggregation_max_entries = 20000
aggregation_interval_buffer_size = 50
```

## Options

### Scanner

| Option | Default | Description |
|--------|---------|-------------|
| `sigma_enabled` | `true` | Enable Sigma rule engine |
| `sigma_rules_path` | `rules/sigma` | Path to Sigma rules directory |
| `yara_enabled` | `true` | Enable YARA scanner |
| `yara_rules_path` | `rules/yara` | Path to YARA rules directory |

### Logging

| Option | Default | Description |
|--------|---------|-------------|
| `level` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `directory` | `logs` | Log output directory |
| `filename` | `rustinel.log` | Log filename (daily rotation applied) |
| `console_output` | `true` | Mirror logs to stdout |

Rule logic evaluation errors from Sigma are only emitted at `warn`, `debug`, or `trace` levels.

### Alerts

| Option | Default | Description |
|--------|---------|-------------|
| `directory` | `logs` | Alert output directory |
| `filename` | `alerts.json` | Alert filename (NDJSON, daily rotation) |

### Network

| Option | Default | Description |
|--------|---------|-------------|
| `aggregation_enabled` | `true` | Enable connection aggregation to reduce event volume |
| `aggregation_max_entries` | `20000` | Maximum unique connections to track |
| `aggregation_interval_buffer_size` | `50` | Intervals to store for beacon detection |

Connection aggregation suppresses repeated connections from the same process to the same destination, emitting only the first connection. This significantly reduces event volume while preserving detection capability. Timing data is collected for future beacon detection analysis.

## Environment Variables

Override any setting using `EDR__` prefix with double underscore separators:

```bash
# Set log level to debug
set EDR__LOGGING__LEVEL=debug

# Custom rules path
set EDR__SCANNER__SIGMA_RULES_PATH=C:\custom\sigma

# Run
rustinel.exe
```

## CLI Overrides

Only the log level can be overridden via CLI:

```bash
rustinel run --log-level debug
```

CLI flags apply to `run` only. Service management commands do not pass flags to the service process.

## Examples

### Minimal Config (Sigma Only)

```toml
[scanner]
yara_enabled = false
```

### Debug Mode

```toml
[logging]
level = "debug"
console_output = true
```

### Custom Paths

```toml
[scanner]
sigma_rules_path = "C:\\SecurityRules\\sigma"
yara_rules_path = "C:\\SecurityRules\\yara"

[logging]
directory = "C:\\Logs\\Rustinel"

[alerts]
directory = "C:\\Logs\\Rustinel"
```
