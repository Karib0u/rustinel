# Local Demo Script

End-to-end helper for the bundled `whoami` Sigma demo: verify prerequisites,
fire the trigger, wait for an alert, and print the latest ECS NDJSON line from
today's alert file.

The scripts read `alerts.directory` and `alerts.filename` from `config.toml`
(defaults: `logs` and `alerts.json`), then watch
`{directory}/{filename}.{YYYY-MM-DD}`.

Rustinel must already be running in another terminal:

```bash
sudo ./rustinel run
```

## Linux & macOS

From the Rustinel install directory (where `config.toml` and `rules/` live):

```bash
./examples/demo/run-local-demo.sh
```

Options:

```text
--root PATH       Rustinel install directory (default: auto-detect)
--trigger-only    Skip agent and prerequisite checks
--timeout SECS    Seconds to wait for a new alert (default: 15)
--siem NAME       Print next-step commands for elastic or splunk
-h, --help        Show this help
```

## Windows

From an elevated PowerShell in the install directory:

```powershell
.\examples\demo\run-local-demo.ps1
```

Options:

```text
-Root PATH        Rustinel install directory (default: auto-detect)
-TriggerOnly      Skip agent and prerequisite checks
-TimeoutSeconds   Seconds to wait for a new alert (default: 15)
-Siem elastic|splunk   Print next-step commands for a SIEM demo
-Help             Show this help
```

## Expected success

On success the script exits `0` and prints the latest alert, for example:

```json
{
  "@timestamp": "...",
  "event": { "kind": "alert", ... },
  "rule": { "name": "Example - Whoami Execution (Linux)", ... }
}
```

## Validation

Run the lightweight checks for config parsing and argument handling:

```bash
./examples/demo/validate.sh
```

## SIEM next steps

After a local alert is confirmed:

```bash
./examples/demo/run-local-demo.sh --siem elastic
./examples/demo/run-local-demo.sh --siem splunk
```

See [SIEM Demos](../../docs/siem-demos.md) for full Elastic and Splunk lab setup.

## Troubleshooting

- **Agent not running** — start Rustinel first (`sudo ./rustinel run` on Linux/macOS).
- **Timeout** — confirm bundled rules are present under `rules/sigma/` and Sigma is enabled in `config.toml`.
- **Custom alert paths** — set `[alerts].directory` and `[alerts].filename` in `config.toml`; the demo scripts follow those values.
- **macOS** — support is experimental; see [Getting Started](../../docs/getting-started.md).
