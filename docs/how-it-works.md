# How it works

```text
 OS telemetry          normalize            detect                  output
┌──────────────┐    ┌─────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ ETW / eBPF / │───▶│ one event   │───▶│ Sigma, IOC       │───▶│ alerts.json      │
│ ESF + bpf    │    │ model       │    │ YARA, hash (bg)  │    │ active response  │
└──────────────┘    └─────────────┘    └──────────────────┘    └──────────────────┘
```

## Sensors

Rustinel uses the telemetry each OS already provides.
It ships no kernel driver.

| Platform | Source | Collects |
| --- | --- | --- |
| Windows | ETW and the System and Security event logs | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task, Security audit events |
| Linux | eBPF programs | Process, network, file, DNS |
| macOS | Endpoint Security, and packet capture on `/dev/bpf` | Process and file; network and DNS |

Details per platform are in [Platform coverage](coverage.md).

## One event model

Every event is converted to one model with Sysmon-style field names, such as `Image`, `CommandLine`, and `TargetFilename`.
A Sigma rule uses the same names on every platform, as long as the platform collects that field.
Processes already running at startup are inventoried, so their events carry an executable path too.

## Detection

- **Sigma** and **IP, domain, and path indicators** run on every event as it arrives.
- **YARA** and **hash indicators** run in the background on new executables and written files, so they never slow Sigma down.

See [Detection](detection.md) for how each engine decides what to alert on.

## Output

Alerts are appended to `alerts.json.<date>` as ECS NDJSON, one per line, and optionally sent to [webhooks](output.md#webhooks).
The operational log `rustinel.log.<date>` records what the agent itself is doing.
Both rotate daily.
If [active response](active-response.md) is on, alerts at or above its severity threshold also kill the process.

## Under load

Queues between stages are bounded.
When events arrive faster than they can be processed, Rustinel drops and counts them rather than slow the host, see [Telemetry loss](telemetry-loss.md).

## Hot reload

Rule and indicator files reload without a restart, and so does the `[response]` section of the config.
A reload that fails keeps the previous rules.
See [What reloads](configuration.md#what-reloads).
