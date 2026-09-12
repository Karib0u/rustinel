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

## Detection

- **Sigma** and **IP, domain, and path indicators** run on every event as it arrives.
- **YARA** and **hash indicators** run in the background when a process starts, on its executable.

See [Detection](detection.md) for how each engine picks what to alert on.

## Output

Alerts are appended to `alerts.json.<date>` as ECS NDJSON, one per line.
The operational log `rustinel.log.<date>` records what the agent itself is doing.
Both rotate daily.
If [active response](active-response.md) is on, alerts at or above its severity threshold also kill the process.

## Bounded queues

Every step hands events to the next through a queue of fixed size.
When a queue is full, new events are dropped instead of slowing the sensor.
A burst therefore causes a gap in detection, never a slowdown.
Rustinel counts every drop, see [Telemetry loss](telemetry-loss.md).

## Hot reload

Rustinel watches its rule folders and its config file.

- Sigma, YARA, and IOC files reload after a short delay when they change.
- In the config file, only the `[response]` section reloads.
  Other changes need a restart.
- A reload that fails keeps the previous rules active.
