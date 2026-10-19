# Agent health

How a SIEM knows the agent is alive, why it stopped, and when it died without saying so.

## Heartbeat

A stopped agent writes nothing, so a SIEM can only notice absence, and absence needs something regular to be absent.
Rustinel writes one NDJSON line to `heartbeat.json.<date>` in the log directory every `telemetry.snapshot_interval_secs` (30 by default), starting as soon as the agent runs.
The file rotates daily like the alert file, and it is separate so tools that count lines in `alerts.json` stay correct.
It has its own writer, so it never waits behind alert output or the sensor queue.
It is not part of the alert file, so add `heartbeat.json.*` to your log shipper's paths, next to `alerts.json.*`.
`rustinel doctor` warns when the service is running and the file is not being updated.

Each line is a few hundred bytes: `@timestamp`, `event.dataset` (`edr.agent.heartbeat`), the [host and agent identity](output.md#host-and-agent-identity) (`host.name`, `agent.version`, and the rest), `uptime_secs`, and `dropped_total`, the items shed by every bounded queue since the agent started.
The full counters stay in [`telemetry.json`](telemetry.md).
Set `heartbeat.webhooks = true` to send each line to the alert webhooks as well; it is off by default.

To find a host that went quiet, alert when a `host.name` has no heartbeat for three intervals (90 seconds by default).
In Elastic, with the file shipped to an index of your choosing:

```
FROM heartbeat-* | STATS last = MAX(@timestamp) BY host.name | WHERE last < NOW() - 90 seconds
```

## Lifecycle alerts

Both are `Agent` alerts with `event.dataset` `edr.agent`, written directly to the sink like the loss alerts.
They bypass [deduplication](detection.md#deduplication), active response never sees them, and `rustinel replay` never emits them.

| `rule.name` | When | `edr.rule.severity` |
| --- | --- | --- |
| `agent::lifecycle::stopping` | Shutdown has drained the sensors and the alert sink is about to close | `Low`, `High` for `sensor_failure` |
| `agent::lifecycle::unclean_shutdown` | At startup, the previous run never reached the end of its shutdown | `High` |

`stopping` carries `edr.agent.lifecycle.reason`:

| Reason | Meaning |
| --- | --- |
| `signal` | SIGINT, SIGTERM, SIGHUP, or Ctrl+C. A service stop on Linux and macOS arrives as SIGTERM, so `rustinel service restart` and the stop before an update also report `signal` |
| `service_stop` | The Windows service manager stopped the service |
| `sensor_failure` | A sensor failed to start or ended on its own, or a critical worker exited. The agent exits with status 1 so the service manager restarts it |

The agent keeps a `run-state` file in `agent.directory`.
It says `running` and the agent's pid from startup, and `stopped` once shutdown has finished.
If startup finds `running` and that pid is gone, the last run was killed or crashed, and `unclean_shutdown` is written with `edr.agent.lifecycle.last_snapshot_at`, the time of that run's last `telemetry.json` snapshot, when one exists.
A graceful stop, `rustinel service restart`, and a restart after `rustinel update` leave `stopped` and do not alert.
A `sensor_failure` exit writes `stopping` and marks the run `stopped`, so the supervised restart does not raise a second alert for the same incident.
A first run, with no file, writes nothing.
A second agent started while the first is alive, such as a console run next to the service, leaves the file alone and reports nothing.
A host reboot that ends the agent without a graceful stop still raises `unclean_shutdown` at the next start.
