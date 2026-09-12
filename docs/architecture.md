# Internals

A map of the code for contributors.
For the user-level picture, see [How it works](how-it-works.md).

## Layout

```text
src/
├── main.rs          CLI entry point
├── cli/             clap definitions and the generated CLI reference
├── config.rs        loading, discovery, defaults; config/reference.rs documents every option
├── runtime/         startup, shared pipeline construction, shutdown ordering
├── sensor/
│   ├── windows/     ETW sessions and Event Log subscriptions
│   ├── linux/       eBPF loader, ring readers, decoders
│   └── macos/       Endpoint Security and /dev/bpf capture
├── models/          NormalizedEvent, alert, and ECS models
├── normalizer/      builds NormalizedEvent, enrichment from caches
├── state/           process, SID, and DNS caches
├── engine/          Sigma loading, logsource routing, evaluation (RSigma)
├── scanner/         YARA compilation and scanning
├── memory/          per-platform process memory reads for YARA
├── ioc/             indicator loading and matching
├── alerts/          ECS NDJSON sink and deduplication
├── response/        active response
├── reload/          file watching, debounce, atomic detector swap
├── telemetry/       loss counters and telemetry.json
├── doctor/          `rustinel doctor` checks
├── capture/, replay/  recordings
├── rules.rs, rules/ rule pack catalog and installation
├── setup.rs, service.rs, platform/  managed install and native services
├── update.rs        `rustinel update`
├── utils/           path allowlists, file identity, PE parsing, helpers
└── field_availability.rs  per-platform field contract, source of generated docs
ebpf/src/            Linux eBPF programs and the event ABI
```

## Event path

1. A platform sensor emits a `SensorEvent` into the bounded `sensor_events` channel.
2. `SensorEventRouter` hands each event to `SigmaDetectionHandler` and `YaraEventHandler`.
3. `SigmaDetectionHandler` normalizes the event, evaluates Sigma and inline IOC checks, and queues hash jobs for process starts.
4. `YaraEventHandler` queues process-start executables for the YARA worker.
5. Hits go to `AlertSink` (ECS NDJSON) and, when enabled, `ResponseEngine`.

Every hop is a bounded channel that drops instead of blocking, with counters in `src/telemetry`.
Blocking an ETW callback or an eBPF ring reader would lose events in the kernel instead.

`runtime/pipeline.rs` builds this pipeline for all three platforms.
Platform runtimes keep privilege checks, sensor startup, and platform enrichment.
`runtime/shutdown.rs` drains sensors, then workers, then flushes deduplication and the final telemetry snapshot.

## Detectors and reload

Live detectors sit behind `engine::DetectorStore` (`src/engine/detectors.rs`).
`reload/watcher.rs` watches files, falling back to polling; `reload/worker.rs` debounces, rebuilds only the changed detector, validates it, and swaps it atomically.
Readers keep the previous instance until they finish.

## Path allowlists

`src/utils/path_allowlist.rs` applies three matching policies, kept for compatibility with existing configs and covered by `tests/path_allowlist.rs`:

| Caller | Windows | Linux and macOS | Prefix match | Empty entry |
| --- | --- | --- | --- | --- |
| YARA | case-insensitive, `/` becomes `\` | case-sensitive | at a separator | ignored |
| IOC hashing | case-insensitive, `/` becomes `\` | case-sensitive | raw prefix | matches every path |
| Active response | case-insensitive, `/` becomes `\` | case-insensitive | at a separator | ignored |

## Windows sensor

- Two real-time ETW sessions: `rustinel-etw-process` for Kernel-Process, sized and flushed for latency so command lines can be read before short processes exit, and `rustinel-etw-trace` for the high-volume providers, sized for bursts.
  Inspect them with `Get-EtwTraceSession -Name rustinel-etw-trace` (or `rustinel-etw-process`).
- A classic kernel logger supplies creation-time command lines and SIDs, joined to Kernel-Process events by PID, parent PID, and time.
- At startup, key and file name snapshots let registry and file writes through pre-existing handles be named.
- Event Log subscriptions read System event 7045 and six Security events, filtered by an XPath query.
  Read positions are saved under `logging.directory/event-log`.

## Linux sensor

eBPF programs attach to tracepoints for exec, exit, fork, file syscalls, and DNS sends, and to socket `fexit` hooks when kernel BTF allows it.
Hook availability and struct offsets are discovered at startup from tracefs and BTF; nothing depends on the build machine's kernel.
A missing hook degrades only its feature.
The loader refuses an object whose event ABI does not match.

## macOS sensor

`EsfSensor` subscribes to Endpoint Security exec, exit, and file events.
`BpfSensor` opens one `/dev/bpf` device per active interface and attributes flows to processes through a periodically refreshed socket list.
Endpoint Security is required; packet capture is best effort.
