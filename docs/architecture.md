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
├── models/          CanonicalEvent, the generated NormalizedEvent view, alert, and ECS models
├── normalizer/      builds the stable NormalizedEvent compatibility view
├── state/           HostState, bounded attribution indexes and inventory
├── artifact.rs      single-open executable resolution and bounded result stores
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

1. A platform sensor emits a `RawEvent` into the bounded `sensor_events` channel.
   Process records retain native numeric identities and source-specific facts; the other categories are migrated independently.
2. `HostState` performs host-dependent enrichment after that channel and creates a provenance-carrying `CanonicalEvent`.
3. Artifact-bearing events are queued for the bounded `artifact_resolution` resolver.
   It opens the image once, validates its `FileIdentity`, reads it once, and fans those bytes out to PE metadata, IOC hashing, and YARA.
4. Admission routes every event to the downstream `SensorEventRouter` exactly once and in `ingest_seq` order, for Sigma/IOC detection or capture.
   Only PE metadata, which Sigma can match, may hold an event, for at most a 100 ms admission budget; later events wait behind it.
   YARA file and IOC hash alerts come from the same resolver result after admission; YARA memory scanning remains a separate worker.
5. Hits go to `AlertSink` (ECS NDJSON) and, when enabled, `ResponseEngine`.

Capture also receives `CanonicalEvent`.
Recording schema v2 deliberately serializes its unchanged `NormalizedEvent` view, and replay wraps that same view back in a canonical event, so existing recordings remain compatible.

Sensor and background-worker queues are bounded channels that drop instead of blocking, with counters in `src/telemetry`.
Canonicalization runs synchronously in the sensor-channel worker, but file opening, reading, PE parsing, hashing, and YARA file scanning do not.
A slow artifact delays routing by at most the admission budget, never more, because order is kept and the budget is measured from each event's own arrival.
If the artifact queue is full, a job exceeds its deadline, or PE metadata misses the budget, the event is admitted without that enrichment and the outcome is counted.
Opens and reads run on at most four I/O threads; a thread blocked in the OS keeps its slot until the call returns, and non-regular Unix files are opened nonblocking and rejected.
Blocking an ETW callback or an eBPF ring reader would lose events in the kernel instead.

`runtime/pipeline.rs` builds this pipeline for all three platforms.
Platform runtimes keep privilege checks and sensor startup; `HostState` owns live enrichment and cache-backed normalization.
`runtime/shutdown.rs` drains sensors, then workers, then flushes deduplication and the final telemetry snapshot.

## Host attribution state

`state::HostState` owns process metadata, cached SID and UID resolution, DNS correlation, Linux directory descriptors, and Windows file, registry, and process-identity indexes.
Detection and capture share the same construction and `StateLimits` entry ceilings; retired processes also have an entry cap.
The telemetry reporter reads a weak reference to the active state, so its snapshot does not keep a stopped runtime alive.

Startup inventories use `/proc` on Linux, `libproc` on macOS, and the native process snapshot on Windows.
Linux inventory keys retain kernel birth-time reconciliation; macOS and Windows use the same native start timestamp as their event collectors.
Enrichment always requires a matching PID and process identity.
The inventory reports scanned, seeded, skipped, duration, and failure information through host-state telemetry.

## Detectors and reload

Live detectors sit behind `engine::DetectorStore` (`src/engine/detectors.rs`).
`reload/watcher.rs` watches files, falling back to polling; `reload/worker.rs` debounces, rebuilds only the changed detector, validates it, and swaps it atomically.
Readers keep the previous instance until they finish.
Artifact stores are separate by consumer and keyed by the same `FileIdentity`, with one shared eviction policy.
A YARA reload advances its generation and invalidates only YARA results; PE metadata, hashes, and imphashes remain valid for that identity.
Signature revocation freshness can invalidate the signature store independently without reopening the file.

## Path allowlists

`src/utils/path_allowlist.rs` applies three matching policies, kept for compatibility with existing configs and covered by `tests/path_allowlist.rs`:

| Caller | Windows | Linux and macOS | Prefix match | Empty entry |
| --- | --- | --- | --- | --- |
| YARA | case-insensitive, `/` becomes `\` | case-sensitive | at a separator | ignored |
| IOC hashing | case-insensitive, `/` becomes `\` | case-sensitive | raw prefix | matches every path |
| Active response | case-insensitive, `/` becomes `\` | case-insensitive | at a separator | ignored |

## Windows sensor

- Two real-time ETW sessions: `rustinel-etw-process` for Kernel-Process, sized and flushed for latency so post-channel host enrichment can read command lines before short processes exit, and `rustinel-etw-trace` for the high-volume providers, sized for bursts.
  The ETW decoder itself performs no live process query.
  Inspect them with `Get-EtwTraceSession -Name rustinel-etw-trace` (or `rustinel-etw-process`).
- A classic kernel logger supplies creation-time command lines and SIDs, joined to Kernel-Process events by PID, parent PID, and time.
- At startup, key and file name snapshots let registry and file writes through pre-existing handles be named.
- Event Log subscriptions read System event 7045 and six Security events, filtered by an XPath query.
  Read positions are saved under `logging.directory/event-log`.

## Linux sensor

eBPF programs attach to tracepoints for exec, exit, fork, file syscalls, and DNS sends and receives, and to socket `fexit` hooks when kernel BTF allows it.
File syscall tracepoints remain the event source; optional BTF-planned probes add inode and device identity without changing path or completion semantics.
Hook availability and struct offsets are discovered at startup from tracefs and BTF; nothing depends on the build machine's kernel.
A missing hook degrades only its feature.
The loader refuses an object whose event ABI does not match.

## macOS sensor

`EsfSensor` subscribes to Endpoint Security exec, exit, and file events.
`BpfSensor` opens one `/dev/bpf` device per active interface and attributes flows to processes through a periodically refreshed socket list.
Endpoint Security is required; packet capture is best effort.
