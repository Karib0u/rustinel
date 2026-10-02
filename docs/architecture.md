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
├── models/          CanonicalEvent, field-view mappings, the stable recorded view, alert, and ECS models
├── normalizer/      builds the stable NormalizedEvent compatibility view
├── state/           HostState, bounded attribution indexes and inventory
├── artifact.rs      single-open executable resolution and bounded result stores
├── engine/          Sigma loading, logsource routing, evaluation (RSigma)
├── scanner/         YARA compilation and scanning
├── memory/          per-platform process memory reads for YARA
├── ioc/             indicator loading and matching
├── alerts/          ECS NDJSON sink, deduplication, and webhook delivery
├── response/        active response
├── reload/          file watching, debounce, atomic detector swap
├── telemetry/       loss counters and telemetry.json
├── doctor/          `rustinel doctor` checks
├── capture/, replay/  recordings
├── rules.rs, rules/ rule pack catalog and installation
├── setup.rs, service.rs, platform/  managed install and native services
├── update.rs        `rustinel update`
├── utils/           path allowlists, file identity, PE parsing, helpers
└── field_availability.rs  per-view and per-platform field contract, source of generated docs
ebpf/src/            Linux eBPF programs and the event ABI
```

## Event path

1. A platform sensor emits a `RawEvent` into the bounded `sensor_events` channel.
   Process records retain native numeric identities and source-specific facts; the other categories are migrated independently.
2. `HostState` performs host-dependent enrichment after that channel and creates a provenance-carrying `CanonicalEvent`.
3. Process starts and image loads use the bounded `artifact_resolution` queue.
   Selected file events use a separate `artifact_written_files` queue, so written files cannot displace image jobs.
   The image queue holds up to 256 jobs, and the written-file queue holds up to 8,192 jobs.
   Written files settle for 250 ms in a map of up to 8,192 targets keyed by path and object identity, with a deadline-ordered queue and repeated writes coalesced.
   At table capacity, new targets check up to 64 pending paths for disappearance, rotating through deadline order and wrapping at the end.
   Vanished targets are removed from both indexes and the arrival-identity cache, and counted as open failures; lookup errors leave the job pending.
   Linux (eBPF) and macOS (Endpoint Security) measure that identity in the kernel at event time.
   Kernel-File ETW carries no file ID, so on Windows the written-file worker reads the volume file ID from the path when it receives the job, before the settle delay.
   It opens the file once, validates it against that identity, reads it once, and fans those bytes out to PE metadata, IOC hashing, and YARA.
   A written file without an identity is skipped and counted, never scanned by path alone.
4. Admission routes every event to the downstream `SensorEventRouter` exactly once and in `ingest_seq` order, for Sigma/IOC detection or capture.
   Sigma logsource routes select a compiled field view over the canonical event.
   View tables map external rule names to Rustinel semantic accessors, so adding a vocabulary does not change platform sensors.
   Only PE metadata, which Sigma can match, may hold an event, for at most a 100 ms admission budget; later events wait behind it.
   YARA file and IOC hash alerts come from the same resolver result after admission.
   Sigma rules on `Hashes` or `Imphash` are left out of admission for events the resolver will hash; a deferred detection stage evaluates them once, in arrival order, when the resolver publishes those fields or a 2 second budget expires.
   YARA memory scanning remains a separate worker by design: it reads a live process keyed by process identity, after a delay, under one budget shared across regions.
   Linux descriptor-path and memfd executables resolve through `/proc/<pid>/exe`, with a file identity captured before queueing and process lifetime checks around the open.
   Memfd executions queue memory scans even when scanning every process is disabled.
5. Hits go to `AlertSink` (ECS NDJSON) and, when enabled, `ResponseEngine`.

Capture also receives `CanonicalEvent`.
Recording schema v2 deliberately serializes its unchanged `NormalizedEvent` view, and replay wraps that same view back in a canonical event, so existing recordings remain compatible.
The `sysmon` view is the default rendering and retains the complete compatibility surface, including Rustinel's `ImageSource`, `ImageTruncated`, and `PathTruncated` fidelity fields.

Sensor and background-worker queues are bounded channels that drop instead of blocking, with counters in `src/telemetry`.
Canonicalization runs synchronously in the sensor-channel worker, but file opening, reading, PE parsing, hashing, and YARA file scanning do not.
A slow artifact delays routing by at most the admission budget, never more, because order is kept and the budget is measured from each event's own arrival.
The deferred detection stage has its own bounded queue and budget and never holds admission.
When that queue is full, the event keeps every rule at admission, evaluated without the fields, and the outcome is counted.
Admission and deferred passes share one correlation state; each pass keeps its own best match.
A recording holds the event as admitted, so replay evaluates deferred-pass rules once without the fields, and its header reports how many rules that affects.
If the artifact queue is full, a job exceeds its deadline, or PE metadata misses the budget, the event is admitted without that enrichment and the outcome is counted.
Each artifact queue has at most four I/O threads, so blocked written-file I/O cannot occupy image slots.
A thread blocked in the OS keeps its slot until the call returns, and non-regular Unix files are opened nonblocking and rejected.
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
- Event Log subscriptions read System event 7045 and the Security audit events in [Sigma rules](sigma.md#windows-security-events), filtered by a structured query with one `Select` per family: an event is only reachable if it is in both the query and the [`FIELD_AVAILABILITY`](field-availability.md) table.
  Read positions are saved under `logging.directory/event-log`.

## Linux sensor

eBPF programs attach to tracepoints for exec, exit, fork, file syscalls, and DNS sends and receives, and to socket `fexit` hooks when kernel BTF allows it.
File syscall tracepoints remain the event source; optional BTF-planned probes add inode and device identity without changing path or completion semantics.
Hook availability and struct offsets are discovered at startup from tracefs and BTF; nothing depends on the build machine's kernel.
A missing hook degrades only its feature.
`CurrentDirectory` is read from `/proc/<pid>/cwd` after the event leaves the ring reader, and kept only when the BTF process identity still matches the live process.
The loader refuses an object whose event ABI does not match.

## macOS sensor

`EsfSensor` subscribes to Endpoint Security exec, exit, and file events.
`BpfSensor` opens one `/dev/bpf` device per active interface and attributes flows to processes through a periodically refreshed socket list.
Endpoint Security is required; packet capture is best effort.

## Callback panic audit

The callback policy is in [Sensor callback failures](operations.md#sensor-callback-failures).
The two application-owned `catch_unwind` guards serve unwinding development and test builds; release aborts bypass them.
ETW uses ferrisetw's native guard, which calls `exit(1)` on an unwinding panic, for manifest, classic-process, and file-rundown callbacks.

| Path reachable from callbacks | Disposition |
| --- | --- |
| ESF `Message::time()` | Replaced with `raw_time()` and checked timestamp conversion; negative seconds, invalid nanoseconds, or an unrepresentable time drop the event through `Option` |
| ESF `Process::start_time()` binding arithmetic | Retained: the kernel supplies a nonnegative `timeval` with microseconds below one million, its duration arithmetic fits, and the binding checks `SystemTime` addition; event arguments and paths cannot change these fields |
| ESF sequence, identity, and collector mutex `unwrap`/`expect` | Recover poisoned locks for derived state, including the telemetry snapshot reader, so a caught panic does not cause repeated poison panics; an absent collector snapshot is initialized |
| ESF sequence counters | Saturating additions prevent counter overflow; `sequence_gap` subtracts only when the new sequence exceeds the previous one |
| ESF identity map ranges and file normalization `expect` | Retained: ranges always use one PID with ordered generation bounds; the four closed `FileAction` variants map to the static normalization table and have unit coverage |
| All five Event Log XML timestamp decoders | Share checked `SystemTime` addition; malformed, pre-epoch, or unrepresentable timestamps return decoder errors and take the recoverable `decode_errors` path |
| Application XML `values[index]` | Removed: named fields read the current XML node directly; positional fields use `get` |
| Event Log XML rendering and mutexes | Buffer sizes use `u32::div_ceil`; the UTF-16 slice ends at a position found within that buffer; decode/render errors are returned and locks recover poisoning; native context and handle validity belong to the subscription lifecycle |
| Event Log health counter additions and telemetry indexes | Retained: overflow requires more than `u64::MAX` callback incidents, independently of record IDs or XML; the channel index is found or inserted under the same lock |
| ETW routing `unreachable!` arms | Retained: categories come from the static provider table; process and PowerShell routes return early, file/registry have dedicated paths, and Event Log categories have no ETW providers |
| ETW process-correlation indexing, deque `unwrap`, and count subtraction | Retained: indexes are checked against length or obtained by enumeration, front/remove operations occur under exclusive access, and each pending entry increments the count once before removal |
| ETW process Windows metadata `expect` | Retained: the manifest decoder constructs `RawProcessPlatform::Windows`; native content cannot select another platform variant |
| ETW timestamp arithmetic and time-difference `unwrap` | Retained: an `i64` FILETIME clamped at the Unix epoch fits Windows' `u64` FILETIME range; one of the two ordered time differences succeeds; extreme FILETIMEs have unit coverage |
| ETW WBEM SID slices and registry value byte decoding | Retained: SID header, subauthority count, and total length are checked before slicing; registry values use checked byte slices and reject truncated data |
| ETW path/correlation mutexes | Recover poisoned locks rather than panic; caches are bounded, and count/path-byte arithmetic uses stored entry sizes, not unchecked native lengths |
| Shared file identity, path normalization, warning limiter, and queue telemetry | Retained: stat timestamp arithmetic widens `i64` to `i128`; NT path slicing follows a matching UTF-8 prefix; poisoned drive-map locks return missing mappings; warning counts saturate; queue category indexes come from an exhaustive static match |
| Binding property parsing and FFI | The used ferrisetw integer/IP parsers check slice lengths, strings use complete UTF-16 chunks, and property extraction checks remaining payload bounds; its GUID parser's unchecked fixed slices are not called; Endpoint Security accessors rely on live kernel messages and version-gated fields |

Allocation failure and invalid native pointers are outside decoder error recovery.
Keep new event-derived lengths, timestamps, and enum values on checked error or `Option` paths rather than adding panic sites.
