# telemetry.json

The running agent rewrites `telemetry.json` in its log directory every `telemetry.snapshot_interval_secs` (30 by default) and at shutdown.
It holds counts only, never endpoint data.
All counters start at zero when the agent starts.
`rustinel doctor` reads this file; see [Telemetry loss](telemetry-loss.md) for how to use it.

## Top level

| Field | Content |
| --- | --- |
| `version`, `pid`, `captured_at`, `uptime_secs` | Which agent wrote the snapshot, and when |
| `channels` | One entry per queue, see below |
| `sensor_events_by_category` | Accepted and dropped sensor events by category (process, network, file, ...) |
| `artifact_resolver` | Single-open executable resolution outcomes and store occupancy |
| `linux_ebpf` | Linux kernel and userspace counters |
| `macos_collectors` | macOS Endpoint Security and packet capture loss |
| `windows_event_log` | Windows System and Security subscription health |
| `field_fidelity` | Counts by populated field and [fidelity limitation](output.md#field-provenance) at normalization |
| `windows_process_command_line` | Windows process starts with and without a command line |
| `windows_process_correlation` | Windows process metadata sources |
| `registry` | Windows registry key-path resolution |
| `file_attribution` | Windows file path resolution |
| `etw_decode` | Windows ETW decoding outcomes |

Platform sections appear only on their platform.

## `host_state`

Present when the runtime has initialized attribution state.
Counts describe retained entries, including expired entries awaiting lazy cleanup, rather than exact memory bytes.
The snapshot reads each index separately while events continue to arrive.

| Field | Meaning |
| --- | --- |
| `limits` | Entry ceilings: configured `processes`, 4,096 `users`, 10,000 `dns`, and 8,192 `paths` per index |
| `processes`, `retired_processes` | Live metadata and recently exited processes; each has the configured process ceiling |
| `process_identities` | Windows process lifetimes used for timestamp-based attribution; has the process ceiling |
| `users`, `dns` | Cached account resolutions and IP-to-hostname mappings |
| `paths` | Retained directory paths on Linux, or combined file and registry paths on Windows, including startup and recently closed entries |
| `attribution_loss` | Process-state updates without a usable subject identity or image, unknown process stops, and unusable Linux directory-open updates |
| `inventory` | Startup process enumeration: `scanned`, `seeded`, `skipped`, `duration_ms`, and optional `error` |

Windows keeps separate bounded indexes for file objects, file keys, file startup names, registry keys, registry startup names, and recently closed registry keys.
The recently closed registry index is capped at 4,096 entries.
A process skipped because it vanished, was inaccessible, or exceeded the entry ceiling contributes to `inventory.skipped`.
Linux startup attribution also requires kernel process birth-time support.

## `artifact_resolver`

The resolver opens each process image at most once per submitted event and shares the bytes between PE metadata, IOC hashing, signature/imphash extension points, and YARA.
Its consumer results remain in separate `FileIdentity`-keyed stores under one eviction ceiling.

| Field | Meaning |
| --- | --- |
| `queue_capacity`, `deadline_ms` | Fixed pending-work bound and maximum resolver time budget; a smaller configured YARA timeout can shorten a job |
| `admission_budget_ms` | Longest PE metadata may hold an event before it is admitted without it |
| `admission_budget_exceeded` | Events admitted without PE metadata because resolution missed the budget |
| `admission_backpressure` | Events that waited for room in the ordered admission queue; each wait is bounded by the budget |
| `queued`, `resolved` | Jobs admitted and completed |
| `cache_hits`, `cache_misses` | Whole-job cache outcomes after the identity was measured |
| `queue_saturated`, `worker_saturated`, `deadline_exceeded` | Enrichment shed because the resolver queue was full, an I/O thread could not be started, or no I/O slot freed before the job's deadline; the event is still admitted |
| `open_failed`, `identity_mismatch`, `read_failed`, `consumer_failed`, `oversized` | Explicit unavailable outcomes by cause |
| `pe_entries`, `hash_entries`, `imphash_entries`, `signature_entries`, `yara_entries` | Occupancy of every separate result store |
| `yara_generation` | Active cache generation; only YARA entries invalidate on a successful YARA reload |
| `evicted` | File identities removed from all stores by the shared eviction policy |

## `channels`

| Field | Meaning |
| --- | --- |
| `channel` | Queue name, such as `sensor_events` or `yara_file_scan` |
| `capacity` | Queue size |
| `accepted` | Items that entered the queue |
| `dropped` | Items dropped because the queue was full. This is the detection gap |
| `dropped_channel_closed` | Items dropped during shutdown. Not a gap |
| `high_water_mark` | Deepest the queue got |

## `linux_ebpf`

`families` has one entry per kernel ring (process, network, file, DNS):

| Field | Meaning |
| --- | --- |
| `kernel_seen` | Events that passed the kernel filter |
| `kernel_submitted` | Events written to the ring |
| `kernel_ring_full` | Events lost to a full ring |
| `kernel_oversized` | Events too large for the ring |
| `kernel_map_full` | Events lost to a full kernel map |
| `in_flight` | Events still in the ring when the snapshot was taken. Not a loss |
| `userspace_received` | Records read from the ring |
| `userspace_decoded` | Records with a valid layout |
| `short_reads` | Records too short to decode |
| `userspace_internal` | Control records used inside the reader |
| `canonical_emitted` | Events passed on to the detectors |
| `userspace_dropped` | Decoded records that produced no event |
| `unresolved_file_events` | File events dropped because their path could not be rebuilt |

`abi_version` and `features` list which kernel hooks are active or degraded.

## `macos_collectors`

| Field | Meaning |
| --- | --- |
| `esf.received` | Endpoint Security messages received |
| `esf.kernel_dropped` | Messages the kernel dropped, from sequence gaps |
| `esf.kernel_dropped_by_event_type` | The same drops by event type. Do not add to the total |
| `bpf.kernel_received`, `bpf.kernel_dropped` | Packets seen and dropped by the kernel, summed over interfaces |
| `bpf.stats_polls`, `bpf.stats_errors` | Successful and failed reads of the kernel counters |
| `bpf.interfaces.<name>` | The same per interface, plus `active`, `link_type`, and `error` |

## `windows_event_log`

One entry per channel (`System`, `Security`):

| Field | Meaning |
| --- | --- |
| `active` | The subscription is running |
| `delivered` | Records decoded |
| `last_record_id` | Last record read. Rustinel resumes from it after a restart |
| `subscription_errors` | Subscription failures. The sensor stops on the first one |
| `live_stale` | Times Windows reported that records were missed |
| `resume_failures` | Times the saved position could not be resumed |
| `retention_wraps` | Times records were overwritten before being read |
| `checkpoint_errors`, `decode_errors` | Failures saving the position or decoding a record |
| `last_error` | The most recent error |

The read position is saved under `event-log/` in the log directory.
Keep it when rotating logs, or Rustinel restarts from the oldest record.

## Windows process sections

`windows_process_command_line` counts process starts whose command line was `attempted`, `captured`, and `missed`.

`windows_process_correlation` counts how process metadata from two ETW sources was joined: `matched`, `unmatched`, `conflicting`, `classic_unmatched`, `classic_command_line`, `classic_records`, `rundown`, `decode_failed`, and `session_failures`.

## `registry`

| Field | Meaning |
| --- | --- |
| `events_received` | Registry writes decoded |
| `events_resolved` | Writes passed on with a key path |
| `events_unresolved` | Writes dropped for lack of a key path. This is the gap |
| `resolved_from_snapshot` | Resolved from the key list taken at startup |
| `resolved_after_close` | Resolved from a key that had just been closed |
| `snapshot_keys`, `rundown_attempted` | Size of the startup key list, and whether it was taken |
| `naming_create`, `naming_open`, `naming_failed` | Events that named a key, and those whose open failed |

## `file_attribution`

| Field | Meaning |
| --- | --- |
| `attempted` | File events that needed a path |
| `resolved_from_event` | Named by the event itself |
| `resolved_from_index` | Named from earlier events for the same file handle |
| `unresolved` | Dropped for lack of a path. This is the gap |
| `index_capacity_evictions` | Handles forgotten because the index was full |
| `rundown` | The file list taken at startup: whether it was accepted, and its size |

## `etw_decode`

| Field | Meaning |
| --- | --- |
| `records_received` | ETW records received |
| `records_filtered` | Records ignored on purpose. Not a loss |
| `records_indexed` | Records used only to name later events |
| `records_decoded` | Records that produced an event |
| `records_unattributed` | Records dropped for lack of a path |
| `schema_errors`, `unsupported_layouts`, `fieldless_payloads` | Records that could not be decoded |
| `events_emitted` | Events passed on |
| `failures` | Decode failures by provider, event ID, and version (up to 32 keys) |
| `unkeyed_failures` | Failures past the 32-key limit |

`records_filtered` through `fieldless_payloads` add up to `records_received`.
A difference is reported as `etw_decode_reconciliation`.
