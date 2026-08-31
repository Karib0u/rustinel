# Architecture

## Overview

### Data Plane

```text
                      ┌───────────────────────────────┐
                      │ Platform Sensor               │
                      │ ETW / eBPF / ESF + bpf        │
                      └─────────────────┬─────────────┘
                                        ▼
                            ┌──────────────────────┐
                            │ SensorEventRouter    │
                            └─────────┬─────┬──────┘
                                      │     │
                       ┌──────────────┘     └──────────────┐
                       ▼                                   ▼
        ┌───────────────────────────┐         ┌──────────────────────┐
        │ SigmaDetectionHandler     │         │ YaraEventHandler     │
        │ normalize + Sigma + IOC   │         │ process start only   │
        │ queue IOC hash jobs       │         └─────────┬────────────┘
        └──────────┬────────────────┘                   ▼
                   ▼                        ┌──────────────────────┐
        ┌───────────────────────────┐       │ YARA worker          │
        │ Normalizer + shared state │       │ cached file scans    │
        │ process / SID / DNS / net │       └─────────┬────────────┘
        └──────┬──────────┬─────────┘                 │
               ▼          ▼                           │
      ┌─────────────┐ ┌─────────────┐                 │
      │ Sigma       │ │ IOC engine  │                 │
      │ engine      │ │ + hash work │                 │
      └──────┬──────┘ └──────┬──────┘                 │
             └─────────┬─────┴───────────────┬────────┘
                       ▼                     ▼
                  ┌────────────────────────────┐
                  │ Detection hit / alert      │
                  └──────────┬─────────┬───────┘
                             │         │
                             ▼         ▼
                  ┌──────────────┐ ┌──────────────────┐
                  │ AlertSink    │ │ ResponseEngine   │
                  │ ECS NDJSON   │ │ optional kill    │
                  └──────────────┘ └──────────────────┘
```

### Control Plane

```text
              ┌────────────────────────────────────────┐
              │ AppConfig                              │
              │ defaults + config.toml + EDR__* env   │
              └───────────────┬────────────────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
     ┌──────────────────────┐      ┌──────────────────────┐
     │ Logging setup        │      │ DetectorStore        │
     │ operational logs +   │      │ Sigma / YARA / IOC   │
     │ alert output sink    │      │ live detector set    │
     └──────────────────────┘      └──────────┬───────────┘
                                               ▲
                                               │ atomic swap
                                  ┌────────────┴────────────┐
                                  │ Reload poller + worker  │
                                  │ rules/current/{sigma,yara} │
                                  │ rules/current/ioc/*        │
                                  └─────────────────────────┘
```

The key split in the codebase is between the hot event path and the control plane. Raw sensor events stay on a small shared pipeline, while rule loading, reloads, logging setup, and detector replacement happen off to the side.

## Sensor Layer

### Windows

The Windows sensor uses ETW for realtime providers and a filtered Windows Event
Log subscription for Service Control Manager event 7045. It currently covers:

- Process
- Image load
- Network
- File
- Registry
- DNS
- PowerShell (script block and module logging)
- WMI
- Service creation
- Task creation

The ETW providers include:

- `Microsoft-Windows-Kernel-Process`
- `Microsoft-Windows-Kernel-Network`
- `Microsoft-Windows-Kernel-File`
- `Microsoft-Windows-Kernel-Registry`
- `Microsoft-Windows-DNS-Client`
- `Microsoft-Windows-PowerShell`
- `Microsoft-Windows-WMI-Activity`
- `Microsoft-Windows-TaskScheduler`

Service creation comes from the System event log rather than the classic
Service Control Manager provider, which does not deliver event 7045 to realtime
user ETW sessions.

### Linux

The Linux sensor loads eBPF programs with Aya and currently covers:

- Process execution and exit, with command lines captured in the kernel: argv is snapshotted at `execve`/`execveat` entry, where it is still mapped, and joined to the `sched_process_exec` event that follows, so short-lived processes keep their `CommandLine`
- Network connect activity
- File create, delete, change, and rename flows
- DNS queries observed from userspace `sendto`, `sendmsg`, and `sendmmsg` calls. The eBPF program emits a bounded raw DNS payload and userspace parses `QueryName`, keeping string parsing out of the verifier-sensitive in-kernel path. Linux DNS response answers are not parsed yet, so `QueryResults` remains unavailable on Linux.

The loader attaches a mix of tracepoints and kprobes: `sched_process_exec` and
`sched_process_exit`, enter/exit pairs on `execve`, `execveat`, `openat`,
`unlinkat`, `renameat`, and `renameat2`, entry hooks on `connect`, `sendto`,
`sendmsg`, and `sendmmsg`, and a `vfs_create` kprobe. The authoritative list is
in `src/sensor/linux/`.

Requirements for the Linux sensor are kernel 5.8+, BTF, and eBPF privileges.

### macOS

macOS telemetry comes from two native sources feeding the same shared pipeline:

- Endpoint Security (`EsfSensor`) for process and file events: process exec and
  exit, and file create, delete, rename, and modify (the modify signal is a
  close-after-write, which keeps the high-volume close stream down to real
  content changes). Exec events carry the executable path, arguments, and
  parent pid directly; the parent image is enriched via libproc.
- `/dev/bpf` packet capture (`BpfSensor`) for network and DNS: outbound TCP
  connection initiations (SYN) and DNS queries parsed from port 53 traffic,
  reusing the shared DNS query-name parser. Connection events are attributed to
  a process on a best-effort basis by matching the connection's ports against
  open sockets via libproc.

The Endpoint Security sensor is the primary source and is required; the bpf
capture source is best-effort and the agent degrades to Endpoint Security only
if it cannot start. Requirements for the macOS sensor are root, the
`com.apple.developer.endpoint-security.client` entitlement (or SIP/AMFI relaxed
for local testing), and access to the bpf device nodes.

## Shared Pipeline

Once a platform sensor emits a raw `SensorEvent`, the rest of the runtime is shared:

1. `SensorEventRouter` fans each event out to `SigmaDetectionHandler` and `YaraEventHandler`.
2. `SigmaDetectionHandler` normalizes the event, evaluates Sigma, runs inline IOC checks, and queues process-start hash jobs when IOC hashing is enabled.
3. `YaraEventHandler` only handles process-start events and queues executable paths to the YARA worker.
4. YARA scans and IOC hash calculations run off the hot path in background workers.
5. Detection hits are written as ECS NDJSON through `AlertSink` and can also be handed to `ResponseEngine`.

Every hop in that list crosses a bounded channel that sheds load rather than
blocking its producer, trading a detection gap for stability. Each channel
therefore carries atomic counters (accepted, dropped, and peak queue depth) in
`src/telemetry`, published to `telemetry.json` beside the logs so the gap is
measurable from outside the process. See
[Pipeline Telemetry](configuration.md#pipeline-telemetry) for the counters and
[Limitations](limitations.md#pipeline-and-operations) for what shedding costs.

## Detector Store and Hot Reload

Live detector instances sit behind `DetectorStore`:

- Sigma rules are compiled into the active `Engine`
- YARA rules are compiled into the active `Scanner`
- IOC indicator files are loaded into the active `IocEngine`

If hot reload is enabled:

- The watcher monitors filesystem events on Sigma, YARA, and IOC folders (falling back to a 60-second polling cadence if watcher setup fails)
- The worker debounces/coalesces changes and rebuilds only the affected detector set
- Successful rebuilds are swapped in atomically
- Failed rebuilds keep the previous live detector instances

## Normalization and Enrichment

The normalizer keeps one event model across all three platforms and adds context where available:

- Sysmon-style field names in a single `NormalizedEvent` model
- `ProcessCache` for process metadata and parent correlation
- `SidCache` for Windows SID-to-user resolution
- `DnsCache` for DNS answer to later network-event correlation
- `ConnectionAggregator` for repeated-connection metrics and interval tracking. This is observational only: every network event is still forwarded to the detectors
- Lazy process-context enrichment on alerts so non-process detections can still carry process details

On Windows, the agent also snapshots running processes during startup so `ProcessCache` is warm before the first new process event arrives.

## Detection and Response

### Sigma

- Rules are parsed and classified at load time by `product`, `service`, and `category`
- Conditions are precompiled
- Rules are bucketed by normalized logsource
- Unsupported or deferred logsource combinations are skipped at load time

### YARA

- Rules compile at startup and hot reload
- Scans trigger from process-start events
- Scanning runs in a background worker
- Shared allowlists prevent scanning trusted paths
- Results are cached per file identity with a 10,000-entry cap and a 6-hour TTL

### IOC

- Domains, IPs/CIDRs, path regexes, and file hashes are supported
- Domain, IP, and path-regex matching runs inline on normalized events
- File hashing runs in a background worker on process-start events
- Path allowlists and file-size caps reduce unnecessary hashing
- Hash results are cached per file identity with a 10,000-entry cap and a 6-hour TTL

### Active Response

- Optional and disabled by default
- Alerts above the configured threshold are queued to a background worker
- Windows uses process termination APIs
- Linux and macOS use `SIGKILL`

## Current Cross-Platform Scope

| Capability | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Process telemetry | Yes | Yes | Yes |
| Network telemetry | Yes | Yes | Yes |
| File telemetry | Yes | Yes | Yes |
| DNS telemetry | Yes | Yes | Yes |
| Registry telemetry | Yes | No | No |
| Image load telemetry | Yes | No | No |
| PowerShell telemetry | Yes | No | No |
| WMI telemetry | Yes | No | No |
| Service telemetry | Yes | No | No |
| Task telemetry | Yes | No | No |
| Built-in service management | Yes | No | No |
