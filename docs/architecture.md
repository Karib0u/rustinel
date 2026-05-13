# Architecture

## Overview

### Data Plane

```text
                      ┌───────────────────────────────┐
                      │ Platform Sensor               │
                      │ Windows ETW or Linux eBPF     │
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
                                  │ rules/sigma rules/yara  │
                                  │ rules/ioc/*             │
                                  └─────────────────────────┘
```

The key split in the codebase is between the hot event path and the control plane. Raw sensor events stay on a small shared pipeline, while rule loading, reloads, logging setup, and detector replacement happen off to the side.

## Sensor Layer

### Windows

The Windows sensor is ETW-based and currently covers:

- Process
- Image load
- Network
- File
- Registry
- DNS
- PowerShell
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
- `Microsoft-Windows-Service-Control-Manager`
- `Microsoft-Windows-TaskScheduler`

### Linux

The Linux sensor loads eBPF programs with Aya and currently covers:

- Process execution and exit
- Network connect activity
- File create, delete, change, and rename flows
- DNS queries observed from userspace sends. The eBPF program emits a bounded raw DNS payload and userspace parses `QueryName`, keeping string parsing out of the verifier-sensitive in-kernel path. Linux DNS response answers are not parsed yet, so `QueryResults` remains unavailable on Linux.

The current loader attaches a mix of tracepoints and kprobes, including:

- `sched:sched_process_exec`
- `sched:sched_process_exit`
- `syscalls:sys_enter_connect`
- `syscalls:sys_enter_openat`
- `syscalls:sys_exit_openat`
- `syscalls:sys_enter_unlinkat`
- `syscalls:sys_exit_unlinkat`
- `syscalls:sys_enter_renameat`
- `syscalls:sys_exit_renameat`
- `syscalls:sys_enter_renameat2`
- `syscalls:sys_exit_renameat2`
- `syscalls:sys_enter_sendto`
- `kprobe:vfs_create`

Requirements for the Linux sensor are kernel 5.8+, BTF, and eBPF privileges.

## Shared Pipeline

Once a platform sensor emits a raw `SensorEvent`, the rest of the runtime is shared:

1. `SensorEventRouter` fans each event out to `SigmaDetectionHandler` and `YaraEventHandler`.
2. `SigmaDetectionHandler` normalizes the event, evaluates Sigma, runs inline IOC checks, and queues process-start hash jobs when IOC hashing is enabled.
3. `YaraEventHandler` only handles process-start events and queues executable paths to the YARA worker.
4. YARA scans and IOC hash calculations run off the hot path in background workers.
5. Detection hits are written as ECS NDJSON through `AlertSink` and can also be handed to `ResponseEngine`.

## Detector Store and Hot Reload

Live detector instances sit behind `DetectorStore`:

- Sigma rules are compiled into the active `Engine`
- YARA rules are compiled into the active `Scanner`
- IOC indicator files are loaded into the active `IocEngine`

If hot reload is enabled:

- The poller fingerprints Sigma, YARA, and IOC files on disk
- The worker debounces changes and rebuilds only the affected detector set
- Successful rebuilds are swapped in atomically
- Failed rebuilds keep the previous live detector instances

## Normalization and Enrichment

The normalizer keeps one event model across both platforms and adds context where available:

- Sysmon-style field names in a single `NormalizedEvent` model
- `ProcessCache` for process metadata and parent correlation
- `SidCache` for Windows SID-to-user resolution
- `DnsCache` for DNS answer to later network-event correlation
- `ConnectionAggregator` for repeated network-connection suppression and interval tracking
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
- Linux uses `SIGKILL`

## Current Cross-Platform Scope

| Capability | Windows | Linux |
| --- | --- | --- |
| Process telemetry | Yes | Yes |
| Network telemetry | Yes | Yes |
| File telemetry | Yes | Yes |
| DNS telemetry | Yes | Yes |
| Registry telemetry | Yes | No |
| Image load telemetry | Yes | No |
| PowerShell telemetry | Yes | No |
| WMI telemetry | Yes | No |
| Service telemetry | Yes | No |
| Task telemetry | Yes | No |
| Built-in service management | Yes | No |
