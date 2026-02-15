# Architecture

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Windows Kernel                          │
│  (Process, Network, File, Registry, DNS, PowerShell, etc.) │
└─────────────────────────────────────────────────────────────┘
                              │ ETW Events
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Collector                              │
│              (ETW providers, event routing)                 │
└─────────────────────────────────────────────────────────────┘
                              │ Raw Events
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Normalizer                              │
│        (ETW → Sysmon format, path/user enrichment)         │
└─────────────────────────────────────────────────────────────┘
                              │ Normalized Events
                    ┌─────────┼─────────┐
                    ▼         ▼         ▼
         ┌────────────┐ ┌──────────┐ ┌──────────────┐
         │   Sigma    │ │   YARA   │ │  IOC Engine  │
         │  (rules)   │ │ (files)  │ │ (indicators) │
         └────────────┘ └──────────┘ └──────────────┘
                    │         │         │
                    └─────────┼─────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Alert Sink                              │
│               (ECS 9.3.0 NDJSON output)                     │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Collector

Manages ETW trace sessions and routes events to handlers.

**ETW Providers:**
- Microsoft-Windows-Kernel-Process
- Microsoft-Windows-Kernel-Network
- Microsoft-Windows-Kernel-File
- Microsoft-Windows-Kernel-Registry
- Microsoft-Windows-DNS-Client
- Microsoft-Windows-PowerShell
- Microsoft-Windows-WMI-Activity
- Microsoft-Windows-Service-Control-Manager
- Microsoft-Windows-TaskScheduler

**Noise Reduction:**
- Kernel-level keyword filtering excludes read/write operations
- Router-level filtering drops high-volume network events

### Normalizer

Converts raw ETW events to Sigma-compatible format.

**Enrichment:**
- NT paths → DOS paths (`\Device\HarddiskVolume2\...` → `C:\...`)
- PE metadata extraction (OriginalFileName, Product, Description)
- Parent process correlation
- SID → Domain\User resolution
- DNS IP → hostname mapping
- Process context (`Image`, `CommandLine`, parent metadata) is attached lazily on alerts, not on every normalized event

**Event ID Mapping:**
| ETW Event | Sysmon or Windows ID |
|-----------|----------------------|
| Process Start | 1 |
| Process Stop | 5 |
| Image Load | 7 |
| File Create | 11 |
| File Delete | 23 |
| Registry Create/Delete | 12 |
| Registry SetValue | 13 |
| Network Connect (TCP/UDP) | 3 |
| DNS Query | 22 |
| WMI Event | 19 |
| PowerShell Script Block | 4104 |
| Service Creation | 7045 |
| Task Creation | 106 |

### State Caches

Thread-safe caches for performance:

- **ProcessCache** - Process info with (PID, CreationTime) keys for handling PID reuse
- **SidCache** - SID → username mappings with async background resolution
- **DnsCache** - IP → hostname with 15-minute TTL
- **ConnectionAggregator** - Deduplicates repeated network connections, tracks timing for beacon detection

### Detection Engines

**Sigma Engine:**
- Parses YAML rules with boolean logic
- Skips unsupported rules at load time (`category`, `product`, `service`)
- Evaluates only rules in relevant category buckets per event
- Precompiles condition trees at startup
- Supports core Sigma modifiers like `contains`, `re`, `cidr`, `base64`, `fieldref`, `windash`
- Evaluates in real-time per event

**YARA Scanner:**
- Compiles rules at startup
- Background worker for non-blocking scans
- Triggers on process creation events
- Skips allowlisted path prefixes before queueing and in the worker

**IOC Engine:**
- Matches atomic indicators: hashes (MD5/SHA1/SHA256), IPs/CIDRs, domains (exact + suffix), path regexes
- Domain, IP, and path checks run inline (negligible overhead with small indicator sets)
- Hash computation runs in a dedicated `spawn_blocking` worker thread
- Hash allowlist uses shared `allowlist.paths` by default (or `ioc.hash_allowlist_paths` override)
- File size limit prevents hashing oversized binaries
- File identity cache (path + size + mtime) avoids re-hashing unchanged files

### Alert Sink

Writes detections to NDJSON files in ECS 9.3.0 format for SIEM ingestion.
