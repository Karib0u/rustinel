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
                    ┌─────────┴─────────┐
                    ▼                   ▼
         ┌──────────────────┐  ┌──────────────────┐
         │   Sigma Engine   │  │   YARA Scanner   │
         │  (rule matching) │  │ (file scanning)  │
         └──────────────────┘  └──────────────────┘
                    │                   │
                    └─────────┬─────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Alert Sink                              │
│                  (ECS NDJSON output)                        │
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

**Event ID Mapping:**
| ETW Event | Sysmon ID |
|-----------|-----------|
| Process Start | 1 |
| Process Stop | 5 |
| Image Load | 7 |
| File Create | 11 |
| File Delete | 23 |
| Registry Create | 12 |
| Registry SetValue | 13 |
| Network Connect | 3 |
| DNS Query | 22 |

### State Caches

Thread-safe caches for performance:

- **ProcessCache** - Process info with (PID, CreationTime) keys for handling PID reuse
- **SidCache** - SID → username mappings with async background resolution
- **DnsCache** - IP → hostname with 15-minute TTL
- **ConnectionAggregator** - Deduplicates repeated network connections, tracks timing for beacon detection

### Detection Engines

**Sigma Engine:**
- Parses YAML rules with boolean logic
- Supports 15+ modifiers (contains, regex, base64, etc.)
- Evaluates in real-time per event

**YARA Scanner:**
- Compiles rules at startup
- Background worker for non-blocking scans
- Triggers on process creation events

### Alert Sink

Writes detections to NDJSON files in ECS format for SIEM ingestion.
