# Roadmap

This roadmap describes planned areas of work.

It is not a strict release commitment.

## Sensor

### Linux

- **DNS response enrichment** — Linux DNS query names are extracted in userspace from raw eBPF payload events. Future work should parse DNS responses for `QueryResults` and DNS answer-to-network correlation.
- **Expanded file telemetry** — cover `chmod`, `chown`, `truncate`, and `link` syscalls to close gaps in file-integrity coverage.
- **Container context** — enrich process events with cgroup, namespace, and container runtime metadata so rules can scope to specific workloads.

### Windows

- **ETW integrity checks** — detect ETW session tampering and provider blinding that could suppress telemetry.
- **Deep inspection via stack walking** — identify shellcode and "floating code" executing outside mapped image regions.

### Cross-Platform

- **Periodic YARA sweeps** — scheduled background scans of running processes independent of creation events.

## Detection

### YARA memory scanning enhancements

YARA memory scanning is available as an optional detector for process memory.
Future work is focused on improving coverage and operator control:

- Periodic process sweeps independent of process creation events
- Better memory-region selection
- Optional executable-only private-region scanning
- Richer memory match metadata in alerts

Memory scanning remains privilege-dependent and platform behavior differs between
Windows process-memory APIs and Linux `/proc/<pid>/mem` access.

### More Sigma examples

More example Sigma rules are planned for common detection scenarios, including:

- Suspicious PowerShell
- WMI abuse
- Service creation
- Scheduled task creation
- Suspicious Linux process execution
- Suspicious network activity

### Better IOC examples

More IOC examples are planned for:

- Hash matching
- Domain matching
- IP matching
- Path regex matching

## Telemetry

### Expanded Linux eBPF coverage

Linux support currently focuses on process, network, file, and DNS telemetry.

Future work may expand Linux coverage depending on stability, portability, and usefulness.

### Better normalization documentation

More documentation is planned around how raw ETW and eBPF events are normalized into Rustinel’s shared event model.

## Operations

### SIEM integration examples

Rustinel writes ECS NDJSON alerts.

Future documentation should include examples for ingesting those alerts into common SIEM and log platforms.

### Deployment examples

More deployment examples are planned for:

- Windows service mode
- Linux supervisor-based deployment
- Lab environments
- Detection engineering environments

### Hardening guidance

Optional hardening guidance is planned for users who want to make Rustinel harder to stop or identify.

This may include recommendations around:

- Installation paths
- Service names
- File permissions
- Logging locations
- Operational monitoring

## Community

Useful community contributions include:

- Testing on different Windows and Linux versions
- Reporting telemetry gaps
- Improving documentation
- Adding Sigma examples
- Adding YARA examples
- Adding safe demo scenarios
- Testing SIEM ingestion
