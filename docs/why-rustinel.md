# Why Rustinel

Rustinel was created because there was a real gap in the open-source endpoint detection space.

When I started the project, I could not find an open-source endpoint detection engine that combined:

- Native Windows telemetry through ETW
- Native Linux telemetry through eBPF
- A single cross-platform detection pipeline
- Support for community detection formats like Sigma and YARA
- IOC matching for hashes, IPs, domains, and path regexes
- ECS NDJSON alert output
- A performant, memory-safe implementation in Rust

Some tools solve parts of this problem, but Rustinel aims to bring these pieces together in one transparent and extensible agent.

## Design goals

Rustinel is built around a few simple goals.

### Native telemetry

Rustinel uses telemetry sources that already exist in the operating system.

On Windows, Rustinel uses ETW.

On Linux, Rustinel uses eBPF.

On macOS, Rustinel uses Apple's Endpoint Security framework plus `/dev/bpf` capture (experimental).

The goal is to collect useful host telemetry without maintaining a traditional custom Windows kernel driver.

### Cross-platform detection

Windows, Linux, and macOS are different, but many detection engineering concepts are shared.

Rustinel normalizes events into a shared model so detection logic can be reused where possible.

### Community rule formats

Detection engineers already use Sigma and YARA.

Rustinel supports those formats so teams can reuse existing detection content instead of converting everything to a proprietary rule format.

### Transparency

Rustinel is open source because endpoint detection should be inspectable.

Defenders should be able to understand:

- What telemetry is collected
- How events are normalized
- How detections are evaluated
- What alerts are generated
- Where the limits are

### Practical output

Rustinel writes alerts as ECS NDJSON.

This makes alerts easy to ingest into SIEM, logging, and analysis pipelines.

## Non-goals

Rustinel is not trying to replace every feature of a mature commercial EDR.

It does not currently aim to provide:

- Kernel-level self-protection
- Full anti-tamper protection
- Pre-execution blocking
- Managed response workflows
- A full enterprise console
- Cloud-managed policy orchestration

The goal is different: provide a transparent open-source detection engine for blue teams, researchers, and detection engineers.