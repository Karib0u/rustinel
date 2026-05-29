# Limitations

Rustinel is designed for transparent, rule-based endpoint detection.

Like any detection system, it has boundaries. This page documents them clearly.

## Current limitations

### No commercial EDR-style self-protection

Rustinel does not currently provide the same anti-tamper or self-protection capabilities as mature commercial EDR agents.

A sufficiently privileged attacker may be able to stop, disable, or interfere with user-mode components or telemetry sources.

### No traditional Windows kernel driver

Rustinel uses ETW on Windows rather than a custom Windows kernel driver.

This improves stability and keeps the design simpler, but it also means Rustinel does not have the same visibility or enforcement points as a driver-backed agent.

### Kernel-level threats

Rustinel is not designed today to detect or stop kernel-mode rootkits.

Kernel-level threats, vulnerable driver abuse, and direct telemetry tampering may require additional controls.

### Memory-only payloads

Payloads that exist only in memory can be harder to detect if they do not create useful telemetry or leave a file that can be scanned.

YARA memory scanning is available but optional and privilege-dependent. It can improve coverage against packed, obfuscated, and runtime-unpacked payloads, but access to another process's memory may be blocked by operating-system policy, process protection, sandboxing, or missing privileges.

### Living-off-the-land activity

Legitimate administrative tools can be abused by attackers.

Rustinel can detect suspicious behavior when matching Sigma rules exist, but heavily obfuscated or context-dependent living-off-the-land activity may still evade detection.

### IOC limitations

IOC matching is deterministic.

It depends on the quality and relevance of the provided indicators.

Hashes, IPs, domains, and path regexes are useful, but they should not be the only detection layer.

### Encrypted C2

Encrypted C2 over trusted or common infrastructure may not be detected by simple IOC matching alone.

Behavioral detection is needed to identify suspicious activity around the network communication.

### macOS network and DNS attribution

On macOS, network and DNS telemetry comes from `/dev/bpf` packet capture rather
than a per-process hook. This has a few consequences:

- Connections are attributed to a process on a best-effort basis by matching
  ports against open sockets, which is racy: a short-lived socket may close
  before it can be matched, leaving the connection unattributed.
- DNS query events are not attributed to a process.
- Capture binds to a single interface (default `en0`, override with
  `RUSTINEL_BPF_INTERFACE`); traffic on other interfaces is not seen.

A future NetworkExtension-based source would carry the owning process with each
flow and remove these limitations.

### macOS memory scanning

YARA memory scanning on macOS uses `task_for_pid`, which is heavily restricted:
it generally requires root and SIP/AMFI relaxation or a specific entitlement.
When access is denied, memory scanning simply returns nothing.

## How to think about Rustinel

Rustinel should be viewed as a transparent open-source detection engine.

It is useful for:

- Detection engineering
- Endpoint telemetry collection
- Rule testing
- SIEM pipeline testing
- Research
- Lab deployments
- Blue-team experimentation

It should not be presented as a full commercial EDR replacement today.

## Planned improvements

Areas planned for improvement include:

- Scheduled YARA memory sweeps and richer memory match metadata
- Expanded telemetry coverage
- More detection examples
- More deployment hardening options
- Better documentation around operational security and limitations
