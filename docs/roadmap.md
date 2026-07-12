# Roadmap

This page summarizes the active GitHub backlog. Priorities may change, and an
open issue is not a release commitment. Follow the linked issue for current
scope, discussion, and acceptance criteria.

## Immediate Correctness

- [#164: stop connection aggregation from permanently suppressing detection](https://github.com/Karib0u/rustinel/issues/164)
- [#35: revalidate process identity before YARA memory scans](https://github.com/Karib0u/rustinel/issues/35)
- [#32: capture `sendmsg` and `sendmmsg` DNS queries on Linux](https://github.com/Karib0u/rustinel/issues/32)

## Telemetry Fidelity

- [#166: route Windows Kernel-Network events by operation and protocol](https://github.com/Karib0u/rustinel/issues/166)
- [#168: preserve absolute Linux file paths and report truncation](https://github.com/Karib0u/rustinel/issues/168)
- [#142: capture Linux process arguments in the kernel](https://github.com/Karib0u/rustinel/issues/142)
- [#140: add telemetry drop counters and backpressure visibility](https://github.com/Karib0u/rustinel/issues/140)
- [#141: report rules that have no active backing collector](https://github.com/Karib0u/rustinel/issues/141)

## Detection Reliability

- [#165: prevent distinct event subjects from sharing a deduplication key](https://github.com/Karib0u/rustinel/issues/165)
- [#160: correct deduplication rollup counts](https://github.com/Karib0u/rustinel/issues/160)
- [#170: align deduplication window behavior with its documented semantics](https://github.com/Karib0u/rustinel/issues/170)
- [#167: harden YARA and IOC caches against file replacement](https://github.com/Karib0u/rustinel/issues/167)
- [#169: distinguish YARA scan failures from clean results](https://github.com/Karib0u/rustinel/issues/169)
- [#161: close the Unicode case-insensitive Sigma matching gap](https://github.com/Karib0u/rustinel/issues/161)
- [#162: add YARA scan timeouts and file-size limits](https://github.com/Karib0u/rustinel/issues/162)

## Engineering Quality

- [#159: bound the process cache](https://github.com/Karib0u/rustinel/issues/159)
- [#163: restrict alert and log file permissions](https://github.com/Karib0u/rustinel/issues/163)
- [#135: add a SigmaHQ corpus smoke test in CI](https://github.com/Karib0u/rustinel/issues/135)
- [#136: expand direct matcher edge-case tests](https://github.com/Karib0u/rustinel/issues/136)
- [#137: cover alert construction and field-mapping degradation](https://github.com/Karib0u/rustinel/issues/137)
- [#138: migrate away from unmaintained `serde_yaml`](https://github.com/Karib0u/rustinel/issues/138)
- [#139: avoid AGPL `evalexpr` releases](https://github.com/Karib0u/rustinel/issues/139)
- [#171: isolate configuration tests from managed host state](https://github.com/Karib0u/rustinel/issues/171)

## Longer-Term Direction

- [#143: design correlation and temporal rule support](https://github.com/Karib0u/rustinel/issues/143)
- [#145: replace macOS `/dev/bpf` capture with NetworkExtension](https://github.com/Karib0u/rustinel/issues/145)
- [#146: expand Linux file telemetry](https://github.com/Karib0u/rustinel/issues/146)
- [#147: add periodic YARA memory sweeps](https://github.com/Karib0u/rustinel/issues/147)
- [#148: add Linux container context](https://github.com/Karib0u/rustinel/issues/148)
- [#149: make RSigma the default backend and stage built-in removal](https://github.com/Karib0u/rustinel/issues/149)
- [#111: add safe atomic rules pack updates](https://github.com/Karib0u/rustinel/issues/111)

The complete backlog is available in
[GitHub Issues](https://github.com/Karib0u/rustinel/issues).
