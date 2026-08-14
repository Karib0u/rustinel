# Roadmap

This roadmap describes the direction of Rustinel development and groups the
current GitHub backlog into planned release themes. It is a living document:
the linked issues contain the current scope, discussion, and acceptance
criteria, and release contents may change as the work progresses.

## v1.3.0: Stability and platform support

The v1.3.0 release focuses on stability across process, network, YARA, and
configuration handling on supported platforms. It includes improvements to:

- process cache bounds and process identity validation before memory scans
- YARA and hash cache handling when files are replaced
- reporting YARA scan failures separately from clean results
- Windows network routing and network aggregation
- Linux DNS capture through `sendmsg` and `sendmmsg`
- alert and log file permissions
- process and network configuration

Three additional issues block the final release. Each one causes Rustinel to
report something, and to report it wrongly: a bypass that suppresses detection
entirely, a severity that is silently lowered, and a count that is inflated.
Shipping a stability release with any of them is the wrong trade, so they are
pulled ahead of the v1.3.1 patch release.

| Issue | Focus |
|---|---|
| [#226: resolve process images from `/proc/<pid>/exe`](https://github.com/Karib0u/rustinel/issues/226) | Stop relative `execve` paths from bypassing YARA scanning and path-based Sigma rules. |
| [#183: prevent low-severity rules from hiding higher-severity matches](https://github.com/Karib0u/rustinel/issues/183) | Ensure low-severity rules cannot hide higher-severity matches. |
| [#160: correct event.count over-counting](https://github.com/Karib0u/rustinel/issues/160) | Correct `event.count` over-counting in deduplication rollups. |

## v1.3.1: Detection correctness

This patch release addresses focused correctness gaps in rule evaluation,
deduplication windows, and configuration test isolation.

| Issue | Focus |
|---|---|
| [#179: report unsupported RSigma correlations and filters](https://github.com/Karib0u/rustinel/issues/179) | Report correlations and filters that RSigma parses but the runtime silently ignores. |
| [#170: align deduplication window behavior](https://github.com/Karib0u/rustinel/issues/170) | Align deduplication window behavior with its documented semantics. |
| [#161: define non-ASCII Sigma matching](https://github.com/Karib0u/rustinel/issues/161) | Fix or explicitly define non-ASCII case-insensitive Sigma matching. |
| [#171: isolate configuration tests from managed host state](https://github.com/Karib0u/rustinel/issues/171) | Keep configuration tests independent from real managed host configuration. |

Deduplication work stays together: #170 follows #160 in the same subsystem, so
the window semantics and the rollup counters are settled in one pass.

## v1.4.0: Telemetry and detection model improvements

This release expands the telemetry available to rules and improves the safety,
diagnostics, and compatibility of detection and alerting.

| Issue | Focus |
|---|---|
| [#168: preserve absolute Linux file identity](https://github.com/Karib0u/rustinel/issues/168) | Preserve absolute Linux file identity and explicitly report truncated paths. |
| [#238: resolve Windows Kernel-File paths](https://github.com/Karib0u/rustinel/issues/238) | Attribute pathless Kernel-File events, stop name-cache events surfacing as `file_change`, and make truncation observable. |
| [#239: align file Modify normalization across platforms](https://github.com/Karib0u/rustinel/issues/239) | Give a file modification the same Sigma category on Linux, macOS, and Windows. |
| [#142: capture Linux argv in the kernel](https://github.com/Karib0u/rustinel/issues/142) | Capture Linux argv in the kernel for short-lived processes. |
| [#162: add YARA scan timeouts and file-size controls](https://github.com/Karib0u/rustinel/issues/162) | Add YARA scan timeouts and maximum file-size controls. |
| [#140: expose telemetry counters](https://github.com/Karib0u/rustinel/issues/140) | Expose received, dropped, and high-water telemetry counters. |
| [#141: report rules without backing collectors](https://github.com/Karib0u/rustinel/issues/141) | Report rules that cannot fire because no collector provides their telemetry. |
| [#135: add a pinned SigmaHQ corpus smoke test](https://github.com/Karib0u/rustinel/issues/135) | Add a pinned SigmaHQ corpus smoke test. |
| [#136: add backend-neutral Sigma edge-case coverage](https://github.com/Karib0u/rustinel/issues/136) | Add backend-neutral Sigma modifier and edge-case coverage. |
| [#137: test alert construction and degradation](https://github.com/Karib0u/rustinel/issues/137) | Test alert construction and incomplete-event degradation behavior. |
| [#222: update alert output to ECS 9.5.0](https://github.com/Karib0u/rustinel/issues/222) | Move alert output to ECS 9.5.0 before the ECS model changes in #182. |
| [#182: preserve Sigma metadata and severity](https://github.com/Karib0u/rustinel/issues/182) | Preserve Sigma metadata, ATT&CK tags, references, and severity semantics. |
| [#138: replace unmaintained serde_yaml](https://github.com/Karib0u/rustinel/issues/138) | Replace unmaintained `serde_yaml` after the corpus baseline exists. |
| [#221: add a generic webhook output sink](https://github.com/Karib0u/rustinel/issues/221) | Push ECS alerts to configurable HTTP endpoints with bounded queuing and retries. |

Path identity comes first: #168 is the file-event form of the process-image
defect fixed in #226, and #142 covers the same collector, so the three are
cheapest to reason about close together.

File identity is the same problem on Windows: #238 is the Kernel-File form of
#168, since events carrying write semantics arrive with no path at all and the
events that do carry paths are name-cache bookkeeping. #239 follows it rather
than leading, because #238 settles what `file_change` means — writes, or the
creation-time changes the Sigma category actually denotes — and converging the
platforms on a definition that #238 then revises would mean doing it twice.

The webhook sink is included here rather than later because it is the one
backlog item with an identified external consumer waiting on it. It also
introduces the multi-destination sink abstraction that the native sinks in
#220 reuse.

This is the largest release on the roadmap. If it needs to be cut, #136 and
#137 move to v1.5.0 without blocking anything else, and #239 moves with #238
since it is a small follow-on to that work rather than an independent item.

## v1.5.0: RSigma transition and telemetry capture

This release makes RSigma the default evaluation backend while retaining the
built-in backend as a documented fallback, covered by capability, debugging,
documentation, and licensing work. It also lands the first piece of the
telemetry capture stream.

| Issue | Focus |
|---|---|
| [#190: test RSigma runtime capabilities](https://github.com/Karib0u/rustinel/issues/190) | Test every advertised RSigma-specific capability through the runtime adapter. |
| [#189: restore RSigma match-debug parity](https://github.com/Karib0u/rustinel/issues/189) | Restore RSigma match-debug parity with the built-in backend. |
| [#191: reconcile Sigma capability documentation](https://github.com/Karib0u/rustinel/issues/191) | Reconcile parser, library, and runtime capability documentation. |
| [#149: make RSigma the default backend](https://github.com/Karib0u/rustinel/issues/149) | Make RSigma the default while retaining a documented built-in fallback. |
| [#139: resolve the evaluator licensing strategy](https://github.com/Karib0u/rustinel/issues/139) | Resolve or close the evaluator licensing strategy based on the built-in backend decision. |
| [#231: resolve relative argv paths in CommandLine rules](https://github.com/Karib0u/rustinel/issues/231) | Close the argv half of the relative-path evasion gap, which depends on kernel argv capture in #142. |
| [#228: write normalized events to an NDJSON file](https://github.com/Karib0u/rustinel/issues/228) | Add a bounded, non-blocking `EventSink` capturing every normalized event, disabled by default. |

The built-in backend is expected to remain available throughout the v1.x
series. Its removal, if it becomes appropriate, is reserved for a future
major release.

## v1.6.0: Alert delivery, capture workflow, and replay

This release completes two threads started earlier. Alert delivery gains its
remaining destination, and the capture stream gains the workflow and analysis
commands built on top of #228.

Rustinel normalizes every sensor event into a single model, then discards it
unless a rule matches. The capture point is after normalization and before
detection, so recorded events are exactly what Sigma, IOC, and YARA receive.
The capture stream stays separate from the alert sinks in #221 and #220; those
deliver detections, while capture is high-volume, host-local, and serves
analysis rather than alerting.

| Issue | Focus |
|---|---|
| [#220: emit to native OS log sinks](https://github.com/Karib0u/rustinel/issues/220) | Route alerts and operational logs to the Windows Event Log, the systemd journal or syslog, and macOS unified logging. |
| [#229: add a time-boxed capture command](https://github.com/Karib0u/rustinel/issues/229) | Run `rustinel capture --duration 10m` to collect events plus provenance metadata in one command. |
| [#230: replay captured telemetry offline](https://github.com/Karib0u/rustinel/issues/230) | Re-evaluate a capture against Sigma and IOC with no sensor and no privileges. |
| [#195: add optional all-matches mode](https://github.com/Karib0u/rustinel/issues/195) | Add an optional all-matches Sigma alert mode, unblocked once #183 ships. |
| [#146: expand Linux file telemetry](https://github.com/Karib0u/rustinel/issues/146) | Add chmod, chown, truncate, and link telemetry, building on #168. |

The capture items are strictly sequential behind #228: #229 is a thin workflow
wrapper over it, and #230 should not start before there are captures worth
replaying. #230 also owns a correctness prerequisite: `NormalizedEvent` does
not round-trip losslessly today, so replay would silently mis-evaluate rules
until that is fixed.

Rotation, compression, and a custom capture archive format are deliberately
excluded. A size cap and a directory of plain NDJSON and JSON files cover the
malware-analysis and rule-authoring workflows, and remain readable with
ordinary tools.

The counters in #140 and the capture stream reinforce each other: #140 makes
telemetry loss quantifiable, and capture makes the retained telemetry
inspectable. Capture also gives the collector and normalization fixes in #168,
#226, #142, and #146 a direct way to verify their output.

## Longer-term product and platform work

The following work depends on the foundations above or requires additional
platform design. These items remain part of the active backlog without a
committed release target.

| Issue | Focus |
|---|---|
| [#184: add per-rule compatibility diagnostics](https://github.com/Karib0u/rustinel/issues/184) | Build per-rule compatibility diagnostics after #141, #179, and #191. Split the epic first. |
| [#111: add atomic rules-pack updates](https://github.com/Karib0u/rustinel/issues/111) | Add safe atomic rules-pack updates and rollback. |
| [#148: add Linux container and cgroup context](https://github.com/Karib0u/rustinel/issues/148) | Add container and cgroup context to Linux process events. |
| [#147: evaluate periodic YARA memory sweeps](https://github.com/Karib0u/rustinel/issues/147) | Evaluate bounded periodic YARA memory sweeps after #162. |
| [#143: design stateful Sigma correlation](https://github.com/Karib0u/rustinel/issues/143) | Design stateful Sigma correlation and temporal evaluation. |
| [#151: evaluate cargo-nextest](https://github.com/Karib0u/rustinel/issues/151) | Adopt cargo-nextest only if CI measurements justify it. |
| [#145: replace macOS BPF capture](https://github.com/Karib0u/rustinel/issues/145) | Replace macOS BPF capture only after resolving Apple entitlement and distribution requirements. |

The complete backlog is available in
[GitHub Issues](https://github.com/Karib0u/rustinel/issues).
