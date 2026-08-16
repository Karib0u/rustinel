# Roadmap

This roadmap explains the direction of Rustinel development and why the work is
sequenced the way it is.

The authoritative scope of each release lives in
[GitHub Milestones](https://github.com/Karib0u/rustinel/milestones), which track
the current issue list, progress, and pull requests. This page does not repeat
those lists; it records the reasoning behind them. Release contents may change
as implementation and validation uncover new information.

## v1.3.1: Detection correctness

[Milestone](https://github.com/Karib0u/rustinel/milestone/2)

A focused patch release covering rule evaluation, deduplication windows, and
configuration test isolation. Each item causes Rustinel to report something and
to report it wrongly.

Deduplication work stays together: the window semantics and the rollup counters
are settled in one pass, so the sliding-window fix follows the `event.count`
over-counting fix in the same subsystem rather than in a later release.

## v1.4.0: Normalized-event capture and replay

[Milestone](https://github.com/Karib0u/rustinel/milestone/3)

Rustinel normalizes every sensor event into a single model, then discards it
unless a rule matches. This release makes that stream recordable and replayable:
a capture sink at the post-normalization boundary, a `rustinel capture` command,
and offline `rustinel replay` evaluation with no sensor and no privileges.

The release pairs capture with the collector fixes that determine what a
recorded event actually contains. That pairing is the point, not a coincidence.

**Why the normalization fixes ship in the same release.** A capture is only as
good as the event model it records, and replay depends on checked-in golden
fixtures. Absolute Linux file identity, Windows Kernel-File path resolution,
cross-platform `Modify` category alignment, and kernel argv capture all change
the content of a normalized event. Shipping capture first would freeze the
defective shape into every field recording and into the regression fixtures,
then require re-cutting them a release later — with the golden Sigma assertion
changing meaning underneath.

**Why Windows path work leads the file-identity thread.** Kernel-File events
carrying write semantics arrive with no path at all, while the events that do
carry paths are name-cache bookkeeping. Settling what `file_change` means comes
first; converging the platforms on a definition that is then revised would mean
doing the convergence twice.

**Why telemetry counters are a prerequisite.** Capture must never silently
discard events — loss has to be explicit in the manifest and the shutdown
summary. The received, dropped, and high-water counters provide that accounting,
and the flight recorder extends the same conventions rather than inventing a
parallel observability model.

**Replay owns a correctness prerequisite.** `NormalizedEvent` does not round-trip
losslessly today: `EventFields` must dispatch on the recorded event category
rather than untagged structural inference, and derived `EventID` state must be
rebuilt after deserialization. Until that is fixed, replay would silently
mis-evaluate rules.

Rotation, compression, and a custom capture archive format are deliberately
excluded. A size cap and plain NDJSON plus a JSON manifest cover the
malware-analysis and rule-authoring workflows and stay readable with ordinary
tools.

## v1.5.0: Endpoint flight recorder

[Milestone](https://github.com/Karib0u/rustinel/milestone/4)

When explicitly enabled, live protection retains a bounded rolling window of
normalized events and asynchronously preserves the behavior surrounding a
detection as an investigation package. The primary user is an incident
responder. Preservation is best-effort and must never delay normalization,
detection, alert output, or active response.

The recorder is disabled by default, local, and quota-bound. Overlapping
detections coalesce into a single package. Packages are replayable through their
`events.ndjson` recording, which is why the recorder follows capture and replay
rather than leading them — it reuses that recording format and the shared
normalized-event detector service instead of defining its own.

Windows is the first implementation and acceptance target, including the runtime
overhead gate; the architecture stays shared across platforms. Linux and macOS
validation is tracked as a follow-up and does not block the initial release.

Evidence acquisition, package encryption, remote upload, and package-aware
replay are out of scope.

## v1.6.0: Detection model and alert delivery

[Milestone](https://github.com/Karib0u/rustinel/milestone/5)

The Sigma and alerting thread deferred while capture landed: a pinned SigmaHQ
corpus smoke test, backend-neutral modifier and edge-case coverage, alert
construction and degradation tests, ECS 9.5.0, preserved Sigma metadata and
severity semantics, diagnostics for rules that cannot fire because no collector
provides their telemetry, and the generic webhook sink.

ECS 9.5.0 lands before the metadata and severity model changes, so the output
schema moves once rather than twice. The webhook sink introduces the
multi-destination sink abstraction that native OS log sinks later reuse.

## Unscheduled backlog

[All open issues without a milestone](https://github.com/Karib0u/rustinel/issues?q=is%3Aissue+is%3Aopen+no%3Amilestone)

These items are active but not committed to a release, either because they
depend on foundations above or because they need additional design.

**The RSigma transition.** Making RSigma the default evaluation backend depends
on testing every advertised runtime capability, restoring match-debug parity,
reconciling parser and runtime capability documentation, and resolving the
evaluator licensing strategy. The built-in backend is expected to remain
available throughout the v1.x series; its removal, if it becomes appropriate, is
reserved for a future major release.

**Work gated on earlier releases.** Relative argv paths in `CommandLine` rules
close the second half of a path-evasion gap and depend on kernel argv capture.
Expanded Linux file telemetry builds on absolute path identity. Per-rule
compatibility diagnostics depend on inert-rule reporting and the capability
documentation reconciliation, and the epic should be split first. An optional
all-matches Sigma mode is unblocked but low priority. Bounded periodic YARA
memory sweeps depend on scan timeouts and file-size guards.

**Work needing design or external resolution.** Stateful Sigma correlation and
temporal evaluation is the largest open design question; because the flight
recorder is fundamentally a temporal artifact, the design pass belongs alongside
the recorder work rather than long after it. Replacing macOS BPF capture with a
NetworkExtension flow source is blocked on Apple entitlement and distribution
requirements. Native OS log sinks follow the webhook sink. Atomic rules-pack
updates, Linux container and cgroup context, and a `cargo-nextest` evaluation
carry no dependency, only priority.

The complete backlog is available in
[GitHub Issues](https://github.com/Karib0u/rustinel/issues).
