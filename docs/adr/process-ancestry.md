# Bounded process ancestry for Sigma

Process creation rules need to identify a process by its ancestors even when an intermediate process changes the immediate parent.

## Decision

Expose `GrandparentImage`, `GrandparentCommandLine`, and `AncestorImages` as conditional, derived fields in the Sysmon-compatible process creation view on Windows, Linux, and macOS.
The two scalar fields come from the second ancestor.
The array contains known images from the nearest eight ancestors in order, including the parent and excluding the event's own image.
Eight levels cover multiple intermediates while keeping the work and output bounded.
The process creation event records the values for replay.

Process starts and fork inheritance retain the observed parent's start key alongside the existing parent PID.
Normalization follows those exact identities in the live cache and in the retired cache for up to 60 seconds after retirement, subject to capacity.
The walk stops before a repeated identity and at the first missing or expired link.
A replacement with the same PID cannot fill the gap.
Captured values retain any known fidelity limitations from their source fields.

An inventory entry for a pre-agent process can contribute its cached image or command line when the sensor resolves the entry's stable identity.
Its PID-only parent relationship ends the walk.
A process missing from inventory or telemetry contributes no value.
Inventory describes the process as seen at startup, and subsequent observations can update metadata for the same identity.
A native identity that survives an exec can therefore expose the image currently held for that identity at normalization time.
This is a bounded view of observed host state.

## Cost

The parent start key adds eight bytes per cached process (376 to 384 bytes measured on arm64).
At the default cap of 65,536 entries in each of the live and retired caches, the extra metadata is 1 MiB across both tables before allocator and hash-table slack.
Each walk takes one live-table read lock and, on the first live miss, one retired-table read lock.
It checks at most eight keys with up to two hash lookups per key, and reuses the clock reading for the cache insert.
It issues no OS process queries.
Event enrichment copies only the known images and the grandparent command line.

An optimized, single-threaded microbenchmark of the cache walk on an Apple M1 Max visited one live ancestor in about 39 ns and eight live ancestors in about 389 ns.
Eight ancestors with the oldest retired took about 353 ns.
Each figure is the median of seven batches of one million walks over the same cached chain.
The visitor borrowed each image, so these figures isolate cache traversal from event allocation, Sigma evaluation, and lock contention.

## Sigma selectors

In rsigma-eval 0.27.0, scalar string matchers apply to each array member.
For example, `AncestorImages|endswith: '\w3wp.exe'` matches when any cached ancestor image has that suffix.
A YAML list under the same field ORs the rule values by default.
Adding `|all` requires every rule value to match somewhere in the array, potentially on different members.
For same-member predicates, `sigma-version: 3` supports an `AncestorImages[any]` block with `.` referring to each image.
These forms are covered by evaluation tests.
See the [Sigma array matching proposal](https://github.com/SigmaHQ/sigma-specification/issues/212) and the [pinned evaluator](https://docs.rs/crate/rsigma-eval/0.27.0).
