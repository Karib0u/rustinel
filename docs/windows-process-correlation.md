# Windows process metadata correlation

Issue #393 adds a classic process system logger alongside the manifest
Kernel-Process session. Manifest records remain the sole source of normalized
process creations, full executable paths, creation FILETIME, and integrity
level. Classic Start records supply the creation-time command line and WBEM SID.
Executable identity is never inferred from the command line.

The correlator requires equal PID and parent PID, a classic timestamp no earlier
than manifest CreateTime, and source timestamps within 1 ms. Known classic end
times bound the lifetime. Ambiguous candidates remain unmatched. The reorder
window is two seconds of monotonic arrival time, with a shared 4,096-record
capacity and an independent 50 ms expiry worker. Expiry and capacity eviction
release pending manifest events using their previously captured fallback.
Stops waiting behind a creation are released after it. Unpaired classic records
never produce an additional creation.

UniqueProcessKey is used only as a classic kernel-object identity for end
observations. It is never assigned to ProcessStartKey.start_time. DCStart seeds
bounded classic object state but cannot match a new creation or emit an alert;
existing process-cache initialization continues to use the startup snapshot.
The classic logger builder accepts additional kernel providers for future file
rundown work. Its buffers, flush interval, lifecycle, and loss accounting are
separate from the two manifest sessions.

The live-query fallback checks CreateTime and reads the command line through
the same process handle. It is captured immediately in the manifest callback,
not after the reorder wait. If classic collection fails, pending records are
released and subsequent manifest records pass through immediately. The failure
is counted. Classic flushing uses the existing process flush interval; zero
retains native timer delivery.

## Evidence and diagnostics

`WindowsProcessMetadata` retains the command-line source (`classic` or
`live_query`), raw SID, session ID, and any conflicting live-query command line.
ECS carries the same evidence under `edr.process.windows_metadata`, and preserves
the raw SID in `user.id` even after account-name resolution. Recording round
trips preserve both evidence and sparse Derived provenance. Live-query command
lines, conflicting live-query evidence, and resolved account names are Derived.
SID resolution uses the existing asynchronous queue; its positive and negative
cache is bounded at 4,096 entries. Failed lookup preserves the raw SID.

`telemetry.json` and `doctor` expose `windows_process_correlation`:

- `matched`, `unmatched`, and `conflicting` are distinct manifest outcomes.
- `classic_unmatched` counts expired or evicted classic Starts.
- `classic_command_line` counts command lines taken from classic payloads.
- `classic_records`, `rundown`, `decode_failed`, and `session_failures` describe
  collection independently of normalized creations.

A conflicting pair normally uses the creation-time value but retains the queried value,
logs a warning, and makes doctor report a warning. The existing final
command-line attempted/captured/missed counters remain unchanged in meaning.

**Long command lines have a measured source limit.** On the tested Windows 11
build, a 20,058-character command line was only 1,024 UTF-16 characters in the
classic payload. The live query retained the complete value. All ten such
controlled cases were reported as conflicts, with both values retained. The
`command_line_may_be_truncated` flag identifies classic values at this observed
boundary. It is a conservative heuristic, not a guarantee that other lengths
are complete. When the classic value reaches this boundary and the verified
live-query value is strictly longer with exactly the same prefix, detection
uses the live value, marked Derived. The original classic value is retained in
`classic_command_line`; the pair remains counted as conflicting. Different
prefixes, shorter values, and values below the observed boundary do not trigger
this recovery. Without a live backup, detection still has only the truncated
classic value. The native recovery rerun selected the full live value for all
ten controlled long-command-line events, with Derived provenance and the
original classic prefix retained. No additional Sigma rule coverage is claimed.

## Repeatable comparison

Build `examples/windows_process_capture.rs` against both the baseline and the
modified source using the same profile, then copy each executable before
building the other. The baseline used here is main commit
`2cf83757751acfd09fe74c5c3c9ad2bdc01c6157`. Run as administrator, without another
instance using the same Rustinel session names:

```powershell
cargo build --locked --example windows_process_capture
.\target\debug\examples\windows_process_capture.exe 100 50 > capture-100-50.json
.\target\debug\examples\windows_process_capture.exe 300 10 > capture-300-10.json
.\target\debug\examples\windows_process_capture.exe 500 0 > capture-500-0.json
.\target\debug\examples\windows_process_capture.exe 100 10 wow64 > capture-wow64.json
.\target\debug\examples\windows_process_capture.exe 10 10 long > capture-long.json
.\target\debug\examples\windows_process_capture.exe 100 10 native 0 > capture-delayed.json
```

Arguments are child count, launch spacing in milliseconds, optional workload
variant, and optional process flush interval. Children are short-lived cmd.exe
processes carrying unique Unicode markers. The helper retains child handles
until launch completes, waits for exit, drains for three seconds, and shuts down
the sensor. JSON contains expected PIDs/markers, normalized events, delivery
latency, process CPU seconds, ETW loss, and a telemetry snapshot. Summarize with:

```sh
python scripts/bench/windows-process-correlation.py capture-*.json
```

These are sensor and normalizer measurements with debug builds, not release
throughput or full detection-pipeline benchmarks. CPU is total helper process
CPU, including startup, shutdown, and the six seconds of warmup/drain. Runs were
sequential on the six-vCPU, 8 GiB Windows lab on 2026-09-10. Spacing is requested
spacing; process launch overhead lowers the achieved rate.

| Workload | Mode | Actual starts/s | Creations | Complete command lines | p95 latency ms | CPU seconds | ETW loss |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100, 50 ms | Manifest | 17.8 | 100/100 | 100/100 | 4.79 | 0.69 | 0 |
| 100, 50 ms | Hybrid | 17.8 | 100/100 | 100/100 | 5.45 | 0.92 | 0 |
| 300, 10 ms | Manifest | 62.4 | 300/300 | 300/300 | 4.83 | 1.73 | 0 |
| 300, 10 ms | Hybrid | 63.0 | 300/300 | 300/300 | 5.21 | 1.58 | 0 |
| 500, burst | Manifest | 174.8 | 500/500 | 497/500 | 5.20 | 1.91 | 0 |
| 500, burst | Hybrid | 181.8 | 500/500 | 500/500 | 5.66 | 2.36 | 0 |
| 100, WOW64 | Manifest | 61.9 | 100/100 | 100/100 | 4.77 | 0.61 | 0 |
| 100, WOW64 | Hybrid | 62.8 | 100/100 | 100/100 | 5.55 | 0.72 | 0 |

In the 500-child burst, Image, ProcessStartTime, ParentProcessId, and
IntegrityLevel were present in 500/500 events in both builds. User was present
in 0/500 baseline events and 500/500 hybrid events.

No workload produced duplicate creations. All controlled hybrid command lines
in this table came from classic records. With forced flushing disabled, all
100 markers were still captured after the children had exited, with 979.7 ms
p95 latency. Stopping only the classic session before launching 100 children
produced 100 immediate manifest fallbacks, all marked Derived, and counted one
session failure plus 100 unmatched joins.

The source probe also observed startup records for System, csrss.exe, and
lsass.exe, including their raw S-1-5-18 SID. System's empty command line remained
an empty string. These are startup observations, not a test of creating a new
protected process. Unit tests separately cover empty/Unicode/long strings,
32-bit and 64-bit WBEM SID layouts, invalid SID lengths, exact-lifetime live
queries, PID reuse, source skew, ambiguous joins, reverse arrival, stop ordering,
expiry/capacity, rundown suppression, recording, and ECS evidence.

The earlier parallel-session non-observation was not reproduced: a fresh
source probe paired all 100 controlled Starts, and the integrated runs above
also received both sources. In the fresh probe the paired source timestamps
differed by 2.6 to 9.7 microseconds. The original transient cause remains
undetermined; coexistence is supported by these repeatable measurements, not
assumed from successful session creation alone.

References: [classic process layout](https://learn.microsoft.com/en-us/windows/win32/etw/process-typegroup1)
and [system logger multiplexing](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session).

## Validation

The native Windows suite passed 577 tests across 34 suites, with eight existing
manual/environment tests ignored. The final Windows library rerun passed all
450 tests. The macOS library suite passed all 385 tests. Clippy with
`--locked --all-targets -- -D warnings`, formatting, and whitespace checks passed
on the final changes (Clippy on both platforms).

The first full Windows integration build hit MSVC PDB generation limit LNK1318.
The successful retry used one build job and `_LINK_=/DEBUG:NONE` for that shell
only; repository build settings were not changed. These settings affect symbol
generation, not the test assertions or the previously recorded comparison runs.
