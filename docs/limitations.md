# Limitations

Rustinel is a transparent, rule-based endpoint detection engine. Like any
detection system it has boundaries - and because Rustinel is open source, we
document them in full rather than hide them.

This page documents Rustinel's known limitations for the current release.

> **Reading guide.** Items marked **silent risk** are the most important: they can
> cause a rule to *not fire* - or match the wrong thing - with no error. Check
> these before you rely on a detection.

## Highest impact: detections that can silently not fire

| Limitation | Area |
| --- | --- |
| Registry value *data* is never captured; `Details` holds the value *name* instead | Windows |
| Process events carry no hashes (`Hashes` / `Imphash`) | Windows |
| Command line is lost for short-lived processes | Windows | Linux |
| No stateful correlation or filter evaluation; unsupported documents are reported at load time | Engine |
| Rules are silently inert when no collector backs their logsource | Engine |
| Telemetry is dropped under burst load (no backpressure) | Pipeline |

---

## Windows (ETW)

Rustinel collects Windows telemetry through ETW rather than a kernel driver.
Coverage is the broadest of the three platforms, but several Sysmon-style fields
are unavailable.

- **Registry value data is not captured (silent risk).** Unlike Sysmon, `Details`
  maps to the registry *value name*, not the data written to it - the
  Kernel-Registry provider doesn't emit value data. A rule matching on written
  content silently matches the value name instead.
- **Registry `TargetObject` is a relative path (silent risk).** Full key paths
  (e.g. `HKLM\...\Run`) aren't resolved, so `endswith`-style key matches may miss.
- **No process or image-load hashes (silent risk).** There is no `Hashes`/`Imphash`
  on process or image-load events, so the many Sigma rules keyed on them can
  never fire. Hash matching exists only in the file/IOC scanner.
- **Some process fields are always empty.** `IntegrityLevel`, `User`, `LogonId`,
  `LogonGuid`, `ParentCommandLine`, and often `CurrentDirectory` aren't populated
  by the provider; rules filtering on them won't match.
- **Command line lost for short-lived processes (silent risk).** When ETW omits
  `CommandLine`, it is back-filled by querying the live process - fast-exiting
  processes are already gone, exactly when it matters most.
- **PowerShell 7 (`pwsh`) is not covered.** Only Windows PowerShell 5.1
  script-block telemetry is collected; PowerShell Core uses a different provider.
  No module logging.
- **No network data-volume telemetry.** Only connect / disconnect / accept
  survive; bytes-sent/received events are dropped, so exfil-by-volume heuristics
  aren't possible.
- **DNS `QueryType` is always empty.** The DNS record type is not populated on
  Windows.
- **No injection or driver-load visibility.** No equivalent of CreateRemoteThread,
  ProcessAccess, named-pipe, or driver-load providers - injection-based TTPs leave
  little telemetry.
- **Writes through handles opened before startup are invisible (silent risk).**
  Kernel-File reports writes by kernel pointer, not by path, so the sensor learns
  each handle's path from the `Create` that opened it. A handle already open when
  the sensor starts was never seen being named, so writes through it cannot be
  attributed and are dropped rather than reported without a path. Long-lived
  holders - database files, service logs - stay unobserved until the handle is
  closed and reopened, which for some services means until the next reboot.
  The count is logged as `unresolved_file_events`, so the size of the gap is
  visible even though the events themselves are not.

## Linux (eBPF)

The Linux sensor covers process, network, file, and DNS.

- **Kernel-captured argv is bounded.** Argv is snapshotted in eBPF at
  `execve`/`execveat` entry, so a process that exits before userspace drains the
  ring still reports its command line. The capture is capped at 512 bytes total,
  32 arguments, and 127 bytes per argument; past any of those the event is
  flagged truncated and the loader falls back to `/proc/<pid>/cmdline`, which is
  complete but only readable while the process is alive. A command line longer
  than the caps *and* a process that exits first is the remaining gap, and it
  yields a truncated command line rather than an empty one. A process that
  changes its own argv after `execve` (`setproctitle`) reports what it was
  launched with, not what `/proc` would show later.
- **Paths are truncated.** The image path is capped at 128 bytes and `comm` at
  16, which can break `Image|endswith` matches. This only affects processes that
  exit before enrichment: `Image` normally comes from `/proc/<pid>/exe`, which is
  absolute, symlink-resolved, and untruncated. The raw kernel `execve()` argument
  is the fallback, and it is both truncated and possibly relative.
- **File paths are capped at 511 bytes, and the overflow is marked.** File events
  capture each path in a fixed kernel buffer. A longer path is cut and the event
  carries `PathTruncated` (`edr.file.path_truncated` in ECS) naming which side
  was cut, so a consumer can tell an incomplete path from a complete one. Since
  truncation removes the end of the path, `|endswith` rules and extension IOCs
  are the ones it defeats.
- **File events whose path cannot be placed are dropped (bounded, counted).**
  `openat`, `unlinkat`, and `renameat*` name their target with a directory
  descriptor plus a name that may be relative to it, and the kernel does not
  expose the resolved path on these tracepoints. A working-directory-relative
  name is placed with `/proc/<pid>/cwd` when the ring is drained; a
  descriptor-relative one with the index described below. A process that exits
  before the drain leaves a name neither source can place, and it is dropped
  rather than reported as if it were a path — `TargetFilename` of `passwd` would
  match rules written for `/etc/passwd`. The running total is logged as
  `unresolved_file_events`.
- **Descriptors opened without `O_DIRECTORY` keep the stale-fd race (silent
  risk).** Directory descriptors are normally named when they are opened: the
  sensor watches `openat` with `O_DIRECTORY` or `O_PATH` and indexes the
  resulting `(pid, fd)`, which is what `opendir(3)` and the directory readers in
  Go, Rust, and Java all use. A descriptor the index never saw - opened before
  the sensor started, produced by `dup` or inherited across `fork`, or opened
  with a bare `O_RDONLY` (legal for a directory; CPython's `shutil.rmtree` does
  exactly this) - falls back to reading `/proc/<pid>/fd/<dfd>` at drain time,
  milliseconds after the syscall. A process that walks a tree recycles fd
  numbers faster than that, so the answer can name a different directory, and
  nothing observable distinguishes it from the ordinary case. Measured on a lab
  VM, one `rmtree` produced two such paths. Widening the index to every
  read-only open closes the gap but costs 20-29% on a file-read-heavy workload
  (`tar -cf /dev/null /usr/share`) against ~0% for the current filter, so it is
  not done. A descriptor reused for a *non*-directory is always caught, because
  `/proc/<pid>/fd` reports those as `socket:[…]` rather than a path.
- **`..` is collapsed lexically**, not by walking the filesystem, since the file
  a delete or rename names is usually gone by the time the event is drained.
  That differs from the kernel's resolution only when a path component is a
  symlink.
- **DNS is UDP port 53 only.** DNS-over-TCP, DoH (443), and DoT (853) are
  invisible; long query names are dropped, QTYPE is limited to
  A/NS/CNAME/PTR/TXT/AAAA, and answers (`QueryResults`) aren't parsed.
- **Network is outbound `connect()` only.** No inbound / `accept()` visibility;
  failed connections are still logged (captured at syscall entry); plain UDP
  `sendto` isn't seen; only AF_INET / AF_INET6.
- **No library-load, module-load, or ptrace events.** Sigma rules in those Linux
  categories never match.
- **Kernel requirements.** Needs Linux 5.8+ with BTF and
  `CAP_BPF`, `CAP_PERFMON`, and `CAP_NET_ADMIN`, or `CAP_SYS_ADMIN`; older or BTF-less kernels and many restricted
  containers are unsupported.

## macOS (ESF) - experimental

macOS support is experimental and detection-only.

- **Process and file events only from Endpoint Security.** No image-load, script,
  WMI, service, or task equivalents.

### macOS Network and DNS Attribution

- **Network/DNS attribution is best-effort.** Telemetry comes from `/dev/bpf`
  capture, not a per-process hook: connections are matched to processes by port
  (racy), DNS events aren't attributed to a process, and capture binds to a
  single interface (default `en0`, override with `RUSTINEL_BPF_INTERFACE`).

### macOS Memory Scanning

- **Memory scanning is restricted.** YARA memory scanning uses `task_for_pid`,
  which generally needs root plus SIP/AMFI relaxation or an entitlement; when
  denied it returns nothing.
- **No active response.** Process termination is unsupported on macOS -
  detection only.

## Detection engine (Sigma)

- **No stateful correlation or filter evaluation (explicit runtime boundary).**
  Each event is matched independently - no state, window, count, or throttle.
  Sigma correlation (`event_count`, `value_count`, `temporal`,
  `temporal_ordered`) and legacy aggregations (`| count() by ...`, `near`) are
  unsupported, so brute-force, beaconing, and "N events in M minutes"
  detections can't be expressed. Sigma filter documents are not applied. The
  RSigma parser recognizes both document types, but Rustinel reports them as
  unsupported with source context and counts them in load and reload summaries.
- **Unsupported modifiers reject the whole rule.** A rule using a modifier
  outside the supported set (e.g. `|expand`, `|gzip`, `|minlength`) is dropped at
  load, not partially matched.
- **Rules are inert without a backing collector (silent risk).** Rules for a
  product/category the running platform doesn't collect will load but never fire.
  On Linux/macOS a large share of a Windows-oriented ruleset is effectively dead
  weight - don't read rule count as coverage.

## Pipeline & operations

- **Telemetry is dropped under load (silent risk).** Sensor channels are bounded and
  drop on overflow, with only a periodic warning. Under burst load you get silent
  detection gaps, not slowdown.
- **Rules catalog trust is release-bound in Phase 1.** `rustinel rules install`
  trusts HTTPS GitHub release assets from `Karib0u/rustinel-rules` and requires
  the artifact SHA-256 from the released catalog to match before activation. The
  catalog is not separately signed in this phase, so protect release publishing
  credentials and review release assets before promoting them.
- **Active response is kill-after-the-fact.** The only response is process
  termination, fired after the event is processed - the process may already have
  done its work or exited. A PID-reuse race is narrowed by identity checks but not
  eliminated. There is no quarantine, file deletion, network isolation, or
  registry rollback.
- **No self-protection or tamper resistance.** A privileged attacker can stop the
  ETW trace, unload eBPF, or kill the agent.

## Detection philosophy & posture

- **Not a commercial EDR replacement.** Rustinel uses ETW on Windows rather than
  a kernel driver - simpler and more stable, but without a driver's visibility or
  enforcement points. It is not designed to detect kernel-mode rootkits,
  vulnerable-driver abuse, or direct telemetry tampering.
- **IOC matching is only as good as its indicators.** It is deterministic and
  fast, but hashes, IPs, domains, and path regexes should complement behavioral
  detection, not stand alone. Encrypted C2 over trusted infrastructure often
  evades IOC matching and needs behavioral signals.
- **Memory-only and living-off-the-land activity is hard.** Payloads that never
  touch disk, and abuse of legitimate admin tools, may produce little useful
  telemetry. YARA memory scanning helps against packed and runtime-unpacked
  payloads but is optional and privilege-dependent.

## How to think about Rustinel

Rustinel is a transparent open-source detection engine - best for detection
engineering, telemetry collection, rule development and testing, SIEM pipeline
validation, research, lab deployments, and blue-team experimentation. It should
not be presented as a full commercial EDR replacement today.

## Planned improvements

- Richer process telemetry (hashes, more reliable command line) and additional
  providers
- Correlation / temporal rule support
- Backpressure and load-shedding visibility
- Scheduled YARA memory sweeps and richer memory match metadata
- macOS hardening toward production readiness
- Continued documentation of operational security and limitations
