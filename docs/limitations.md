# Limitations

What Rustinel cannot see or do.
Items marked **Silent** make a rule quietly not fire, with no error.
Check them before relying on a detection.

Fields each platform never fills are listed in [Field availability](field-availability.md).

## Scope

- **Detection, not protection.**
  No anti-tamper, pre-execution blocking, or quarantine, and response happens after the fact.
  See [Security model](security.md#scope).
- **Written-file scanning depends on sensor identity.**
  A file event without object identity is skipped and counted rather than opened by path alone.
  Windows reads the identity from the path milliseconds after the event, so a file replaced within that gap is not detected as a replacement, and files on network volumes are not scanned.
  Windows cache flushes by the System process do not queue a second scan, so content written only through a memory-mapped view after the settle delay is not rescanned.
  Unsupported extensions without a recognized file signature are not scanned.
  Memory scanning is optional and needs privileges.
- **Memory-only and living-off-the-land activity** leaves little telemetry.
- **Out of scope by decision.**
  Other platforms, cross-host correlation, software inventory, vulnerability exposure, and blocking are boundaries, see [Not in scope](coverage.md#not-in-scope).

## Detection engine

- **Silent: rules without a collector.**
  A rule for a logsource the platform does not collect loads and never fires, see [Platform coverage](coverage.md).
- **Silent: fields never filled.**
  A rule that needs a field listed in [Field availability](field-availability.md) never matches.
  `rustinel sigma doctor` reports the affected rule and field, while respecting alternatives and negation in the rule condition.
- **Unsupported modifiers reject the rule.**
  The rule is dropped at load and reported, never partly applied.
- **One Sigma alert per event by default.**
  When several rules match an event, only the highest severity one is reported, unless `scanner.sigma_match_mode = "all"`.
  Correlation alerts are added separately.
- **Correlation state resets on reload.**
  Open windows are forgotten when Sigma rules reload.

## Pipeline

- **Events are dropped under bursts.**
  Queues shed events instead of blocking the sensor.
  Drops are counted, see [Telemetry loss](telemetry-loss.md), but there is no sampling or prioritization.
- **Written-file scans can be shed under pressure.**
  Written files use an 8,192-job queue and a separate table of up to 8,192 path and object targets settling for 250 ms.
  At table capacity, each new target checks up to 64 pending paths and frees slots for files that have vanished, continuing from the previous check on the next arrival.
  If the queue is full or that check frees no slot, the new file is not scanned by YARA or hash IOCs and is counted under `artifact_resolver.written_file_dropped`.
  Base file telemetry and Sigma evaluation still run; `rustinel doctor` reports shed scans as a detection gap.

## Windows

- **`Hashes`, `Imphash`, `Signed`, `Signature`, and `SignatureStatus` arrive after the event.**
  Rules on them run up to 2 seconds later, read the file as it is then, and cannot match in replay.
  Signature fields are absent, not `false`, when verification did not finish, for files in an AppX or MSIX package that the signed block map does not list, and revocation is not checked.
  See [Deferred pass](detection.md#deferred-pass).
- **Command lines can be missing or cut.**
  The ETW source cuts command lines at 1,024 characters.
  Rustinel reads the full value from the live process when it still exists and marks it `derived`.
  A process that exits first keeps the short value, or none.
- **Silent: registry paths are NT paths.**
  `TargetObject` starts with `\REGISTRY\MACHINE\...`, never `HKLM\...`, so `startswith: 'HKLM'` does not match.
- **Some registry and file writes have no path.**
  They are dropped and counted (`registry_path_resolution`, `file_path_attribution`).
  Writes by protected system processes are the usual cause.
- **Silent: registry value data relies on an undocumented ETW option.**
  If a Windows update removes it, `Details` is empty and a warning is logged at startup.
  Binary values appear as `Binary Data`.
- **Windows updates can change ETW event layouts.**
  Records that no longer decode are counted as `etw_decode`.
- **Extreme process bursts can overflow ETW buffers.**
  The loss is logged as a warning, and a recording made during it is marked incomplete.
- **Silent: Security events need audit policy.**
  Windows audits logons, account and group changes, and audit policy changes by default, but not scheduled tasks, registry values, credential validation, or the filtering platform.
  See [Windows host logging](windows-logging.md).
- **Silent: only the Security event IDs listed in [Windows Security events](windows-security-events.md) are collected.**
  Rules for other IDs never match.
- **Silent: connection audit events are off by default.**
  5156, 5157, and 5152 are read only with `windows.security_filtering_platform_connections = true`.
- **Silent: domain controller audit events are off by default.**
  4768, 4769, 4662, 4742, 4661, 4673, 5137, and 5141 are read only with `windows.security_domain_controller_events = true`.
- **Silent: WMI event IDs are not Sysmon's.**
  `wmi_event` rules that select on `EventID` never match.
  Permanent subscription bindings emit native 5861 events under `service: wmi`.
  Existing subscriptions are not enumerated at startup, and removing a binding does not emit another 5861 event.
- **PowerShell:** script block and module content is limited to Windows PowerShell 5.1.
  Classic engine starts include version 2 through event 400.
  PowerShell 7 is not collected.
  Module logging (4103) needs host policy, and its text is in the host's language.
- **No telemetry** for named pipes, process tampering, or network data volume, and not yet for remote threads, process access, or file reads.
  Named pipes and process tampering need a kernel driver.
  The rest are planned, see [Platform coverage](coverage.md#telemetry-that-is-missing).
- **Injection needs a driver or a protected process.**
  APC injection, remote memory writes, and the true `GrantedAccess` of a process handle come from the Threat Intelligence provider, which only a protected process light can consume.
  Rustinel ships no driver and does not run as one, so these stay out of reach.
  Process access is planned from Kernel-Audit-API-Calls, which does not carry `GrantedAccess`.
- **`IntegrityLevel`** exists on process start events only.

## Linux

- **Kernel 5.8 or later.**
  Many restricted containers cannot load eBPF.
- **Some stable kernels run syscall hooks on CPU 0 only.**
  Ubuntu `7.0.0-38` and 7.1.y kernels from 7.1.6 carry a backport that skips eBPF programs on syscall tracepoints that copy user memory, such as `openat` and `unlink`, on any CPU without a perf event.
  Rustinel opens a counting perf event on every online CPU for those tracepoints, so file events are seen on all CPUs.
  If it cannot, for example at the open-file limit, `doctor` reports the hook as `(per-CPU)` under `linux_ebpf_file_capability` and file events made on the uncovered CPUs are missed.
  CPUs brought online after startup are not covered until Rustinel restarts.
- **Long values are cut.**
  `Image` at 255 bytes, `CommandLine` at 512 bytes, 32 arguments, or 127 bytes per argument, and file paths at 511 bytes.
  Cutting removes the end, which is what `|endswith` and extension indicators match, see [Fields](sigma.md#fields).
- **`Image` is the path given to `execve()`**, so it can be relative.
  A process that rewrites its own arguments reports the originals.
- **Process artifact scans need a readable process context.**
  YARA file and hash IOC scans can miss a container process that exits before resolution or whose `/proc` entries cannot be read.
  Artifact resolver failures are counted in [doctor](doctor.md).
- **Scripts need a file snapshot.**
  Without a sensor-provided file identity, the artifact worker measures script identity when it resolves the path.
  A script changed before this snapshot can be scanned as its later version.
  A removed file or a change after the snapshot can prevent scanning.
- **Relative scripts use the process's live working directory.**
  A changed directory can prevent scanning the original script.
- **File events whose path cannot be rebuilt are dropped** and counted as `unresolved_file_events`.
- **Silent: stale directory descriptors.**
  A file path relative to a directory descriptor opened before Rustinel started, duplicated, inherited, or opened without `O_DIRECTORY` is resolved through `/proc` a moment later.
  If the process reused the descriptor number by then, the path is wrong.
- **`..` is collapsed as text**, without following symlinks.
- **Silent: network source fields need BTF.**
  Without kernel BTF, only outgoing connections are seen, and `SourceIp`, `SourcePort`, and `Protocol` are empty.
  `doctor` warns with `linux_ebpf_network_tuple_capability`.
- **Loopback connections and failed connects are not reported.**
  A connect still in progress is reported and not retracted if it later fails.
- **Process identity fields need BTF.**
  Without it, `User` and related fields are empty and `doctor` warns with `linux_task_<field>`.
- **File object identity needs BTF.**
  Without it, file events still use syscall paths and success checks, but inode and device identity are unavailable.
  `doctor` reports the unavailable `file_identity` hook.
- **Parent identity** is derived for `CLONE_PARENT`, and can be missing for processes that started before Rustinel.
- **Container context is on process start events only**, and needs cgroup v2.
  File, network, and DNS events do not carry `ContainerId`, and on a cgroup v1 host the container fields are always empty.
- **Silent: unrecognized container layouts look like host processes.**
  Docker, containerd, CRI-O, Podman, and LXC are recognized.
  Any other runtime, such as systemd-nspawn, gives a `CgroupPath` and no `ContainerId`.
- **Only the container ID and runtime are reported**, from the cgroup path.
  No name, image, or labels: Rustinel never queries a runtime socket.
- **Containers are identified by cgroup, not namespace.**
  `nsenter` without a cgroup change keeps the caller's attribution.
  A container removed before a backlogged event is enriched leaves that event unresolved, never reported as the host.
- **DNS:** plain DNS to port 53, over UDP or TCP.
  Queries come from `sendto`, `sendmsg`, `sendmmsg`, and `write`, and responses from `recvfrom`, `recvmsg`, `recvmmsg`, and `read`.
  Answers are decoded for A, AAAA, and CNAME records within the first 512 bytes of a response.
  A socket connected to port 53 before Rustinel started is missed until it is reopened.
  Without kernel BTF, queries and responses carried by `write` and `read` are missed, as the pure-Go resolver sends them.
  `RecordType` is `OTHER` for anything but A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, and ANY.
  `QueryStatus` is the DNS response code, such as `0` for success and `3` for NXDOMAIN, not a Windows status code.
- **DNS over TCP** is seen only when the message and its two-byte length arrive in one buffer, or in the two `sendmsg` buffers BIND and `dig` use.
  A resolver that sends the length separately with `writev`, as glibc does, is missed for queries.
  Its responses are read in two parts, and the message part is still captured.
  A stream read that returns a fragment of a message is not reassembled.
- **Silent: DNS over TLS and HTTPS are not visible.**
  The traffic is encrypted and no hook sees the name.
  Port 853 is not watched, and a DoH client looks like any other HTTPS connection.
- **Names are kept up to the 512-byte capture limit.**
  A legal name is at most 253 characters, which fits.
  A name that runs past the limit, as a non-compliant tunnel can send, is reported as far as it was read, with `QueryTruncated` set to `true` and no `RecordType`.
  Only the first `iovec` of a datagram, or the first two for a TCP query, is read.
- **No telemetry** for library loads, kernel module loads, ptrace, or file timestamp changes (`file_change`).
  Sensitive file reads are planned, see [Platform coverage](coverage.md#telemetry-that-is-missing).

## macOS

macOS support is experimental.

- **Only process and file events come from Endpoint Security.**
  No image load, script, WMI, service, or task equivalents, and no `file_change`.
- **Network and DNS come from packet capture.**
  They are matched to a process through a socket list refreshed every 250 ms, so short connections can stay unattributed.
- **Silent: `Initiated` is always absent.**
  A packet capture cannot tell who opened a connection, so rules on it never match.
- **New interfaces are picked up within 5 seconds.**
  Packets on an interface that comes up, such as a VPN, are missed until then.
  A packet seen on two interfaces can produce two events.
- **No reassembly.**
  IP fragments are not joined, and DNS over TCP must fit in one segment.
- **Silent: parent fields need an observed parent.**
  `ParentImage` and `ParentCommandLine` are empty unless Rustinel saw the parent's exec or found it running at startup, and has not evicted it.
- **Memory scanning is mostly unavailable.**
  It needs `task_for_pid`, which macOS denies to most callers.
  Denied scans return nothing.
- **Some processes cannot be killed.** macOS protects SIP processes even from root.
  The failure is logged.
