# Limitations

What Rustinel cannot see or do.
Items marked **Silent** make a rule quietly not fire, with no error.
Check them before relying on a detection.

Fields each platform never fills are listed in [Field availability](field-availability.md).

## Scope

- **Not a commercial EDR.**
  No kernel self-protection, pre-execution blocking, anti-tamper, or management console.
  A privileged attacker can stop the ETW trace, unload the eBPF programs, or kill the agent.
- **Response happens after the fact.**
  The only action is killing the process, after its event was processed.
  It may have finished already.
  There is no quarantine, file deletion, network isolation, or rollback.
- **Written-file scanning depends on sensor identity.**
  A file event without event-time object identity is skipped and counted rather than opened by path alone.
  Unsupported extensions without a recognized file signature are not scanned.
  Memory scanning is optional and needs privileges.
- **Memory-only and living-off-the-land activity** leaves little telemetry.
- **Rule packs are not signed.**
  `rules install` trusts HTTPS GitHub release assets and checks their SHA-256 against the catalog, which is not signed itself.

## Detection engine

- **Silent: rules without a collector.**
  A rule for a logsource the platform does not collect loads and never fires.
  `rustinel doctor` counts them as `sigma_rules_inert`.
  Rule count is not coverage.
- **Silent: fields never filled.**
  A rule that needs a field listed in [Field availability](field-availability.md) never matches.
  `rustinel sigma doctor` reports the affected rule and field, while respecting alternatives and negation in the rule condition.
- **Unsupported modifiers reject the rule.**
  The rule is dropped at load and reported, never partly applied.
- **One alert per event.**
  When several rules match an event, only the highest severity one is reported.
  Correlation alerts are added separately.
- **Correlation state resets on reload.**
  Open windows are forgotten when Sigma rules reload.

## Pipeline

- **Events are dropped under bursts.**
  Queues shed events instead of blocking the sensor.
  Drops are counted, see [Telemetry loss](telemetry-loss.md), but there is no sampling or prioritization.

## Windows

- **`Hashes` and `Imphash` arrive after the event.**
  Rules on them run in a separate pass, up to 2 seconds later, and see the file as it is when it is read.
  An executable or DLL replaced right after it starts or loads is hashed as the replacement.
  Images larger than 128 MB, unreadable images, and images the resolver cannot reach in time are evaluated without the fields.
  Recordings do not carry these fields, so replay cannot reproduce a match that needed them.
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
- **Silent: only the Security event IDs listed in [Sigma rules](sigma.md#windows-security-events) are collected.**
  Rules for other IDs never match.
  Domain controller events such as 4662, 4768, and 4769 are not among them yet.
- **Silent: connection audit events are off by default.**
  5156, 5157, and 5152 are read only with `windows.security_filtering_platform_connections = true`.
- **Silent: WMI event IDs are not Sysmon's.**
  `wmi_event` rules that select on `EventID` never match.
  WMI persistence is not collected.
- **PowerShell:** only Windows PowerShell 5.1 is collected, module logging (4103) needs host policy, and its text is in the host's language.
- **No telemetry** for remote threads, process access, named pipes, driver loads, or network data volume.
- **`IntegrityLevel`** exists on process start events only.

## Linux

- **Kernel 5.8 or later.**
  Many restricted containers cannot load eBPF.
- **`Image` is the path given to `execve()`.**
  It can be relative, and is cut at 255 bytes (`ImageTruncated` is set).
- **Command lines are cut** at 512 bytes, 32 arguments, or 127 bytes per argument.
  A process that rewrites its own arguments reports the originals.
- **File paths are cut at 511 bytes** (`PathTruncated` is set).
  Cutting removes the end, which is what `|endswith` and extension indicators match.
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
  File, network, and DNS events do not carry `ContainerId`.
  On a cgroup v1 host, `CgroupPath`, `ContainerId`, and `ContainerRuntime` are always empty.
- **Silent: unrecognized container layouts look like host processes.**
  Docker, containerd, CRI-O, Podman, and LXC cgroup layouts are recognized.
  A process in any other runtime, such as systemd-nspawn, has a `CgroupPath` and no `ContainerId`.
- **Container name, image, and labels are not reported.**
  Rustinel reads only what the cgroup path carries and never queries a runtime socket.
- **A cgroup removed before enrichment leaves the event unresolved, never reported as the host.**
  Enrichment runs moments after the exec, so this needs a backlogged pipeline and a container that is already gone.
  The fallback scan checks at most 65536 directory entries and stops after a 10 ms work budget, with 8192 cached cgroups and a maximum depth of 32.
  A cgroup outside the scanned part of the hierarchy can also remain unresolved.
- **Namespace membership alone does not determine container identity.**
  Containers can share namespaces, and namespace inode numbers are recycled.
  `nsenter` without a cgroup change keeps the caller's cgroup attribution.
- **DNS:** plain UDP on port 53 only, and long names are dropped.
  Answers are decoded for A, AAAA, and CNAME records within the first 512 bytes of a response.
  A socket connected to port 53 before Rustinel started is missed until it is reopened.
  Responses read with `recvmmsg` are not captured, and without kernel BTF neither are queries and responses carried by `write` and `read`, as the pure-Go resolver does.
  `RecordType` is `OTHER` for anything but A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, and ANY.
  `QueryStatus` is the DNS response code, such as `0` for success and `3` for NXDOMAIN, not a Windows status code.
- **No telemetry** for library loads, kernel module loads, ptrace, or file timestamp changes (`file_change`).

## macOS

macOS support is experimental.

- **Only process and file events come from Endpoint Security.**
  No image load, script, WMI, service, or task equivalents, and no `file_change`.
- **Network and DNS come from packet capture.**
  They are matched to a process through a socket list refreshed every 250 ms, so short connections can stay unattributed.
- **Silent: `Initiated` is always absent.**
  A packet capture cannot tell who opened a connection, so rules on it never match.
- **Interfaces are chosen at startup.**
  Restart Rustinel after connecting a VPN or adding an interface.
  A packet seen on two interfaces can produce two events.
- **No reassembly.**
  IP fragments are not joined, and DNS over TCP must fit in one segment.
- **Silent: parent fields need an observed parent.**
  `ParentImage` and `ParentCommandLine` are empty when Rustinel never saw the parent start or has evicted it.
- **Memory scanning is mostly unavailable.**
  It needs `task_for_pid`, which macOS denies to most callers.
  Denied scans return nothing.
- **Some processes cannot be killed.** macOS protects SIP processes even from root.
  The failure is logged.
