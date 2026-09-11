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
- **YARA scans only executables that run.**
  A file written to disk and never executed is not scanned.
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

- **Silent: no hashes on process or image-load events.**
  Rules on `Hashes` or `Imphash` never fire.
  Hashing exists only for IOC matching.
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
  Only logon (4624) is audited by default.
  See [Windows host logging](windows-logging.md).
- **Silent: only six Security event IDs are collected:** 4624, 4656, 4663, 4697, 5136, and 5145.
  Rules for other IDs never match.
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
- **Parent identity** is derived for `CLONE_PARENT`, and can be missing for processes that started before Rustinel.
- **DNS:** plain UDP on port 53 only, no answers, and long names are dropped.
  `RecordType` is `OTHER` for anything but A, NS, CNAME, PTR, TXT, and AAAA.
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
