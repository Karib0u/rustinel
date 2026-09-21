# Field availability

Fields that a platform's sensors never fill in a named field view, and why.
A Sigma rule that requires one of these fields loads but never matches.

The full contract, including fields that are only sometimes filled, is in [`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).
`rustinel doctor` summarizes it for the current platform as `field_availability`.

Each contract entry names its `view` and has a `since` value.
A version string is the first released Rustinel version where that field reached its current `availability`; `null` means the current availability existed at or before the oldest supported release.
If availability narrows, such as from `always` to `conditional`, `since` is the release that introduced the narrower guarantee.
The same rule applies to `never`: when a formerly populated field becomes unavailable, `since` records the release that introduced that regression.

<!-- BEGIN GENERATED FIELD AVAILABILITY -->
This table is generated from `FIELD_AVAILABILITY` in `src/field_availability.rs`.
Edit that table and run `cargo run --bin generate-docs`.

| View | Platform | Category | Event / action | Source | Unavailable field | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| `sysmon` | linux | `file_event` | `create, delete, modify, rename` | `file syscall tracepoints` | `CreationUtcTime` | the eBPF file probes do not read file timestamps |
| `sysmon` | linux | `file_event` | `create, delete, modify, rename` | `file syscall tracepoints` | `PreviousCreationUtcTime` | the eBPF file probes do not read file timestamps |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `Company` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `Description` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `FileVersion` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `IntegrityLevel` | Windows integrity levels do not exist on Linux |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `OriginalFileName` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `Product` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `TargetImage` | a process-creation event has no target process |
| `sysmon` | macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryResults` | the BPF DNS path emits queries, not responses |
| `sysmon` | macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryStatus` | the BPF DNS path emits queries, not responses |
| `sysmon` | macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `CreationUtcTime` | ESF file notifications do not carry file timestamps |
| `sysmon` | macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `PathTruncated` | ESF paths are not copied through a fixed Rustinel buffer |
| `sysmon` | macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `PreviousCreationUtcTime` | ESF file notifications do not carry file timestamps |
| `sysmon` | macos | `network_connection` | `3 / connect` | `/dev/bpf` | `Initiated` | a wire capture cannot determine whether the local host initiated the flow |
| `sysmon` | macos | `network_connection` | `3 / connect` | `/dev/bpf` | `User` | BPF packets do not carry process user identity |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `CgroupId` | macOS process events do not have a Linux kernel cgroup identifier |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Company` | PE version resources are Windows-only |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Description` | PE version resources are Windows-only |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `FileVersion` | PE version resources are Windows-only |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `ImageSource` | ESF supplies the executable path directly |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `ImageTruncated` | ESF does not use the Linux raw-image buffer |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `IntegrityLevel` | Windows integrity levels do not exist on macOS |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `OriginalFileName` | PE version resources are Windows-only |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Product` | PE version resources are Windows-only |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `TargetImage` | a process-creation event has no target process |
| `sysmon` | windows | `create_remote_thread` | `8` | `none` | `*` | no Rustinel sensor produces remote-thread creation telemetry |
| `sysmon` | windows | `dns_query` | `3006 / query, 3008 / query` | `Microsoft-Windows-DNS-Client` | `RecordType` | the subscribed DNS Client events do not expose the query record type |
| `sysmon` | windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `CreationUtcTime` | Kernel-File reports the information class, not the new timestamp |
| `sysmon` | windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `PathTruncated` | ETW delivers a complete path or no attributable event |
| `sysmon` | windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `PreviousCreationUtcTime` | Kernel-File reports the information class, not the old timestamp |
| `sysmon` | windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `SourceFilename` | Kernel-File does not provide the old name on emitted rename events |
| `sysmon` | windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Signature` | Kernel-Process image-load events contain no signer identity |
| `sysmon` | windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Signed` | Kernel-Process image-load events contain no Authenticode result |
| `sysmon` | windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `User` | Kernel-Process image-load events contain no user identity |
| `sysmon` | windows | `pipe_created` | `17` | `Microsoft-Windows-Kernel-File` | `*` | named-pipe activity is not carried by Microsoft-Windows-Kernel-File and is not available from ETW |
| `sysmon` | windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `CgroupId` | Windows process events do not have a Linux kernel cgroup identifier |
| `sysmon` | windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `CurrentDirectory` | Microsoft-Windows-Kernel-Process does not expose the working directory |
| `sysmon` | windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `TargetImage` | a process-creation event has no target process |
| `sysmon` | windows | `service_creation` | `7045 / register` | `Service Control Manager` | `Image` | System event 7045 does not carry a creating process image |
| `sysmon` | windows | `service_creation` | `7045 / register` | `Service Control Manager` | `ProcessId` | System event 7045 does not carry process identity |
| `sysmon` | windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `Image` | TaskScheduler event 106 does not carry a process image |
| `sysmon` | windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `ProcessId` | TaskScheduler event 106 does not carry process identity |
| `sysmon` | windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `TaskContent` | TaskScheduler event 106 does not carry the task XML definition |
| `sysmon` | windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `User` | TaskScheduler event 106 has UserContext, not a Sysmon User field |
<!-- END GENERATED FIELD AVAILABILITY -->

## Windows process user validation

Windows process `User` is measured from the SID in the correlated classic ETW process record.
Account-name lookup happens after collection, and the resolved Sysmon-style name is marked as derived.
`ParentUser` is derived only through the stable parent process identity, so PID reuse cannot select a different process.

The ignored native test can be run from an Administrator shell:

```powershell
cargo test --locked --test windows_process_user -- --ignored --nocapture
```

On 2026-09-17, Windows 11 build 26200.9457 populated `User` for 64 of 64 short-lived `cmd.exe` starts and `ParentUser` for 64 of 64.
The same run started a temporary LocalSystem service process and matched a Sigma rule requiring `User: NT AUTHORITY\SYSTEM`.
