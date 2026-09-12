# Field availability

Fields that a platform's sensors never fill, and why.
A Sigma rule that requires one of these fields loads but never matches.

The full contract, including fields that are only sometimes filled, is in [`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).
`rustinel doctor` summarizes it for the current platform as `field_availability`.

<!-- BEGIN GENERATED FIELD AVAILABILITY -->
This table is generated from `FIELD_AVAILABILITY` in `src/field_availability.rs`.
Edit that table and run `cargo run --bin generate-docs`.

| Platform | Category | Event / action | Source | Unavailable field | Reason |
| --- | --- | --- | --- | --- | --- |
| linux | `dns_query` | `22 / query` | `socket send tracepoints` | `QueryResults` | the eBPF DNS probe emits outbound queries and does not parse responses |
| linux | `dns_query` | `22 / query` | `socket send tracepoints` | `QueryStatus` | the eBPF DNS probe does not parse response status |
| linux | `file_event` | `create, delete, modify, rename` | `file syscall tracepoints` | `CreationUtcTime` | the eBPF file probes do not read file timestamps |
| linux | `file_event` | `create, delete, modify, rename` | `file syscall tracepoints` | `PreviousCreationUtcTime` | the eBPF file probes do not read file timestamps |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `Company` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `Description` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `FileVersion` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `IntegrityLevel` | Windows integrity levels do not exist on Linux |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `OriginalFileName` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `Product` | PE version resources are Windows-only |
| linux | `process_creation` | `1 / start` | `execve tracepoints` | `TargetImage` | a process-creation event has no target process |
| macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryResults` | the BPF DNS path emits queries, not responses |
| macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryStatus` | the BPF DNS path emits queries, not responses |
| macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `CreationUtcTime` | ESF file notifications do not carry file timestamps |
| macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `PathTruncated` | ESF paths are not copied through a fixed Rustinel buffer |
| macos | `file_event` | `create, delete, modify, rename` | `Endpoint Security file notifications` | `PreviousCreationUtcTime` | ESF file notifications do not carry file timestamps |
| macos | `network_connection` | `3 / connect` | `/dev/bpf` | `Initiated` | a wire capture cannot determine whether the local host initiated the flow |
| macos | `network_connection` | `3 / connect` | `/dev/bpf` | `User` | BPF packets do not carry process user identity |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `CgroupId` | macOS process events do not have a Linux kernel cgroup identifier |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Company` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Description` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `FileVersion` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `ImageSource` | ESF supplies the executable path directly |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `ImageTruncated` | ESF does not use the Linux raw-image buffer |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `IntegrityLevel` | Windows integrity levels do not exist on macOS |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `OriginalFileName` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Product` | PE version resources are Windows-only |
| macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `TargetImage` | a process-creation event has no target process |
| windows | `create_remote_thread` | `8` | `none` | `*` | no Rustinel sensor produces remote-thread creation telemetry |
| windows | `dns_query` | `22 / query` | `Microsoft-Windows-DNS-Client` | `RecordType` | the subscribed DNS Client events do not expose the query record type |
| windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `CreationUtcTime` | Kernel-File reports the information class, not the new timestamp |
| windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `PathTruncated` | ETW delivers a complete path or no attributable event |
| windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `PreviousCreationUtcTime` | Kernel-File reports the information class, not the old timestamp |
| windows | `file_event` | `create, delete, modify, rename, set` | `Microsoft-Windows-Kernel-File` | `SourceFilename` | Kernel-File does not provide the old name on emitted rename events |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Hashes` | loaded images are not hashed by this collector |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Imphash` | loaded images are not hashed by this collector |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Signature` | Kernel-Process image-load events contain no signer identity |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `Signed` | Kernel-Process image-load events contain no Authenticode result |
| windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `User` | Kernel-Process image-load events contain no user identity |
| windows | `pipe_created` | `17` | `Microsoft-Windows-Kernel-File` | `*` | named-pipe activity is not carried by Microsoft-Windows-Kernel-File and is not available from ETW |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `CgroupId` | Windows process events do not have a Linux kernel cgroup identifier |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `CurrentDirectory` | Microsoft-Windows-Kernel-Process does not expose the working directory |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `Hashes` | process images are not hashed by this collector |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `Imphash` | process images are not hashed by this collector |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `TargetImage` | a process-creation event has no target process |
| windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `User` | Microsoft-Windows-Kernel-Process does not expose process user identity |
| windows | `service_creation` | `7045 / register` | `Service Control Manager` | `Image` | System event 7045 does not carry a creating process image |
| windows | `service_creation` | `7045 / register` | `Service Control Manager` | `ProcessId` | System event 7045 does not carry process identity |
| windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `Image` | TaskScheduler event 106 does not carry a process image |
| windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `ProcessId` | TaskScheduler event 106 does not carry process identity |
| windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `TaskContent` | TaskScheduler event 106 does not carry the task XML definition |
| windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `User` | TaskScheduler event 106 has UserContext, not a Sysmon User field |
<!-- END GENERATED FIELD AVAILABILITY -->
