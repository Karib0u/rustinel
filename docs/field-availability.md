# Field availability

Fields that a platform's sensors never fill in a named field view, and why.
A Sigma rule that requires one of these fields loads but never matches.

The full contract, including fields that are only sometimes filled, is in [`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).
`rustinel doctor` summarizes it for the current platform as `field_availability`.

In the JSON, each entry's `since` is the first release with its current availability, or `null` when it predates the oldest supported release.
If availability narrows, `since` records the release that introduced the narrower guarantee.
`unreleased` marks availability on the development branch that no release has shipped yet; a released contract never contains it.

## Process access

The shared `ProcessAccess` event describes a subject attempting to access another process. It carries the source and target identity when available, the requested access in the collector's vocabulary, an outcome (`success`, `failure`, or `unknown`), and the native result code if the collector observed it. Future producers can leave fields absent when their source cannot measure them.

The Windows collector routes `Microsoft-Windows-Kernel-Audit-API-Calls` event 5 to Sigma `product: windows`, `category: process_access`. `EventID` remains `5`. The fields are:

| Field | Meaning |
| --- | --- |
| `SourceProcessId`, `TargetProcessId` | Caller PID from the ETW header and attempted target PID from the payload. The invalid target sentinel `4294967295` leaves the target PID absent. |
| `SourceImage`, `TargetImage`, `SourceUser`, `TargetUser` | Resolved against the lifetimes active at the event timestamp. Rustinel uses its bounded process cache, with no per-event live process queries or wait for missing state. |
| `DesiredAccess` | Requested mask as lowercase hexadecimal, such as `0x1000` or `0x2000000` (`MAXIMUM_ALLOWED`). |
| `ReturnCode` | Native `NTSTATUS` bit pattern in unsigned decimal, such as `0` for success or `3221225506` for access denied. |
| `AccessOutcome` | `success` or `failure` based on `NT_SUCCESS`. A rule can select `success` if it requires a handle to have been opened. |

`GrantedAccess` stays absent for every event. A successful explicit `0x1000` request opened a handle with `0x1000` granted. A successful `MAXIMUM_ALLOWED` request for `0x2000000` opened a handle with `0x1fffff` granted. [Issue #302 validation](https://github.com/Karib0u/rustinel/issues/302)

Sigma doctor reports a rule that requires `GrantedAccess` as unsatisfiable.

The `windows_process_access` telemetry snapshot reports received and decoded records. It counts missing images and invalid targets for records that reach normalization. The per-category ingress counters report accepted records and queue drops. ETW reports kernel-buffer loss for the shared session and cannot attribute it to individual providers.

<!-- BEGIN GENERATED FIELD AVAILABILITY -->
This table is generated from `FIELD_AVAILABILITY` in `src/field_availability.rs`.
Edit that table and run `cargo run --bin generate-docs`.

| View | Platform | Category | Event / action | Source | Unavailable field | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `SYSCALL` | the eBPF file probes do not retain which syscall produced the event |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `a0` | raw syscall arguments are not captured for file events |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `a1` | raw syscall arguments are not captured for file events |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `a2` | raw syscall arguments are not captured for file events |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `a3` | raw syscall arguments are not captured for file events |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `a4` | raw syscall arguments are not captured for file events |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `a5` | raw syscall arguments are not captured for file events |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `a6` | raw syscall arguments are not captured for file events |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `a7` | raw syscall arguments are not captured for file events |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `key` | an audit key is a label an operator configures on an audit rule; it is not a fact about the event, so the view never manufactures one |
| `auditd` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `unit` | no Rustinel sensor produces service start or stop records, which carry `unit` |
| `auditd` | linux | `process_creation` | `1 / start` | `execve tracepoints (IA32 CommandLine observed on x86-64)` | `key` | an audit key is a label an operator configures on an audit rule; it is not a fact about the event, so the view never manufactures one |
| `auditd` | linux | `process_creation` | `1 / start` | `execve tracepoints (IA32 CommandLine observed on x86-64)` | `nametype` | exec telemetry does not model per-path name types |
| `auditd` | linux | `process_creation` | `1 / start` | `execve tracepoints (IA32 CommandLine observed on x86-64)` | `unit` | no Rustinel sensor produces service start or stop records, which carry `unit` |
| `sysmon` | linux | `auth_log` | `0, 5, 6` | `other privileged auth facility writers` | `Outcome` | the line reports no authentication outcome: a session boundary or an unparsed line |
| `sysmon` | linux | `auth_log` | `5, 6` | `other privileged auth facility writers` | `SourceIp` | the line names no remote address |
| `sysmon` | linux | `auth_log` | `6` | `other privileged auth facility writers` | `TargetUserId` | pam_unix names only the user when a session closes |
| `sysmon` | linux | `auth_log` | `0` | `other privileged auth facility writers` | `TargetUserName` | no parser claimed the line; match its text through `Message` |
| `sysmon` | linux | `auth_log` | `0, 5, 6` | `sshd` | `Outcome` | the line reports no authentication outcome: a session boundary or an unparsed line |
| `sysmon` | linux | `auth_log` | `5, 6` | `sshd` | `SourceIp` | the line names no remote address |
| `sysmon` | linux | `auth_log` | `6` | `sshd` | `TargetUserId` | pam_unix names only the user when a session closes |
| `sysmon` | linux | `auth_log` | `0` | `sshd` | `TargetUserName` | no parser claimed the line; match its text through `Message` |
| `sysmon` | linux | `auth_log` | `0, 5, 6` | `su` | `Outcome` | the line reports no authentication outcome: a session boundary or an unparsed line |
| `sysmon` | linux | `auth_log` | `10, 5, 6, 9` | `su` | `SourceIp` | the line names no remote address |
| `sysmon` | linux | `auth_log` | `6` | `su` | `TargetUserId` | pam_unix names only the user when a session closes |
| `sysmon` | linux | `auth_log` | `0` | `su` | `TargetUserName` | no parser claimed the line; match its text through `Message` |
| `sysmon` | linux | `auth_log` | `0, 5, 6` | `sudo` | `Outcome` | the line reports no authentication outcome: a session boundary or an unparsed line |
| `sysmon` | linux | `auth_log` | `5, 6, 7, 8` | `sudo` | `SourceIp` | the line names no remote address |
| `sysmon` | linux | `auth_log` | `6` | `sudo` | `TargetUserId` | pam_unix names only the user when a session closes |
| `sysmon` | linux | `auth_log` | `0` | `sudo` | `TargetUserName` | no parser claimed the line; match its text through `Message` |
| `sysmon` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `CreationUtcTime` | the eBPF file probes do not read file timestamps |
| `sysmon` | linux | `file_event` | `create, delete, modify, rename` | `native file syscall tracepoints (io_uring and IA32 activity counts depend on kernel support)` | `PreviousCreationUtcTime` | the eBPF file probes do not read file timestamps |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `Company` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `Description` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `FileVersion` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `IntegrityLevel` | Windows integrity levels do not exist on Linux |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `OriginalFileName` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `Product` | PE version resources are Windows-only |
| `sysmon` | linux | `process_creation` | `1 / start` | `execve tracepoints` | `TargetImage` | a process-creation event has no target process |
| `sysmon` | macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryResults` | the BPF DNS path emits queries, not responses |
| `sysmon` | macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryStatus` | the BPF DNS path emits queries, not responses |
| `sysmon` | macos | `dns_query` | `22 / query` | `/dev/bpf` | `QueryTruncated` | the BPF DNS path parses one packet and drops a question it cannot finish |
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
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `LogonId` | Endpoint Security exec events do not carry a logon session |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `OriginalFileName` | PE version resources are Windows-only |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `Product` | PE version resources are Windows-only |
| `sysmon` | macos | `process_creation` | `1 / start` | `Endpoint Security exec` | `TargetImage` | a process-creation event has no target process |
| `sysmon` | windows | `application` | `1000 / access` | `Application Error` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `1 / access` | `Audit-CVE` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `216 / access, 325 / access, 326 / access, 327 / access` | `ESENT` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `4 / access` | `MSExchange Control Panel` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `2027 / access` | `MSMQ` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `15457 / access, 18456 / access, 33205 / access, 8128 / access` | `MSSQL*` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `1 / access` | `Microsoft-Windows-Audit-CVE` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `524 / access` | `Microsoft-Windows-Backup` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `865 / access, 866 / access, 867 / access, 868 / access, 882 / access` | `Microsoft-Windows-SoftwareRestrictionPolicies` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `1511 / access` | `Microsoft-Windows-User Profiles Service` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `1033 / access, 1034 / access, 1040 / access, 1042 / access, 11724 / access` | `MsiInstaller` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `200 / access, 201 / access` | `ScreenConnect` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `1001 / access` | `Windows Error Reporting` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `application` | `7053 / access` | `Windows Server Update Services` | `Message` | formatted, localized messages are not rendered by the XML subscription |
| `sysmon` | windows | `create_remote_thread` | `8` | `none` | `*` | no Rustinel sensor produces remote-thread creation telemetry |
| `sysmon` | windows | `dns_query` | `3006 / query, 3008 / query` | `Microsoft-Windows-DNS-Client` | `QueryTruncated` | ETW delivers whole DNS Client events |
| `sysmon` | windows | `dns_query` | `3006 / query, 3008 / query` | `Microsoft-Windows-DNS-Client` | `RecordType` | the subscribed DNS Client events do not expose the query record type |
| `sysmon` | windows | `driver_load` | `6 / load` | `Microsoft-Windows-Kernel-Process` | `User` | Kernel-Process image-load events contain no user identity |
| `sysmon` | windows | `file_event` | `11 / create, 2 / set, 23 / delete, 65 / modify, 71 / rename` | `Microsoft-Windows-Kernel-File` | `CreationUtcTime` | Kernel-File reports the information class, not the new timestamp |
| `sysmon` | windows | `file_event` | `11 / create, 2 / set, 23 / delete, 65 / modify, 71 / rename` | `Microsoft-Windows-Kernel-File` | `PathTruncated` | ETW delivers a complete path or no attributable event |
| `sysmon` | windows | `file_event` | `11 / create, 2 / set, 23 / delete, 65 / modify, 71 / rename` | `Microsoft-Windows-Kernel-File` | `PreviousCreationUtcTime` | Kernel-File reports the information class, not the old timestamp |
| `sysmon` | windows | `file_event` | `11 / create, 2 / set, 23 / delete, 65 / modify, 71 / rename` | `Microsoft-Windows-Kernel-File` | `SourceFilename` | Kernel-File does not provide the old name on emitted rename events |
| `sysmon` | windows | `image_load` | `7 / load` | `Microsoft-Windows-Kernel-Process` | `User` | Kernel-Process image-load events contain no user identity |
| `sysmon` | windows | `pipe_created` | `17` | `Microsoft-Windows-Kernel-File` | `*` | named-pipe activity is not carried by Microsoft-Windows-Kernel-File and is not available from ETW |
| `sysmon` | windows | `process_access` | `5 / access` | `Microsoft-Windows-Kernel-Audit-API-Calls` | `CallTrace` | Audit-API event 5 does not collect a call stack |
| `sysmon` | windows | `process_access` | `5 / access` | `Microsoft-Windows-Kernel-Audit-API-Calls` | `Channel` | the real-time audit trace is routed by provider and event ID |
| `sysmon` | windows | `process_access` | `5 / access` | `Microsoft-Windows-Kernel-Audit-API-Calls` | `GrantedAccess` | Audit-API event 5 records the requested DesiredAccess and ReturnCode. Actual granted rights are unknown even when the call succeeds. |
| `sysmon` | windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `CgroupId` | Windows process events do not have a Linux kernel cgroup identifier |
| `sysmon` | windows | `process_creation` | `1 / start` | `Microsoft-Windows-Kernel-Process` | `TargetImage` | a process-creation event has no target process |
| `sysmon` | windows | `ps_module` | `4103 / execute` | `PowerShellCore` | `User` | the PowerShellCore 4103 payload has no standalone user field |
| `sysmon` | windows | `ps_script` | `4104 / execute` | `PowerShellCore` | `User` | the PowerShellCore 4104 payload does not carry a user |
| `sysmon` | windows | `service_creation` | `7045 / register` | `Service Control Manager` | `Image` | System event 7045 does not carry a creating process image |
| `sysmon` | windows | `service_creation` | `7045 / register` | `Service Control Manager` | `ProcessId` | System event 7045 does not carry process identity |
| `sysmon` | windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `Image` | TaskScheduler event 106 does not carry a process image |
| `sysmon` | windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `ProcessId` | TaskScheduler event 106 does not carry process identity |
| `sysmon` | windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `TaskContent` | TaskScheduler event 106 does not carry the task XML definition |
| `sysmon` | windows | `task_creation` | `106 / register` | `Microsoft-Windows-TaskScheduler` | `User` | TaskScheduler event 106 has UserContext, not a Sysmon User field |
<!-- END GENERATED FIELD AVAILABILITY -->
