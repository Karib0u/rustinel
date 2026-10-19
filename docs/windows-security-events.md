# Windows Security events

Rules with `service: security` match on `EventID`.
Only these IDs are collected; a rule for any other ID loads but never matches.

| Event ID | Event | Key fields |
| --- | --- | --- |
| 1102 | Security log cleared | `Provider_Name` (`Microsoft-Windows-Eventlog`) |
| 4624 | Logon | `LogonType`, `AuthenticationPackageName`, `LogonProcessName`, `TargetUserName`, `WorkstationName`, `IpAddress` |
| 4625 | Logon failed | `Status`, `SubStatus`, `FailureReason`, `LogonType`, `TargetUserName`, `WorkstationName`, `IpAddress` |
| 4648 | Logon with explicit credentials | `TargetUserName`, `TargetServerName`, `TargetInfo`, `ProcessName`, `IpAddress` |
| 4656 | Handle requested | `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4657 | Registry value modified | `ObjectName`, `ObjectValueName`, `OperationType`, `OldValue`, `NewValue`, `ProcessName` |
| 4661 ᵏ | Handle requested for a SAM or directory object | `ObjectServer`, `ObjectType`, `ObjectName`, `AccessMask`, `Properties`, `ProcessName` |
| 4662 ᵏ | Operation performed on a directory object | `ObjectType`, `ObjectName`, `AccessMask`, `Properties`, `OperationType` |
| 4663 | Object accessed | `ObjectType`, `ObjectName`, `AccessMask`, `AccessList`, `ProcessName` |
| 4672 ʲ | Special privileges assigned to a new logon | `PrivilegeList` |
| 4673 ᵏ | Privileged service called | `Service`, `PrivilegeList`, `ProcessName` |
| 4697 | Service installed | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` |
| 4698, 4699, 4700, 4701 | Scheduled task created, deleted, enabled, disabled | `TaskName`, `TaskContent` |
| 4702 | Scheduled task updated | `TaskName`, `TaskContentNew` |
| 4719 | Audit policy changed | `SubcategoryGuid`, `AuditPolicyChanges` |
| 4720, 4738 | User account created, changed | `TargetUserName`, `SamAccountName`, `OldUacValue`, `NewUacValue`, `AllowedToDelegateTo`, `SidHistory` |
| 4722, 4724, 4726 | User account enabled, password reset, deleted | `TargetUserName`, `TargetSid` |
| 4728, 4732, 4756 | Member added to a global, local, universal group | `MemberName`, `MemberSid`, `TargetUserName`, `TargetSid` |
| 4740 | User account locked out | `TargetUserName`, `TargetDomainName`, `TargetSid`, `CallerComputerName` |
| 4741, 4743 | Computer account created, deleted | `TargetUserName`, `SamAccountName`, `DnsHostName`, `ServicePrincipalNames` |
| 4742 ᵏ | Computer account changed | `TargetUserName`, `AllowedToDelegateTo`, `OldUacValue`, `NewUacValue`, `ServicePrincipalNames` |
| 4765, 4766 | SID history added, addition failed | `SourceUserName`, `TargetUserName`, `SidList` |
| 4768 ᵏ | Kerberos TGT requested | `TargetUserName`, `ServiceName`, `Status`, `TicketOptions`, `TicketEncryptionType`, `PreAuthType`, `IpAddress` |
| 4769 ᵏ | Kerberos service ticket requested | `TargetUserName`, `ServiceName`, `Status`, `TicketOptions`, `TicketEncryptionType`, `IpAddress` |
| 4771 | Kerberos pre-authentication failed | `TargetUserName`, `ServiceName`, `Status`, `PreAuthType`, `IpAddress` |
| 4776 | Credentials validated | `PackageName`, `TargetUserName`, `Workstation`, `Status` |
| 4781 | Account renamed | `OldTargetUserName`, `NewTargetUserName` |
| 4794 | DSRM administrator password set | `Workstation`, `Status` |
| 4799 ʲ | Local group membership enumerated | `TargetUserName`, `TargetSid`, `CallerProcessId`, `CallerProcessName` |
| 4817 | Object auditing settings changed | `ObjectType`, `ObjectName`, `OldSd`, `NewSd` |
| 5136 | Directory object changed | `ObjectDN`, `ObjectClass`, `AttributeLDAPDisplayName`, `AttributeValue`, `OperationType` |
| 5137 ᵏ, 5141 ᵏ | Directory object created, deleted | `ObjectDN`, `ObjectClass`, `DSName` |
| 5140 ʲ | Network share accessed | `ShareName`, `ShareLocalPath`, `ObjectType`, `AccessMask`, `IpAddress`, `IpPort` |
| 5145 | Share access checked | `ShareName`, `ShareLocalPath`, `RelativeTargetName`, `AccessMask`, `AccessList`, `IpAddress` |
| 5152 ⁱ | Packet dropped | `Application`, `Direction`, `SourceAddress`, `DestAddress`, `DestPort`, `FilterName` |
| 5156 ⁱ, 5157 ⁱ | Connection allowed, blocked | `Application`, `Direction`, `SourceAddress`, `SourcePort`, `DestAddress`, `DestPort`, `LayerRTID` |
| 5379 | Credential Manager credentials read | `TargetName`, `Type`, `ReadOperation`, `ReturnCode`, `ClientProcessId` |
| 5447 | Filtering platform filter changed | `FilterName`, `ChangeType`, `LayerName`, `ProviderName` |
| 6416 | Device recognized | `DeviceId`, `DeviceDescription`, `ClassName` |

ⁱ Only with `windows.security_filtering_platform_connections = true`, see [Windows host logging](windows-logging.md#filtering-platform-connections).

ʲ Only with `windows.security_long_tail_events = true`, see [Windows host logging](windows-logging.md#long-tail-events).

ᵏ Only with `windows.security_domain_controller_events = true`, see [Windows host logging](windows-logging.md#domain-controller-events).

Every event except 4768, 4769, 4771, 4776, and the filtering platform events also carries `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, and `SubjectLogonId`.
The connection events name the process `ProcessID` or `ProcessId`, depending on the Windows build: write rules against `Application` instead.
The complete field list for each ID is in [`compatibility/field-availability.json`](https://github.com/Karib0u/rustinel/blob/main/compatibility/field-availability.json).
The Kerberos events (4768, 4769) name the account `TargetUserName` and carry no `Subject*` fields.
