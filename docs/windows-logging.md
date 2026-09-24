# Windows host logging

Some Windows telemetry exists only when the host is configured to produce it.
Rustinel subscribes to it but never changes host policy.
Without the policy, the matching rules load and stay silent.

| Rules | Needs |
| --- | --- |
| `service: security` | [Audit policy](#audit-policy), for most event IDs |
| `service: security` on 5156, 5157, 5152 | [Filtering platform connections](#filtering-platform-connections) |
| `ps_module` (event 4103) | [Module Logging](#powershell-module-logging) |
| `ps_script` (event 4104) for ordinary scripts | [Script Block Logging](#powershell-script-block-logging) |

`ps_classic_start` uses event 400 from the `Windows PowerShell` channel and needs no additional host policy.

## Application channel

Rustinel subscribes to selected Application channel provider and event ID pairs used by the SigmaHQ corpus.
The originating Windows provider is exposed as `Provider_Name`; `event.provider` identifies the Rustinel Event Log collector.
The source program must be installed and produce its events for a rule to fire.
SQL Server instance providers are accepted when their name contains `MSSQL` and the event ID is in the supported set.

`Data` joins non-empty raw `EventData` values with newlines.
For Application Error event 1000, the positional values also populate `AppName`, `AppVersion`, `ModuleName`, and `ExceptionCode` when present.
`Level` retains the numeric value from the Windows system header.
Formatted, localized `Message` text is unavailable, so rules requiring `Message` are reported as unsatisfiable by `sigma doctor`.

The supported provider and event ID pairs are recorded in the [field availability table](field-availability.md).

## Audit policy

Each Security event is written only when its audit subcategory is enabled.
Windows enables some of them out of the box, as the **Default** column shows, but editions differ and Group Policy often changes them.
Check the real policy with `auditpol /get /category:*`.

| Event | Audit subcategory | GUID prefix | Default |
| --- | --- | --- | --- |
| 4624 logon | Logon | `{0CCE9215-…}` | Success |
| 4625 logon failed | Logon | `{0CCE9215-…}` | Varies |
| 4648 explicit credentials | Logon | `{0CCE9215-…}` | Success |
| 4776 credentials validated | Credential Validation | `{0CCE923F-…}` | Varies |
| 4771 Kerberos pre-authentication failed | Kerberos Authentication Service (domain controllers) | `{0CCE9242-…}` | Domain controllers |
| 4720, 4722, 4724, 4726, 4738, 4765, 4766, 4781, 4794 user accounts | User Account Management | `{0CCE9235-…}` | Success |
| 4728, 4732, 4756 group membership | Security Group Management | `{0CCE9237-…}` | Success |
| 4741, 4743 computer accounts | Computer Account Management (domain controllers) | `{0CCE9236-…}` | Domain controllers |
| 4719, 4817 audit policy changed | Audit Policy Change | `{0CCE922F-…}` | Success |
| 1102 Security log cleared | None, always written | | Always |
| 4697 service installed | Security System Extension | `{0CCE9211-…}` | No |
| 4698 to 4702 scheduled tasks | Other Object Access Events | `{0CCE9227-…}` | No |
| 4656 handle requested | File System, Registry, Kernel Object, SAM | `{0CCE921D-…}`, `{0CCE921E-…}`, `{0CCE921F-…}`, `{0CCE9220-…}` | No |
| 4663 object access | File System, Registry, Kernel Object | `{0CCE921D-…}`, `{0CCE921E-…}`, `{0CCE921F-…}` | No |
| 4657 registry value modified | Registry | `{0CCE921E-…}` | No |
| 5145 share access check | Detailed File Share | `{0CCE9244-…}` | No |
| 5136 directory object changed | Directory Service Changes (domain controllers) | `{0CCE923C-…}` | No |
| 5447 filtering platform filter changed | Filtering Platform Policy Change | `{0CCE9233-…}` | No |
| 6416 device recognized | Plug and Play Events | `{0CCE9248-…}` | No |
| 5156, 5157 connection allowed, blocked | Filtering Platform Connection | `{0CCE9226-…}` | No |
| 5152 packet dropped | Filtering Platform Packet Drop | `{0CCE9225-…}` | No |

Every GUID ends in `-69AE-11D9-BED3-505054503030`.

Back up the current policy, then enable what you need from an elevated prompt:

```bat
auditpol /backup /file:C:\auditpol-before.csv
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /get /category:*
```

!!! note "Non-English Windows"
    `auditpol` takes the localized subcategory name.
    Use the GUID instead: `auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable`.
    `auditpol /list /subcategory:* /v` prints names next to GUIDs.

- **4656, 4657, and 4663 also need a SACL** on each file, key, or object you want to watch (Properties, Security, Advanced, Auditing).
  The subcategory alone logs nothing.
- **Detailed File Share and Kernel Object are high volume.**
  Size the Security log accordingly: `wevtutil sl Security /ms:<bytes>`.
- **Failed logons can burst.**
  An exposed RDP or SMB service under password spraying writes one 4625 per attempt.

Group Policy has the same settings under *Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration*.

### Filtering platform connections

Events 5156 (connection allowed), 5157 (connection blocked), and 5152 (packet dropped) need two switches:

1. The host audits them: enable *Filtering Platform Connection* and, for 5152, *Filtering Platform Packet Drop*.
2. Rustinel reads them: set `security_filtering_platform_connections = true` under `[windows]`.

They are off in Rustinel by default because Windows writes one record per connection.
An idle Windows 11 lab VM wrote about 96 of them per minute, roughly 200 times the rate of its logon events.
Size the Security log before enabling them, or older records will be overwritten before other rules see them.

## PowerShell module logging

Without Module Logging, PowerShell never writes event 4103.
Enable it for all modules:

```powershell
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path "$key\ModuleNames" -Force | Out-Null
New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force
```

Or in Group Policy: *Windows Components > Windows PowerShell > Turn on Module Logging*, with module names set to `*`.
`ModuleNames` must not be empty.

## PowerShell script block logging

Windows logs suspicious script blocks (4104) on its own.
To log every script block, enable *Turn on PowerShell Script Block Logging* in the same Group Policy folder.
Check the current value:

```powershell
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging
```

## Limits

- Script block and module content is collected from Windows PowerShell 5.1.
  Classic engine starts also include version 2 through event 400.
  PowerShell 7 (`pwsh`) uses a different provider and is not collected.
- `ContextInfo` and `Payload` (4103) are written in the host's display language.
  A rule that matches an English label such as `Host Application =` fires only on English hosts.
