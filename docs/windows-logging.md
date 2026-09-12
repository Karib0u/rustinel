# Windows host logging

Some Windows telemetry exists only when the host is configured to produce it.
Rustinel subscribes to it but never changes host policy.
Without the policy, the matching rules load and stay silent.

| Rules | Needs |
| --- | --- |
| `service: security` except logon (4624) | [Audit policy](#audit-policy) |
| `ps_module` (event 4103) | [Module Logging](#powershell-module-logging) |
| `ps_script` (event 4104) for ordinary scripts | [Script Block Logging](#powershell-script-block-logging) |

## Audit policy

Rustinel reads six Security events.
Only 4624 is audited by default.

| Event | Audit subcategory | GUID prefix |
| --- | --- | --- |
| 4624 logon | Logon (on by default) | `{0CCE9215-…}` |
| 4697 service installed | Security System Extension | `{0CCE9211-…}` |
| 4656 handle requested | File System, Registry, Kernel Object, SAM | `{0CCE921D-…}`, `{0CCE921E-…}`, `{0CCE921F-…}`, `{0CCE9220-…}` |
| 4663 object access | File System, Registry, Kernel Object | `{0CCE921D-…}`, `{0CCE921E-…}`, `{0CCE921F-…}` |
| 5145 share access check | Detailed File Share | `{0CCE9244-…}` |
| 5136 directory object changed | Directory Service Changes (domain controllers) | `{0CCE923C-…}` |

Every GUID ends in `-69AE-11D9-BED3-505054503030`.

Back up the current policy, then enable what you need from an elevated prompt:

```bat
auditpol /backup /file:C:\auditpol-before.csv
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /get /category:*
```

!!! note "Non-English Windows"
    `auditpol` takes the localized subcategory name.
    Use the GUID instead: `auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable`.
    `auditpol /list /subcategory:* /v` prints names next to GUIDs.

- **4656 and 4663 also need a SACL** on each file, key, or object you want to watch (Properties, Security, Advanced, Auditing).
  The subcategory alone logs nothing.
- **Detailed File Share and Kernel Object are high volume.**
  Size the Security log accordingly: `wevtutil sl Security /ms:<bytes>`.

Group Policy has the same settings under *Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration*.

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

- Only Windows PowerShell 5.1 is collected.
  PowerShell 7 (`pwsh`) uses a different provider.
- `ContextInfo` and `Payload` (4103) are written in the host's display language.
  A rule that matches an English label such as `Host Application =` fires only on English hosts.
