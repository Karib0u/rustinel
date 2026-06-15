[CmdletBinding()]
param(
    [string]$Root = "",
    [switch]$TriggerOnly,
    [int]$TimeoutSeconds = 15,
    [ValidateSet("", "elastic", "splunk")]
    [string]$Siem = "",
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
    @"
Verify the bundled whoami demo end-to-end.

Rustinel must already be running (for example: .\rustinel.exe run).

Usage:
  .\run-local-demo.ps1 [-Root PATH] [-TriggerOnly] [-TimeoutSeconds SECS] [-Siem elastic|splunk]

Options:
  -Root PATH           Rustinel install directory (default: auto-detect)
  -TriggerOnly         Skip agent and prerequisite checks
  -TimeoutSeconds      Seconds to wait for a new alert (default: 15)
  -Siem elastic|splunk Print next-step commands for a SIEM demo
  -Help                Show this help
"@
}

function Detect-Root {
    $dir = (Get-Location).Path
    while ($dir) {
        if (Test-Path -LiteralPath (Join-Path $dir "config.toml")) {
            return $dir
        }
        $parent = Split-Path -Parent $dir
        if (-not $parent -or $parent -eq $dir) {
            break
        }
        $dir = $parent
    }

    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidate = (Resolve-Path (Join-Path $scriptRoot "..\..")).Path
    if (Test-Path -LiteralPath (Join-Path $candidate "config.toml")) {
        return $candidate
    }

    return $null
}

function Find-Binary {
    param([string]$InstallRoot)

    foreach ($candidate in @(
            (Join-Path $InstallRoot "rustinel.exe"),
            (Join-Path $InstallRoot "target\release\rustinel.exe"),
            (Join-Path $InstallRoot "target\debug\rustinel.exe")
        )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return $null
}

function Get-AlertFiles {
    param([string]$InstallRoot)

    $pattern = Join-Path $InstallRoot "logs\alerts.json*"
    return @(Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue)
}

function Get-AlertLineCount {
    param([string]$InstallRoot)

    $total = 0
    foreach ($file in Get-AlertFiles -InstallRoot $InstallRoot) {
        $total += (Get-Content -LiteralPath $file.FullName | Measure-Object -Line).Lines
    }
    return $total
}

function Get-LatestAlertLine {
    param([string]$InstallRoot)

    $files = Get-AlertFiles -InstallRoot $InstallRoot
    if (-not $files -or $files.Count -eq 0) {
        return $null
    }

    $latest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    return (Get-Content -LiteralPath $latest.FullName -Tail 1)
}

function Write-AlertJson {
    param([string]$Line)

    try {
        $Line | ConvertFrom-Json | ConvertTo-Json -Depth 20
    }
    catch {
        Write-Output $Line
    }
}

function Show-SiemHint {
    param(
        [string]$InstallRoot,
        [string]$Name
    )

    switch ($Name) {
        "elastic" {
            @"

Next — Elastic SIEM demo:
  cd examples\siem\elastic
  docker compose up -d elasticsearch kibana
  `$env:RUSTINEL_ALERTS_DIR = "$InstallRoot\logs"
  docker compose up filebeat

Kibana: http://localhost:5601 — search: event.kind : "alert"
"@
        }
        "splunk" {
            $date = Get-Date -Format "yyyy-MM-dd"
            @"

Next — Splunk SIEM demo:
  cd examples\siem\splunk
  docker compose up -d
  python3 send-alerts.py $InstallRoot\logs\alerts.json.$date

Splunk Web: http://localhost:8000 — search: index=main source=rustinel event.kind=alert
"@
        }
    }
}

if ($Help) {
    Show-Usage
    exit 0
}

if (-not $Root) {
    $Root = Detect-Root
    if (-not $Root) {
        Write-Error "Could not find Rustinel install directory (expected config.toml). Run from the install directory or pass -Root PATH."
    }
}

$Root = (Resolve-Path -LiteralPath $Root).Path

if (-not $TriggerOnly) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root "config.toml"))) {
        Write-Error "Missing config.toml in $Root"
    }

    if (-not (Find-Binary -InstallRoot $Root)) {
        Write-Error "Rustinel binary not found under $Root. Build with cargo build --release or install a release from https://github.com/Karib0u/rustinel/releases"
    }

    $agent = Get-Process -Name rustinel -ErrorAction SilentlyContinue
    if (-not $agent) {
        Write-Error @"
Rustinel agent is not running.
Start it in another terminal:
  cd $Root
  .\rustinel.exe run
"@
    }

    Write-Host "Rustinel install: $Root"
    Write-Host "Agent: running"
}

$before = Get-AlertLineCount -InstallRoot $Root
Write-Host "Firing bundled demo trigger (whoami /all)..."
whoami /all | Out-Null

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$found = $false

while ((Get-Date) -lt $deadline) {
    $after = Get-AlertLineCount -InstallRoot $Root
    if ($after -gt $before) {
        $found = $true
        break
    }
    Start-Sleep -Milliseconds 200
}

if (-not $found) {
    Write-Error "No new alert within ${TimeoutSeconds}s. Check logs under $Root\logs\ and confirm Sigma rules are loaded."
}

$line = Get-LatestAlertLine -InstallRoot $Root
if (-not $line) {
    Write-Error "Alert count increased but no alert line could be read."
}

Write-Host "Latest alert:"
Write-AlertJson -Line $line

if ($Siem) {
    Show-SiemHint -InstallRoot $Root -Name $Siem
}

Write-Host "Demo succeeded."
exit 0
