param(
    [ValidateSet("baseline", "with-agent")]
    [string]$Mode = "with-agent",
    [string]$AgentPath = ".\target\release\rustinel.exe",
    [string]$AgentArgs = "run --console",
    [string]$ProcessName = "rustinel",
    [string]$OutputDir = ".\target\rustinel-bench",
    [int]$IdleSeconds = 60,
    [int]$ProcessLaunches = 500,
    [int]$FileCount = 2000,
    [int]$FileSizeBytes = 1024,
    [string]$AlertGlob = ".\logs\alerts.json*",
    [string]$AlertRuleName = "Rustinel Benchmark Whoami Windows",
    [string]$SigmaRulesPath = ".\rules\sigma",
    [string]$YaraRulesPath = ".\rules\yara",
    [string]$IocRulesPath = ".\rules\ioc",
    [switch]$SkipCargo,
    [switch]$NoAlertLatency,
    [switch]$NoBenchmarkTriggerRule,
    [switch]$ProcessOnly,
    [switch]$FileOnly,
    [switch]$CargoOnly,
    [switch]$KeepAgent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$workloadSelectorCount = 0
foreach ($selector in @($ProcessOnly, $FileOnly, $CargoOnly)) {
    if ($selector) {
        $workloadSelectorCount++
    }
}
if ($workloadSelectorCount -gt 1) {
    throw "Use only one of -ProcessOnly, -FileOnly, or -CargoOnly."
}
$runProcessWorkload = -not ($FileOnly -or $CargoOnly)
$runFileWorkload = -not ($ProcessOnly -or $CargoOnly)
$runCargoWorkload = -not ($ProcessOnly -or $FileOnly -or $SkipCargo)
$workloadMode = if ($ProcessOnly) { "process-only" } elseif ($FileOnly) { "file-only" } elseif ($CargoOnly) { "cargo-only" } else { "all" }

function Get-NowIso {
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function New-BenchDirectory {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $dir = Join-Path $OutputDir "$Mode-windows-$timestamp"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return (Resolve-Path $dir).Path
}

function Get-AgentProcesses {
    @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
}

function Get-AlertLineCount {
    param([string]$RuleName = "")

    $total = 0
    $needle = if ($RuleName.Length -gt 0) { '"rule.name":"' + $RuleName + '"' } else { "" }
    foreach ($file in @(Get-ChildItem -Path $AlertGlob -ErrorAction SilentlyContinue)) {
        try {
            if ($needle.Length -gt 0) {
                $total += @(Select-String -Path $file.FullName -SimpleMatch $needle -ErrorAction Stop).Count
            } else {
                $total += @(Get-Content -Path $file.FullName -ErrorAction Stop).Count
            }
        } catch {
            Write-Warning "Unable to read alert file $($file.FullName): $_"
        }
    }
    return $total
}

function Get-OperationalLogOffsets {
    $offsets = @{}
    foreach ($file in @(Get-ChildItem -Path ".\logs\rustinel.log.*" -File -ErrorAction SilentlyContinue)) {
        $offsets[$file.FullName] = $file.Length
    }
    return $offsets
}

function Get-AppendedLogText {
    param([hashtable]$Offsets)

    $builder = [System.Text.StringBuilder]::new()
    foreach ($file in @(Get-ChildItem -Path ".\logs\rustinel.log.*" -File -ErrorAction SilentlyContinue)) {
        $offset = if ($Offsets.ContainsKey($file.FullName)) { [int64]$Offsets[$file.FullName] } else { [int64]0 }
        if ($file.Length -le $offset) {
            continue
        }

        $stream = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            [void]$stream.Seek($offset, [System.IO.SeekOrigin]::Begin)
            $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8, $true, 4096, $true)
            try {
                [void]$builder.Append($reader.ReadToEnd())
            } finally {
                $reader.Dispose()
            }
        } finally {
            $stream.Dispose()
        }
    }
    return $builder.ToString()
}

function Get-EtwDropSummary {
    param([hashtable]$Offsets)

    $text = Get-AppendedLogText -Offsets $Offsets
    $dropWarnings = [regex]::Matches($text, "Sensor event channel full; dropping ETW event").Count
    $counterMatches = [regex]::Matches($text, "dropped_events=(\d+)")
    $finalCounter = [int64]0
    foreach ($match in $counterMatches) {
        $finalCounter = [int64]$match.Groups[1].Value
    }

    return [pscustomobject]@{
        warning_count = $dropWarnings
        final_counter = $finalCounter
    }
}

function Test-IdleHasAgentSamples {
    param([string]$SamplesPath)

    if (-not (Test-Path $SamplesPath)) {
        return $false
    }

    foreach ($sample in @(Import-Csv -Path $SamplesPath)) {
        if ($sample.label -eq "idle" -and [int]$sample.pid_count -gt 0) {
            return $true
        }
    }
    return $false
}

function New-BenchmarkSigmaCorpus {
    param(
        [string]$SourcePath,
        [string]$RuleName
    )

    $dest = Join-Path $script:RunDir "sigma-benchmark"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    if (Test-Path $SourcePath) {
        foreach ($item in @(Get-ChildItem -Path $SourcePath -Force -ErrorAction SilentlyContinue)) {
            Copy-Item -LiteralPath $item.FullName -Destination $dest -Recurse -Force
        }
    }

    $rulePath = Join-Path $dest "rustinel_benchmark_whoami_windows.yml"
    $rule = @"
title: $RuleName
id: 9a782d5f-37f8-4f1d-9f64-e41881f5d3b7
status: test
description: Stable Windows whoami trigger used by Rustinel benchmark latency checks.
author: Rustinel
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\whoami.exe'
  selection_cmd:
    CommandLine|contains: ' /all'
  condition: selection_img and selection_cmd
level: low
"@
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($rulePath, $rule, $utf8NoBom)
    return (Resolve-Path $dest).Path
}

function Measure-AgentResources {
    param(
        [string]$Label,
        [int]$DurationSeconds,
        [string]$SamplesPath
    )

    $logicalCpus = [Math]::Max([Environment]::ProcessorCount, 1)
    $samples = New-Object System.Collections.Generic.List[object]
    $previousCpu = $null
    $previousTime = $null

    for ($i = 0; $i -le $DurationSeconds; $i++) {
        $now = Get-Date
        $procs = @(Get-AgentProcesses)
        $cpuSeconds = ($procs | ForEach-Object { if ($null -ne $_.CPU) { $_.CPU } else { 0 } } | Measure-Object -Sum).Sum
        if ($null -eq $cpuSeconds) {
            $cpuSeconds = 0
        }
        $workingSetBytes = ($procs | ForEach-Object { $_.WorkingSet64 } | Measure-Object -Sum).Sum
        if ($null -eq $workingSetBytes) {
            $workingSetBytes = 0
        }
        $threadCount = ($procs | ForEach-Object { $_.Threads.Count } | Measure-Object -Sum).Sum
        if ($null -eq $threadCount) {
            $threadCount = 0
        }

        $cpuPercent = 0.0
        if ($null -ne $previousCpu -and $null -ne $previousTime) {
            $elapsed = [Math]::Max(($now - $previousTime).TotalSeconds, 0.001)
            $cpuPercent = [Math]::Max(0.0, (($cpuSeconds - $previousCpu) / $elapsed / $logicalCpus) * 100.0)
        }

        $sample = [pscustomobject]@{
            timestamp = (Get-NowIso)
            label = $Label
            pid_count = $procs.Count
            cpu_percent = [Math]::Round($cpuPercent, 3)
            working_set_mb = [Math]::Round($workingSetBytes / 1MB, 3)
            threads = [int]$threadCount
        }
        $samples.Add($sample)

        $previousCpu = $cpuSeconds
        $previousTime = $now

        if ($i -lt $DurationSeconds) {
            Start-Sleep -Seconds 1
        }
    }

    $samples | Export-Csv -Path $SamplesPath -NoTypeInformation -Append
    $cpuValues = @($samples | Select-Object -Skip 1 | ForEach-Object { $_.cpu_percent } | Sort-Object)
    $rssValues = @($samples | ForEach-Object { $_.working_set_mb } | Sort-Object)
    $p95Index = if ($cpuValues.Count -gt 0) { [Math]::Min($cpuValues.Count - 1, [Math]::Ceiling($cpuValues.Count * 0.95) - 1) } else { 0 }

    return [pscustomobject]@{
        label = $Label
        seconds = $DurationSeconds
        cpu_avg_percent = if ($cpuValues.Count -gt 0) { [Math]::Round((($cpuValues | Measure-Object -Average).Average), 3) } else { 0.0 }
        cpu_p95_percent = if ($cpuValues.Count -gt 0) { [Math]::Round($cpuValues[$p95Index], 3) } else { 0.0 }
        working_set_avg_mb = if ($rssValues.Count -gt 0) { [Math]::Round((($rssValues | Measure-Object -Average).Average), 3) } else { 0.0 }
        working_set_max_mb = if ($rssValues.Count -gt 0) { [Math]::Round((($rssValues | Measure-Object -Maximum).Maximum), 3) } else { 0.0 }
        threads_max = if ($samples.Count -gt 0) { (($samples | ForEach-Object { $_.threads }) | Measure-Object -Maximum).Maximum } else { 0 }
    }
}

function Measure-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "Running $Name..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = "ok"
    $errorMessage = $null
    try {
        & $Action
    } catch {
        $status = "error"
        $errorMessage = $_.Exception.Message
        Write-Warning "$Name failed: $errorMessage"
    } finally {
        $sw.Stop()
    }

    return [pscustomobject]@{
        name = $Name
        status = $status
        duration_ms = [int64]$sw.ElapsedMilliseconds
        error = $errorMessage
    }
}

function Invoke-ProcessLaunchWorkload {
    for ($i = 0; $i -lt $ProcessLaunches; $i++) {
        $proc = Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "exit", "0" -WindowStyle Hidden -PassThru
        $proc.WaitForExit()
    }
}

function Invoke-FileIoWorkload {
    $workDir = Join-Path $script:RunDir "file-io"
    if (Test-Path $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null

    $buffer = New-Object byte[] $FileSizeBytes
    for ($i = 0; $i -lt $FileCount; $i++) {
        [System.IO.File]::WriteAllBytes((Join-Path $workDir "sample-$i.bin"), $buffer)
    }
    foreach ($file in Get-ChildItem -Path $workDir -File) {
        $stream = [System.IO.File]::OpenRead($file.FullName)
        try {
            [void]$stream.ReadByte()
        } finally {
            $stream.Dispose()
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force
}

function Invoke-CargoBuildWorkload {
    if ($SkipCargo) {
        return "skipped"
    }
    if ($null -eq (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found"
    }
    & cargo build --locked --release
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
}

function Measure-AlertLatency {
    if ($NoAlertLatency) {
        return $null
    }

    $before = Get-AlertLineCount -RuleName $AlertRuleName
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & whoami /all | Out-Null
    while ($sw.Elapsed.TotalSeconds -lt 15) {
        Start-Sleep -Milliseconds 100
        $after = Get-AlertLineCount -RuleName $AlertRuleName
        if ($after -gt $before) {
            $sw.Stop()
            return [int64]$sw.ElapsedMilliseconds
        }
    }
    $sw.Stop()
    return $null
}

function Get-MachineInfo {
    $os = [Environment]::OSVersion.VersionString
    $cpu = "unknown"
    $totalMemoryMb = 0

    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($null -ne $osInfo.Caption) {
            $os = $osInfo.Caption
        }
    } catch {
        Write-Warning "Unable to query operating system metadata through CIM: $($_.Exception.Message)"
    }

    try {
        $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        if ($null -ne $cpuInfo.Name) {
            $cpu = $cpuInfo.Name
        }
    } catch {
        Write-Warning "Unable to query CPU metadata through CIM: $($_.Exception.Message)"
    }

    try {
        $computerInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($null -ne $computerInfo.TotalPhysicalMemory) {
            $totalMemoryMb = [Math]::Round($computerInfo.TotalPhysicalMemory / 1MB, 0)
        }
    } catch {
        Write-Warning "Unable to query memory metadata through CIM: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        os = $os
        cpu = $cpu
        logical_cpus = [Environment]::ProcessorCount
        total_memory_mb = $totalMemoryMb
    }
}

function Count-RuleFiles {
    param(
        [string]$Path,
        [string[]]$Extensions
    )

    if (-not (Test-Path $Path)) {
        return 0
    }

    $count = 0
    foreach ($ext in $Extensions) {
        $count += @(Get-ChildItem -Path $Path -Recurse -File -Filter "*.$ext" -ErrorAction SilentlyContinue).Count
    }
    return $count
}

function Count-NonCommentLines {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return 0
    }

    $count = 0
    foreach ($file in @(Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue)) {
        try {
            foreach ($line in Get-Content -Path $file.FullName -ErrorAction Stop) {
                $trimmed = $line.Trim()
                if ($trimmed.Length -gt 0 -and -not $trimmed.StartsWith("#")) {
                    $count++
                }
            }
        } catch {
            Write-Warning "Unable to read IOC file $($file.FullName): $_"
        }
    }
    return $count
}

function Get-RuleInventory {
    return [pscustomobject]@{
        sigma_rules_path = $effectiveSigmaRulesPath
        sigma_rule_files = Count-RuleFiles -Path $effectiveSigmaRulesPath -Extensions @("yml", "yaml")
        yara_rules_path = $YaraRulesPath
        yara_rule_files = Count-RuleFiles -Path $YaraRulesPath -Extensions @("yar", "yara")
        ioc_rules_path = $IocRulesPath
        ioc_non_comment_lines = Count-NonCommentLines -Path $IocRulesPath
        note = "Counts describe the configured rule corpus on disk. Runtime logs contain parser skips and loaded-rule details."
    }
}

$script:RunDir = New-BenchDirectory
$samplesPath = Join-Path $script:RunDir "resource-samples.csv"
$summaryPath = Join-Path $script:RunDir "summary.json"
$startedAgent = $null
$effectiveSigmaRulesPath = $SigmaRulesPath
$validationErrors = New-Object System.Collections.Generic.List[string]
$operationalLogOffsets = Get-OperationalLogOffsets
$previousEnv = @{
    sigma = $env:EDR__SCANNER__SIGMA_RULES_PATH
    yara = $env:EDR__SCANNER__YARA_RULES_PATH
    ioc_hashes = $env:EDR__IOC__HASHES_PATH
    ioc_ips = $env:EDR__IOC__IPS_PATH
    ioc_domains = $env:EDR__IOC__DOMAINS_PATH
    ioc_paths = $env:EDR__IOC__PATHS_REGEX_PATH
}

try {
    Write-Host "Writing benchmark output to $script:RunDir"

    if ($Mode -eq "with-agent") {
        $existing = @(Get-AgentProcesses)
        if ($existing.Count -eq 0) {
            if (-not (Test-Path $AgentPath)) {
                throw "AgentPath not found: $AgentPath. Build first with cargo build --release or pass -AgentPath."
            }
            if (-not $NoBenchmarkTriggerRule) {
                $effectiveSigmaRulesPath = New-BenchmarkSigmaCorpus -SourcePath $SigmaRulesPath -RuleName $AlertRuleName
                Write-Host "Using benchmark Sigma corpus: $effectiveSigmaRulesPath"
            }
            $env:EDR__SCANNER__SIGMA_RULES_PATH = $effectiveSigmaRulesPath
            $env:EDR__SCANNER__YARA_RULES_PATH = $YaraRulesPath
            $env:EDR__IOC__HASHES_PATH = Join-Path $IocRulesPath "hashes.txt"
            $env:EDR__IOC__IPS_PATH = Join-Path $IocRulesPath "ips.txt"
            $env:EDR__IOC__DOMAINS_PATH = Join-Path $IocRulesPath "domains.txt"
            $env:EDR__IOC__PATHS_REGEX_PATH = Join-Path $IocRulesPath "paths_regex.txt"
            Write-Host "Starting Rustinel: $AgentPath $AgentArgs"
            $startedAgent = Start-Process -FilePath (Resolve-Path $AgentPath).Path -ArgumentList $AgentArgs -WindowStyle Hidden -PassThru
            Start-Sleep -Seconds 5
            if (@(Get-AgentProcesses).Count -eq 0) {
                [void]$validationErrors.Add("with-agent mode did not observe an agent process after startup")
            }
        } else {
            Write-Host "Using existing $ProcessName process: $($existing.Id -join ', ')"
            if (-not $NoBenchmarkTriggerRule) {
                Write-Warning "Benchmark trigger rule cannot be injected into an already-running agent. Restart Rustinel or pass -NoBenchmarkTriggerRule if the existing config already contains the trigger rule."
            }
        }
    }

    $resourceSummaries = New-Object System.Collections.Generic.List[object]
    $steps = New-Object System.Collections.Generic.List[object]

    $resourceSummaries.Add((Measure-AgentResources -Label "idle" -DurationSeconds $IdleSeconds -SamplesPath $samplesPath))
    if ($Mode -eq "with-agent" -and -not (Test-IdleHasAgentSamples -SamplesPath $samplesPath)) {
        [void]$validationErrors.Add("with-agent idle samples did not observe pid_count > 0")
    }
    if ($runProcessWorkload) {
        $steps.Add((Measure-Step -Name "process_launch_$ProcessLaunches" -Action { Invoke-ProcessLaunchWorkload }))
        $resourceSummaries.Add((Measure-AgentResources -Label "post_process_launch_idle" -DurationSeconds 10 -SamplesPath $samplesPath))
    }
    if ($runFileWorkload) {
        $steps.Add((Measure-Step -Name "file_io_${FileCount}x${FileSizeBytes}" -Action { Invoke-FileIoWorkload }))
    }

    if ($runCargoWorkload) {
        $steps.Add((Measure-Step -Name "cargo_build_release" -Action { Invoke-CargoBuildWorkload }))
    }

    $alertLatency = Measure-AlertLatency
    if ($Mode -eq "with-agent" -and -not $NoAlertLatency -and $null -eq $alertLatency) {
        [void]$validationErrors.Add("with-agent alert latency was null")
    }
    if (@($steps | Where-Object { $_.status -eq "error" }).Count -gt 0) {
        [void]$validationErrors.Add("one or more workload steps failed")
    }
    $etwDrops = Get-EtwDropSummary -Offsets $operationalLogOffsets
    if ($Mode -eq "with-agent" -and $null -ne $etwDrops.final_counter -and $etwDrops.final_counter -gt 0) {
        [void]$validationErrors.Add("ETW drops were observed")
    }

    $machineInfo = Get-MachineInfo
    $ruleInventory = Get-RuleInventory

    $summary = [pscustomobject]@{
        generated_at = Get-NowIso
        platform = "windows"
        mode = $Mode
        agent_path = $AgentPath
        process_name = $ProcessName
        machine = $machineInfo
        rule_inventory = $ruleInventory
        parameters = [pscustomobject]@{
            idle_seconds = $IdleSeconds
            process_launches = $ProcessLaunches
            file_count = $FileCount
            file_size_bytes = $FileSizeBytes
            alert_rule_name = $AlertRuleName
            benchmark_trigger_rule = -not $NoBenchmarkTriggerRule
            effective_sigma_rules_path = $effectiveSigmaRulesPath
            workload_mode = $workloadMode
        }
        resource_summaries = $resourceSummaries
        workload_steps = $steps
        alert_latency_ms = $alertLatency
        etw_drops = $etwDrops
        valid = $validationErrors.Count -eq 0
        validation_errors = @($validationErrors)
        samples_csv = $samplesPath
        notes = @(
            "Run once with -Mode baseline and once with -Mode with-agent on the same machine.",
            "Alert latency is null when no new alert line appears within 15 seconds."
        )
    }

    $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryPath -Encoding UTF8
    Write-Host "Summary: $summaryPath"
    Write-Host "Samples: $samplesPath"
    if ($validationErrors.Count -gt 0) {
        throw "Invalid benchmark run: $($validationErrors -join '; ')"
    }
} finally {
    if ($null -ne $startedAgent -and -not $KeepAgent) {
        Write-Host "Stopping Rustinel process $($startedAgent.Id)"
        Stop-Process -Id $startedAgent.Id -Force -ErrorAction SilentlyContinue
    }
    $env:EDR__SCANNER__SIGMA_RULES_PATH = $previousEnv.sigma
    $env:EDR__SCANNER__YARA_RULES_PATH = $previousEnv.yara
    $env:EDR__IOC__HASHES_PATH = $previousEnv.ioc_hashes
    $env:EDR__IOC__IPS_PATH = $previousEnv.ioc_ips
    $env:EDR__IOC__DOMAINS_PATH = $previousEnv.ioc_domains
    $env:EDR__IOC__PATHS_REGEX_PATH = $previousEnv.ioc_paths
}
