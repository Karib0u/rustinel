param(
    [string]$Repo = "Karib0u/rustinel",
    [string]$Version = "latest",
    [string]$InstallDir = (Join-Path (Get-Location) "rustinel"),
    [switch]$Run,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Show-InstallScope {
    Write-Host "This script only installs published Rustinel release binaries."
    Write-Host "It does not install Rust, Cargo, or build Rustinel from source."
    Write-Host "Source build guide: https://docs.rustinel.io/getting-started/#compile-from-source"
}

function Test-TruthyEnv {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $normalized = $Value.Trim().ToLowerInvariant()
    return @("1", "true", "yes", "on") -contains $normalized
}

function Show-PromotionCommand {
    param([string]$Path)

    Write-Host "Permanent deployment command:"
    Write-Host "  Set-Location `"$Path`"; .\rustinel.exe setup --yes"
}

function Show-PortableEvaluation {
    param(
        [string]$Path,
        [string]$ReleaseVersion
    )

    $demoRulesPath = Join-Path $Path "rules\sigma"
    $demoRulesStatus = "not found"
    $demoRule = Get-ChildItem -Path $demoRulesPath -Filter "*whoami*.yml" -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($demoRule) {
        $demoRulesStatus = "present"
    }

    Write-Host ""
    Write-Host "Rustinel $ReleaseVersion installed to:"
    Write-Host "  $Path"
    Write-Host ""
    Write-Host "Portable evaluation mode:"
    Write-Host "  Package: $Path"
    Write-Host "  Config: $(Join-Path $Path 'config.toml')"
    Write-Host "  Demo rules: $demoRulesPath ($demoRulesStatus)"
    Write-Host "  Alerts: $(Join-Path $Path 'logs\alerts.json.*')"
    Write-Host "  Active response: disabled in bundled config"
    Write-Host ""
    Write-Host "Start monitoring from an elevated PowerShell:"
    Write-Host "  Set-Location `"$Path`""
    Write-Host "  .\rustinel.exe run"
    Write-Host ""
    Write-Host "Demo trigger from another PowerShell:"
    Write-Host "  whoami"
    Write-Host ""
    Write-Host "Show the alert:"
    Write-Host "  Get-Content `"$Path\logs\alerts.json.*`""
    Write-Host ""
    Show-PromotionCommand -Path $Path
}

$InvokedFromStream = [string]::IsNullOrEmpty($PSCommandPath)

if (-not $PSBoundParameters.ContainsKey("Repo") -and -not [string]::IsNullOrWhiteSpace($env:RUSTINEL_REPO)) {
    $Repo = $env:RUSTINEL_REPO
}

if (-not $PSBoundParameters.ContainsKey("Version") -and -not [string]::IsNullOrWhiteSpace($env:RUSTINEL_VERSION)) {
    $Version = $env:RUSTINEL_VERSION
}

if (-not $PSBoundParameters.ContainsKey("InstallDir") -and -not [string]::IsNullOrWhiteSpace($env:RUSTINEL_INSTALL_DIR)) {
    $InstallDir = $env:RUSTINEL_INSTALL_DIR
}

if (-not $PSBoundParameters.ContainsKey("Run") -and (Test-TruthyEnv $env:RUSTINEL_RUN)) {
    $Run = $true
}

if (-not $PSBoundParameters.ContainsKey("Force") -and (Test-TruthyEnv $env:RUSTINEL_FORCE)) {
    $Force = $true
}

$RunEvaluation = [bool]$Run -or $InvokedFromStream

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "Only 64-bit Windows is supported by the published release archive."
}

if ($Version -eq "latest") {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $release.tag_name.TrimStart("v")
} else {
    $Version = $Version.TrimStart("v")
}

$asset = "rustinel-$Version-x86_64-pc-windows-msvc.zip"
$checksums = "rustinel-$Version-checksums-sha256.txt"
$baseUrl = "https://github.com/$Repo/releases/download/v$Version"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "rustinel-install-$([System.Guid]::NewGuid())"

New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $assetPath = Join-Path $tmp $asset
    $checksumsPath = Join-Path $tmp $checksums

    # GitHub redirects release assets to a presigned CDN URL signed for GET, so a
    # HEAD probe is rejected and Invoke-WebRequest throws a false "not found".
    # Let the actual GET download be the existence check instead.
    Write-Host "Downloading $asset"
    try {
        Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $assetPath
    } catch {
        Show-InstallScope
        throw "No published release asset found for this host: $asset. Release page: https://github.com/$Repo/releases/tag/v$Version"
    }
    Invoke-WebRequest -Uri "$baseUrl/$checksums" -OutFile $checksumsPath

    $expected = Get-Content $checksumsPath |
        Where-Object { $_ -match [regex]::Escape($asset) } |
        ForEach-Object { ($_ -split "\s+")[0].ToLowerInvariant() } |
        Select-Object -First 1

    if (-not $expected) {
        throw "Checksum file did not contain $asset"
    }

    $actual = (Get-FileHash -Algorithm SHA256 $assetPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $asset. Expected $expected, got $actual."
    }

    $extractDir = Join-Path $tmp "extract"
    Expand-Archive -Path $assetPath -DestinationPath $extractDir
    $packageDir = Join-Path $extractDir "rustinel-$Version-x86_64-pc-windows-msvc"

    if (-not (Test-Path $packageDir)) {
        throw "Archive did not contain expected directory: rustinel-$Version-x86_64-pc-windows-msvc"
    }

    if (Test-Path $InstallDir) {
        if ($Force) {
            Remove-Item -Recurse -Force $InstallDir
        } else {
            throw "Install directory already exists: $InstallDir. Pass -Force or choose another -InstallDir."
        }
    }

    New-Item -ItemType Directory -Path $InstallDir | Out-Null
    Copy-Item -Path (Join-Path $packageDir "*") -Destination $InstallDir -Recurse -Force

    Show-PortableEvaluation -Path $InstallDir -ReleaseVersion $Version

    if ($RunEvaluation) {
        Set-Location $InstallDir
        Write-Host ""
        Write-Host "Starting portable evaluation. Trigger detection with: whoami"
        Write-Host "Alerts are written to: $(Join-Path $InstallDir 'logs\alerts.json.*')"
        Write-Host ""
        & .\rustinel.exe run
        $runStatus = $LASTEXITCODE
        if ($null -eq $runStatus) {
            $runStatus = 0
        }
        Write-Host ""
        Show-PromotionCommand -Path $InstallDir
        if ($runStatus -ne 0 -and -not $InvokedFromStream) {
            exit $runStatus
        }
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
