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

    Write-Host ""
    Write-Host "Rustinel $Version installed to:"
    Write-Host "  $InstallDir"
    Write-Host ""
    Write-Host "Try the bundled demo rule from an elevated PowerShell:"
    Write-Host "  Set-Location `"$InstallDir`""
    Write-Host "  .\rustinel.exe run"
    Write-Host "  whoami /all"
    Write-Host "  Get-Content .\logs\alerts.json.*"
    Write-Host ""

    if ($Run) {
        Set-Location $InstallDir
        & .\rustinel.exe run
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
