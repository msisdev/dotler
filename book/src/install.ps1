# One-liner installer for dotler prebuilt release binaries on Windows.
# Usage:
#   irm https://msisdev.github.io/dotler/install.ps1 | iex
#
# Environment variables:
#   $env:DOTLER_INSTALL_DIR  Target directory for dotler.exe (default: $HOME\.local\bin)
#   $env:DOTLER_VERSION      Release tag to install, e.g. v0.1.0 (default: latest)
#   $env:DOTLER_REPO         GitHub repository owner/name (default: msisdev/dotler)

$ErrorActionPreference = 'Stop'

$Repo = if ($env:DOTLER_REPO) { $env:DOTLER_REPO } else { "msisdev/dotler" }
$Version = if ($env:DOTLER_VERSION) { $env:DOTLER_VERSION } else { "latest" }
$InstallDir = if ($env:DOTLER_INSTALL_DIR) { $env:DOTLER_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }

$ArchRaw = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToUpperInvariant()
$Target = switch ($ArchRaw) {
    "X64"   { "x86_64-pc-windows-msvc" }
    "AMD64" { "x86_64-pc-windows-msvc" }
    "ARM64" { "aarch64-pc-windows-msvc" }
    default { throw "Unsupported Windows CPU architecture: $ArchRaw" }
}

$Archive = "dotler-$Target.zip"
$ChecksumFile = "$Archive.sha256"

if ($env:DOTLER_RELEASE_BASE_URL) {
    $BaseUrl = $env:DOTLER_RELEASE_BASE_URL.TrimEnd('/')
} elseif ($Version -eq "latest") {
    $BaseUrl = "https://github.com/$Repo/releases/latest/download"
} else {
    $Tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $BaseUrl = "https://github.com/$Repo/releases/download/$Tag"
}

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dotler-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

try {
    $ArchivePath = Join-Path $TmpDir $Archive
    $ChecksumPath = Join-Path $TmpDir $ChecksumFile

    Write-Host "Downloading dotler ($Target) from $Repo..."
    Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile $ArchivePath -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/$ChecksumFile" -OutFile $ChecksumPath -UseBasicParsing

    $ExpectedHash = ((Get-Content -Path $ChecksumPath -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    $ActualHash = (Get-FileHash -Algorithm SHA256 -Path $ArchivePath).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "SHA-256 checksum mismatch (expected $ExpectedHash, got $ActualHash)."
    }

    Expand-Archive -Path $ArchivePath -DestinationPath $TmpDir -Force
    $ExeSource = Join-Path $TmpDir "dotler.exe"
    if (-not (Test-Path $ExeSource)) {
        throw "Extracted archive did not contain 'dotler.exe'."
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $ExeDest = Join-Path $InstallDir "dotler.exe"
    Move-Item -Path $ExeSource -Destination $ExeDest -Force

    Write-Host "Installed dotler to $ExeDest"
    & $ExeDest --version

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathParts = if ($UserPath) { $UserPath -split ';' } else { @() }
    if ($PathParts -notcontains $InstallDir) {
        $NewUserPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "Added '$InstallDir' to your User PATH."
    }
} finally {
    if (Test-Path $TmpDir) {
        Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
