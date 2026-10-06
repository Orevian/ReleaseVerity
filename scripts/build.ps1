<#
.SYNOPSIS
  Builds ReleaseVerity: CLI, desktop app, portable folder and Windows installer.

.DESCRIPTION
  One entry point for every artifact:

    scripts\build.ps1 -Target cli        # dist\cli\releaseverity.exe
    scripts\build.ps1 -Target desktop    # target\release\releaseverity-desktop.exe (ReleaseVerity.exe in dist)
    scripts\build.ps1 -Target portable   # dist\portable\ReleaseVerity\  + dist\artifacts\ReleaseVerity-<ver>-portable-x64.zip
    scripts\build.ps1 -Target installer  # dist\installer\ReleaseVerity-Setup-x64.exe   (needs Inno Setup 6)
    scripts\build.ps1                    # = -Target all

  The product version is read from [workspace.package] in Cargo.toml (single source of truth).
  The icon is icon.ico in the repository root, embedded unmodified. Packaging stops with a clear
  message if it is missing. Set RELEASEVERITY_ICON to use an icon from another location.

.NOTES
  Requirements: Rust (MSVC toolchain), and for -Target installer Inno Setup 6
  (winget install JRSoftware.InnoSetup).
#>
[CmdletBinding()]
param(
    [ValidateSet('cli', 'desktop', 'portable', 'installer', 'all')]
    [string]$Target = 'all',
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

function Get-ProductVersion {
    $m = Select-String -Path (Join-Path $Root 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $m) { throw 'Could not read the product version from [workspace.package] in Cargo.toml.' }
    return $m.Matches[0].Groups[1].Value
}

function Find-Iscc {
    $cmd = Get-Command iscc -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @(
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
            (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'))) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    return $null
}

function Assert-Safe-Dist([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $dist = [System.IO.Path]::GetFullPath((Join-Path $Root 'dist'))
    if (-not $full.StartsWith($dist + [System.IO.Path]::DirectorySeparatorChar)) { throw "Refusing to touch $full (outside dist)." }
}

$Version = Get-ProductVersion
$Dist = Join-Path $Root 'dist'
$needsIcon = $Target -in @('desktop', 'portable', 'installer', 'all')

# --- icon ---------------------------------------------------------------------------------
$Icon = if ($env:RELEASEVERITY_ICON) { $env:RELEASEVERITY_ICON } else { Join-Path $Root 'icon.ico' }
if ($needsIcon -and -not (Test-Path $Icon)) {
    throw @"
icon.ico was not found at: $Icon

ReleaseVerity embeds the project's own icon (unmodified) into ReleaseVerity.exe, the installer, the Start Menu
and desktop shortcuts. Place icon.ico in the repository root (or set RELEASEVERITY_ICON) and run again.
"@
}

Write-Host "ReleaseVerity $Version  -  target: $Target" -ForegroundColor Green

# --- tests (optional) ---------------------------------------------------------------------
if ($Test) {
    Step 'Running tests'
    cargo test --workspace --locked
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
}

# --- compile ------------------------------------------------------------------------------
$packages = switch ($Target) {
    'cli' { @('releaseverity-cli') }
    'desktop' { @('releaseverity-desktop', 'releaseverity-agent') }
    default { @('releaseverity-cli', 'releaseverity-desktop', 'releaseverity-agent') }
}
Step ("Compiling (release): " + ($packages -join ', '))
if ($needsIcon) {
    $env:RELEASEVERITY_REQUIRE_ICON = '1'
    $env:RELEASEVERITY_ICON = (Resolve-Path $Icon).Path
}
$cargoArgs = @('build', '--release', '--locked')
foreach ($p in $packages) { $cargoArgs += @('-p', $p) }
cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
$rel = Join-Path $Root 'target\release'

if ($Target -eq 'cli') {
    $out = Join-Path $Dist 'cli'
    New-Item -ItemType Directory -Force $out | Out-Null
    Copy-Item (Join-Path $rel 'releaseverity.exe') $out -Force
    Write-Host "CLI: $out\releaseverity.exe" -ForegroundColor Green
    return
}
if ($Target -eq 'desktop') {
    Write-Host "Desktop: $rel\releaseverity-desktop.exe (shipped as ReleaseVerity.exe)" -ForegroundColor Green
    return
}

# --- portable / onedir folder -------------------------------------------------------------
$Portable = Join-Path $Dist 'portable\ReleaseVerity'
Step "Assembling $Portable"
Assert-Safe-Dist $Portable
if (Test-Path $Portable) { Remove-Item -Recurse -Force $Portable }
foreach ($d in @('', 'cli', 'resources', 'locales', 'config', 'docs')) {
    New-Item -ItemType Directory -Force (Join-Path $Portable $d) | Out-Null
}
Copy-Item (Join-Path $rel 'releaseverity-desktop.exe') (Join-Path $Portable 'ReleaseVerity.exe')
Copy-Item (Join-Path $rel 'releaseverity-agent.exe') (Join-Path $Portable 'releaseverity-agent.exe')
Copy-Item (Join-Path $rel 'releaseverity.exe') (Join-Path $Portable 'cli\releaseverity.exe')
Copy-Item $Icon (Join-Path $Portable 'resources\icon.ico')
Copy-Item (Join-Path $Root 'locales\*.json') (Join-Path $Portable 'locales')
foreach ($f in @('LICENSE', 'README.md', 'CHANGELOG.md', 'SECURITY.md')) {
    if (Test-Path (Join-Path $Root $f)) { Copy-Item (Join-Path $Root $f) $Portable }
}
if (Test-Path (Join-Path $Root 'docs')) { Copy-Item (Join-Path $Root 'docs\*') (Join-Path $Portable 'docs') -Recurse -Force }
Set-Content -Path (Join-Path $Portable 'config\README.txt') -Encoding Ascii -Value @(
    'This folder marks this copy of ReleaseVerity as PORTABLE.',
    'Settings, the database, logs and reports are stored in the "data" folder next to ReleaseVerity.exe',
    'instead of in %APPDATA%. Delete this folder to switch back to the per-user location.')

# Third-party notices + SBOM (generated from the real dependency graph).
Step 'Generating SBOM and third-party notices'
New-Item -ItemType Directory -Force (Join-Path $Dist 'artifacts') | Out-Null
& (Join-Path $PSScriptRoot 'gen-sbom.ps1') -Version $Version -SbomPath (Join-Path $Dist "artifacts\ReleaseVerity-$Version.cdx.json") -NoticesPath (Join-Path $Portable 'resources\THIRD_PARTY_NOTICES.md')
if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { throw 'SBOM generation failed.' }

# --- zip ------------------------------------------------------------------------------------
$Artifacts = Join-Path $Dist 'artifacts'
$zip = Join-Path $Artifacts "ReleaseVerity-$Version-portable-x64.zip"
Step "Creating $zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
# bsdtar (built into Windows 10+) writes standards-compliant zips with forward slashes.
tar.exe -a -c -f $zip -C (Join-Path $Dist 'portable') ReleaseVerity
if ($LASTEXITCODE -ne 0) { throw 'Creating the portable zip failed.' }

# --- installer ------------------------------------------------------------------------------
if ($Target -in @('installer', 'all')) {
    $iscc = Find-Iscc
    if (-not $iscc) {
        throw "Inno Setup 6 was not found. Install it (winget install JRSoftware.InnoSetup) and run again; the portable folder and zip were built."
    }
    $InstOut = Join-Path $Dist 'installer'
    New-Item -ItemType Directory -Force $InstOut | Out-Null
    Step "Compiling installer with $iscc"
    & $iscc /Qp "/DAppVersion=$Version" "/DSourceDir=$Portable" "/DOutputDir=$InstOut" "/DIconFile=$((Resolve-Path $Icon).Path)" (Join-Path $Root 'setup.iss')
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed.' }
    Copy-Item (Join-Path $InstOut 'ReleaseVerity-Setup-x64.exe') $Artifacts -Force
}

# --- checksums ------------------------------------------------------------------------------
Step 'Writing SHA256SUMS'
$sums = Get-ChildItem $Artifacts -File | Where-Object { $_.Name -ne 'SHA256SUMS' } | Sort-Object Name | ForEach-Object {
    $h = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLowerInvariant()
    "$h  $($_.Name)"
}
Set-Content -Path (Join-Path $Artifacts 'SHA256SUMS') -Value $sums -Encoding Ascii

Write-Host ''
Write-Host 'Done:' -ForegroundColor Green
Write-Host "  portable folder : $Portable\ReleaseVerity.exe"
Write-Host "  artifacts       : $Artifacts"
if (Test-Path (Join-Path $Dist 'installer\ReleaseVerity-Setup-x64.exe')) { Write-Host "  installer       : $(Join-Path $Dist 'installer\ReleaseVerity-Setup-x64.exe')" }
