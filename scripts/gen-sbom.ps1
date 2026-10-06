<#
.SYNOPSIS
  Generates a CycloneDX 1.5 SBOM and a third-party notices file from the real Cargo dependency graph.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Version,
    [Parameter(Mandatory)] [string]$SbomPath,
    [Parameter(Mandatory)] [string]$NoticesPath
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Dependencies actually linked for Windows x64 (what ships), not the whole multi-platform graph.
$json = cargo metadata --format-version 1 --locked --filter-platform x86_64-pc-windows-msvc | Out-String
if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed.' }
$meta = $json | ConvertFrom-Json

$workspaceIds = @{}
foreach ($id in $meta.workspace_members) { $workspaceIds[$id] = $true }

$components = @()
$notices = @()
foreach ($p in ($meta.packages | Sort-Object name, version)) {
    if ($workspaceIds.ContainsKey($p.id)) { continue }
    $purl = "pkg:cargo/$($p.name)@$($p.version)"
    $c = [ordered]@{
        type    = 'library'
        name    = $p.name
        version = $p.version
        purl    = $purl
    }
    if ($p.license) { $c['licenses'] = @(@{ expression = $p.license }) }
    if ($p.repository) { $c['externalReferences'] = @(@{ type = 'vcs'; url = $p.repository }) }
    $components += $c
    $lic = if ($p.license) { $p.license } else { 'see crate' }
    $repo = if ($p.repository) { $p.repository } else { '' }
    $notices += "| $($p.name) | $($p.version) | $lic | $repo |"
}

$bom = [ordered]@{
    bomFormat    = 'CycloneDX'
    specVersion  = '1.5'
    serialNumber = 'urn:uuid:' + [guid]::NewGuid().ToString()
    version      = 1
    metadata     = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        tools     = @(@{ vendor = 'ReleaseVerity'; name = 'scripts/gen-sbom.ps1'; version = $Version })
        component = [ordered]@{ type = 'application'; name = 'ReleaseVerity'; version = $Version; purl = "pkg:generic/releaseverity@$Version" }
    }
    components   = $components
}
New-Item -ItemType Directory -Force (Split-Path -Parent $SbomPath) | Out-Null
$bom | ConvertTo-Json -Depth 8 | Set-Content -Path $SbomPath -Encoding UTF8
Write-Host "SBOM: $SbomPath ($($components.Count) components)"

New-Item -ItemType Directory -Force (Split-Path -Parent $NoticesPath) | Out-Null
$header = @(
    '# Third-party notices',
    '',
    "ReleaseVerity $Version is built from the open-source Rust crates below. Each crate is licensed",
    'under the terms shown; full license texts are available in each crate''s repository.',
    '',
    '| Crate | Version | License | Repository |',
    '|---|---|---|---|'
)
Set-Content -Path $NoticesPath -Value ($header + $notices) -Encoding UTF8
Write-Host "Notices: $NoticesPath"
