<#
.SYNOPSIS
  Builds a clean, granular git history for ReleaseVerity: one commit per file, in dependency order,
  each with a meaningful Conventional-Commit message.

.DESCRIPTION
  Files are taken from the working tree (respecting .gitignore), so build output (target\, dist\)
  is never committed. The order follows how the product was built: workspace and tooling, core,
  Repro Engine, agent + sandbox, ShipCheck, GitHub, services, CLI, desktop app, installer and
  scripts, documentation, GitHub automation.

  If the repository already has commits, the script refuses to run unless -Force is given. With
  -Force it keeps the old history safe under a tag (backup/before-history-<timestamp>) and then
  rebuilds the branch from scratch.

.PARAMETER Remote
  Remote URL (default: https://github.com/Orevian/ReleaseVerity.git).

.PARAMETER Branch
  Branch to create (default: main).

.PARAMETER UserName / UserEmail
  Author identity. Defaults to your git config (user.name / user.email).

.PARAMETER Push
  Push to the remote after the history is built. Needs -Force when the remote already has commits.

.PARAMETER DryRun
  Print the commit plan without touching git.

.EXAMPLE
  .\history.ps1 -DryRun
  .\history.ps1 -Force -Push
#>
[CmdletBinding()]
param(
    [string]$Remote = 'https://github.com/Orevian/ReleaseVerity.git',
    [string]$Branch = 'main',
    [string]$UserName,
    [string]$UserEmail,
    [switch]$Push,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
Set-Location $Root

function Invoke-Git {
    # Run git, fail loudly on a non-zero exit code.
    & git @args
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed (exit code $LASTEXITCODE)" }
}

# ---------------------------------------------------------------------------------------------
# The plan: pattern (relative path, forward slashes, -like wildcards) -> commit message.
# {file} = file name, {path} = relative path. Every matching file gets its OWN commit.
# ---------------------------------------------------------------------------------------------
$core = 'crates/releaseverity-core'
$repro = 'crates/releaseverity-repro'
$agent = 'crates/releaseverity-agent'
$ship = 'crates/releaseverity-shipcheck'
$gh = 'crates/releaseverity-github'
$svc = 'crates/releaseverity-services'
$cli = 'crates/releaseverity-cli'
$ui = 'crates/releaseverity-desktop'

$Plan = @(
    # --- repository scaffolding -------------------------------------------------------------
    ,@('.gitignore', 'chore: ignore build output (target, dist) and local data')
    ,@('.gitattributes', 'chore: normalise line endings to LF and mark binary files')
    ,@('rustfmt.toml', 'chore: configure rustfmt (max_width 140)')
    ,@('.cargo/config.toml', 'build: link the C runtime statically so binaries run on a clean Windows install')
    ,@('LICENSE', 'docs: add the Apache-2.0 license')
    ,@('Cargo.toml', 'build: create the Rust workspace with a single-source product version')
    ,@('locales/en.json', 'feat(i18n): add the English message catalog')
    ,@('locales/tr.json', 'feat(i18n): add the Turkish message catalog')

    # --- core ---------------------------------------------------------------------------------
    ,@("$core/Cargo.toml", 'build(core): add the core crate manifest')
    ,@("$core/src/model.rs", 'feat(core): add the domain model (status, check result, run, verdict, localizable messages)')
    ,@("$core/src/config.rs", 'feat(core): add config.toml handling with validation and portable-mode data directory discovery')
    ,@("$core/src/logging.rs", 'feat(core): add structured JSONL logging split by category')
    ,@("$core/src/hash.rs", 'feat(core): add streaming SHA-256/SHA-512 file hashing')
    ,@("$core/src/proc.rs", 'feat(core): add a timeout-bounded process runner and pid liveness check')
    ,@("$core/src/i18n.rs", 'feat(core): add the localization engine over the JSON catalogs')
    ,@("$core/src/db.rs", 'feat(core): add SQLite storage with migrations and crash recovery of interrupted runs')
    ,@("$core/src/check.rs", 'feat(core): add the check pipeline contract and real progress events')
    ,@("$core/src/scoring.rs", 'feat(core): add release score and verdict computation')
    ,@("$core/src/report.rs", 'feat(core): add HTML, Markdown and JSON reports with the environment matrix')
    ,@("$core/src/lib.rs", 'feat(core): expose the core library and the product version')

    # --- Repro Engine -------------------------------------------------------------------------
    ,@("$repro/Cargo.toml", 'build(repro): add the Repro Engine crate manifest')
    ,@("$repro/src/assets.rs", 'feat(repro): classify release assets and parse checksum files')
    ,@("$repro/src/git.rs", 'feat(repro): add git integrity, tag resolution and tag signature verification')
    ,@("$repro/src/inspect.rs", 'feat(repro): add artifact inspection for PE, ELF and ZIP files')
    ,@("$repro/src/diff.rs", 'feat(repro): add binary difference analysis that names the probable cause')
    ,@("$repro/src/sbom.rs", 'feat(repro): add CycloneDX and SPDX SBOM validation')
    ,@("$repro/src/provenance.rs", 'feat(repro): add SLSA / in-toto provenance parsing and digest binding')
    ,@("$repro/src/signature.rs", 'feat(repro): add Authenticode and detached GPG signature verification')
    ,@("$repro/src/checks.rs", 'feat(repro): add the Repro Engine checks (source, checksum, signature, provenance, SBOM, reproducibility)')
    ,@("$repro/src/lib.rs", 'feat(repro): assemble the Repro Engine check list')
    ,@("$repro/tests/pipeline.rs", 'test(repro): add end-to-end pipeline tests on real git repositories')

    # --- agent + built-in sandbox -----------------------------------------------------------------
    ,@("$agent/Cargo.toml", 'build(agent): add the test agent crate manifest')
    ,@("$agent/src/lib.rs", 'feat(agent): define the host/agent protocol (spec, steps, progress, report)')
    ,@("$agent/src/winproc.rs", 'feat(agent): supervise processes in Job Objects (process tree, limits, timeouts, hang detection)')
    ,@("$agent/src/ac.rs", 'feat(agent): add the built-in AppContainer sandbox (no network, no access outside its grants)')
    ,@("$agent/src/runner.rs", 'feat(agent): add the install, launch, smoke and uninstall plan')
    ,@("$agent/src/main.rs", 'feat(agent): add the agent executable')
    ,@("$agent/examples/crash_app.rs", 'test(agent): add a fixture application that really crashes')
    ,@("$agent/examples/gui_ok.rs", 'test(agent): add a healthy GUI fixture application')
    ,@("$agent/examples/hang_app.rs", 'test(agent): add a GUI fixture that stops responding')

    # --- ShipCheck Engine --------------------------------------------------------------------------
    ,@("$ship/Cargo.toml", 'build(shipcheck): add the ShipCheck Engine crate manifest')
    ,@("$ship/src/runner.rs", 'feat(shipcheck): add the host, Windows Sandbox and built-in sandbox runners')
    ,@("$ship/src/agent_msgs.rs", 'feat(shipcheck): localize the agent step messages')
    ,@("$ship/src/checks.rs", 'feat(shipcheck): add per-environment install, launch, smoke and uninstall checks')
    ,@("$ship/src/docs.rs", 'feat(shipcheck): add documentation checks (installation, usage, upgrade)')
    ,@("$ship/src/lib.rs", 'feat(shipcheck): assemble the ShipCheck Engine')
    ,@("$ship/tests/host_e2e.rs", 'test(shipcheck): add end-to-end tests with real crash, hang and sandbox scenarios')

    # --- GitHub integration --------------------------------------------------------------------------
    ,@("$gh/Cargo.toml", 'build(github): add the GitHub integration crate manifest')
    ,@("$gh/src/credstore.rs", 'feat(github): store the token in Windows Credential Manager')
    ,@("$gh/src/lib.rs", 'feat(github): add the API client, release asset download and check publishing')

    # --- services ----------------------------------------------------------------------------------------
    ,@("$svc/Cargo.toml", 'build(services): add the services crate manifest')
    ,@("$svc/src/environments.rs", 'feat(services): detect the available execution environments and tools')
    ,@("$svc/src/request.rs", 'feat(services): build verification requests shared by the CLI and the desktop app')
    ,@("$svc/src/github.rs", 'feat(services): download GitHub release assets as a pipeline step and publish checks')
    ,@("$svc/src/lib.rs", 'feat(services): add the single API used by every front end')

    # --- CLI -------------------------------------------------------------------------------------------------
    ,@("$cli/Cargo.toml", 'build(cli): add the CLI crate manifest')
    ,@("$cli/src/ui.rs", 'feat(cli): add terminal rendering (optional colour, ASCII fallback, tables)')
    ,@("$cli/src/main.rs", 'feat(cli): add the releaseverity command')
    ,@("$cli/tests/cli.rs", 'test(cli): add end-to-end tests of the real binary')

    # --- desktop app --------------------------------------------------------------------------------------------
    ,@("$ui/Cargo.toml", 'build(desktop): add the desktop app crate manifest')
    ,@("$ui/build.rs", 'build(desktop): compile the UI and embed icon.ico and version metadata')
    ,@("$ui/ui/theme.slint", 'feat(desktop): add the design tokens (dark and light) and the localization global')
    ,@("$ui/ui/state.slint", 'feat(desktop): add the data shapes and application state shared with Rust')
    ,@("$ui/ui/widgets.slint", 'feat(desktop): add the shared widgets (buttons, fields, badges, status glyphs)')
    ,@("$ui/ui/icons/*", 'feat(desktop): add icon {file}')
    ,@("$ui/ui/pages/common.slint", 'feat(desktop): add the run table and page header components')
    ,@("$ui/ui/pages/dashboard.slint", 'feat(desktop): add the dashboard')
    ,@("$ui/ui/pages/lists.slint", 'feat(desktop): add the projects, runs, environments, artifacts and reports pages')
    ,@("$ui/ui/pages/detail.slint", 'feat(desktop): add the release detail page with the environment matrix')
    ,@("$ui/ui/pages/wizard.slint", 'feat(desktop): add the new verification workflow')
    ,@("$ui/ui/pages/live.slint", 'feat(desktop): add the live run screen driven by engine events')
    ,@("$ui/ui/pages/repro.slint", 'feat(desktop): add the reproducibility view')
    ,@("$ui/ui/pages/settings.slint", 'feat(desktop): add the settings page')
    ,@("$ui/ui/main.slint", 'feat(desktop): add the main window and navigation')
    ,@("$ui/src/view.rs", 'feat(desktop): add conversions from the domain model to UI rows')
    ,@("$ui/src/data.rs", 'feat(desktop): load real data into the UI models')
    ,@("$ui/src/settings.rs", 'feat(desktop): generate the settings rows from the real config')
    ,@("$ui/src/main.rs", 'feat(desktop): wire the pages to the services layer')

    # --- product, installer and build -------------------------------------------------------------------------------
    ,@('icon.ico', 'feat(branding): add the product icon')
    ,@('setup.iss', 'build(installer): add the Inno Setup installer')
    ,@('scripts/gen-sbom.ps1', 'build: generate the CycloneDX SBOM and third-party notices from the dependency graph')
    ,@('scripts/build.ps1', 'build: add the one-command build for CLI, desktop, portable folder and installer')

    # --- documentation --------------------------------------------------------------------------------------------------
    ,@('tests/README.md', 'docs(tests): describe the test layout')
    ,@('docs/architecture.md', 'docs: describe the architecture')
    ,@('docs/security-model.md', 'docs: describe the security model and its limits')
    ,@('docs/cli.md', 'docs: add the CLI reference')
    ,@('docs/shipcheck.md', 'docs: explain ShipCheck environments and what each can test')
    ,@('docs/images/*', 'docs: add screenshot {file}')
    ,@('README.md', 'docs: add the README')
    ,@('README.tr.md', 'docs: add the Turkish README')
    ,@('CONTRIBUTING.md', 'docs: add contributing guidelines')
    ,@('SECURITY.md', 'docs: add the security policy')
    ,@('CODE_OF_CONDUCT.md', 'docs: add the code of conduct')
    ,@('CHANGELOG.md', 'docs: add the changelog')

    # --- GitHub automation ------------------------------------------------------------------------------------------------
    ,@('.github/workflows/ci.yml', 'ci: add the CI workflow (lint, typecheck, unit, integration, build)')
    ,@('.github/workflows/release.yml', 'ci: add the release workflow (portable, installer, checksums, provenance, GitHub Release)')
    ,@('integrations/github/action/action.yml', 'feat(action): add the ReleaseVerity GitHub Action')
    ,@('integrations/github/action/README.md', 'docs(action): document the GitHub Action')
    ,@('.github/ISSUE_TEMPLATE/bug_report.yml', 'chore(github): add the bug report issue template')
    ,@('.github/ISSUE_TEMPLATE/feature_request.yml', 'chore(github): add the feature request issue template')
    ,@('.github/ISSUE_TEMPLATE/verification_issue.yml', 'chore(github): add the verification issue template')
    ,@('.github/ISSUE_TEMPLATE/config.yml', 'chore(github): route security reports away from public issues')
    ,@('.github/PULL_REQUEST_TEMPLATE.md', 'chore(github): add the pull request template')
    ,@('.github/dependabot.yml', 'chore(github): enable Dependabot for cargo and actions')
    ,@('history.ps1', 'chore: add the script that rebuilds a granular git history')
    ,@('Cargo.lock', 'build: lock dependency versions')
)

# ---------------------------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git was not found on PATH.' }

# Files to commit: everything not ignored, as relative paths with forward slashes.
function Get-WorkingFiles {
    $out = & git ls-files --others --cached --exclude-standard -z
    $files = ($out -join '') -split "`0" | Where-Object { $_ }
    $files | ForEach-Object { $_.Replace('\', '/') } | Sort-Object -Unique
}

# Resolve the plan against the files that actually exist.
function Resolve-Plan([string[]]$Files) {
    $remaining = New-Object System.Collections.Generic.List[string]
    $Files | ForEach-Object { $remaining.Add($_) }
    $steps = @()
    foreach ($entry in $Plan) {
        $pattern = $entry[0]
        $hits = @($remaining | Where-Object { $_ -like $pattern } | Sort-Object)
        if ($hits.Count -eq 0) {
            Write-Warning "plan entry matches nothing: $pattern"
            continue
        }
        foreach ($f in $hits) {
            $leaf = $f.Substring($f.LastIndexOf('/') + 1)
            $msg = $entry[1].Replace('{file}', $leaf).Replace('{path}', $f)
            $steps += [pscustomobject]@{ File = $f; Message = $msg }
            [void]$remaining.Remove($f)
        }
    }
    foreach ($f in ($remaining | Sort-Object)) {
        $steps += [pscustomobject]@{ File = $f; Message = "chore: add $f" }
    }
    $steps
}

# In a repository with history the working files are tracked (index) files; in a fresh one they are untracked.
$hasGit = Test-Path (Join-Path $Root '.git')
$hasCommits = $false
if ($hasGit) {
    & git rev-parse --verify HEAD *> $null
    $hasCommits = ($LASTEXITCODE -eq 0)
}

$files = if ($hasGit) { Get-WorkingFiles } else {
    Get-ChildItem -Recurse -File -Force | Where-Object { $_.FullName -notmatch '\\(\.git|target|dist)\\' } |
        ForEach-Object { $_.FullName.Substring($Root.Length + 1).Replace('\', '/') }
}
$steps = Resolve-Plan $files

if ($DryRun) {
    $i = 0
    foreach ($s in $steps) { $i++; '{0,3}. {1}  <-  {2}' -f $i, $s.Message, $s.File }
    Write-Host ''
    Write-Host "$($steps.Count) commits would be created." -ForegroundColor Green
    return
}

# ---------------------------------------------------------------------------------------------
# Safety: never rewrite existing history by accident
# ---------------------------------------------------------------------------------------------
if ($hasCommits -and -not $Force) {
    throw "This repository already has commits. Rebuilding the history rewrites branch '$Branch'.`nThe old history is kept under a backup tag. Re-run with -Force to continue (or use -DryRun to preview)."
}

if (-not $UserName) { $UserName = (& git config user.name) }
if (-not $UserEmail) { $UserEmail = (& git config user.email) }
if (-not $UserName -or -not $UserEmail) {
    throw 'No git identity. Pass -UserName and -UserEmail, or run: git config --global user.name "..." ; git config --global user.email "..."'
}

if (-not $hasGit) { Invoke-Git init --quiet }

if ($hasCommits) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = "backup/before-history-$stamp"
    Invoke-Git tag $backup HEAD
    Write-Host "Old history kept as tag: $backup" -ForegroundColor Yellow
    # Start an unrelated history; the working tree stays exactly as it is.
    Invoke-Git checkout --orphan history-rebuild --quiet
    & git rm -r -f --cached . --quiet *> $null
} else {
    Invoke-Git checkout -B history-rebuild --quiet 2> $null
}

# ---------------------------------------------------------------------------------------------
# One commit per file
# ---------------------------------------------------------------------------------------------
$total = $steps.Count
$n = 0
foreach ($s in $steps) {
    $n++
    Invoke-Git add -- $s.File
    Invoke-Git -c "user.name=$UserName" -c "user.email=$UserEmail" commit --quiet -m $s.Message
    Write-Progress -Activity 'Building history' -Status "$n / $total  $($s.File)" -PercentComplete ([int](100 * $n / $total))
}
Write-Progress -Activity 'Building history' -Completed

# The branch you asked for now points at the rebuilt history.
Invoke-Git branch -M $Branch

# Everything must be committed: the new tree must equal the working tree.
$dirty = & git status --porcelain
if ($dirty) { Write-Warning "Uncommitted changes remain:`n$($dirty -join "`n")" }

Write-Host ''
Write-Host "Done: $total commits on '$Branch'." -ForegroundColor Green
& git log --oneline -n 8

# ---------------------------------------------------------------------------------------------
# Remote / push
# ---------------------------------------------------------------------------------------------
$existing = & git remote 2> $null
if ($existing -contains 'origin') {
    Invoke-Git remote set-url origin $Remote
} else {
    Invoke-Git remote add origin $Remote
}
Write-Host "Remote 'origin' -> $Remote"

if ($Push) {
    if ($Force) { Invoke-Git push -u origin $Branch --force } else { Invoke-Git push -u origin $Branch }
    Write-Host 'Pushed.' -ForegroundColor Green
} else {
    Write-Host ''
    Write-Host 'Not pushed. To publish:' -ForegroundColor Cyan
    Write-Host "  git push -u origin $Branch$(if ($Force) { ' --force' })"
}
