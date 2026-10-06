# Contributing to ReleaseVerity

Thank you for helping. ReleaseVerity's one rule is **reality over appearance**: a feature either measures something for real or says it cannot. Please keep it that way.

## Principles

1. **No fake results.** No hard-coded scores, no simulated progress, no placeholder "pass". If a check cannot run, return `Skipped` (not applicable) or `Error` (could not measure) with a reason — never `Pass`.
2. **One core, thin front ends.** CLI and desktop contain no verification logic. New behaviour goes into `releaseverity-core`, an engine, or `releaseverity-services`, and both front ends call it.
3. **Test with the real thing.** Prefer real git repositories, real files and real processes over mocks. A fake server is acceptable only for an *external* service (see the GitHub client tests).
4. **Both languages.** Every user-visible string lives in `locales/en.json` and `locales/tr.json`. Tests fail if a key is missing from either file, if placeholders differ, or if the UI uses a key that does not exist.
5. **Security first.** Anything an environment agent reports is untrusted data: bound and validate it. Never run untrusted code on the host without the explicit opt-in.

## Repository layout

```text
crates/
  releaseverity-core        models, SQLite, config, logging, i18n, scoring, reports, process runner
  releaseverity-repro       Repro Engine: git, checksums, signatures, provenance, SBOM, binary diff
  releaseverity-shipcheck   ShipCheck Engine: environment runners, install/launch/smoke/uninstall checks, docs checks
  releaseverity-agent       the agent that runs inside the clean environment (+ the AppContainer sandbox)
  releaseverity-github      GitHub API client, Windows Credential Manager storage, check publishing
  releaseverity-services    the single API used by every front end
  releaseverity-cli         `releaseverity` command
  releaseverity-desktop     native desktop app (Slint)
locales/                en.json, tr.json
integrations/github/    the GitHub Action
scripts/                build.ps1, gen-sbom.ps1
setup.iss               Inno Setup installer
docs/                   architecture, security model, CLI reference, …
```

## Development setup

```powershell
git clone https://github.com/Orevian/ReleaseVerity && cd ReleaseVerity
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Windows 10/11 with the Rust MSVC toolchain and Git is the reference environment. The Repro Engine, core and CLI also build on Linux.

Useful developer flags of the desktop app: `--page N`, `--run ID`, `--lang en|tr`, `--theme dark|light`, `--size WxH`, `--screenshot out.png` (renders the real UI to a PNG and exits).

## Adding a check

1. Implement `releaseverity_core::check::Check` in the right engine; return a `CheckResult` with **evidence** (machine-readable facts).
2. Use catalog keys for every message: `CheckResult::msg(id, category, status, "m.your.key", &[("arg", value)])`, `.cause_key(..)`, `.suggestion_key(..)`. Add the keys to **both** locale files.
3. Add it to the engine's `checks()` list, give it a weight in `scoring.rs` (and decide whether it is critical).
4. Add a test that exercises it against real inputs, including the failure path.

## Pull requests

- Keep commits focused; use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- Update `CHANGELOG.md` under *Unreleased*.
- CI must pass: `fmt`, `clippy -D warnings`, tests.
- UI changes: attach a screenshot produced with `--screenshot`, in English and Türkçe if text changed.
- Security-relevant changes: explain the threat model impact in the PR description.

## Reporting problems

Use the issue templates (bug, feature, verification issue). **Security vulnerabilities must not be filed as public issues** — see [SECURITY.md](SECURITY.md).

By contributing you agree that your contributions are licensed under the Apache-2.0 license.
