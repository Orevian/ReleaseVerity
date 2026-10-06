# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-06

First public version.

### Added
- **Core**: domain model, SQLite storage (migrations, crash recovery by owning process), `config.toml`, structured JSONL logging (`application`, `verification`, `shipcheck`, `repro`), English/Türkçe localization with message catalogs, scoring and verdict, HTML/Markdown/JSON reports, timeout-bounded process runner.
- **Repro Engine**: git integrity and tag → commit verification, tag signature check, SHA-256/512 checksums against published checksum files, Authenticode and detached GPG signatures, SLSA/in-toto provenance digest binding (+ `gh attestation verify`), CycloneDX/SPDX SBOM validation, PE/ELF/ZIP-aware binary difference analysis with probable causes.
- **ShipCheck Engine**: agent-based install → launch → smoke → uninstall testing; crash, hang and timeout classification; Job Object supervision (process tree, memory/process limits); documentation checks.
- **Isolation**: ReleaseVerity's own AppContainer sandbox (no network, no access outside its grants), Windows Sandbox runner with Smart App Control detection, explicit-opt-in host runner.
- **CLI** (`releaseverity`): `init`, `project`, `verify`, `repro verify|compare`, `shipcheck run|install|smoke`, `artifact inspect`, `sbom inspect`, `report generate|export|list`, `environment list|inspect`, `github login|logout|status|releases`, `doctor`, `config`, `version`.
- **Desktop app** (Rust + Slint, native): dashboard, projects, releases, verification runs, environments, artifacts, reports, settings, guided new-verification workflow, live run screen driven by engine events, release detail with Environment Matrix, reproducibility view; dark and light themes; English and Türkçe.
- **GitHub integration**: repositories, branches, tags, releases and assets (streamed download), commits, Actions runs, pull requests, checks; results published as a Check Run (commit status fallback); token in Windows Credential Manager.
- **Packaging**: `scripts/build.ps1` (CLI, desktop, portable, installer), Inno Setup `setup.iss`, SBOM and third-party notices generation, SHA256SUMS; statically linked binaries.
- **GitHub Action** `releaseverity-action`, CI and release workflows, issue and pull request templates.

### Known limitations
See the *Limitations* section of the README.

[Unreleased]: https://github.com/Orevian/ReleaseVerity/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Orevian/ReleaseVerity/releases/tag/v0.1.0
