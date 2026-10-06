# Tests

Tests live next to the code they exercise (Rust convention) and run with a single command:

```powershell
cargo test --workspace
```

| Where | What | Real or mocked |
|---|---|---|
| `crates/*/src/**` (`#[cfg(test)]`) | unit tests: scoring, config, database, i18n catalogs, parsers, binary diff, Job Objects, AppContainer isolation | real files, real processes, real SQLite |
| `crates/releaseverity-repro/tests/pipeline.rs` | Repro Engine end to end through the same orchestrator the CLI and GUI use | real git repositories, real hashing |
| `crates/releaseverity-shipcheck/tests/host_e2e.rs` | ShipCheck end to end: install / launch / smoke / uninstall, crash / hang / timeout, the built-in sandbox | real agent binary, real processes, real GUI fixtures (`crates/releaseverity-agent/examples`) |
| `crates/releaseverity-cli/tests/cli.rs` | the `releaseverity` binary: exit codes, colour, English/Türkçe output, reports | real binary, real repos |
| `crates/releaseverity-github/src/lib.rs` | GitHub client against a local HTTP server speaking the REST API; Credential Manager round trip | fake server only for the *external* service |
| `crates/releaseverity-desktop/src/settings.rs` | every string key used by the UI exists in both languages | — |

Rules: no mock may fabricate a success; Windows-only tests are gated with `cfg(windows)`.
