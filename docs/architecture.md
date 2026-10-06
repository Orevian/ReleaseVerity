# Architecture

ReleaseVerity is a Rust workspace. One core and one service layer sit under three front ends; two engines produce the results.

```text
                       releaseverity-core
        models · SQLite · config · logging · i18n · scoring · reports · process runner
                             │
          ┌──────────────────┼────────────────────┐
     releaseverity-cli    releaseverity-desktop     GitHub Action (runs the CLI)
          └──────────────────┼────────────────────┘
                    releaseverity-services
                             │
        ┌───────────────┬────┴────────────┬────────────────┐
  releaseverity-repro  releaseverity-shipcheck  releaseverity-github  (Windows Credential Manager)
                             │
                      releaseverity-agent
```

**Dependency rule:** `core` depends on no engine and no front end. Engines depend on `core`. `services` depends on engines. Front ends depend only on `services` (and re-exported `core` types). The CLI and the desktop app therefore cannot drift apart: a capability exists once, in an engine or in `services`.

## The pipeline contract

An engine contributes `Check`s (`releaseverity_core::check`):

```rust
trait Check { fn id(&self) -> &'static str; fn category(&self) -> Category;
              fn environment(&self) -> Option<String>; fn run(&self, ctx: &mut Context) -> CheckResult; }
```

`run_checks` executes them in order, times each one, logs it, and emits `RunEvent`s (`Started`, `StepStarted`, `Progress`, `StepFinished`, `Finished`). Progress messages are emitted **by the checks while they work** (cloning, hashing, downloading…), never by a timer. The desktop live screen and the CLI both render these events.

`Context` carries the config, the target (repository, tag, assets, rebuilt file, ShipCheck package), a work directory, the logger, a cancellation flag and the facts discovered by earlier checks (repository directory, resolved commit, artifacts).

## Results

`CheckResult` holds `status` (`pass`, `warn`, `fail`, `skipped`, `error`), a summary, optional cause/suggestion, `details` (log), `evidence` (machine-readable JSON), the environment, exit code and failure kind (`crashed`, `hung`, `timeout`, `exit_code`).

- `error` means *could not measure* — it is never a pass and never reads as "the release is bad".
- Messages are catalog keys + arguments (`Msg`). The English text is derived from the English catalog; the user's language is applied when rendering, so a stored run can be shown in either language.

## Scoring (`scoring.rs`)

Weighted average (pass 1.0, warn 0.6, fail/error 0); skipped checks are excluded. Verdict: a critical failure, or a failure with score < 60 → `failed`; any error without failure → `inconclusive`; warnings or non-critical failures → `verified_with_warnings`; otherwise `verified`.

## ShipCheck architecture

```text
 host (releaseverity-shipcheck)                         environment
 ───────────────────────────                        ─────────────────────────────────────
 EnvRunner (appcontainer | windows-sandbox | host)
   stage: in\ (agent, spec.json, package)  out\
   start ───────────────────────────────────▶  releaseverity-agent spec.json out\
   tail progress.jsonl  ◀── real step events ──  install → files → launch → smoke → uninstall
   read + validate report.json  ◀───────────────  (each step: status, exit code, log, facts)
```

The agent is the only code that runs software under test. It places every process in a Job Object (kill-on-close, memory and process limits), detects crashes by NTSTATUS exit codes, hangs by `IsHungAppWindow`, and timeouts by terminating the whole process tree. The host treats the agent's files as untrusted data.

One agent run per environment feeds that environment's install / launch / smoke / uninstall checks, which is what makes the Environment Matrix.

## Storage

SQLite (`releaseverity.db`, WAL mode, schema migrations tracked with `PRAGMA user_version`): projects, releases, runs (with owning pid, so crash recovery only touches runs of dead processes), results (full JSON), artifacts, reports, settings. Data directory: `RELEASEVERITY_HOME`, else portable `data\` next to the app (when a `config\` folder exists), else `%APPDATA%\ReleaseVerity`.

## Desktop app

Slint UI (`crates/releaseverity-desktop/ui`) bound to one global, `AppState`. Rust fills it from real data on every page open; long work (verification, tag listing, GitHub lookups, environment probes) runs on worker threads that post updates to the UI thread. Strings come from the same catalogs as the CLI through the `Tr` global.

## Concurrency and cleanup

- Verification runs on its own thread with its own SQLite connection.
- Work directories are removed by a drop guard on every exit path; sandbox VMs by a guard that force-closes them; AppContainer profiles are deleted when the agent exits.
