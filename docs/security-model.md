# Security model

ReleaseVerity's job is to run software it has no reason to trust and report on it, **without being compromised by it**.

## Assets and threats

| Asset | Threat |
|---|---|
| The user's PC | A tested installer/app modifies files, registry, or other processes |
| ReleaseVerity itself (verdicts, database) | A tested program, or the agent's output, corrupts results or the host process |
| GitHub token | Leakage through files, logs or reports |
| Verification honesty | A mismatch reported as success |

## Controls

### 1. Isolation first
`--env auto` picks the strongest isolation that can run the package:

- **`appcontainer` — ReleaseVerity's own sandbox.** The agent creates a disposable Windows AppContainer profile per run and starts the application inside it with `CreateProcessW` + `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`. Enforced by the OS: the process can only touch locations whose ACL names its container SID (ReleaseVerity grants the extracted package read/execute and nothing else); it has **no network capability, not even loopback**; HKLM is read-only; low integrity. The test suite proves each of these (a write outside the grants is denied, a read of an ungranted file is denied, a loopback connection that succeeds from the host is blocked from the container).
- **`windows-sandbox`**: a disposable VM, networking disabled by default, VGpu/audio/video/clipboard/printer redirection disabled, the input folder mapped read-only and a single output folder writable.
- **`host`**: no isolation. Refused unless `security.allow_host_execution = true` (Settings → Security). The UI and CLI state this plainly.

Installers are never run in the built-in sandbox (they need `Program Files` and `HKLM`); ReleaseVerity refuses and explains instead of weakening the sandbox.

### 2. Process control (Job Objects)
Every process under test, in every backend, runs in a Job Object: the whole process tree is tracked (including children that outlive the parent), memory and active-process limits apply (`security.max_memory_mb`, `security.max_processes`), the tree is terminated on timeout, and `KILL_ON_JOB_CLOSE` guarantees nothing survives the agent.

### 3. Timeouts everywhere
Installation, launch, smoke, cleanup, build and network operations all have configurable limits (`[timeouts]` in `config.toml`). The host also enforces an overall limit per environment run and destroys the environment on expiry.

### 4. The agent's output is untrusted data
`progress.jsonl` is tailed with bounded reads; `report.json` is size-limited (4 MiB), parsed strictly, step counts and text fields are bounded and logs truncated. The Windows Sandbox output folder is the only writable channel and is treated as hostile.

### 5. Guaranteed cleanup
Work directories are removed by drop guards on all paths (success, error, cancellation); Windows Sandbox is force-closed by a guard; extracted portable packages are removed and verified gone.

### 6. Secrets
The GitHub token is stored in Windows Credential Manager (`CredWriteW`, per-user DPAPI-backed) or read from `RELEASEVERITY_GITHUB_TOKEN`/`GITHUB_TOKEN` in CI. It is never written to `config.toml`, SQLite, logs or reports.

### 7. Input hygiene
Zip entries are extracted with `enclosed_name` (zip-slip rejected); downloaded asset names are reduced to a file name (no `..`, no separators); repository URLs, tags and smoke arguments are passed as argv elements, never through a shell.

### 8. Honest verdicts
`Error` ("could not verify") is distinct from `Fail`. Provenance attestations whose signature was not cryptographically verified are a **warning**, not a pass. Missing tools produce `Skipped`/`Error` with the reason, never a silent success.

## What this does **not** protect against

- An AppContainer is a process sandbox, not a VM. A kernel or sandbox-escape vulnerability would defeat it. Use a VM-backed environment for hostile installers.
- Windows Sandbox on recent Windows enforces Smart App Control inside the guest; unsigned software cannot run there (ReleaseVerity detects and reports this).
- `host` mode is trust-based by design.
- Code signing of ReleaseVerity's own binaries is not set up yet.

Report vulnerabilities privately — see [SECURITY.md](../SECURITY.md).
