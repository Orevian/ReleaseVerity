# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting). If that is unavailable, contact the maintainers at the address listed on the repository profile and include "ReleaseVerity security" in the subject.

Please include: what you found, how to reproduce it, the affected version (`releaseverity version`), and your assessment of the impact. We aim to acknowledge reports within 3 working days and to provide a fix or a mitigation plan within 30 days, and we will credit you unless you prefer to stay anonymous.

## Supported versions

Security fixes are released for the latest minor version.

## Scope — what ReleaseVerity protects

ReleaseVerity executes software it does not trust (ShipCheck). The following are in scope and are treated as vulnerabilities:

- A tested program escaping ReleaseVerity's isolation (AppContainer sandbox, Windows Sandbox configuration, Job Object limits) or affecting the host without the explicit host-execution opt-in
- The environment agent's output (`progress.jsonl`, `report.json`) causing memory exhaustion, code execution or path traversal in the host
- Path traversal when extracting archives or downloading release assets
- Leakage of the GitHub token (it must only ever live in Windows Credential Manager or an environment variable)
- A verification that reports a pass although the checked property does not hold (for example a checksum or signature mismatch reported as success)
- Command injection through repository URLs, tags, file names or smoke-test arguments

## Security model in short

See [docs/security-model.md](docs/security-model.md) for the full model, including its limits. Highlights:

- Isolation first; execution on the host needs `security.allow_host_execution = true`.
- Every test process runs in a Job Object: process-tree tracking, memory and process limits, hard timeouts, kill-on-close cleanup.
- The built-in sandbox is a Windows AppContainer: no network (not even loopback), no file access outside granted folders.
- Anything the agent reports is untrusted data: size-limited, bounded and validated by the host.
- Secrets are stored in Windows Credential Manager, never in `config.toml` or SQLite.
- Downloaded and extracted file names are sanitised (no `..`, no absolute paths).

## Known limits (not vulnerabilities)

- An AppContainer is not a virtual machine; a kernel exploit would escape it. Use a VM-backed environment for hostile installers.
- `host` execution is intentionally not isolated.
- Release binaries are not code-signed yet.
