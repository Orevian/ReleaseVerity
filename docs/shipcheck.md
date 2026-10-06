# ShipCheck: environments and what they can test

ShipCheck answers "does this actually install and run?" by doing it: clean environment → installer → files and registry → launch → smoke tests → uninstall → cleanup.

## Choosing an environment

| `--env` | Needs | Isolation | Installer | Portable | Notes |
|---|---|---|:-:|:-:|---|
| `auto` *(default)* | — | best available | ✓ | ✓ | portable → `appcontainer`; installer → `windows-sandbox` |
| `appcontainer` | any Windows | OS-enforced process sandbox | ✗ | ✓ | ReleaseVerity's own sandbox; no network |
| `windows-sandbox` | Windows Pro/Enterprise/Education + the feature enabled | disposable VM | ✓ | ✓ | guest enforces Smart App Control on recent Windows → signed software only |
| `host` | `security.allow_host_execution = true` | none | ✓ | ✓ | trusted software only |

`releaseverity environment list` (and the **Environments** page) shows what is available *on this PC*, probing for real.

### Testing an unsigned installer
Windows Sandbox cannot run unsigned code when Smart App Control is enforced inside it (ReleaseVerity detects this within seconds and says so — no long timeout). Options: a VM without Smart App Control, a clean CI runner (the GitHub Action on `windows-latest`), `--env host` for software you trust (use a per-user install such as Inno Setup's `/CURRENTUSER` so no elevation is needed), or code-sign the package.

## What is checked

| Check | Success means |
|---|---|
| **Installation** | the installer exited 0 (or 3010), and the installed application, its install directory, shortcuts and the Add/Remove Programs entry (publisher, version) were found |
| **Launch** | console apps exit 0 within the launch timeout; GUI apps (`--gui`) stay alive for `--alive` seconds with a responsive window |
| **Smoke tests** | each `--smoke "<args> => <text>"` exits 0 (or the expected code) and its output contains the text |
| **Uninstall** | the registered uninstaller ran, files and the registry entry are gone (leftovers → warning) |
| **Documentation** | the README/docs at the release tag contain installation, usage and upgrade sections |

Failures are classified: **APPLICATION CRASHED** (fatal NTSTATUS exit code such as `0xC0000005`), **APPLICATION HUNG** (window stopped responding), **TEST TIMEOUT** (process tree terminated), unexpected exit code. An installer error carries the real exit code and, for MSI, the Windows Installer meaning (for example 1603).

## Timeouts

```toml
[timeouts]
install_secs = 120
launch_secs  = 30
smoke_secs   = 60
cleanup_secs = 30
build_secs   = 1800
network_secs = 60
```

## Limits

`appcontainer` = no VM. `windows-sandbox` = one session at a time. The Hyper-V checkpoint backend, Linux and macOS runners, and automated sandboxed rebuilds are on the roadmap.
