# CLI reference

```text
releaseverity [--home DIR] [--lang en|tr] [--no-color] [--ascii] [--json] <command>
```

| Global option | Meaning |
|---|---|
| `--home DIR` / `RELEASEVERITY_HOME` | data directory (default: portable `data\`, else `%APPDATA%\ReleaseVerity`) |
| `--lang en\|tr` | output language (default: `general.language` in config) |
| `--no-color` / `NO_COLOR` | disable colour; output stays fully usable |
| `--ascii` / `RELEASEVERITY_ASCII` | `OK / WARN / FAIL` instead of `✓ ⚠ ✗` |
| `--json` | machine-readable output where supported |

## Commands

| Command | Purpose |
|---|---|
| `init` | create the data directory, default `config.toml`, database |
| `project add <name> --repo URL \| --path DIR [--branch main]` · `list` · `remove <name>` | manage projects |
| `verify [release] --repo URL\|PATH \| --project NAME --release TAG [options]` | verify a release with all engines |
| `repro verify …` | the same, Repro Engine checks only |
| `repro compare <release-artifact> <local-build>` | byte-level comparison with probable causes |
| `shipcheck run \| install \| smoke --package PATH [options]` | installation and runtime testing |
| `artifact inspect <file>` | format, hashes, sections / entries, signature presence |
| `sbom inspect <file>` | validate a CycloneDX/SPDX document |
| `report generate\|export [--run ID] --format html\|json\|markdown [--out FILE]` · `report list` | reports from stored runs |
| `environment list \| inspect <id>` | execution environments and their availability |
| `github login [--stdin\|--token T]` · `logout` · `status` · `releases <repo>` | GitHub account and releases |
| `doctor` | tools, storage and environments |
| `config [list\|get KEY\|set KEY VALUE\|path]` | configuration (validated) |
| `version` | version |

### `verify` options

| Option | |
|---|---|
| `--repo URL\|PATH`, `--project NAME`, `--release TAG` | what to verify. A GitHub repo's release assets are downloaded automatically |
| `--asset FILE\|DIR` (repeatable) | use local release files instead of downloading |
| `--rebuilt FILE` | your rebuild of the artifact, compared bit for bit |
| `--only source,checksum,signature,provenance,sbom,repro,docs,install,launch,smoke,uninstall,assets,shipcheck` | restrict checks |
| `--package PATH` `--package-kind installer\|portable` `--installer-args "…"` `--exe NAME` `--launch-args "…"` `--gui` `--smoke "<args> => <expected output>"` (repeatable) `--env auto,appcontainer,windows-sandbox,host` `--no-uninstall` `--alive SECS` | installation and runtime testing |
| `--report html,json,markdown` `--out DIR` | write reports |
| `--strict` | warnings fail the run (exit 1) |
| `--publish` | publish the verdict as a GitHub Check on the release commit |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | verified (or verified with warnings, unless `--strict`) |
| 1 | failed |
| 2 | error or invalid usage |
| 3 | inconclusive (nothing failed, but required checks could not run) |

### Examples

```powershell
releaseverity verify --repo https://github.com/BurntSushi/ripgrep --release 14.1.1 --report html
releaseverity shipcheck run --package .\app.zip --exe app.exe --launch-args "--version" --smoke "--version => 1.0"
releaseverity --lang tr report export --run 3 --format markdown --out rapor.md
releaseverity config set timeouts.install_secs 300
```

A run is stored in the local database; `report` commands re-render it in the language you choose.
