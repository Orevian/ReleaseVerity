# ReleaseVerity GitHub Action

Verifies a release with ReleaseVerity on a clean GitHub-hosted runner, writes JSON/HTML reports, publishes a **GitHub Check** on the release commit and **fails the workflow** when the release fails.

```yaml
name: Verify release
on:
  release:
    types: [published]

permissions:
  contents: read
  checks: write        # to publish the ReleaseVerity check

jobs:
  verify:
    runs-on: ubuntu-latest        # or windows-latest
    steps:
      - uses: Orevian/releaseverity-action@v1
        with:
          release: ${{ github.event.release.tag_name }}
          strict: false
```

The action's source lives in this repository at `integrations/github/action`; publish it as its own repository (for example `Orevian/releaseverity-action`) and tag it `v1`.

## Inputs

| Input | Default | |
|---|---|---|
| `release` | `github.ref_name` | tag to verify |
| `repository` | `github.repository` | `owner/name` |
| `only` | all | `source,assets,checksum,signature,provenance,sbom,docs,repro` |
| `strict` | `false` | warnings fail the job |
| `publish-check` | `true` | publish the verdict as a Check Run |
| `report-formats` | `json,html` | `html`, `json`, `markdown` |
| `version` | `latest` | ReleaseVerity release to run |
| `token` | `github.token` | download, read the release, publish the check |

Outputs: `score`, `verdict`, `report-directory`. Reports are uploaded as the `releaseverity-reports` artifact and a console summary is added to the job summary.

## Notes

- The downloaded ReleaseVerity build is verified against the published `SHA256SUMS` before it is run.
- With the default `GITHUB_TOKEN` the action can create a **Check Run** (`checks: write`). A personal access token cannot; ReleaseVerity then falls back to a commit status.
- On `ubuntu-latest` the Repro Engine checks run (source, release assets, checksums, signatures, provenance, SBOM, docs). Installation and runtime testing (ShipCheck) are Windows features: use `windows-latest` and the `shipcheck` command in a normal workflow step — a fresh GitHub-hosted VM is a clean, disposable environment for unsigned installers too.
