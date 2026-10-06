## What and why

<!-- What does this change, and what problem does it solve? -->

## How it was verified

- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check`
- [ ] Tested against **real** inputs (no mock-based success paths)

## Checklist

- [ ] No fake results: unmeasurable things return `Skipped` / `Error` with a reason
- [ ] User-visible text is in `locales/en.json` **and** `locales/tr.json`
- [ ] `CHANGELOG.md` updated (Unreleased)
- [ ] Docs updated (README / `docs/`) if behaviour changed
- [ ] UI change: screenshot attached (`--screenshot`)
- [ ] Security impact considered (isolation, untrusted agent output, secrets) — described below if relevant

## Security impact

<!-- "None" or explain. -->
