//! The Repro Engine's checks. Each one performs the real operation and reports evidence.

use crate::assets::{self, parse_checksum_file, Algo, AssetRole};
use crate::{diff, git, inspect, provenance, sbom, signature};
use releaseverity_core::check::{Check, Context};
use releaseverity_core::model::{Category, CheckResult, Status};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

pub fn github_slug(repo: &str) -> Option<String> {
    let r = repo.trim_end_matches('/').trim_end_matches(".git");
    let idx = r.find("github.com")?;
    let rest = r[idx + "github.com".len()..].trim_start_matches(['/', ':']);
    let mut it = rest.split('/');
    let (o, n) = (it.next()?, it.next()?);
    (!o.is_empty() && !n.is_empty()).then(|| format!("{o}/{n}"))
}

// ---------------------------------------------------------------------------
// source.integrity
// ---------------------------------------------------------------------------

pub struct SourceIntegrity;

impl Check for SourceIntegrity {
    fn id(&self) -> &'static str {
        "source.integrity"
    }
    fn category(&self) -> Category {
        Category::Trust
    }

    fn run(&self, ctx: &mut Context) -> CheckResult {
        let id = self.id();
        let err = |m: String| CheckResult::new(id, Category::Trust, Status::Error, m);
        if !git::available() {
            return CheckResult::msg(id, Category::Trust, Status::Error, "m.git.missing", &[]).suggestion_key("m.git.missing.fix", &[]);
        }
        let repo = ctx.target.repo.clone();
        let dir: PathBuf = match &ctx.target.local_repo {
            Some(p) => p.clone(),
            None if Path::new(&repo).is_dir() => PathBuf::from(&repo),
            None => {
                let dest = ctx.work_dir.join("repo");
                if dest.exists() {
                    let _ = std::fs::remove_dir_all(&dest);
                }
                ctx.progress(format!("cloning {repo}"));
                if let Err(e) = git::clone(&repo, &dest, secs(ctx.config.timeouts.network_secs.max(120))) {
                    return CheckResult::msg(id, Category::Trust, Status::Error, "m.repo.obtain.fail", &[])
                        .cause(format!("{e:#}"))
                        .suggestion_key("m.repo.obtain.fix", &[]);
                }
                dest
            }
        };
        if !git::is_repo(&dir) {
            return CheckResult::msg(id, Category::Trust, Status::Fail, "m.repo.not-git", &[("path", &dir.display().to_string())]);
        }
        ctx.progress("verifying git object integrity (fsck)");
        match git::fsck(&dir, secs(600)) {
            Ok((true, _)) => {
                ctx.state.repo_dir = Some(dir.clone());
                CheckResult::msg(id, Category::Trust, Status::Pass, "m.repo.fsck.ok", &[]).evidence(json!({ "repo_dir": dir }))
            }
            Ok((false, out)) => {
                ctx.state.repo_dir = Some(dir);
                CheckResult::msg(id, Category::Trust, Status::Fail, "m.repo.fsck.bad", &[])
                    .details(out)
                    .suggestion_key("m.repo.fsck.fix", &[])
            }
            Err(e) => err(format!("{e:#}")),
        }
    }
}

// ---------------------------------------------------------------------------
// source.tag
// ---------------------------------------------------------------------------

pub struct SourceTag;

impl Check for SourceTag {
    fn id(&self) -> &'static str {
        "source.tag"
    }
    fn category(&self) -> Category {
        Category::Trust
    }

    fn run(&self, ctx: &mut Context) -> CheckResult {
        let id = self.id();
        let Some(dir) = ctx.state.repo_dir.clone() else {
            return CheckResult::msg(id, Category::Trust, Status::Skipped, "m.repo.unavailable", &[]);
        };
        let tag = ctx.target.tag.clone();
        let info = match git::resolve_tag(&dir, &tag) {
            Ok(Some(t)) => t,
            Ok(None) => {
                return CheckResult::msg(id, Category::Trust, Status::Fail, "m.tag.missing", &[("tag", &tag)])
                    .suggestion_key("m.tag.missing.fix", &[])
            }
            Err(e) => return CheckResult::new(id, Category::Trust, Status::Error, format!("{e:#}")),
        };
        ctx.state.commit = Some(info.commit.clone());
        let sig = git::verify_tag_signature(&dir, &info);
        let commit = info.commit[..12].to_string();
        let (status, key, args, details): (Status, &str, Vec<(&str, String)>, Option<String>) = match &sig {
            Ok(git::TagSignature::Valid(raw)) => (Status::Pass, "m.tag.signed", vec![], Some(raw.clone())),
            Ok(git::TagSignature::Unsigned) => {
                (Status::Pass, if info.annotated { "m.tag.annotated" } else { "m.tag.lightweight" }, vec![], None)
            }
            Ok(git::TagSignature::Invalid(raw)) => {
                let key = raw.lines().find_map(|l| l.strip_prefix("[GNUPG:] NO_PUBKEY ")).map(str::trim);
                match key {
                    Some(k) => (Status::Warn, "m.tag.nokey", vec![("key", k.to_string())], Some(raw.clone())),
                    None => (Status::Warn, "m.tag.unverified", vec![], Some(raw.clone())),
                }
            }
            Err(e) => (Status::Warn, "m.tag.sigerror", vec![("err", format!("{e:#}"))], None),
        };
        let mut all_args: Vec<(&str, String)> = vec![("tag", tag.clone()), ("commit", commit)];
        all_args.extend(args);
        let arg_refs: Vec<(&str, &str)> = all_args.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut r = CheckResult::msg(id, Category::Trust, status, key, &arg_refs).evidence(json!({
            "tag": tag, "commit": info.commit, "tag_object": info.object, "annotated": info.annotated,
            "signature": match &sig { Ok(git::TagSignature::Valid(_)) => "valid", Ok(git::TagSignature::Unsigned) => "unsigned", _ => "unverified" },
        }));
        r.details = details;
        if status == Status::Warn {
            r = r.suggestion_key("m.tag.sig.fix", &[]);
        }
        r
    }
}

// ---------------------------------------------------------------------------
// artifact.checksum
// ---------------------------------------------------------------------------

pub struct ArtifactChecksum;

impl Check for ArtifactChecksum {
    fn id(&self) -> &'static str {
        "artifact.checksum"
    }
    fn category(&self) -> Category {
        Category::Trust
    }

    fn run(&self, ctx: &mut Context) -> CheckResult {
        let id = self.id();
        let artifacts: Vec<PathBuf> = assets::of_role(&ctx.target.assets, AssetRole::Artifact).into_iter().cloned().collect();
        if artifacts.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Skipped, "m.assets.none", &[]);
        }
        let mut inspected = Vec::new();
        for a in &artifacts {
            ctx.progress(format!("hashing {}", assets::file_name(a)));
            match inspect::inspect(a) {
                Ok(i) => inspected.push(i),
                Err(e) => return CheckResult::new(id, Category::Trust, Status::Error, format!("{e:#}")),
            }
        }
        ctx.state.artifacts = inspected.iter().map(|i| i.info.clone()).collect();

        let mut entries = Vec::new();
        for f in assets::of_role(&ctx.target.assets, AssetRole::ChecksumFile) {
            match std::fs::read_to_string(f) {
                Ok(t) => entries.extend(parse_checksum_file(f, &t)),
                Err(e) => return CheckResult::new(id, Category::Trust, Status::Error, format!("cannot read {}: {e}", f.display())),
            }
        }
        let table: Vec<_> = inspected
            .iter()
            .map(|i| json!({"name": i.info.name, "size": i.info.size, "sha256": i.info.sha256, "sha512": i.info.sha512}))
            .collect();
        if entries.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Warn, "m.sum.none", &[])
                .evidence(json!({ "artifacts": table }))
                .suggestion_key("m.sum.none.fix", &[]);
        }
        let (mut ok, mut bad, mut unlisted) = (vec![], vec![], vec![]);
        for i in &inspected {
            let e = entries.iter().find(|e| e.file.rsplit(['/', '\\']).next() == Some(i.info.name.as_str()));
            match e {
                None => unlisted.push(i.info.name.clone()),
                Some(e) => {
                    let actual = if e.algo == Algo::Sha256 { &i.info.sha256 } else { &i.info.sha512 };
                    if *actual == e.hex {
                        ok.push(i.info.name.clone());
                    } else {
                        bad.push(json!({"file": i.info.name, "expected": e.hex, "actual": actual}));
                    }
                }
            }
        }
        let evidence = json!({ "verified": ok, "mismatched": bad, "not_listed": unlisted, "artifacts": table });
        if !bad.is_empty() {
            let d = bad
                .iter()
                .map(|b| {
                    format!(
                        "{}\n  expected {}\n  actual   {}",
                        b["file"].as_str().unwrap_or(""),
                        b["expected"].as_str().unwrap_or(""),
                        b["actual"].as_str().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            CheckResult::msg(id, Category::Trust, Status::Fail, "m.sum.mismatch", &[("n", &bad.len().to_string())])
                .details(d)
                .evidence(evidence)
                .cause_key("m.sum.mismatch.cause", &[])
                .suggestion_key("m.sum.mismatch.fix", &[])
        } else if ok.is_empty() {
            CheckResult::msg(id, Category::Trust, Status::Warn, "m.sum.nolisted", &[]).evidence(evidence)
        } else if !unlisted.is_empty() {
            CheckResult::msg(
                id,
                Category::Trust,
                Status::Warn,
                "m.sum.partial",
                &[("ok", &ok.len().to_string()), ("n", &unlisted.len().to_string())],
            )
            .evidence(evidence)
        } else {
            CheckResult::msg(id, Category::Trust, Status::Pass, "m.sum.ok", &[("n", &ok.len().to_string())]).evidence(evidence)
        }
    }
}

// ---------------------------------------------------------------------------
// artifact.signature
// ---------------------------------------------------------------------------

pub struct ArtifactSignature;

impl Check for ArtifactSignature {
    fn id(&self) -> &'static str {
        "artifact.signature"
    }
    fn category(&self) -> Category {
        Category::Trust
    }

    fn run(&self, ctx: &mut Context) -> CheckResult {
        use signature::SigState;
        let id = self.id();
        let artifacts: Vec<PathBuf> = assets::of_role(&ctx.target.assets, AssetRole::Artifact).into_iter().cloned().collect();
        if artifacts.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Skipped, "m.assets.none", &[]);
        }
        let sigs: Vec<PathBuf> = assets::of_role(&ctx.target.assets, AssetRole::DetachedSignature).into_iter().cloned().collect();
        let mut rows = vec![];
        for a in &artifacts {
            let name = assets::file_name(a);
            ctx.progress(format!("checking signature of {name}"));
            let kind = ctx
                .state
                .artifacts
                .iter()
                .find(|x| x.name == name)
                .map(|x| x.kind.clone())
                .or_else(|| inspect::inspect(a).ok().map(|i| i.info.kind))
                .unwrap_or_default();
            let state = if let Some(s) = sigs.iter().find(|s| assets::file_name(s).starts_with(&name)) {
                ("detached", signature::gpg_detached(s, a))
            } else if kind == "pe" || kind == "msi" {
                let embedded = std::fs::read(a).ok().and_then(|b| inspect::pe_layout(&b)).map(|l| l.cert_size > 0).unwrap_or(kind == "msi");
                ("authenticode", signature::authenticode(a, embedded))
            } else {
                ("none", SigState::Unsigned)
            };
            rows.push((name, state));
        }
        let fmt = |s: &SigState| match s {
            SigState::Valid { signer } => json!({"state": "valid", "signer": signer}),
            SigState::Unsigned => json!({"state": "unsigned"}),
            SigState::Invalid { reason } => json!({"state": "invalid", "reason": reason}),
            SigState::Unavailable { reason } => json!({"state": "unavailable", "reason": reason}),
        };
        let evidence = json!(rows
            .iter()
            .map(|(n, (m, s))| {
                let mut v = fmt(s);
                v["file"] = json!(n);
                v["method"] = json!(m);
                v
            })
            .collect::<Vec<_>>());
        let detail = rows.iter().map(|(n, (m, s))| format!("{n} [{m}]: {}", fmt(s))).collect::<Vec<_>>().join("\n");
        let any = |f: fn(&SigState) -> bool| rows.iter().any(|(_, (_, s))| f(s));
        let all_valid = rows.iter().all(|(_, (_, s))| matches!(s, SigState::Valid { .. }));
        let n = rows.len().to_string();
        let (status, key) = if any(|s| matches!(s, SigState::Invalid { .. })) {
            (Status::Fail, "m.sig.invalid")
        } else if all_valid {
            (Status::Pass, "m.sig.valid")
        } else if any(|s| matches!(s, SigState::Unavailable { .. })) {
            (Status::Warn, "m.sig.unavailable")
        } else if any(|s| matches!(s, SigState::Valid { .. })) {
            (Status::Warn, "m.sig.some")
        } else {
            (Status::Warn, "m.sig.none")
        };
        let mut r = CheckResult::msg(id, Category::Trust, status, key, &[("n", &n)]).details(detail).evidence(evidence);
        if status == Status::Fail {
            r = r.cause_key("m.sig.invalid.cause", &[]).suggestion_key("m.sig.invalid.fix", &[]);
        } else if status == Status::Warn {
            r = r.suggestion_key("m.sig.warn.fix", &[]);
        }
        r
    }
}

// ---------------------------------------------------------------------------
// provenance
// ---------------------------------------------------------------------------

pub struct Provenance;

impl Check for Provenance {
    fn id(&self) -> &'static str {
        "provenance"
    }
    fn category(&self) -> Category {
        Category::Trust
    }

    fn run(&self, ctx: &mut Context) -> CheckResult {
        let id = self.id();
        let artifacts: Vec<PathBuf> = assets::of_role(&ctx.target.assets, AssetRole::Artifact).into_iter().cloned().collect();
        if artifacts.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Skipped, "m.assets.none", &[]);
        }
        let hashes: Vec<(String, String)> = artifacts
            .iter()
            .filter_map(|a| releaseverity_core::hash::hash_file(a).ok().map(|h| (assets::file_name(a), h.sha256)))
            .collect();

        // 1. Cryptographic verification through GitHub's attestation service when possible.
        let slug = github_slug(&ctx.target.repo);
        let mut gh_verified = vec![];
        if let (Some(slug), true) = (&slug, releaseverity_core::proc::exists_on_path("gh")) {
            for a in &artifacts {
                ctx.progress(format!("gh attestation verify {}", assets::file_name(a)));
                let mut c = std::process::Command::new("gh");
                c.args(["attestation", "verify"]).arg(a).args(["--repo", slug]);
                if let Ok(o) = releaseverity_core::proc::run(&mut c, secs(ctx.config.timeouts.network_secs.max(60))) {
                    if o.success() {
                        gh_verified.push(assets::file_name(a));
                    }
                }
            }
        }
        if gh_verified.len() == artifacts.len() {
            return CheckResult::msg(id, Category::Trust, Status::Pass, "m.prov.gh", &[])
                .evidence(json!({ "verified_by": "gh attestation verify", "artifacts": gh_verified }));
        }

        // 2. Local attestation files: check digest binding (signature NOT verified).
        let files: Vec<PathBuf> = assets::of_role(&ctx.target.assets, AssetRole::Attestation).into_iter().cloned().collect();
        if files.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Warn, "m.prov.none", &[]).suggestion_key("m.prov.none.fix", &[]);
        }
        let mut stmts = vec![];
        for f in &files {
            match std::fs::read_to_string(f).map_err(anyhow::Error::from).and_then(|t| provenance::parse(&t)) {
                Ok(mut v) => stmts.append(&mut v),
                Err(e) => {
                    return CheckResult::msg(
                        id,
                        Category::Trust,
                        Status::Fail,
                        "m.prov.invalid",
                        &[("file", &assets::file_name(f)), ("err", &format!("{e:#}"))],
                    )
                }
            }
        }
        let mut unbound = vec![];
        for (name, sha) in &hashes {
            if !stmts.iter().any(|s| s.subjects.iter().any(|x| x.sha256.as_deref() == Some(sha.as_str()))) {
                unbound.push(name.clone());
            }
        }
        let commit_mismatch = match (&ctx.state.commit, stmts.iter().find_map(|s| s.source_commit.clone())) {
            (Some(c), Some(p)) if !c.starts_with(&p) && !p.starts_with(c.as_str()) => Some((c.clone(), p)),
            _ => None,
        };
        let evidence = json!({
            "statements": stmts,
            "unbound_artifacts": unbound,
            "signature_verified": false,
        });
        if !unbound.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Fail, "m.prov.unbound", &[])
                .evidence(evidence)
                .details(format!("No attestation subject digest matches: {}", unbound.join(", ")))
                .cause_key("m.prov.unbound.cause", &[]);
        }
        if let Some((tag_commit, prov_commit)) = commit_mismatch {
            return CheckResult::msg(id, Category::Trust, Status::Fail, "m.prov.commit", &[])
                .evidence(evidence)
                .details(format!("tag commit {tag_commit}\nattested   {prov_commit}"));
        }
        CheckResult::msg(id, Category::Trust, Status::Warn, "m.prov.unsigned", &[])
            .evidence(evidence)
            .suggestion_key("m.prov.unsigned.fix", &[])
    }
}

// ---------------------------------------------------------------------------
// sbom
// ---------------------------------------------------------------------------

pub struct Sbom;

impl Check for Sbom {
    fn id(&self) -> &'static str {
        "sbom"
    }
    fn category(&self) -> Category {
        Category::Trust
    }

    fn run(&self, ctx: &mut Context) -> CheckResult {
        let id = self.id();
        let mut candidates: Vec<(String, String)> = vec![]; // (origin, content)
        for f in assets::of_role(&ctx.target.assets, AssetRole::Sbom) {
            if let Ok(t) = std::fs::read_to_string(f) {
                candidates.push((assets::file_name(f), t));
            }
        }
        let mut lockfiles = vec![];
        if let Some(dir) = &ctx.state.repo_dir {
            let rev = if ctx.target.tag.is_empty() { "HEAD" } else { ctx.target.tag.as_str() };
            if let Ok(files) = git::list_files(dir, rev) {
                for f in &files {
                    if sbom::looks_like_sbom_path(f) && candidates.is_empty() {
                        if let Ok(t) = git::show_file(dir, rev, f) {
                            candidates.push((format!("{rev}:{f}"), t));
                        }
                    }
                    let base = f.rsplit('/').next().unwrap_or(f);
                    if sbom::LOCKFILES.contains(&base) {
                        lockfiles.push(f.clone());
                    }
                }
            }
        }
        if candidates.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Warn, "m.sbom.none", &[])
                .evidence(json!({ "lockfiles_in_source": lockfiles }))
                .suggestion_key("m.sbom.none.fix", &[]);
        }
        let mut summaries = vec![];
        let mut errors = vec![];
        for (origin, text) in &candidates {
            match sbom::parse(text) {
                Ok(s) => summaries.push((origin.clone(), s)),
                Err(e) => errors.push(format!("{origin}: {e:#}")),
            }
        }
        let evidence = json!({
            "sboms": summaries.iter().map(|(o, s)| json!({"origin": o, "summary": s})).collect::<Vec<_>>(),
            "parse_errors": errors, "lockfiles_in_source": lockfiles,
        });
        let Some((origin, best)) = summaries.iter().max_by_key(|(_, s)| s.components) else {
            return CheckResult::msg(id, Category::Trust, Status::Fail, "m.sbom.invalid", &[])
                .details(errors.join("\n"))
                .evidence(evidence);
        };
        let args = [
            ("format", best.format.as_str()),
            ("spec", best.spec_version.as_str()),
            ("origin", origin.as_str()),
            ("n", &best.components.to_string()),
            ("v", &best.with_version.to_string()),
            ("l", &best.with_license.to_string()),
        ];
        if best.issues.is_empty() {
            CheckResult::msg(id, Category::Trust, Status::Pass, "m.sbom.summary", &args).evidence(evidence)
        } else {
            CheckResult::msg(id, Category::Trust, Status::Warn, "m.sbom.summary", &args).details(best.issues.join("\n")).evidence(evidence)
        }
    }
}

// ---------------------------------------------------------------------------
// repro.rebuild — compares the release artifact with a local rebuild
// ---------------------------------------------------------------------------

pub struct Reproducibility;

impl Check for Reproducibility {
    fn id(&self) -> &'static str {
        "repro.rebuild"
    }
    fn category(&self) -> Category {
        Category::Build
    }

    fn run(&self, ctx: &mut Context) -> CheckResult {
        let id = self.id();
        let Some(rebuilt) = ctx.target.rebuilt.clone() else {
            return CheckResult::msg(id, Category::Build, Status::Skipped, "m.repro.none", &[]);
        };
        let artifacts: Vec<PathBuf> = assets::of_role(&ctx.target.assets, AssetRole::Artifact).into_iter().cloned().collect();
        let rname = assets::file_name(&rebuilt);
        let Some(release) =
            artifacts.iter().find(|a| assets::file_name(a) == rname).or(if artifacts.len() == 1 { artifacts.first() } else { None })
        else {
            return CheckResult::msg(id, Category::Build, Status::Error, "m.repro.ambiguous", &[])
                .suggestion_key("m.repro.ambiguous.fix", &[]);
        };
        ctx.progress("hashing release artifact and local rebuild");
        let (ha, hb) = match (releaseverity_core::hash::hash_file(release), releaseverity_core::hash::hash_file(&rebuilt)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return CheckResult::new(id, Category::Build, Status::Error, format!("{e}")),
        };
        let base = json!({
            "release": {"file": release, "sha256": ha.sha256, "size": ha.size},
            "local": {"file": rebuilt, "sha256": hb.sha256, "size": hb.size},
        });
        if ha.sha256 == hb.sha256 {
            return CheckResult::msg(id, Category::Build, Status::Pass, "m.repro.same", &[]).evidence(base);
        }
        ctx.progress("analysing binary differences");
        match diff::compare(release, &rebuilt) {
            Ok(rep) => {
                let mut ev = base;
                ev["diff"] = serde_json::to_value(&rep).unwrap_or_default();
                let mut r =
                    CheckResult::msg(id, Category::Build, Status::Fail, "m.repro.diff", &[("n", &rep.total_diff_bytes.to_string())]);
                if let Some(c) = rep.causes.first() {
                    let args: Vec<(&str, &str)> = c.args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                    r = r.cause_key(&format!("cause.{}", c.code), &args);
                }
                let lines: Vec<String> = rep
                    .regions
                    .iter()
                    .filter(|x| x.diff_bytes > 0 || rep.kind == "zip")
                    .map(|x| format!("{:<22} {:>6.2}% of diff  ({:.2}% of region changed)", x.name, x.share_pct, x.changed_pct))
                    .collect();
                r.details = Some(lines.join("\n"));
                r.evidence = ev;
                r.suggestion_key("m.repro.diff.fix", &[])
            }
            Err(e) => CheckResult::msg(id, Category::Build, Status::Fail, "m.repro.nodiff", &[]).cause(format!("{e:#}")).evidence(base),
        }
    }
}
