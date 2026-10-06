//! End-to-end: real git repo, real files, real hashing — through the same
//! orchestrator the CLI and GUI use. No mocks.

use releaseverity_core::check::{run_checks, Context, VerifyTarget};
use releaseverity_core::config::Config;
use releaseverity_core::logging::Logger;
use releaseverity_core::model::{CheckResult, Status};
use releaseverity_core::scoring;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git").current_dir(dir).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn repo_with_tag(dir: &Path) -> String {
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["config", "user.email", "t@e.com"]);
    git(dir, &["config", "user.name", "T"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
    git(dir, &["config", "tag.gpgsign", "false"]);
    std::fs::write(dir.join("Cargo.lock"), "# lock\n").unwrap();
    git(dir, &["add", "."]);
    git(dir, &["commit", "-q", "-m", "init"]);
    git(dir, &["tag", "-a", "v1.0.0", "-m", "r"]);
    git(dir, &["rev-parse", "HEAD"])
}

fn run(repo: &Path, tag: &str, assets: Vec<PathBuf>, rebuilt: Option<PathBuf>) -> Vec<CheckResult> {
    let work = tempfile::tempdir().unwrap();
    let target = VerifyTarget {
        project_name: "demo".into(),
        repo: repo.to_string_lossy().into(),
        local_repo: None,
        tag: tag.into(),
        assets,
        rebuilt,
        ..Default::default()
    };
    let mut ctx = Context::new(Config::default(), target, work.path().to_path_buf(), Logger::null());
    run_checks(&releaseverity_repro::checks(), &mut ctx).results
}

fn by<'a>(r: &'a [CheckResult], id: &str) -> &'a CheckResult {
    r.iter().find(|x| x.id == id).unwrap_or_else(|| panic!("no result {id}"))
}

#[test]
fn good_release_verifies_and_bad_checksum_fails() {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let commit = repo_with_tag(&repo);

    let assets = d.path().join("assets");
    std::fs::create_dir(&assets).unwrap();
    let art = assets.join("demo-1.0.0.bin");
    std::fs::write(&art, b"release payload").unwrap();
    let sha = releaseverity_core::hash::sha256_bytes(b"release payload");
    let sums = assets.join("SHA256SUMS");
    std::fs::write(&sums, format!("{sha}  demo-1.0.0.bin\n")).unwrap();
    std::fs::write(
        assets.join("bom.cdx.json"),
        r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"x","version":"1","licenses":[{"license":{"id":"MIT"}}]}]}"#,
    )
    .unwrap();

    let list = vec![art.clone(), sums.clone(), assets.join("bom.cdx.json")];
    let r = run(&repo, "v1.0.0", list.clone(), None);
    assert_eq!(by(&r, "source.integrity").status, Status::Pass);
    let tag = by(&r, "source.tag");
    assert_eq!(tag.status, Status::Pass);
    assert_eq!(tag.evidence["commit"], commit);
    assert_eq!(by(&r, "artifact.checksum").status, Status::Pass);
    assert_eq!(by(&r, "sbom").status, Status::Pass);
    assert_eq!(by(&r, "provenance").status, Status::Warn, "no attestation supplied");
    assert_eq!(by(&r, "repro.rebuild").status, Status::Skipped);
    assert_ne!(scoring::verdict(&r), releaseverity_core::model::Verdict::Failed);

    // Tamper with the artifact after the checksum was published.
    std::fs::write(&art, b"release payload (tampered)").unwrap();
    let r = run(&repo, "v1.0.0", list, None);
    let c = by(&r, "artifact.checksum");
    assert_eq!(c.status, Status::Fail);
    assert!(c.details.as_deref().unwrap().contains(&sha));
    assert_eq!(scoring::verdict(&r), releaseverity_core::model::Verdict::Failed, "checksum failure is critical");
}

#[test]
fn missing_tag_fails_and_unknown_repo_errors_without_pretending() {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    repo_with_tag(&repo);
    let r = run(&repo, "v9.9.9", vec![], None);
    assert_eq!(by(&r, "source.tag").status, Status::Fail);

    let r = run(&d.path().join("does-not-exist"), "v1", vec![], None);
    let s = by(&r, "source.integrity");
    assert!(matches!(s.status, Status::Error | Status::Fail), "{s:?}");
    assert_eq!(by(&r, "source.tag").status, Status::Skipped);
}

#[test]
fn reproducibility_compares_a_real_rebuild() {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    repo_with_tag(&repo);
    let rel = d.path().join("rel");
    let loc = d.path().join("loc");
    std::fs::create_dir(&rel).unwrap();
    std::fs::create_dir(&loc).unwrap();
    let a = rel.join("app.bin");
    let b = loc.join("app.bin");
    std::fs::write(&a, b"AAAA built at /home/ci/work/src BBBB").unwrap();
    std::fs::write(&b, b"AAAA built at /home/ci/work/src BBBB").unwrap();
    let r = run(&repo, "v1.0.0", vec![a.clone()], Some(b.clone()));
    assert_eq!(by(&r, "repro.rebuild").status, Status::Pass);

    std::fs::write(&b, b"AAAA built at /Users/me/other/src BBBB").unwrap();
    let r = run(&repo, "v1.0.0", vec![a], Some(b));
    let c = by(&r, "repro.rebuild");
    assert_eq!(c.status, Status::Fail);
    assert!(c.summary.contains("NOT REPRODUCIBLE"));
    assert!(c.evidence["diff"]["causes"].as_array().unwrap().iter().any(|x| x["code"] == "embedded_path"));
}

#[test]
fn attestation_digest_binding_is_checked() {
    use base64::Engine;
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let commit = repo_with_tag(&repo);
    let art = d.path().join("app.bin");
    std::fs::write(&art, b"payload").unwrap();
    let sha = releaseverity_core::hash::sha256_bytes(b"payload");
    let mk = |digest: &str, c: &str| {
        let stmt = serde_json::json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"app.bin","digest":{"sha256":digest}}],
          "predicateType":"https://slsa.dev/provenance/v1",
          "predicate":{"buildDefinition":{"resolvedDependencies":[{"uri":"git+x","digest":{"gitCommit":c}}]},"runDetails":{"builder":{"id":"b"}}}});
        let payload = base64::engine::general_purpose::STANDARD.encode(stmt.to_string());
        serde_json::json!({"payloadType":"application/vnd.in-toto+json","payload":payload,"signatures":[{"sig":"x"}]}).to_string()
    };
    let att = d.path().join("multiple.intoto.jsonl");

    std::fs::write(&att, mk(&sha, &commit)).unwrap();
    let r = run(&repo, "v1.0.0", vec![art.clone(), att.clone()], None);
    let p = by(&r, "provenance");
    assert_eq!(p.status, Status::Warn, "digests bind, but the signature is not verified: never a Pass");
    assert_eq!(p.evidence["signature_verified"], false);

    std::fs::write(&att, mk(&"0".repeat(64), &commit)).unwrap();
    assert_eq!(by(&run(&repo, "v1.0.0", vec![art.clone(), att.clone()], None), "provenance").status, Status::Fail);

    std::fs::write(&att, mk(&sha, "ffffffffffffffffffffffffffffffffffffffff")).unwrap();
    assert_eq!(by(&run(&repo, "v1.0.0", vec![art, att], None), "provenance").status, Status::Fail);
}
