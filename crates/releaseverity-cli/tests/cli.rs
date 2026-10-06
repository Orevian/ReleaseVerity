//! End-to-end tests of the real `releaseverity` binary: real git repositories, real files,
//! real exit codes. Each test uses its own RELEASEVERITY_HOME.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn vf(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_releaseverity"));
    c.env("RELEASEVERITY_HOME", home).env_remove("NO_COLOR").env_remove("RELEASEVERITY_AGENT");
    c
}

fn run(home: &Path, args: &[&str]) -> Output {
    vf(home).args(args).output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn git(dir: &Path, args: &[&str]) {
    let o = Command::new("git").current_dir(dir).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

/// A real repo with one commit and the annotated tag v1.0.0.
fn repo(root: &Path) -> PathBuf {
    let dir = root.join("repo");
    std::fs::create_dir_all(&dir).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    for kv in [["user.email", "t@e.com"], ["user.name", "T"], ["commit.gpgsign", "false"], ["tag.gpgsign", "false"]] {
        git(&dir, &["config", kv[0], kv[1]]);
    }
    std::fs::write(dir.join("README.md"), "# Demo\n\n## Installation\nrun it\n\n## Usage\nuse it\n").unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-q", "-m", "init"]);
    git(&dir, &["tag", "-a", "v1.0.0", "-m", "release"]);
    dir
}

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn version_matches_the_workspace_version() {
    let d = tmp();
    let o = run(d.path(), &["version"]);
    assert!(o.status.success());
    assert_eq!(out(&o).trim(), format!("releaseverity {}", env!("CARGO_PKG_VERSION")));
}

#[test]
fn project_lifecycle_and_json_output() {
    let d = tmp();
    let r = repo(d.path());
    let home = d.path().join("home");
    assert!(run(&home, &["project", "add", "Astra", "--path", r.to_str().unwrap()]).status.success());
    assert!(
        !run(&home, &["project", "add", "astra", "--path", r.to_str().unwrap()]).status.success(),
        "names are unique, case-insensitively"
    );
    assert!(!run(&home, &["project", "add", "Bad", "--path", d.path().to_str().unwrap()]).status.success(), "not a git repo");
    let o = run(&home, &["--json", "project", "list"]);
    let v: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v[0]["name"], "Astra");
    assert!(run(&home, &["project", "remove", "Astra"]).status.success());
    assert_eq!(run(&home, &["project", "remove", "Astra"]).status.code(), Some(2));
}

#[test]
fn verify_reports_real_results_without_colour_codes() {
    let d = tmp();
    let r = repo(d.path());
    let home = d.path().join("home");
    let o = run(&home, &["verify", "--repo", r.to_str().unwrap(), "--release", "v1.0.0", "--only", "source,docs", "--no-color", "--ascii"]);
    let s = out(&o);
    // Source and tag verify; the README has no upgrade section → a failed (non-critical) check.
    assert!(s.contains("Source integrity") && s.contains("OK") && s.contains("Git tag"), "{s}");
    assert!(s.contains("Upgrade instructions") && s.contains("FAIL"), "{s}");
    assert!(s.contains("VERIFIED WITH WARNINGS"), "{s}");
    assert_eq!(o.status.code(), Some(0), "warnings alone do not fail the release");
    assert!(!s.contains('\u{1b}'), "no escape codes with --no-color");
    let strict =
        run(&home, &["verify", "--repo", r.to_str().unwrap(), "--release", "v1.0.0", "--only", "source,docs", "--no-color", "--strict"]);
    assert_eq!(strict.status.code(), Some(1), "--strict turns warnings into a failing exit code");
}

#[test]
fn a_missing_tag_fails_the_release_with_exit_code_1() {
    let d = tmp();
    let r = repo(d.path());
    let o = run(&d.path().join("home"), &["verify", "--repo", r.to_str().unwrap(), "--release", "v9", "--only", "source", "--no-color"]);
    assert_eq!(o.status.code(), Some(1));
    let s = out(&o);
    assert!(s.contains("FAILED") && s.contains("tag v9 does not exist"), "{s}");
}

#[test]
fn turkish_output_and_reports_are_localized() {
    let d = tmp();
    let r = repo(d.path());
    let home = d.path().join("home");
    let rep = d.path().join("rep");
    let o = run(
        &home,
        &[
            "--lang",
            "tr",
            "verify",
            "--repo",
            r.to_str().unwrap(),
            "--release",
            "v9",
            "--only",
            "source",
            "--no-color",
            "--report",
            "markdown",
            "--out",
            rep.to_str().unwrap(),
        ],
    );
    let s = out(&o);
    assert!(s.contains("Sürüm Doğrulama") && s.contains("BAŞARISIZ") && s.contains("Skor:"), "{s}");
    assert!(s.contains("v9 etiketi mevcut değil"), "engine messages are translated: {s}");
    let md = std::fs::read_to_string(rep.join("releaseverity-run-1.md")).unwrap();
    assert!(md.contains("etiketi mevcut değil") && md.contains("Önerilen inceleme"), "{md}");
    // The stored run renders in English too: the language is a view concern, not stored text.
    let en = d.path().join("en.md");
    let o = run(&home, &["--lang", "en", "report", "export", "--run", "1", "--format", "markdown", "--out", en.to_str().unwrap()]);
    assert!(o.status.success());
    assert!(std::fs::read_to_string(en).unwrap().contains("tag v9 does not exist"));
}

#[test]
fn reports_are_generated_in_every_format_from_stored_runs() {
    let d = tmp();
    let r = repo(d.path());
    let home = d.path().join("home");
    assert_eq!(run(&home, &["verify", "--repo", r.to_str().unwrap(), "--release", "v1.0.0", "--only", "source"]).status.code(), Some(0));
    for (fmt, needle) in
        [("html", "<!doctype html>"), ("json", "releaseverity.report/1"), ("markdown", "# ReleaseVerity Verification Report")]
    {
        let p = d.path().join(format!("r.{fmt}"));
        assert!(run(&home, &["report", "export", "--format", fmt, "--out", p.to_str().unwrap()]).status.success());
        assert!(std::fs::read_to_string(&p).unwrap().contains(needle), "{fmt}");
    }
    let pdf = d.path().join("x.pdf");
    assert!(
        !run(&home, &["report", "export", "--format", "pdf", "--out", pdf.to_str().unwrap()]).status.success(),
        "PDF is honestly unavailable"
    );
}

#[test]
fn config_is_validated_and_persisted() {
    let d = tmp();
    let home = d.path().join("home");
    assert!(run(&home, &["config", "set", "timeouts.install_secs", "300"]).status.success());
    assert_eq!(out(&run(&home, &["config", "get", "timeouts.install_secs"])).trim(), "300");
    let bad = run(&home, &["config", "set", "general.language", "klingon"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(err(&bad).contains("language"));
    assert!(std::fs::read_to_string(home.join("config.toml")).unwrap().contains("install_secs = 300"));
}

#[test]
fn shipcheck_demands_a_package_instead_of_inventing_results() {
    let d = tmp();
    let o = run(d.path(), &["shipcheck", "run"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("--package"));
}

#[test]
fn repro_compare_distinguishes_identical_and_different_files() {
    let d = tmp();
    let (a, b, c) = (d.path().join("a.bin"), d.path().join("b.bin"), d.path().join("c.bin"));
    std::fs::write(&a, b"same").unwrap();
    std::fs::write(&b, b"same").unwrap();
    std::fs::write(&c, b"different!").unwrap();
    let same = run(d.path(), &["repro", "compare", a.to_str().unwrap(), b.to_str().unwrap(), "--no-color"]);
    assert_eq!(same.status.code(), Some(0));
    assert!(out(&same).contains("REPRODUCIBLE") && !out(&same).contains("NOT REPRODUCIBLE"));
    let diff = run(d.path(), &["repro", "compare", a.to_str().unwrap(), c.to_str().unwrap(), "--no-color"]);
    assert_eq!(diff.status.code(), Some(1));
    assert!(out(&diff).contains("NOT REPRODUCIBLE"));
}

#[test]
fn storage_free_commands_work_even_when_the_data_directory_is_unusable() {
    let d = tmp();
    // RELEASEVERITY_HOME points at a *file*: no database can be created there.
    let blocker = d.path().join("blocker");
    std::fs::write(&blocker, "x").unwrap();
    assert!(run(&blocker, &["environment", "list", "--no-color"]).status.success());
    assert!(run(&blocker, &["version"]).status.success());
    let doctor = run(&blocker, &["doctor", "--no-color", "--ascii"]);
    assert_eq!(doctor.status.code(), Some(1), "doctor reports the broken storage instead of crashing");
    assert!(out(&doctor).contains("storage") && out(&doctor).contains("FAIL"));
}

#[test]
fn artifact_inspect_emits_machine_readable_json() {
    let d = tmp();
    let f = d.path().join("x.bin");
    std::fs::write(&f, b"abc").unwrap();
    let o = run(d.path(), &["--json", "artifact", "inspect", f.to_str().unwrap()]);
    let v: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v["artifact"]["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
