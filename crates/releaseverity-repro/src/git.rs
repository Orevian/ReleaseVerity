//! Thin wrapper over the `git` CLI. Real git, real objects — no re-implementation.

use anyhow::{bail, Context as _, Result};
use releaseverity_core::proc::{self, ProcOutput};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub fn available() -> bool {
    proc::exists_on_path("git")
}

pub fn run(dir: Option<&Path>, args: &[&str], timeout: Duration) -> Result<ProcOutput> {
    let mut c = Command::new("git");
    if let Some(d) = dir {
        c.current_dir(d);
    }
    // Never block on credential prompts; fail fast instead.
    c.env("GIT_TERMINAL_PROMPT", "0").args(args);
    proc::run(&mut c, timeout).context("could not run git (is it installed and on PATH?)")
}

fn ok(dir: &Path, args: &[&str], timeout: Duration) -> Result<String> {
    let o = run(Some(dir), args, timeout)?;
    if o.timed_out {
        bail!("git {} timed out after {}s", args.join(" "), timeout.as_secs());
    }
    if !o.success() {
        bail!("git {} failed: {}", args.join(" "), o.stderr.trim());
    }
    Ok(o.stdout.trim().to_string())
}

/// Tags of a repository, newest first (by tagger/commit date).
pub fn list_tags(dir: &Path) -> Result<Vec<String>> {
    let out = ok(dir, &["tag", "--sort=-creatordate"], Duration::from_secs(30))?;
    Ok(out.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect())
}

/// Tags of a *remote* repository without cloning (`git ls-remote`), sorted by version-ish name, newest first.
pub fn remote_tags(url: &str, timeout: Duration) -> Result<Vec<String>> {
    let o = run(None, &["ls-remote", "--tags", "--refs", "--sort=-v:refname", url], timeout)?;
    if o.timed_out {
        bail!("listing tags of {url} timed out after {}s", timeout.as_secs());
    }
    if !o.success() {
        bail!("could not list tags of {url}: {}", o.stderr.trim());
    }
    Ok(o.stdout.lines().filter_map(|l| l.split_once("refs/tags/").map(|(_, t)| t.trim().to_string())).collect())
}

pub fn is_repo(dir: &Path) -> bool {
    run(Some(dir), &["rev-parse", "--git-dir"], Duration::from_secs(15)).map(|o| o.success()).unwrap_or(false)
}

pub fn clone(url: &str, dest: &Path, timeout: Duration) -> Result<()> {
    let o = run(None, &["clone", "--quiet", "--no-checkout", url, &dest.to_string_lossy()], timeout)?;
    if o.timed_out {
        bail!("cloning {url} timed out after {}s", timeout.as_secs());
    }
    if !o.success() {
        bail!("cloning {url} failed: {}", o.stderr.trim());
    }
    // Make sure all tags are present.
    let _ = run(Some(dest), &["fetch", "--quiet", "--tags"], timeout);
    Ok(())
}

#[derive(Debug, Clone)]
pub struct TagInfo {
    pub name: String,
    /// Object the tag ref points at (tag object for annotated tags).
    pub object: String,
    /// The commit the tag ultimately resolves to.
    pub commit: String,
    pub annotated: bool,
}

pub fn resolve_tag(dir: &Path, tag: &str) -> Result<Option<TagInfo>> {
    let t = Duration::from_secs(30);
    let refname = format!("refs/tags/{tag}");
    let o = run(Some(dir), &["rev-parse", "--verify", "--quiet", &refname], t)?;
    if !o.success() {
        return Ok(None);
    }
    let object = o.stdout.trim().to_string();
    let kind = ok(dir, &["cat-file", "-t", &object], t)?;
    let commit = ok(dir, &["rev-parse", &format!("{refname}^{{commit}}")], t)?;
    Ok(Some(TagInfo { name: tag.into(), object, commit, annotated: kind == "tag" }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagSignature {
    /// `git verify-tag` succeeded.
    Valid(String),
    /// Tag is annotated but carries no signature.
    Unsigned,
    /// A signature exists but verification failed (bad signature, unknown key, no gpg…).
    Invalid(String),
}

pub fn verify_tag_signature(dir: &Path, tag: &TagInfo) -> Result<TagSignature> {
    if !tag.annotated {
        return Ok(TagSignature::Unsigned);
    }
    let body = ok(dir, &["cat-file", "tag", &tag.object], Duration::from_secs(30))?;
    if !body.contains("-----BEGIN PGP SIGNATURE-----") && !body.contains("-----BEGIN SSH SIGNATURE-----") {
        return Ok(TagSignature::Unsigned);
    }
    let o = run(Some(dir), &["verify-tag", "--raw", &tag.name], Duration::from_secs(60))?;
    let text = format!("{}{}", o.stdout, o.stderr);
    if o.success() {
        Ok(TagSignature::Valid(text.trim().to_string()))
    } else {
        Ok(TagSignature::Invalid(text.trim().to_string()))
    }
}

/// Verify object integrity of the repository (hashes of all reachable objects).
pub fn fsck(dir: &Path, timeout: Duration) -> Result<(bool, String)> {
    let o = run(Some(dir), &["fsck", "--connectivity-only", "--no-dangling"], timeout)?;
    if o.timed_out {
        bail!("git fsck timed out after {}s", timeout.as_secs());
    }
    Ok((o.success(), format!("{}{}", o.stdout, o.stderr).trim().to_string()))
}

pub fn head_commit(dir: &Path) -> Result<String> {
    ok(dir, &["rev-parse", "HEAD"], Duration::from_secs(30))
}

/// Whether `commit` exists as a commit object.
pub fn commit_exists(dir: &Path, commit: &str) -> bool {
    run(Some(dir), &["cat-file", "-e", &format!("{commit}^{{commit}}")], Duration::from_secs(30)).map(|o| o.success()).unwrap_or(false)
}

/// List repository files at a tag (no checkout needed).
pub fn list_files(dir: &Path, rev: &str) -> Result<Vec<String>> {
    let out = ok(dir, &["ls-tree", "-r", "--name-only", rev], Duration::from_secs(60))?;
    Ok(out.lines().map(str::to_string).collect())
}

/// Read a file at a revision.
pub fn show_file(dir: &Path, rev: &str, path: &str) -> Result<String> {
    let o = run(Some(dir), &["show", &format!("{rev}:{path}")], Duration::from_secs(60))?;
    if !o.success() {
        bail!("{path} not found at {rev}");
    }
    Ok(o.stdout)
}

#[cfg(test)]
pub mod testutil {
    use super::*;

    /// Create a real repo with one commit and (optionally) a tag. Skips nothing: tests need git.
    pub fn make_repo(dir: &Path, tag: Option<(&str, bool)>) -> String {
        let g = |args: &[&str]| {
            let o = run(Some(dir), args, Duration::from_secs(60)).unwrap();
            assert!(o.success(), "git {args:?}: {}", o.stderr);
            o.stdout.trim().to_string()
        };
        g(&["init", "-q", "-b", "main"]);
        g(&["config", "user.email", "t@example.com"]);
        g(&["config", "user.name", "T"]);
        g(&["config", "commit.gpgsign", "false"]);
        g(&["config", "tag.gpgsign", "false"]);
        std::fs::write(dir.join("README.md"), "# Demo\n\n## Installation\nrun it\n").unwrap();
        g(&["add", "."]);
        g(&["commit", "-q", "-m", "init"]);
        match tag {
            Some((t, true)) => {
                g(&["tag", "-a", t, "-m", "release"]);
            }
            Some((t, false)) => {
                g(&["tag", t]);
            }
            None => {}
        }
        g(&["rev-parse", "HEAD"])
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::make_repo;
    use super::*;

    #[test]
    fn resolves_annotated_and_lightweight_tags_to_commit() {
        let d = tempfile::tempdir().unwrap();
        let head = make_repo(d.path(), Some(("v1.0.0", true)));
        let t = resolve_tag(d.path(), "v1.0.0").unwrap().unwrap();
        assert!(t.annotated);
        assert_eq!(t.commit, head);
        assert_ne!(t.object, head, "annotated tag object differs from commit");
        run(Some(d.path()), &["tag", "light"], Duration::from_secs(30)).unwrap();
        let l = resolve_tag(d.path(), "light").unwrap().unwrap();
        assert!(!l.annotated);
        assert_eq!(l.commit, head);
        assert!(resolve_tag(d.path(), "nope").unwrap().is_none());
        assert_eq!(verify_tag_signature(d.path(), &t).unwrap(), TagSignature::Unsigned);
    }

    #[test]
    fn fsck_and_file_listing() {
        let d = tempfile::tempdir().unwrap();
        make_repo(d.path(), Some(("v1", true)));
        assert!(fsck(d.path(), Duration::from_secs(60)).unwrap().0);
        assert_eq!(list_files(d.path(), "v1").unwrap(), vec!["README.md"]);
        assert!(show_file(d.path(), "v1", "README.md").unwrap().contains("Installation"));
        assert!(is_repo(d.path()));
        run(Some(d.path()), &["tag", "-a", "v2", "-m", "x"], Duration::from_secs(30)).unwrap();
        assert_eq!(list_tags(d.path()).unwrap().len(), 2);
    }

    #[test]
    fn clone_local_repo() {
        let src = tempfile::tempdir().unwrap();
        let head = make_repo(src.path(), Some(("v2", true)));
        let dst = tempfile::tempdir().unwrap();
        let dest = dst.path().join("c");
        clone(&src.path().to_string_lossy(), &dest, Duration::from_secs(60)).unwrap();
        assert_eq!(resolve_tag(&dest, "v2").unwrap().unwrap().commit, head);
    }
}
