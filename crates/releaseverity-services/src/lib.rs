//! The single API surface used by every front end (CLI, desktop, CI action).
//! Front ends never talk to engines or the database directly.

use anyhow::{bail, Context as _, Result};
use releaseverity_core::check::{run_checks, Check, Context, EventSink, NullSink, ShipcheckTarget, VerifyTarget};
use releaseverity_core::config::{Config, Paths};
use releaseverity_core::db::Db;
use releaseverity_core::i18n::I18n;
use releaseverity_core::logging::{Category as LogCat, Level, Logger};
use releaseverity_core::model::*;
use releaseverity_core::report::{self, Format};
use releaseverity_core::scoring;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub mod environments;
pub mod github;
pub mod request;

pub use releaseverity_core as core;
pub use releaseverity_repro as repro;
pub use releaseverity_shipcheck as shipcheck;

pub struct App {
    pub paths: Paths,
    pub config: Config,
    pub db: Db,
    pub logger: Logger,
    pub i18n: I18n,
}

#[derive(Debug, Clone, Default)]
pub struct VerifyRequest {
    /// Registered project name. Supplies repo/path when `repo` is not given.
    pub project: Option<String>,
    /// Repository URL or local path.
    pub repo: Option<String>,
    pub tag: String,
    pub assets: Vec<PathBuf>,
    pub rebuilt: Option<PathBuf>,
    /// Installation/runtime testing (ShipCheck). Without it only source/trust/documentation checks run.
    pub shipcheck: Option<ShipcheckTarget>,
    /// Restrict to these checks (`source`, `checksum`, `signature`, `provenance`, `sbom`, `repro`, `docs`, `install`, `launch`, `smoke`, `uninstall`, `shipcheck`). Empty = all that apply.
    pub only: Vec<String>,
}

impl App {
    pub fn open(paths: Paths) -> Result<Self> {
        paths.ensure()?;
        let config = Config::load(&paths.config_file())?;
        let level = Level::parse(&config.logging.level).unwrap_or(Level::Info);
        let logger = Logger::new(paths.logs_dir(), level);
        let db = Db::open(&paths.database())?;
        db.recover_interrupted_runs()?;
        let i18n = I18n::new(&config.general.language);
        Ok(Self { paths, config, db, logger, i18n })
    }

    pub fn save_config(&mut self) -> Result<()> {
        self.config.save(&self.paths.config_file())?;
        self.i18n = I18n::new(&self.config.general.language);
        Ok(())
    }

    pub fn check_names() -> &'static [&'static str] {
        &[
            "source",
            "checksum",
            "signature",
            "provenance",
            "sbom",
            "repro",
            "docs",
            "assets",
            "install",
            "launch",
            "smoke",
            "uninstall",
            "shipcheck",
        ]
    }

    /// Names of the Repro Engine checks (for `releaseverity repro verify`).
    pub fn repro_names() -> Vec<String> {
        ["source", "checksum", "signature", "provenance", "sbom", "repro"].iter().map(|s| s.to_string()).collect()
    }

    fn selected(&self, only: &[String], ship: &Option<ShipcheckTarget>, package_only: bool, download: bool) -> Result<Vec<Box<dyn Check>>> {
        let mut all = if package_only { vec![] } else { releaseverity_repro::checks() };
        if download {
            // After the tag is resolved, before any asset-based check.
            let at = all.iter().position(|c| c.id() == "artifact.checksum").unwrap_or(all.len());
            all.insert(at, Box::new(github::DownloadAssets { api_url: self.config.github.api_url.clone(), token: self.github_token() }));
        }
        if !package_only {
            all.extend(releaseverity_shipcheck::docs::checks());
        }
        if let Some(t) = ship {
            all.extend(releaseverity_shipcheck::env_checks(t));
        }
        if only.is_empty() {
            return Ok(all);
        }
        let mut ids: Vec<&str> = vec![];
        for n in only {
            match n.to_ascii_lowercase().as_str() {
                "source" => ids.extend(["source.integrity", "source.tag"]),
                "checksum" => ids.push("artifact.checksum"),
                "signature" | "signatures" => ids.push("artifact.signature"),
                "provenance" => ids.push("provenance"),
                "sbom" => ids.push("sbom"),
                "repro" | "reproducibility" => ids.push("repro.rebuild"),
                "assets" | "download" => ids.push("release.assets"),
                "docs" => ids.extend(["docs.installation", "docs.usage", "docs.upgrade"]),
                "install" => ids.push("install.install"),
                "launch" => ids.push("runtime.launch"),
                "smoke" => ids.push("runtime.smoke"),
                "uninstall" => ids.push("install.uninstall"),
                "shipcheck" => ids.extend([
                    "docs.installation",
                    "docs.usage",
                    "docs.upgrade",
                    "install.install",
                    "runtime.launch",
                    "runtime.smoke",
                    "install.uninstall",
                ]),
                other => bail!("unknown check {other:?}; valid: {}", Self::check_names().join(", ")),
            }
        }
        if ship.is_none()
            && ids.iter().any(|i| matches!(*i, "install.install" | "runtime.launch" | "runtime.smoke" | "install.uninstall"))
            && only.iter().all(|o| !matches!(o.as_str(), "shipcheck"))
        {
            bail!("installation/runtime checks need a package: pass --package <installer|zip|dir>");
        }
        // Asset-based checks need the downloaded release files.
        if download
            && ids.iter().any(|i| matches!(*i, "artifact.checksum" | "artifact.signature" | "provenance" | "sbom" | "repro.rebuild"))
            && !ids.contains(&"release.assets")
        {
            ids.push("release.assets");
        }
        // Later checks depend on the repository state; always keep source integrity first.
        let needs_repo = ["sbom", "source.tag", "release.assets", "docs.installation", "docs.usage", "docs.upgrade"];
        if !ids.contains(&"source.integrity") && ids.iter().any(|i| needs_repo.contains(i)) {
            ids.insert(0, "source.integrity");
        }
        Ok(all.into_iter().filter(|c| ids.contains(&c.id())).collect())
    }

    /// Run a verification, persist everything and return the stored run.
    pub fn verify(&self, req: VerifyRequest, sink: Arc<dyn EventSink>, cancel: Arc<AtomicBool>) -> Result<Run> {
        let project = match &req.project {
            Some(n) => Some(self.db.find_project(n)?.with_context(|| format!("no project named {n:?}; see `releaseverity project list`"))?),
            None => None,
        };
        let repo_opt = req.repo.clone().or_else(|| project.as_ref().and_then(|p| p.repo_url.clone().or(p.local_path.clone())));
        // A package can be tested on its own, without a repository (only install/runtime checks apply then).
        let package_only = repo_opt.is_none() && req.shipcheck.is_some();
        let repo = match (repo_opt, &req.shipcheck) {
            (Some(r), _) => r,
            (None, Some(t)) => t.package.to_string_lossy().into_owned(),
            (None, None) => bail!("no repository given: pass --repo or --project"),
        };
        let mut req = req;
        if req.tag.trim().is_empty() {
            if package_only {
                req.tag = "local".into();
            } else {
                bail!("no release tag given (--release)");
            }
        }
        let download = !package_only && req.assets.is_empty() && releaseverity_github::parse_repo(&repo).is_some();
        let checks = self.selected(&req.only, &req.shipcheck, package_only, download)?;
        let name = project.as_ref().map(|p| p.name.clone()).unwrap_or_else(|| {
            repo.trim_end_matches(['/', '\\']).trim_end_matches(".git").rsplit(['/', '\\']).next().unwrap_or(&repo).to_string()
        });
        let run_id = self.db.start_run(project.as_ref().map(|p| p.id), &name, &repo, &req.tag, releaseverity_core::VERSION)?;
        self.logger.info(LogCat::Verification, &format!("run #{run_id} started: {repo} @ {}", req.tag));

        let work = self.paths.work_dir().join(format!("run-{run_id}"));
        std::fs::create_dir_all(&work)?;
        let _cleanup = Cleanup(work.clone()); // guaranteed on every exit path, including errors

        let target = VerifyTarget {
            project_name: name,
            repo: repo.clone(),
            local_repo: None,
            tag: req.tag.clone(),
            assets: req.assets.clone(),
            rebuilt: req.rebuilt.clone(),
            shipcheck: req.shipcheck.clone(),
        };
        let mut ctx = Context::new(self.config.clone(), target, work, self.logger.clone());
        ctx.cancel = cancel;
        ctx.sink = sink;
        let outcome = run_checks(&checks, &mut ctx);

        for r in &outcome.results {
            self.db.add_result(run_id, r)?;
        }
        for a in &ctx.state.artifacts {
            self.db.add_artifact(run_id, a)?;
        }
        let mut verdict = scoring::verdict(&outcome.results);
        if self.config.verification.warnings_as_errors && verdict == Verdict::VerifiedWithWarnings {
            verdict = Verdict::Failed;
        }
        let state = if outcome.cancelled { RunState::Cancelled } else { RunState::Finished };
        self.db.finish_run(run_id, state, ctx.state.commit.as_deref(), scoring::score(&outcome.results), Some(verdict))?;
        if let Some(p) = &project {
            self.db.upsert_release(p.id, &req.tag, ctx.state.commit.as_deref())?;
        }
        self.logger.info(LogCat::Verification, &format!("run #{run_id} finished: {}", verdict.as_str()));
        self.db.get_run(run_id)?.context("run vanished after saving")
    }

    /// Render a stored run. Writes `out` (or the default reports dir) and records it.
    pub fn generate_report(&self, run_id: i64, format: Format, out: Option<&Path>) -> Result<PathBuf> {
        let run = self.db.get_run(run_id)?.with_context(|| format!("no run #{run_id}"))?;
        let text = report::render(&run, format, &self.i18n)?;
        let path = match out {
            Some(p) => p.to_path_buf(),
            None => self.paths.reports_dir().join(format!("run-{run_id}.{}", format.extension())),
        };
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
        self.db.add_report(run_id, format.extension(), &path.to_string_lossy())?;
        Ok(path)
    }

    pub fn null_sink() -> Arc<dyn EventSink> {
        Arc::new(NullSink)
    }
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(d: &Path) -> App {
        App::open(Paths::new(d.join("home"))).unwrap()
    }

    #[test]
    fn selection_validates_names_and_keeps_dependencies() {
        let d = tempfile::tempdir().unwrap();
        let a = app(d.path());
        let ids = |o: &[&str]| {
            a.selected(&o.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &None, false, false)
                .map(|v| v.iter().map(|c| c.id()).collect::<Vec<_>>())
        };
        assert_eq!(ids(&["sbom"]).unwrap(), ["source.integrity", "sbom"]);
        assert_eq!(ids(&[]).unwrap().len(), 10, "repro (7) + docs (3); no package → no install/runtime checks");
        assert!(ids(&["install"]).is_err(), "install checks need --package");
        assert_eq!(ids(&["docs"]).unwrap().len(), 4);
        assert!(ids(&["bogus"]).is_err());
        // GitHub repositories get a download step right before the asset-based checks.
        let gh = a.selected(&[], &None, false, true).unwrap().iter().map(|c| c.id()).collect::<Vec<_>>();
        assert_eq!(&gh[..4], ["source.integrity", "source.tag", "release.assets", "artifact.checksum"]);
        let only = a.selected(&["sbom".to_string()], &None, false, true).unwrap().iter().map(|c| c.id()).collect::<Vec<_>>();
        assert_eq!(only, ["source.integrity", "release.assets", "sbom"]);
    }

    #[test]
    fn rejects_missing_inputs_with_actionable_errors() {
        let d = tempfile::tempdir().unwrap();
        let a = app(d.path());
        let e = a.verify(VerifyRequest { tag: "v1".into(), ..Default::default() }, App::null_sink(), Default::default()).unwrap_err();
        assert!(format!("{e:#}").contains("--repo"));
        let e = a
            .verify(
                VerifyRequest { project: Some("nope".into()), tag: "v1".into(), ..Default::default() },
                App::null_sink(),
                Default::default(),
            )
            .unwrap_err();
        assert!(format!("{e:#}").contains("no project named"));
    }

    #[test]
    fn verify_persists_run_and_report_and_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        let a = app(d.path());
        let repo = d.path().join("r");
        std::fs::create_dir(&repo).unwrap();
        releaseverity_repro::git::run(Some(&repo), &["init", "-q", "-b", "main"], std::time::Duration::from_secs(30)).unwrap();
        // Empty repo: no tag. The run must still be recorded, with a real failure.
        let run = a
            .verify(
                VerifyRequest {
                    repo: Some(repo.to_string_lossy().into()),
                    tag: "v1".into(),
                    only: vec!["source".into()],
                    ..Default::default()
                },
                App::null_sink(),
                Default::default(),
            )
            .unwrap();
        assert_eq!(run.status, RunState::Finished);
        assert_eq!(run.verdict, Some(Verdict::Failed));
        assert!(run.results.iter().any(|r| r.id == "source.tag" && r.status == Status::Fail));
        let p = a.generate_report(run.id, Format::Html, None).unwrap();
        assert!(std::fs::read_to_string(p).unwrap().contains("ReleaseVerity Verification Report"));
        assert_eq!(a.db.list_reports(run.id).unwrap().len(), 1);
        assert!(!a.paths.work_dir().join(format!("run-{}", run.id)).exists(), "work dir cleaned up");
    }
}

// ---------------------------------------------------------------------------
// Read models for front ends
// ---------------------------------------------------------------------------

/// One step of a planned verification (so a UI can list steps before they run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    pub id: String,
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Dashboard {
    pub projects: usize,
    pub verified: usize,
    pub warnings: usize,
    pub failed: usize,
    pub inconclusive: usize,
    /// Mean score of the latest run of every release; `None` when nothing was verified yet.
    pub health: Option<u8>,
    pub recent: Vec<Run>,
}

impl App {
    /// The steps `verify` would run for this request, in order.
    pub fn plan(&self, req: &VerifyRequest) -> Result<Vec<PlannedStep>> {
        let package_only = req.repo.is_none() && req.project.is_none() && req.shipcheck.is_some();
        let download = !package_only && req.assets.is_empty() && req.repo.as_deref().and_then(releaseverity_github::parse_repo).is_some();
        Ok(self
            .selected(&req.only, &req.shipcheck, package_only, download)?
            .iter()
            .map(|c| PlannedStep { id: c.id().to_string(), environment: c.environment() })
            .collect())
    }

    /// Latest run of every distinct release (project + tag).
    pub fn latest_per_release(&self) -> Result<Vec<Run>> {
        let mut seen = std::collections::HashSet::new();
        let mut out = vec![];
        for r in self.db.list_runs(5000, None)? {
            if r.status == RunState::Running {
                continue;
            }
            if seen.insert((r.project_name.to_lowercase(), r.tag.clone())) {
                out.push(r);
            }
        }
        Ok(out)
    }

    pub fn dashboard(&self) -> Result<Dashboard> {
        let latest = self.latest_per_release()?;
        let mut d = Dashboard { projects: self.db.list_projects()?.len(), ..Default::default() };
        let mut scores = vec![];
        for r in &latest {
            match r.verdict {
                Some(Verdict::Verified) => d.verified += 1,
                Some(Verdict::VerifiedWithWarnings) => d.warnings += 1,
                Some(Verdict::Failed) => d.failed += 1,
                _ => d.inconclusive += 1,
            }
            if let Some(s) = r.score {
                scores.push(s as u32);
            }
        }
        if !scores.is_empty() {
            d.health = Some((scores.iter().sum::<u32>() as f64 / scores.len() as f64).round() as u8);
        }
        d.recent = self.db.list_runs(8, None)?;
        Ok(d)
    }

    /// Tags of a local path or a remote URL, newest first.
    pub fn tags_of(source: &str) -> Result<Vec<String>> {
        let s = source.trim();
        if Path::new(s).is_dir() {
            releaseverity_repro::git::list_tags(Path::new(s))
        } else {
            releaseverity_repro::git::remote_tags(s, std::time::Duration::from_secs(60))
        }
    }
}

#[cfg(test)]
mod read_model_tests {
    use super::*;

    #[test]
    fn dashboard_counts_the_latest_run_of_each_release_only() {
        let d = tempfile::tempdir().unwrap();
        let a = App::open(Paths::new(d.path().join("h"))).unwrap();
        let mk = |tag: &str, v: Verdict, score: u8| {
            let id = a.db.start_run(None, "Astra", "r", tag, "0").unwrap();
            a.db.finish_run(id, RunState::Finished, None, Some(score), Some(v)).unwrap();
        };
        mk("v1", Verdict::Failed, 40); // superseded by the re-run below
        mk("v1", Verdict::Verified, 100);
        mk("v2", Verdict::VerifiedWithWarnings, 80);
        let dash = a.dashboard().unwrap();
        assert_eq!((dash.verified, dash.warnings, dash.failed), (1, 1, 0));
        assert_eq!(dash.health, Some(90));
        assert_eq!(dash.recent.len(), 3);
        assert!(App::open(Paths::new(d.path().join("h"))).unwrap().dashboard().is_ok(), "a second connection can open");
    }

    #[test]
    fn plan_lists_steps_with_environments() {
        let d = tempfile::tempdir().unwrap();
        let a = App::open(Paths::new(d.path().join("h"))).unwrap();
        let p = a.plan(&VerifyRequest { repo: Some("x".into()), tag: "v".into(), ..Default::default() }).unwrap();
        assert_eq!(p.first().unwrap().id, "source.integrity");
        assert!(p.iter().all(|s| s.environment.is_none()));
    }
}
