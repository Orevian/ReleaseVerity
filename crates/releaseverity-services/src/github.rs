//! GitHub-backed parts of verification: downloading release assets as a real
//! pipeline step, and publishing the verdict back as a Check.

use crate::App;
use anyhow::{bail, Context as _, Result};
use releaseverity_core::check::{Check, Context};
use releaseverity_core::i18n::I18n;
use releaseverity_core::model::{Category, CheckResult, Run, Status, Verdict};
use releaseverity_core::report::{check_title, verdict_label};
use releaseverity_github::{parse_repo, ApiError, CheckOutput, GitHub, Published};

pub use releaseverity_github as client;

/// Downloads the GitHub Release assets of the tag under verification into the work
/// directory, so the checks after it verify the *published* files.
pub struct DownloadAssets {
    pub api_url: String,
    pub token: Option<String>,
}

impl Check for DownloadAssets {
    fn id(&self) -> &'static str {
        "release.assets"
    }
    fn category(&self) -> Category {
        Category::Trust
    }
    fn run(&self, ctx: &mut Context) -> CheckResult {
        let id = self.id();
        let Some((owner, repo)) = parse_repo(&ctx.target.repo) else {
            return CheckResult::msg(id, Category::Trust, Status::Skipped, "m.rel.notgh", &[]);
        };
        if !ctx.target.assets.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Skipped, "m.rel.local", &[]);
        }
        let gh = GitHub::new(&self.api_url, self.token.clone());
        ctx.progress(format!("looking up release {} of {owner}/{repo}", ctx.target.tag));
        let release = match gh.release_by_tag(&owner, &repo, &ctx.target.tag) {
            Ok(r) => r,
            Err(e @ ApiError::Status { code: 404, .. }) => {
                return CheckResult::msg(id, Category::Trust, Status::Warn, "m.rel.norelease", &[("tag", &ctx.target.tag)])
                    .cause(e.to_string())
                    .suggestion_key("m.rel.norelease.fix", &[]);
            }
            Err(e) => return CheckResult::new(id, Category::Trust, Status::Error, e.to_string()),
        };
        if release.assets.is_empty() {
            return CheckResult::msg(id, Category::Trust, Status::Warn, "m.rel.empty", &[])
                .evidence(serde_json::json!({ "release": release.name, "draft": release.draft, "prerelease": release.prerelease }));
        }
        let dir = ctx.work_dir.join("assets");
        let mut files = vec![];
        let mut total = 0u64;
        for a in &release.assets {
            let name = a.name.clone();
            let sink = ctx.sink.clone();
            let current = id.to_string();
            let mut last = 0u64;
            let r = gh.download_asset(a, &dir, &mut |done, size| {
                // Report real byte progress at most every ~2 MB.
                if done - last >= 2 * 1024 * 1024 || Some(done) == size {
                    last = done;
                    sink.emit(&releaseverity_core::check::RunEvent::Progress {
                        id: current.clone(),
                        message: format!("downloading {name}: {:.1} / {:.1} MB", done as f64 / 1e6, size.unwrap_or(done) as f64 / 1e6),
                    });
                }
            });
            match r {
                Ok(p) => {
                    total += a.size;
                    files.push(p);
                }
                Err(e) => {
                    return CheckResult::msg(
                        id,
                        Category::Trust,
                        Status::Error,
                        "m.rel.dlfail",
                        &[("name", &a.name), ("err", &e.to_string())],
                    )
                }
            }
        }
        let names: Vec<String> = files.iter().filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())).collect();
        ctx.target.assets = files;
        CheckResult::msg(
            id,
            Category::Trust,
            Status::Pass,
            "m.rel.downloaded",
            &[("n", &names.len().to_string()), ("mb", &format!("{:.1}", total as f64 / 1e6))],
        )
        .evidence(serde_json::json!({
            "release": { "tag": release.tag, "name": release.name, "prerelease": release.prerelease, "draft": release.draft },
            "files": names,
        }))
    }
}

impl App {
    /// A GitHub client configured from `config.toml` and the stored (or environment) token.
    pub fn github(&self) -> GitHub {
        GitHub::new(&self.config.github.api_url, client::credstore::load(&self.config.github.credential_name))
    }

    pub fn github_token(&self) -> Option<String> {
        client::credstore::load(&self.config.github.credential_name)
    }

    /// Validate and store a token; returns the account login.
    pub fn github_connect(&self, token: &str) -> Result<String> {
        let gh = GitHub::new(&self.config.github.api_url, Some(token.trim().to_string()));
        let login = gh.login().map_err(|e| anyhow::anyhow!("{e}"))?;
        client::credstore::save(&self.config.github.credential_name, token)?;
        Ok(login)
    }

    pub fn github_disconnect(&self) -> Result<bool> {
        client::credstore::delete(&self.config.github.credential_name)
    }

    /// Publish the run's verdict on its commit. Needs a GitHub repo and a resolved commit.
    pub fn publish_check(&self, run_id: i64) -> Result<Published> {
        let run = self.db.get_run(run_id)?.with_context(|| format!("no run #{run_id}"))?;
        let (owner, repo) = parse_repo(&run.repo).with_context(|| format!("{} is not a GitHub repository", run.repo))?;
        let Some(sha) = run.commit.clone() else { bail!("run #{run_id} has no verified commit to attach a check to") };
        let out = check_output(&run, &self.i18n);
        let token = self.github_token();
        anyhow::ensure!(
            token.is_some(),
            "no GitHub token: connect an account (releaseverity github login) or set RELEASEVERITY_GITHUB_TOKEN"
        );
        GitHub::new(&self.config.github.api_url, token).publish(&owner, &repo, &sha, &out).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// The text shown on the GitHub commit/PR.
pub fn check_output(run: &Run, i18n: &I18n) -> CheckOutput {
    let verdict = run.verdict.unwrap_or(Verdict::Inconclusive);
    let score = run.score.map(|s| s.to_string()).unwrap_or_else(|| "–".into());
    let (conclusion, key) = match verdict {
        Verdict::Verified => ("success", "gh.title.verified"),
        Verdict::VerifiedWithWarnings => ("neutral", "gh.title.warnings"),
        Verdict::Failed => ("failure", "gh.title.failed"),
        Verdict::Inconclusive => ("neutral", "gh.title.inconclusive"),
    };
    let mut s = format!(
        "**{}**  ·  {}/100  ·  `{}` {}\n\n",
        verdict_label(i18n, Some(verdict)),
        score,
        run.tag,
        run.commit.as_deref().map(|c| format!("@ `{}`", &c[..c.len().min(10)])).unwrap_or_default()
    );
    s.push_str("| | Check | Result |\n|---|---|---|\n");
    for r in &run.results {
        let env = r.environment.as_deref().map(|e| format!(" `{e}`")).unwrap_or_default();
        s.push_str(&format!(
            "| {} | {}{} | {} |\n",
            r.status.symbol(),
            check_title(i18n, &r.id),
            env,
            r.summary_text(i18n).replace('|', "\\|").replace('\n', " ")
        ));
    }
    s.push_str(&format!("\n_ReleaseVerity {}_\n", run.tool_version));
    let details_url = match (std::env::var("GITHUB_SERVER_URL"), std::env::var("GITHUB_REPOSITORY"), std::env::var("GITHUB_RUN_ID")) {
        (Ok(srv), Ok(repo), Ok(id)) => Some(format!("{srv}/{repo}/actions/runs/{id}")),
        _ => None,
    };
    CheckOutput { conclusion: conclusion.into(), title: i18n.tf(key, &[("score", &score)]), summary: s, details_url }
}

#[cfg(test)]
mod tests {
    use super::*;
    use releaseverity_core::model::{CheckResult, RunState};

    fn run(v: Verdict, score: u8) -> Run {
        Run {
            id: 1,
            project_id: None,
            project_name: "p".into(),
            repo: "https://github.com/o/r".into(),
            tag: "v1".into(),
            commit: Some("0123456789abcdef".into()),
            status: RunState::Finished,
            score: Some(score),
            verdict: Some(v),
            started_at: chrono::Utc::now(),
            finished_at: None,
            tool_version: "0.1.0".into(),
            results: vec![CheckResult::new("sbom", Category::Trust, Status::Warn, "no SBOM | published")],
            artifacts: vec![],
        }
    }

    #[test]
    fn check_text_reflects_the_real_verdict_in_both_languages() {
        let en = check_output(&run(Verdict::Verified, 94), &I18n::new("en"));
        assert_eq!((en.conclusion.as_str(), en.title.as_str()), ("success", "Release verification passed — 94/100"));
        assert!(en.summary.contains("VERIFIED") && en.summary.contains("0123456789") && en.summary.contains("no SBOM \\| published"));
        let tr = check_output(&run(Verdict::Failed, 40), &I18n::new("tr"));
        assert_eq!(tr.conclusion, "failure");
        assert!(tr.title.contains("başarısız") && tr.title.contains("40/100"), "{}", tr.title);
        assert_eq!(check_output(&run(Verdict::VerifiedWithWarnings, 80), &I18n::new("en")).conclusion, "neutral");
    }
}
