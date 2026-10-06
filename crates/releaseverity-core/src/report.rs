//! Report generation (JSON, Markdown, self-contained HTML) from a stored [`Run`].

use crate::i18n::I18n;
use crate::model::*;
use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
    Html,
}

impl Format {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "json" => Format::Json,
            "md" | "markdown" => Format::Markdown,
            "html" => Format::Html,
            "pdf" => bail!("PDF export is not available yet; export HTML and print to PDF"),
            other => bail!("unknown report format {other:?} (use json, markdown or html)"),
        })
    }
    pub fn extension(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Markdown => "md",
            Format::Html => "html",
        }
    }
}

pub fn render(run: &Run, format: Format, i18n: &I18n) -> Result<String> {
    Ok(match format {
        Format::Json => serde_json::to_string_pretty(&json_value(run))?,
        Format::Markdown => markdown(run, i18n),
        Format::Html => html(run, i18n),
    })
}

fn json_value(run: &Run) -> serde_json::Value {
    serde_json::json!({
        "schema": "releaseverity.report/1",
        "tool": { "name": "ReleaseVerity", "version": run.tool_version },
        "run": run,
    })
}

/// Environment Matrix: rows = install/launch/smoke/uninstall, columns = environments.
#[derive(Debug, Clone)]
pub struct Matrix {
    pub environments: Vec<String>,
    /// (check id, one cell per environment: the result, if that check ran there)
    pub rows: Vec<(&'static str, Vec<Option<CheckResult>>)>,
}

pub fn environment_matrix(results: &[CheckResult]) -> Option<Matrix> {
    let mut envs: Vec<String> = vec![];
    for r in results {
        if let Some(e) = &r.environment {
            if !envs.contains(e) {
                envs.push(e.clone());
            }
        }
    }
    if envs.is_empty() {
        return None;
    }
    let rows = ["install.install", "runtime.launch", "runtime.smoke", "install.uninstall"]
        .into_iter()
        .map(|id| {
            let cells =
                envs.iter().map(|e| results.iter().find(|r| r.id == id && r.environment.as_deref() == Some(e.as_str())).cloned()).collect();
            (id, cells)
        })
        .collect();
    Some(Matrix { environments: envs, rows })
}

/// Localized text of a binary-diff cause stored as JSON (`{code, message, args}`).
pub fn diff_cause_text(i18n: &I18n, cause: &serde_json::Value) -> String {
    let code = cause["code"].as_str().unwrap_or("");
    let key = format!("cause.{code}");
    if i18n.t(&key) == key {
        return cause["message"].as_str().unwrap_or(code).to_string();
    }
    let args: Vec<(String, String)> = cause["args"]
        .as_object()
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
        .unwrap_or_default();
    let refs: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    i18n.tf(&key, &refs)
}

pub fn verdict_label(i18n: &I18n, v: Option<Verdict>) -> String {
    match v {
        Some(v) => i18n.t(&format!("status.{}", v.as_str())),
        None => "-".into(),
    }
}

pub fn check_title(i18n: &I18n, id: &str) -> String {
    let key = format!("check.{id}");
    let t = i18n.t(&key);
    if t == key {
        id.to_string()
    } else {
        t
    }
}

fn dur(run: &Run) -> String {
    match run.finished_at {
        Some(f) => format!("{:.1}s", (f - run.started_at).num_milliseconds() as f64 / 1000.0),
        None => "-".into(),
    }
}

fn markdown(run: &Run, i18n: &I18n) -> String {
    let mut s = String::new();
    s += "# ReleaseVerity Verification Report\n\n";
    s += &format!("- **Project:** {}\n- **Repository:** {}\n- **Release:** {}\n", run.project_name, run.repo, run.tag);
    s += &format!("- **Commit:** {}\n", run.commit.as_deref().unwrap_or("-"));
    s += &format!(
        "- **Score:** {}\n- **Status:** {}\n",
        run.score.map(|x| format!("{x}/100")).unwrap_or_else(|| "-".into()),
        verdict_label(i18n, run.verdict)
    );
    s += &format!(
        "- **Started:** {}\n- **Duration:** {}\n- **Tool version:** ReleaseVerity {}\n- **Run:** #{}\n\n",
        run.started_at.to_rfc3339(),
        dur(run),
        run.tool_version,
        run.id
    );
    if !run.artifacts.is_empty() {
        s += "## Artifacts\n\n| Name | Size | SHA-256 |\n|---|---:|---|\n";
        for a in &run.artifacts {
            s += &format!("| {} | {} | `{}` |\n", a.name, a.size, a.sha256);
        }
        s += "\n";
    }
    if let Some(m) = environment_matrix(&run.results) {
        s += "## Environment Matrix

| |";
        for e in &m.environments {
            s += &format!(" {e} |");
        }
        s += "
|---|";
        for _ in &m.environments {
            s += "---|";
        }
        s += "
";
        for (id, cells) in &m.rows {
            s += &format!("| {} |", check_title(i18n, id));
            for c in cells {
                s += &format!(" {} |", c.as_ref().map(|r| r.status.symbol()).unwrap_or("-"));
            }
            s += "
";
        }
        s += "
";
    }
    for cat in Category::ALL {
        let rs: Vec<_> = run.results.iter().filter(|r| r.category == cat).collect();
        if rs.is_empty() {
            continue;
        }
        s += &format!("## {}\n\n", i18n.t(&format!("category.{}", cat.as_str())));
        for r in rs {
            let env = r.environment.as_deref().map(|e| format!(" [{e}]")).unwrap_or_default();
            s += &format!("- {} **{}**{} — {}\n", r.status.symbol(), check_title(i18n, &r.id), env, r.summary_text(i18n));
            if let Some(c) = r.cause_text(i18n) {
                s += &format!("  - {}: {}\n", i18n.t("error.cause"), c);
            }
            if let Some(c) = r.suggestion_text(i18n) {
                s += &format!("  - {}: {}\n", i18n.t("error.suggestion"), c);
            }
            if let Some(d) = &r.details {
                s += &format!("\n  ```text\n{}\n  ```\n", d.trim_end());
            }
        }
        s += "\n";
    }
    s
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn html(run: &Run, i18n: &I18n) -> String {
    let verdict_class = match run.verdict {
        Some(Verdict::Verified) => "pass",
        Some(Verdict::VerifiedWithWarnings) => "warn",
        Some(Verdict::Failed) => "fail",
        _ => "skip",
    };
    let mut body = String::new();
    for cat in Category::ALL {
        let rs: Vec<_> = run.results.iter().filter(|r| r.category == cat).collect();
        if rs.is_empty() {
            continue;
        }
        body += &format!("<h2>{}</h2><ul>", esc(&i18n.t(&format!("category.{}", cat.as_str()))));
        for r in rs {
            let env = r.environment.as_deref().map(|e| format!(" <span class=env>{}</span>", esc(e))).unwrap_or_default();
            body += &format!(
                "<li class={}><span class=sym>{}</span><div><b>{}</b>{} <span class=muted>— {}</span>",
                r.status.as_str(),
                r.status.symbol(),
                esc(&check_title(i18n, &r.id)),
                env,
                esc(&r.summary_text(i18n))
            );
            if let Some(c) = r.cause_text(i18n) {
                body += &format!("<div class=muted>{}: {}</div>", esc(&i18n.t("error.cause")), esc(&c));
            }
            if let Some(c) = r.suggestion_text(i18n) {
                body += &format!("<div class=muted>{}: {}</div>", esc(&i18n.t("error.suggestion")), esc(&c));
            }
            if let Some(d) = &r.details {
                body += &format!("<pre>{}</pre>", esc(d));
            }
            body += "</div></li>";
        }
        body += "</ul>";
    }
    if let Some(m) = environment_matrix(&run.results) {
        let mut t = String::from("<h2>Environment Matrix</h2><table><tr><th></th>");
        for e in &m.environments {
            t += &format!("<th>{}</th>", esc(e));
        }
        t += "</tr>";
        for (id, cells) in &m.rows {
            t += &format!("<tr><td>{}</td>", esc(&check_title(i18n, id)));
            for c in cells {
                match c {
                    Some(r) => t += &format!("<td class={}>{}</td>", r.status.as_str(), r.status.symbol()),
                    None => t += "<td class=skip>-</td>",
                }
            }
            t += "</tr>";
        }
        t += "</table>";
        body = t + &body;
    }
    let mut arts = String::new();
    for a in &run.artifacts {
        arts += &format!("<tr><td>{}</td><td class=num>{}</td><td><code>{}</code></td></tr>", esc(&a.name), a.size, esc(&a.sha256));
    }
    let arts = if arts.is_empty() {
        String::new()
    } else {
        format!("<h2>Artifacts</h2><table><tr><th>Name</th><th>Size</th><th>SHA-256</th></tr>{arts}</table>")
    };
    format!(
        r#"<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><title>ReleaseVerity Report — {proj} {tag}</title>
<style>
:root{{--bg:#fff;--fg:#1f2328;--mut:#656d76;--line:#d0d7de;--pass:#1a7f37;--warn:#9a6700;--fail:#cf222e;--panel:#f6f8fa}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--pass:#3fb950;--warn:#d29922;--fail:#f85149;--panel:#161b22}}}}
body{{font:14px/1.5 -apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg);max-width:880px;margin:32px auto;padding:0 16px}}
h1{{font-size:20px;margin:0 0 4px}}h2{{font-size:15px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}}
.verdict{{display:inline-block;font-weight:600;padding:2px 8px;border:1px solid currentColor;border-radius:4px}}
.pass{{color:var(--pass)}}.warn{{color:var(--warn)}}.fail,.error{{color:var(--fail)}}.skip,.skipped{{color:var(--mut)}}
.muted{{color:var(--mut)}}.env{{font-size:12px;border:1px solid var(--line);border-radius:3px;padding:0 4px;color:var(--mut)}}
ul{{list-style:none;padding:0;margin:0}}li{{display:flex;gap:10px;padding:6px 0;border-bottom:1px solid var(--line)}}
.sym{{width:16px;font-weight:700}}li>div{{flex:1}}
pre{{background:var(--panel);padding:8px;overflow:auto;font-size:12px;border-radius:4px}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid var(--line);padding:4px 8px;text-align:left;font-size:13px}}
.num{{text-align:right}}code{{font-size:12px;word-break:break-all}}dl{{display:grid;grid-template-columns:120px 1fr;gap:2px 12px;margin:12px 0}}dt{{color:var(--mut)}}dd{{margin:0}}
</style></head><body>
<h1>ReleaseVerity Verification Report</h1>
<div><span class="verdict {vc}">{verdict}</span> &nbsp; <b>{score}</b></div>
<dl><dt>Project</dt><dd>{proj}</dd><dt>Repository</dt><dd>{repo}</dd><dt>Release</dt><dd>{tag}</dd>
<dt>Commit</dt><dd><code>{commit}</code></dd><dt>Started</dt><dd>{started}</dd><dt>Duration</dt><dd>{dur}</dd>
<dt>Tool</dt><dd>ReleaseVerity {ver}</dd><dt>Run</dt><dd>#{id}</dd></dl>
{arts}{body}</body></html>"#,
        lang = i18n.lang(),
        proj = esc(&run.project_name),
        tag = esc(&run.tag),
        repo = esc(&run.repo),
        vc = verdict_class,
        verdict = esc(&verdict_label(i18n, run.verdict)),
        score = run.score.map(|s| format!("{s}/100")).unwrap_or_else(|| "-".into()),
        commit = esc(run.commit.as_deref().unwrap_or("-")),
        started = run.started_at.to_rfc3339(),
        dur = dur(run),
        ver = esc(&run.tool_version),
        id = run.id,
        arts = arts,
        body = body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample() -> Run {
        let mut r = CheckResult::new("source.tag", Category::Trust, Status::Fail, "tag <v1> missing");
        r.cause = Some("no such tag".into());
        Run {
            id: 7,
            project_id: None,
            project_name: "Astra".into(),
            repo: "C:/astra".into(),
            tag: "v1".into(),
            commit: Some("abc".into()),
            status: RunState::Finished,
            score: Some(40),
            verdict: Some(Verdict::Failed),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            tool_version: "0.1.0".into(),
            results: vec![r],
            artifacts: vec![],
        }
    }

    #[test]
    fn all_formats_contain_the_facts_and_escape_html() {
        let i = I18n::new("en");
        let run = sample();
        let j: serde_json::Value = serde_json::from_str(&render(&run, Format::Json, &i).unwrap()).unwrap();
        assert_eq!(j["run"]["score"], 40);
        assert_eq!(j["tool"]["version"], "0.1.0");
        let md = render(&run, Format::Markdown, &i).unwrap();
        assert!(md.contains("**Score:** 40/100") && md.contains("FAILED") && md.contains("no such tag"));
        let h = render(&run, Format::Html, &i).unwrap();
        assert!(h.contains("tag &lt;v1&gt; missing") && !h.contains("<v1>"));
        assert!(Format::parse("pdf").is_err());
    }
}
