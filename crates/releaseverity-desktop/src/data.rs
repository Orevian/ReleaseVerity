//! Loading real data into the UI models (UI thread only).

use crate::view::{self, status_int, verdict_int};
use crate::*;
use releaseverity_services::core::i18n::I18n;
use releaseverity_services::core::model::{Category, CheckResult, FailureKind, Run, Status};
use releaseverity_services::core::report::{check_title, environment_matrix, verdict_label};
use releaseverity_services::App;
use slint::{ModelRc, SharedString, VecModel};

pub fn rows<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

fn strings(v: Vec<String>) -> ModelRc<SharedString> {
    rows(v.into_iter().map(SharedString::from).collect())
}

fn ints(v: Vec<i32>) -> ModelRc<i32> {
    rows(v)
}

pub fn projects(app: &App, i18n: &I18n) -> Vec<ProjectRow> {
    let mut out = vec![];
    for p in app.db.list_projects().unwrap_or_default() {
        let last = app.db.list_runs(1, Some(p.id)).ok().and_then(|v| v.into_iter().next());
        let (mut w, mut f) = (0, 0);
        if let Some(l) = &last {
            if let Ok(Some(full)) = app.db.get_run(l.id) {
                w = full.results.iter().filter(|r| r.status == Status::Warn).count() as i32;
                f = full.results.iter().filter(|r| matches!(r.status, Status::Fail | Status::Error)).count() as i32;
            }
        }
        out.push(view::project_row(&p, last.as_ref(), i18n, w, f));
    }
    out
}

pub fn runs(app: &App, i18n: &I18n) -> Vec<RunRow> {
    app.db.list_runs(300, None).unwrap_or_default().iter().map(|r| view::run_row(r, i18n)).collect()
}

pub fn releases(app: &App, i18n: &I18n) -> Vec<RunRow> {
    app.latest_per_release().unwrap_or_default().iter().map(|r| view::run_row(r, i18n)).collect()
}

pub fn artifacts(app: &App) -> Vec<ArtifactRow> {
    app.db
        .list_artifacts(300)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, project, tag, a)| ArtifactRow {
            name: a.name.into(),
            project: project.into(),
            tag: tag.into(),
            kind: a.kind.to_uppercase().into(),
            size: view::human_size(a.size).into(),
            sha256: a.sha256.into(),
            path: a.path.into(),
        })
        .collect()
}

pub fn reports(app: &App) -> Vec<ReportRow> {
    app.db
        .list_all_reports(300)
        .unwrap_or_default()
        .into_iter()
        .map(|r| ReportRow {
            id: r.id as i32,
            project: r.project.into(),
            tag: r.tag.into(),
            format: r.format.to_uppercase().into(),
            created: view::when(r.created_at).into(),
            path: r.path.into(),
        })
        .collect()
}

pub fn status_text(i18n: &I18n, r: &CheckResult) -> String {
    if let Some(k) = r.failure_kind {
        if r.status == Status::Fail {
            let key = match k {
                FailureKind::Crashed => "failure.crashed",
                FailureKind::Hung => "failure.hung",
                FailureKind::Timeout => "failure.timeout",
                FailureKind::ExitCode => "failure.exitcode",
                FailureKind::Other => "result.fail",
            };
            return i18n.t(key);
        }
    }
    i18n.t(&format!("result.{}", r.status.as_str()))
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// Fill the release-detail page from a stored run.
pub fn fill_detail(ui: &MainWindow, run: &Run, i18n: &I18n) {
    let st = ui.global::<AppState>();
    st.set_detail_id(run.id as i32);
    st.set_detail_title(format!("{} {}", run.project_name, run.tag).into());
    st.set_detail_subtitle(format!("{}  ·  {}", run.repo, run.commit.as_deref().map(|c| &c[..c.len().min(12)]).unwrap_or("–")).into());
    st.set_detail_score(run.score.map(i32::from).unwrap_or(-1));
    st.set_detail_verdict(verdict_int(run.verdict));
    st.set_detail_verdict_text(verdict_label(i18n, run.verdict).into());
    st.set_detail_meta(
        format!(
            "{}  ·  {}  ·  ReleaseVerity {}  ·  {} {}",
            view::when(run.started_at),
            view::duration(run),
            run.tool_version,
            run.artifacts.len(),
            i18n.t("detail.artifacts")
        )
        .into(),
    );

    let mut list = vec![];
    for cat in Category::ALL {
        let members: Vec<(usize, &CheckResult)> = run.results.iter().enumerate().filter(|(_, r)| r.category == cat).collect();
        if members.is_empty() {
            continue;
        }
        list.push(CheckRow {
            kind: 0,
            index: -1,
            title: i18n.t(&format!("category.{}", cat.as_str())).into(),
            summary: "".into(),
            status: 0,
            env: "".into(),
        });
        for (i, r) in members {
            list.push(CheckRow {
                kind: 1,
                index: i as i32,
                title: check_title(i18n, &r.id).into(),
                summary: r.summary_text(i18n).into(),
                status: status_int(r.status),
                env: r.environment.clone().unwrap_or_default().into(),
            });
        }
    }
    st.set_detail_rows(rows(list));

    match environment_matrix(&run.results) {
        Some(m) => {
            st.set_matrix_envs(strings(m.environments.clone()));
            let mrows = m
                .rows
                .iter()
                .map(|(id, cells)| MatrixRow {
                    label: check_title(i18n, id).into(),
                    status: ints(cells.iter().map(|c| c.as_ref().map(|r| status_int(r.status)).unwrap_or(0)).collect()),
                    result_index: ints(
                        m.environments
                            .iter()
                            .map(|e| {
                                run.results
                                    .iter()
                                    .position(|r| r.id == *id && r.environment.as_deref() == Some(e.as_str()))
                                    .map(|p| p as i32)
                                    .unwrap_or(-1)
                            })
                            .collect(),
                    ),
                })
                .collect();
            st.set_matrix_rows(rows(mrows));
        }
        None => {
            st.set_matrix_envs(strings(vec![]));
            st.set_matrix_rows(rows(vec![]));
        }
    }
    // Pre-select the most severe finding so the right-hand panel is useful immediately.
    let first_bad = run
        .results
        .iter()
        .position(|r| matches!(r.status, Status::Fail | Status::Error))
        .or_else(|| run.results.iter().position(|r| r.status == Status::Warn));
    match first_bad {
        Some(i) => fill_selected(ui, run, i as i32, i18n),
        None => st.set_selected_index(-1),
    }
}

pub fn fill_selected(ui: &MainWindow, run: &Run, idx: i32, i18n: &I18n) {
    let st = ui.global::<AppState>();
    let Some(r) = run.results.get(idx as usize) else {
        st.set_selected_index(-1);
        return;
    };
    st.set_selected_index(idx);
    let env = r.environment.as_deref().map(|e| format!("  [{e}]")).unwrap_or_default();
    st.set_sel_title(format!("{}{}", check_title(i18n, &r.id), env).into());
    st.set_sel_status(status_int(r.status));
    st.set_sel_status_text(status_text(i18n, r).into());
    st.set_sel_summary(r.summary_text(i18n).into());
    st.set_sel_cause(r.cause_text(i18n).unwrap_or_default().into());
    st.set_sel_suggestion(r.suggestion_text(i18n).unwrap_or_default().into());
    st.set_sel_details(clip(r.details.as_deref().unwrap_or(""), 6000).into());
    st.set_sel_evidence(
        if r.evidence.is_null() { String::new() } else { clip(&serde_json::to_string_pretty(&r.evidence).unwrap_or_default(), 4000) }
            .into(),
    );
    let mut meta = format!("{}  ·  {} ms", r.id, r.duration_ms);
    if let Some(c) = r.exit_code {
        meta.push_str(&format!("  ·  {} {c}", i18n.t("detail.exit-code")));
    }
    st.set_sel_meta(meta.into());
}

// ---------------------------------------------------------------------------
// Reproducibility page
// ---------------------------------------------------------------------------

pub fn clear_repro(ui: &MainWindow) {
    let st = ui.global::<AppState>();
    st.set_pipe_status(ints(vec![0, 0, 0, 0, 0]));
    st.set_pipe_text(strings(vec![String::new(); 5]));
    st.set_repro_release_hash("".into());
    st.set_repro_local_hash("".into());
    st.set_repro_result(0);
    st.set_repro_result_text("".into());
    st.set_repro_message("".into());
    st.set_repro_regions(rows(vec![]));
    st.set_repro_causes(strings(vec![]));
}

pub fn fill_repro_diff(ui: &MainWindow, evidence: &serde_json::Value, i18n: &I18n) {
    let st = ui.global::<AppState>();
    let regions = evidence["diff"]["regions"].as_array().cloned().unwrap_or_default();
    st.set_repro_regions(rows(
        regions
            .iter()
            .filter(|r| r["diff_bytes"].as_u64().unwrap_or(0) > 0 || evidence["diff"]["kind"] == "zip")
            .map(|r| RegionRow {
                name: r["name"].as_str().unwrap_or("").into(),
                share: format!("{:.2}%", r["share_pct"].as_f64().unwrap_or(0.0)).into(),
                changed: format!("{:.2}%", r["changed_pct"].as_f64().unwrap_or(0.0)).into(),
                bytes: r["diff_bytes"].as_u64().unwrap_or(0).to_string().into(),
                share_value: r["share_pct"].as_f64().unwrap_or(0.0) as f32,
            })
            .collect(),
    ));
    let causes = evidence["diff"]["causes"].as_array().cloned().unwrap_or_default();
    st.set_repro_causes(strings(causes.iter().map(|c| releaseverity_services::core::report::diff_cause_text(i18n, c)).collect()));
}

/// Open the reproducibility view for a stored run (uses the evidence the engine recorded).
pub fn fill_repro_from_run(ui: &MainWindow, run: &Run, i18n: &I18n) {
    clear_repro(ui);
    let st = ui.global::<AppState>();
    let short = |s: &str| s.chars().take(14).collect::<String>();
    let get = |id: &str| run.results.iter().find(|r| r.id == id);
    let stat = |id: &str| get(id).map(|r| status_int(r.status)).unwrap_or(0);
    let repro = get("repro.rebuild");
    st.set_pipe_status(ints(vec![stat("source.integrity"), stat("source.tag"), 4, 4, repro.map(|r| status_int(r.status)).unwrap_or(0)]));
    st.set_pipe_text(strings(vec![
        run.repo.chars().rev().take(26).collect::<Vec<_>>().into_iter().rev().collect(),
        run.commit.as_deref().map(short).unwrap_or_else(|| "–".into()),
        i18n.t("repro.pipe.env"),
        i18n.t("repro.pipe.build"),
        repro.and_then(|r| r.evidence["release"]["sha256"].as_str().map(short)).unwrap_or_else(|| "–".into()),
    ]));
    if let Some(r) = repro {
        let ev = &r.evidence;
        st.set_repro_release(ev["release"]["file"].as_str().unwrap_or("").into());
        st.set_repro_local(ev["local"]["file"].as_str().unwrap_or("").into());
        st.set_repro_release_hash(ev["release"]["sha256"].as_str().unwrap_or("").into());
        st.set_repro_local_hash(ev["local"]["sha256"].as_str().unwrap_or("").into());
        let rs = match r.status {
            Status::Pass => 1,
            Status::Fail => 3,
            Status::Error => 5,
            _ => 0,
        };
        st.set_repro_result(rs);
        st.set_repro_result_text(
            match r.status {
                Status::Pass => i18n.t("repro.result.reproducible"),
                Status::Fail => i18n.t("repro.result.not_reproducible"),
                _ => String::new(),
            }
            .into(),
        );
        fill_repro_diff(ui, ev, i18n);
    }
}
