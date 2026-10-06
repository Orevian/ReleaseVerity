//! Conversions from ReleaseVerity's domain model to the rows the UI displays.
//! Pure functions (no UI types besides the generated row structs) so they are unit-testable.

use crate::{ProjectRow, RunRow};
use chrono::{DateTime, Local, Utc};
use releaseverity_services::core::i18n::I18n;
use releaseverity_services::core::model::{Run, Status, Verdict};
use releaseverity_services::core::report::verdict_label;

pub fn verdict_int(v: Option<Verdict>) -> i32 {
    match v {
        Some(Verdict::Verified) => 1,
        Some(Verdict::VerifiedWithWarnings) => 2,
        Some(Verdict::Failed) => 3,
        Some(Verdict::Inconclusive) => 4,
        None => 0,
    }
}

pub fn status_int(s: Status) -> i32 {
    match s {
        Status::Pass => 1,
        Status::Warn => 2,
        Status::Fail => 3,
        Status::Skipped => 4,
        Status::Error => 5,
    }
}

pub fn when(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string()
}

pub fn duration(run: &Run) -> String {
    match run.finished_at {
        Some(f) => {
            let ms = (f - run.started_at).num_milliseconds().max(0);
            if ms < 60_000 {
                format!("{:.1}s", ms as f64 / 1000.0)
            } else {
                format!("{}m {:02}s", ms / 60_000, (ms / 1000) % 60)
            }
        }
        None => "…".into(),
    }
}

pub fn run_row(r: &Run, i18n: &I18n) -> RunRow {
    let running = r.status == releaseverity_services::core::model::RunState::Running;
    RunRow {
        id: r.id as i32,
        project: r.project_name.clone().into(),
        tag: r.tag.clone().into(),
        score: r.score.map(i32::from).unwrap_or(-1),
        verdict: verdict_int(r.verdict),
        verdict_text: if running { i18n.t("state.running") } else { verdict_label(i18n, r.verdict) }.into(),
        started: when(r.started_at).into(),
        duration: duration(r).into(),
        state: r.status.as_str().into(),
    }
}

pub fn project_row(
    p: &releaseverity_services::core::model::Project,
    last: Option<&Run>,
    i18n: &I18n,
    warnings: i32,
    failures: i32,
) -> ProjectRow {
    ProjectRow {
        name: p.name.clone().into(),
        repo: p.repo_url.clone().or_else(|| p.local_path.clone()).unwrap_or_default().into(),
        branch: p.default_branch.clone().into(),
        latest_release: last.map(|r| r.tag.clone()).unwrap_or_else(|| "–".into()).into(),
        verdict: verdict_int(last.and_then(|r| r.verdict)),
        verdict_text: last.map(|r| verdict_label(i18n, r.verdict)).unwrap_or_else(|| i18n.t("state.never")).into(),
        last_run: last.map(|r| when(r.started_at)).unwrap_or_else(|| "–".into()).into(),
        score: last.and_then(|r| r.score).map(i32::from).unwrap_or(-1),
        warnings,
        failures,
    }
}

pub fn human_size(n: u64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let (mut v, mut i) = (n as f64, 0);
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_verdicts_map_as_the_ui_expects() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(verdict_int(Some(Verdict::VerifiedWithWarnings)), 2);
        assert_eq!(verdict_int(None), 0);
        assert_eq!(status_int(Status::Error), 5);
    }
}
