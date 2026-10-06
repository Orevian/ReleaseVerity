// No console window in release builds.
#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

mod data;
mod settings;
mod view;

use anyhow::Result;
use releaseverity_services::core::check::RunEvent;
use releaseverity_services::core::config::Paths;
use releaseverity_services::core::i18n::I18n;
use releaseverity_services::core::model::{Run, Status};
use releaseverity_services::core::report::{check_title, Format};
use releaseverity_services::request::{self, PackageOptions};
use releaseverity_services::{environments, App, VerifyRequest};
use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

slint::include_modules!();

/// Shared by every callback. Everything inside is `Send + Sync` so background work can use it.
struct Ctx {
    app: Mutex<App>,
    paths: Paths,
    i18n: Mutex<I18n>,
    /// The run shown on the detail page (for selecting individual checks).
    run: Mutex<Option<Run>>,
    cancel: Mutex<Option<Arc<AtomicBool>>>,
    toast_gen: AtomicU64,
}

impl Ctx {
    fn t(&self, key: &str) -> String {
        self.i18n.lock().unwrap().t(key)
    }
    fn i18n(&self) -> I18n {
        self.i18n.lock().unwrap().clone()
    }
}

/// Run `work` on a thread; apply the result on the UI thread. `work` must return plain data
/// (Slint models are not `Send`).
fn bg<T: Send + 'static>(ui: &MainWindow, work: impl FnOnce() -> T + Send + 'static, done: impl FnOnce(&MainWindow, T) + Send + 'static) {
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let v = work();
        let _ = weak.upgrade_in_event_loop(move |ui| done(&ui, v));
    });
}

fn toast(ui: &MainWindow, ctx: &Arc<Ctx>, msg: impl Into<String>) {
    let gen = ctx.toast_gen.fetch_add(1, Ordering::SeqCst) + 1;
    ui.global::<AppState>().set_toast(msg.into().into());
    let (weak, ctx) = (ui.as_weak(), ctx.clone());
    slint::Timer::single_shot(std::time::Duration::from_secs(5), move || {
        if ctx.toast_gen.load(Ordering::SeqCst) == gen {
            if let Some(ui) = weak.upgrade() {
                ui.global::<AppState>().set_toast("".into());
            }
        }
    });
}

fn open_path(p: &Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(not(windows))]
    let _ = std::process::Command::new("xdg-open").arg(p).spawn();
}

fn copy_to_clipboard(text: &str) {
    #[cfg(windows)]
    {
        use std::io::Write;
        use std::os::windows::process::CommandExt;
        if let Ok(mut c) = std::process::Command::new("clip").creation_flags(0x0800_0000).stdin(std::process::Stdio::piped()).spawn() {
            if let Some(mut i) = c.stdin.take() {
                let _ = i.write_all(text.as_bytes());
            }
            let _ = c.wait();
        }
    }
    #[cfg(not(windows))]
    let _ = text;
}

fn set_theme(ui: &MainWindow, dark: bool) {
    ui.global::<Theme>().set_dark(dark);
    ui.global::<Palette>().set_color_scheme(if dark { slint::language::ColorScheme::Dark } else { slint::language::ColorScheme::Light });
}

// ---------------------------------------------------------------------------
// Navigation: every page loads its real data when opened.
// ---------------------------------------------------------------------------

fn go(ui: &MainWindow, ctx: &Arc<Ctx>, page: i32) {
    let st = ui.global::<AppState>();
    let i18n = ctx.i18n();
    if page == 11 && st.get_page() != 12 {
        reset_wizard(ui);
    }
    st.set_page(page);
    match page {
        0 => {
            let app = ctx.app.lock().unwrap();
            if let Ok(d) = app.dashboard() {
                st.set_projects_count(d.projects as i32);
                st.set_verified_count(d.verified as i32);
                st.set_warning_count(d.warnings as i32);
                st.set_failed_count(d.failed as i32);
                st.set_inconclusive_count(d.inconclusive as i32);
                st.set_health(d.health.map(i32::from).unwrap_or(-1));
                st.set_recent_runs(data::rows(d.recent.iter().map(|r| view::run_row(r, &i18n)).collect()));
            }
        }
        1 => st.set_projects(data::rows(data::projects(&ctx.app.lock().unwrap(), &i18n))),
        2 => st.set_releases(data::rows(data::releases(&ctx.app.lock().unwrap(), &i18n))),
        3 => st.set_runs(data::rows(data::runs(&ctx.app.lock().unwrap(), &i18n))),
        4 => {
            // Probing tools/engines runs processes (docker info can be slow): keep it off the UI thread.
            bg(
                ui,
                || (environments::list(), environments::tools()),
                |ui, (envs, tools)| {
                    let st = ui.global::<AppState>();
                    st.set_envs(data::rows(
                        envs.into_iter()
                            .map(|e| EnvRow {
                                id: e.id.into(),
                                name: e.name.into(),
                                isolation: format!("{:?}", e.isolation).to_lowercase().replace("virtualmachine", "vm").into(),
                                available: e.available,
                                detail: e.detail.into(),
                            })
                            .collect(),
                    ));
                    st.set_tools(data::rows(
                        tools
                            .into_iter()
                            .map(|t| ToolRow {
                                name: t.name.into(),
                                version: t.version.unwrap_or_default().into(),
                                found: t.found,
                                purpose: t.purpose.into(),
                            })
                            .collect(),
                    ));
                },
            );
        }
        5 => st.set_artifacts(data::rows(data::artifacts(&ctx.app.lock().unwrap()))),
        6 => st.set_reports(data::rows(data::reports(&ctx.app.lock().unwrap()))),
        7 => load_settings(ui, ctx),
        _ => {}
    }
}

fn load_settings(ui: &MainWindow, ctx: &Arc<Ctx>) {
    let st = ui.global::<AppState>();
    let sec = st.get_settings_section().max(0) as usize;
    let i18n = ctx.i18n();
    let app = ctx.app.lock().unwrap();
    st.set_settings_rows(data::rows(settings::rows(sec, &app.config, &i18n)));
    st.set_settings_note(settings::note(sec, &i18n, releaseverity_services::core::VERSION).into());
    drop(app);
    if sec == 5 {
        refresh_github(ui, ctx);
    }
}

/// Look up the GitHub account state off the UI thread (it needs a network call).
fn refresh_github(ui: &MainWindow, ctx: &Arc<Ctx>) {
    let st = ui.global::<AppState>();
    let (token_present, cred, api) = {
        let app = ctx.app.lock().unwrap();
        (app.github_token().is_some(), app.config.github.credential_name.clone(), app.config.github.api_url.clone())
    };
    if !token_present {
        st.set_gh_connected(false);
        st.set_gh_status(ctx.t("gh.status.none").into());
        return;
    }
    st.set_gh_busy(true);
    st.set_gh_status("…".into());
    let ctx2 = ctx.clone();
    bg(
        ui,
        move || {
            releaseverity_services::github::client::GitHub::new(&api, releaseverity_services::github::client::credstore::load(&cred))
                .login()
                .map_err(|e| e.to_string())
        },
        move |ui, res| {
            let st = ui.global::<AppState>();
            st.set_gh_busy(false);
            match res {
                Ok(login) => {
                    st.set_gh_connected(true);
                    st.set_gh_status(ctx2.i18n().tf("gh.status.connected", &[("login", &login)]).into());
                }
                Err(e) => {
                    // A token exists; show why it fails so it can be replaced.
                    st.set_gh_connected(true);
                    st.set_gh_status(e.into());
                }
            }
        },
    );
}

fn open_run(ui: &MainWindow, ctx: &Arc<Ctx>, id: i32) {
    let run = ctx.app.lock().unwrap().db.get_run(id as i64).ok().flatten();
    let Some(run) = run else { return toast(ui, ctx, ctx.t("err.run-missing")) };
    data::fill_detail(ui, &run, &ctx.i18n());
    *ctx.run.lock().unwrap() = Some(run);
    ui.global::<AppState>().set_page(10);
}

// ---------------------------------------------------------------------------
// Wizard
// ---------------------------------------------------------------------------

fn reset_wizard(ui: &MainWindow) {
    let st = ui.global::<AppState>();
    st.set_wiz_step(0);
    st.set_wiz_error("".into());
    st.set_wiz_tags(data::rows(vec![]));
    st.set_wiz_tags_note("".into());
}

fn pick_folder() -> Option<String> {
    rfd::FileDialog::new().pick_folder().map(|p| p.display().to_string())
}

fn pick_file() -> Option<String> {
    rfd::FileDialog::new().pick_file().map(|p| p.display().to_string())
}

fn env_ids() -> [&'static str; 4] {
    ["auto", "appcontainer", "windows-sandbox", "host"]
}

/// Translate the wizard form into a verification request.
fn wizard_request(ui: &MainWindow, ctx: &Arc<Ctx>) -> Result<VerifyRequest, String> {
    let st = ui.global::<AppState>();
    let src = st.get_wiz_source();
    let t = |k: &str| ctx.t(k);
    let package_only = src == 2;
    let repo = st.get_wiz_repo().trim().to_string();
    if !package_only && repo.is_empty() {
        return Err(t("wiz.err.repo"));
    }
    if src == 1 && !request::path_exists(&repo) {
        return Err(t("wiz.err.repo-path"));
    }
    let tag = st.get_wiz_tag().trim().to_string();
    if !package_only && tag.is_empty() {
        return Err(t("wiz.err.tag"));
    }

    let mut only: Vec<String> = vec![];
    let mut add = |on: bool, names: &[&str]| {
        if on {
            only.extend(names.iter().map(|s| s.to_string()));
        }
    };
    add(st.get_wiz_source_check() && !package_only, &["source", "checksum"]);
    add(st.get_wiz_provenance(), &["provenance"]);
    add(st.get_wiz_signatures(), &["signature"]);
    add(st.get_wiz_sbom(), &["sbom"]);
    add(st.get_wiz_repro(), &["repro"]);
    add(st.get_wiz_docs() && !package_only, &["docs"]);
    add(st.get_wiz_install(), &["install", "uninstall"]);
    add(st.get_wiz_runtime(), &["launch"]);
    add(st.get_wiz_smoke(), &["smoke"]);
    if only.is_empty() {
        return Err(t("wiz.err.no-checks"));
    }

    let wants_ship = st.get_wiz_install() || st.get_wiz_runtime() || st.get_wiz_smoke();
    let package = st.get_wiz_package().trim().to_string();
    let shipcheck = if wants_ship {
        if package.is_empty() {
            return Err(t("wiz.err.package"));
        }
        let smoke_text = st.get_wiz_smoke_text().to_string();
        let opts = PackageOptions {
            package: Some(PathBuf::from(&package)),
            gui: st.get_wiz_gui(),
            smoke: if st.get_wiz_smoke() { smoke_text.lines().map(str::to_string).collect() } else { vec![] },
            environments: vec![env_ids()[st.get_wiz_env().clamp(0, 3) as usize].to_string()],
            launch: st.get_wiz_runtime() || st.get_wiz_smoke(),
            uninstall: st.get_wiz_install(),
            alive_secs: 5,
            ..Default::default()
        };
        let app = ctx.app.lock().unwrap();
        request::build_shipcheck_target(&opts, &app.config).map_err(|e| format!("{e:#}"))?
    } else {
        None
    };
    if st.get_wiz_smoke() && wants_ship && shipcheck.as_ref().is_some_and(|s| s.smoke.is_empty()) {
        return Err(t("wiz.err.smoke"));
    }

    let assets_text = st.get_wiz_assets().trim().to_string();
    let assets = if assets_text.is_empty() {
        vec![]
    } else {
        request::expand_assets(&[PathBuf::from(assets_text)]).map_err(|e| format!("{e:#}"))?
    };
    let rebuilt = Some(st.get_wiz_rebuilt().trim().to_string()).filter(|s| !s.is_empty()).map(PathBuf::from);
    if st.get_wiz_repro() && rebuilt.is_none() {
        return Err(t("wiz.err.rebuilt"));
    }
    Ok(VerifyRequest { project: None, repo: if package_only { None } else { Some(repo) }, tag, assets, rebuilt, shipcheck, only })
}

fn wizard_summary(ui: &MainWindow, ctx: &Arc<Ctx>) -> String {
    let st = ui.global::<AppState>();
    let src = match st.get_wiz_source() {
        0 => ctx.t("wiz.source.github"),
        1 => ctx.t("wiz.source.local"),
        _ => ctx.t("wiz.source.package"),
    };
    let mut l = vec![format!("{:<14}{}", ctx.t("wiz.step.source"), src)];
    if st.get_wiz_source() != 2 {
        l.push(format!("{:<14}{}", ctx.t("cli.repository"), st.get_wiz_repo()));
        l.push(format!("{:<14}{}", ctx.t("cli.release"), st.get_wiz_tag()));
    }
    let checks: Vec<String> = [
        (st.get_wiz_source_check() && st.get_wiz_source() != 2, "check.source.integrity"),
        (st.get_wiz_provenance(), "check.provenance"),
        (st.get_wiz_signatures(), "check.artifact.signature"),
        (st.get_wiz_sbom(), "check.sbom"),
        (st.get_wiz_repro(), "check.repro.rebuild"),
        (st.get_wiz_docs() && st.get_wiz_source() != 2, "check.docs"),
        (st.get_wiz_install(), "check.install.install"),
        (st.get_wiz_runtime(), "check.runtime.launch"),
        (st.get_wiz_smoke(), "check.runtime.smoke"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, k)| ctx.t(k))
    .collect();
    l.push(format!("{:<14}{}", ctx.t("wiz.step.checks"), checks.join(", ")));
    if st.get_wiz_install() || st.get_wiz_runtime() || st.get_wiz_smoke() {
        l.push(format!("{:<14}{}", ctx.t("wiz.step.environment"), env_ids()[st.get_wiz_env().clamp(0, 3) as usize]));
        l.push(format!("{:<14}{}", ctx.t("wiz.package.short"), st.get_wiz_package()));
    }
    l.join("\n")
}

fn update_step(ui: &MainWindow, i: usize, f: impl FnOnce(&mut LiveStep)) {
    let model = ui.global::<AppState>().get_live_steps();
    if let Some(vm) = model.as_any().downcast_ref::<VecModel<LiveStep>>() {
        if let Some(mut row) = vm.row_data(i) {
            f(&mut row);
            vm.set_row_data(i, row);
        }
    }
}

fn start_run(ui: &MainWindow, ctx: &Arc<Ctx>, req: VerifyRequest) {
    let st = ui.global::<AppState>();
    let i18n = ctx.i18n();
    let plan = match ctx.app.lock().unwrap().plan(&req) {
        Ok(p) => p,
        Err(e) => {
            st.set_wiz_error(format!("{e:#}").into());
            return;
        }
    };
    let title = format!(
        "{} {}",
        req.repo.clone().unwrap_or_else(|| req.shipcheck.as_ref().map(|s| s.package.display().to_string()).unwrap_or_default()),
        req.tag
    );
    st.set_live_title(title.into());
    st.set_live_steps(data::rows(
        plan.iter()
            .map(|p| LiveStep {
                title: check_title(&i18n, &p.id).into(),
                env: p.environment.clone().unwrap_or_default().into(),
                status: -1,
                message: "".into(),
            })
            .collect(),
    ));
    st.set_live_total(plan.len() as i32);
    st.set_live_done(0);
    st.set_live_message("".into());
    st.set_live_running(true);
    st.set_detail_id(0);
    st.set_page(12);

    let cancel = Arc::new(AtomicBool::new(false));
    *ctx.cancel.lock().unwrap() = Some(cancel.clone());
    let current = Arc::new(AtomicUsize::new(0));
    let weak = ui.as_weak();
    let sink_weak = weak.clone();
    let sink_i18n = i18n.clone();
    let sink_current = current.clone();
    let sink = move |e: &RunEvent| match e {
        RunEvent::StepStarted { index, .. } => {
            let i = index - 1;
            sink_current.store(i, Ordering::SeqCst);
            let _ = sink_weak.upgrade_in_event_loop(move |ui| update_step(ui_ref(&ui), i, |s| s.status = 0));
        }
        RunEvent::Progress { message, .. } => {
            let (i, m) = (sink_current.load(Ordering::SeqCst), message.clone());
            let _ = sink_weak.upgrade_in_event_loop(move |ui| update_step(ui_ref(&ui), i, |s| s.message = m.into()));
        }
        RunEvent::StepFinished { index, result, .. } => {
            let (i, status, summary) = (index - 1, view::status_int(result.status), result.summary_text(&sink_i18n));
            let done = *index as i32;
            let _ = sink_weak.upgrade_in_event_loop(move |ui| {
                update_step(ui_ref(&ui), i, |s| {
                    s.status = status;
                    s.message = summary.into();
                });
                ui.global::<AppState>().set_live_done(done);
            });
        }
        _ => {}
    };

    let (paths, ctx2) = (ctx.paths.clone(), ctx.clone());
    std::thread::spawn(move || {
        // A fresh App (own SQLite connection) for the worker; WAL mode makes this safe.
        let result = App::open(paths).and_then(|app| app.verify(req, Arc::new(sink), cancel));
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let st = ui.global::<AppState>();
            st.set_live_running(false);
            *ctx2.cancel.lock().unwrap() = None;
            match result {
                Ok(run) => {
                    st.set_detail_id(run.id as i32);
                    st.set_live_done(st.get_live_total());
                    let i18n = ctx2.i18n();
                    toast(
                        &ui,
                        &ctx2,
                        format!("{}  ·  {}", run.project_name, releaseverity_services::core::report::verdict_label(&i18n, run.verdict)),
                    );
                }
                Err(e) => st.set_live_message(format!("{e:#}").into()),
            }
        });
    });
}

/// `upgrade_in_event_loop` hands the closure a `MainWindow`; helper to pass it by reference.
fn ui_ref(ui: &MainWindow) -> &MainWindow {
    ui
}

// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let paths = Paths::discover();
    let app = App::open(paths.clone())?;
    let lang = app.config.general.language.clone();
    let dark = app.config.ui.theme != "light";
    let ctx = Arc::new(Ctx {
        app: Mutex::new(app),
        paths,
        i18n: Mutex::new(I18n::new(&lang)),
        run: Mutex::new(None),
        cancel: Mutex::new(None),
        toast_gen: AtomicU64::new(0),
    });

    let ui = MainWindow::new()?;
    set_theme(&ui, dark);
    let st = ui.global::<AppState>();
    st.set_version(SharedString::from(releaseverity_services::core::VERSION));
    st.set_data_dir(ctx.paths.root.display().to_string().into());
    {
        let ctx = ctx.clone();
        ui.global::<Tr>().on_translate(move |key, _rev| ctx.t(&key).into());
    }

    macro_rules! on {
        ($setter:ident, |$ui:ident, $ctxn:ident $(, $arg:ident)*| $body:block) => {{
            let weak = ui.as_weak();
            let $ctxn = ctx.clone();
            st.$setter(move |$($arg),*| {
                let Some($ui) = weak.upgrade() else { return };
                let _ = &$ctxn;
                $body
            });
        }};
    }

    on!(on_navigate, |ui, ctx, page| {
        go(&ui, &ctx, page);
    });
    on!(on_refresh, |ui, ctx| {
        go(&ui, &ctx, ui.global::<AppState>().get_page());
    });
    on!(on_open_run, |ui, ctx, id| {
        open_run(&ui, &ctx, id);
    });
    on!(on_select_check, |ui, ctx, idx| {
        let run = ctx.run.lock().unwrap().clone();
        if let Some(run) = run {
            data::fill_selected(&ui, &run, idx, &ctx.i18n());
        }
    });
    on!(on_open_repro, |ui, ctx, _id| {
        let run = ctx.run.lock().unwrap().clone();
        if let Some(run) = run {
            data::fill_repro_from_run(&ui, &run, &ctx.i18n());
            ui.global::<AppState>().set_page(13);
        }
    });
    on!(on_generate_report, |ui, ctx, id, fmt| {
        let result = Format::parse(&fmt).and_then(|f| ctx.app.lock().unwrap().generate_report(id as i64, f, None));
        match result {
            Ok(p) => {
                open_path(&p);
                toast(&ui, &ctx, ctx.i18n().tf("cli.report_written", &[("path", &p.display().to_string())]));
            }
            Err(e) => toast(&ui, &ctx, format!("{e:#}")),
        }
    });
    on!(on_open_report, |_ui, ctx, path| {
        open_path(Path::new(path.as_str()));
    });
    on!(on_open_folder, |_ui, ctx, which| {
        let p = match which.as_str() {
            "reports" => ctx.paths.reports_dir(),
            "logs" => ctx.paths.logs_dir(),
            _ => ctx.paths.root.clone(),
        };
        open_path(&p);
    });
    on!(on_copy_text, |ui, ctx, text| {
        copy_to_clipboard(text.as_str());
        toast(&ui, &ctx, ctx.t("toast.copied"));
    });

    // ---- projects ----------------------------------------------------------
    on!(on_project_browse, |ui, ctx| {
        if let Some(p) = pick_folder() {
            ui.global::<AppState>().set_proj_repo(p.into());
        }
    });
    on!(on_project_save, |ui, ctx| {
        let st = ui.global::<AppState>();
        let (name, repo, branch) =
            (st.get_proj_name().trim().to_string(), st.get_proj_repo().trim().to_string(), st.get_proj_branch().trim().to_string());
        let is_url = repo.starts_with("http://") || repo.starts_with("https://") || repo.starts_with("git@") || repo.starts_with("ssh://");
        let result = if name.is_empty() {
            Err(ctx.t("projects.err.name"))
        } else if repo.is_empty() {
            Err(ctx.t("projects.err.repo"))
        } else if !is_url && !releaseverity_services::repro::git::is_repo(Path::new(&repo)) {
            Err(ctx.i18n().tf("projects.err.not-git", &[("path", &repo)]))
        } else {
            let app = ctx.app.lock().unwrap();
            app.db
                .add_project(
                    &name,
                    is_url.then_some(repo.as_str()),
                    (!is_url).then_some(repo.as_str()),
                    if branch.is_empty() { "main" } else { &branch },
                )
                .map(|_| ())
                .map_err(|e| format!("{e:#}"))
        };
        match result {
            Ok(()) => {
                st.set_proj_error("".into());
                st.set_proj_form_open(false);
                st.set_proj_name("".into());
                st.set_proj_repo("".into());
                go(&ui, &ctx, 1);
            }
            Err(e) => st.set_proj_error(e.into()),
        }
    });
    on!(on_remove_project, |ui, ctx, name| {
        let _ = ctx.app.lock().unwrap().db.remove_project(&name);
        go(&ui, &ctx, 1);
    });
    on!(on_verify_project, |ui, ctx, name| {
        let project = ctx.app.lock().unwrap().db.find_project(&name).ok().flatten();
        if let Some(p) = project {
            let st = ui.global::<AppState>();
            reset_wizard(&ui);
            match (p.repo_url, p.local_path) {
                (Some(url), _) => {
                    st.set_wiz_source(0);
                    st.set_wiz_repo(url.into());
                }
                (None, Some(path)) => {
                    st.set_wiz_source(1);
                    st.set_wiz_repo(path.into());
                }
                _ => {}
            }
            st.set_wiz_step(1);
            st.set_page(12 - 1); // wizard
        }
    });

    // ---- wizard ------------------------------------------------------------
    on!(on_wiz_pick, |ui, ctx, what| {
        let st = ui.global::<AppState>();
        match what.as_str() {
            "repo" => {
                if let Some(p) = pick_folder() {
                    st.set_wiz_repo(p.into())
                }
            }
            "package" => {
                if let Some(p) = pick_file() {
                    st.set_wiz_package(p.into())
                }
            }
            "assets" => {
                if let Some(p) = pick_folder() {
                    st.set_wiz_assets(p.into())
                }
            }
            "rebuilt" => {
                if let Some(p) = pick_file() {
                    st.set_wiz_rebuilt(p.into())
                }
            }
            _ => {}
        }
    });
    on!(on_wiz_load_tags, |ui, ctx| {
        let st = ui.global::<AppState>();
        let source = st.get_wiz_repo().trim().to_string();
        if source.is_empty() {
            return st.set_wiz_tags_note(ctx.t("wiz.err.repo").into());
        }
        st.set_wiz_tags_note(ctx.t("wiz.release.loading").into());
        let ctx2 = ctx.clone();
        bg(
            &ui,
            move || App::tags_of(&source).map_err(|e| format!("{e:#}")),
            move |ui, res| {
                let st = ui.global::<AppState>();
                match res {
                    Ok(tags) => {
                        st.set_wiz_tags_note(if tags.is_empty() { ctx2.t("wiz.release.none") } else { String::new() }.into());
                        if st.get_wiz_tag().is_empty() {
                            if let Some(t) = tags.first() {
                                st.set_wiz_tag(t.clone().into());
                            }
                        }
                        st.set_wiz_tags(data::rows(tags.into_iter().map(SharedString::from).collect()));
                    }
                    Err(e) => st.set_wiz_tags_note(e.into()),
                }
            },
        );
    });
    on!(on_wiz_next, |ui, ctx| {
        let st = ui.global::<AppState>();
        let step = st.get_wiz_step();
        let t = |k: &str| ctx.t(k);
        let err = match step {
            0 if st.get_wiz_source() != 2 && st.get_wiz_repo().trim().is_empty() => Some(t("wiz.err.repo")),
            0 if st.get_wiz_source() == 1 && !request::path_exists(&st.get_wiz_repo()) => Some(t("wiz.err.repo-path")),
            0 if st.get_wiz_source() == 2 && st.get_wiz_package().trim().is_empty() => Some(t("wiz.err.package")),
            1 if st.get_wiz_source() != 2 && st.get_wiz_tag().trim().is_empty() => Some(t("wiz.err.tag")),
            _ => None,
        };
        match err {
            Some(e) => st.set_wiz_error(e.into()),
            None => {
                st.set_wiz_error("".into());
                st.set_wiz_step(step + 1);
                if step + 1 == 3 {
                    let note = if st.get_wiz_env() == 3 { t("wiz.env.host.warn") } else { String::new() };
                    st.set_wiz_env_note(note.into());
                }
                if step + 1 == 4 {
                    st.set_wiz_summary(wizard_summary(&ui, &ctx).into());
                }
            }
        }
    });
    on!(on_wiz_start, |ui, ctx| {
        match wizard_request(&ui, &ctx) {
            Ok(req) => {
                ui.global::<AppState>().set_wiz_error("".into());
                start_run(&ui, &ctx, req);
            }
            Err(e) => ui.global::<AppState>().set_wiz_error(e.into()),
        }
    });
    on!(on_wiz_reset, |ui, ctx| {
        reset_wizard(&ui);
    });
    on!(on_live_cancel, |_ui, ctx| {
        if let Some(c) = ctx.cancel.lock().unwrap().as_ref() {
            c.store(true, Ordering::SeqCst);
        }
    });

    // ---- reproducibility ------------------------------------------------------
    on!(on_pick_file, |ui, ctx, which| {
        if let Some(p) = pick_file() {
            let st = ui.global::<AppState>();
            if which.as_str() == "release" {
                st.set_repro_release(p.into())
            } else {
                st.set_repro_local(p.into())
            }
        }
    });
    on!(on_repro_compare, |ui, ctx| {
        let st = ui.global::<AppState>();
        let (a, b) = (PathBuf::from(st.get_repro_release().trim()), PathBuf::from(st.get_repro_local().trim()));
        st.set_repro_busy(true);
        st.set_repro_message("".into());
        let ctx2 = ctx.clone();
        bg(
            &ui,
            move || -> Result<(String, String, Option<releaseverity_services::repro::diff::DiffReport>), String> {
                let ha = releaseverity_services::core::hash::hash_file(&a).map_err(|e| format!("{}: {e}", a.display()))?;
                let hb = releaseverity_services::core::hash::hash_file(&b).map_err(|e| format!("{}: {e}", b.display()))?;
                let rep = if ha.sha256 == hb.sha256 {
                    None
                } else {
                    Some(releaseverity_services::repro::diff::compare(&a, &b).map_err(|e| format!("{e:#}"))?)
                };
                Ok((ha.sha256, hb.sha256, rep))
            },
            move |ui, res| {
                let st = ui.global::<AppState>();
                let i18n = ctx2.i18n();
                data::clear_repro(ui);
                st.set_repro_busy(false);
                match res {
                    Err(e) => {
                        st.set_repro_result(5);
                        st.set_repro_result_text(i18n.t("result.error").into());
                        st.set_repro_message(e.into());
                    }
                    Ok((ha, hb, rep)) => {
                        let same = rep.is_none();
                        st.set_repro_release_hash(ha.clone().into());
                        st.set_repro_local_hash(hb.into());
                        st.set_repro_result(if same { 1 } else { 3 });
                        st.set_repro_result_text(
                            i18n.t(if same { "repro.result.reproducible" } else { "repro.result.not_reproducible" }).into(),
                        );
                        st.set_pipe_status(data::rows(vec![4, 4, 4, 4, if same { 1 } else { 3 }]));
                        st.set_pipe_text(data::rows(vec![
                            SharedString::from("–"),
                            SharedString::from("–"),
                            SharedString::from(i18n.t("repro.pipe.env")),
                            SharedString::from(i18n.t("repro.pipe.build")),
                            SharedString::from(ha.chars().take(14).collect::<String>()),
                        ]));
                        if let Some(r) = rep {
                            let ev = serde_json::json!({ "diff": r });
                            data::fill_repro_diff(ui, &ev, &i18n);
                            st.set_repro_message(
                                i18n.tf("repro.diff-summary", &[("bytes", &r.total_diff_bytes.to_string()), ("kind", &r.kind)]).into(),
                            );
                        }
                    }
                }
            },
        );
    });

    // ---- settings --------------------------------------------------------------
    on!(on_refresh_settings, |ui, ctx| {
        load_settings(&ui, &ctx);
    });
    on!(on_gh_connect, |ui, ctx| {
        let st = ui.global::<AppState>();
        let token = st.get_gh_token().to_string();
        st.set_gh_busy(true);
        let (paths, ctx2) = (ctx.paths.clone(), ctx.clone());
        bg(
            &ui,
            move || App::open(paths).and_then(|a| a.github_connect(&token)).map_err(|e| format!("{e:#}")),
            move |ui, res| {
                let st = ui.global::<AppState>();
                st.set_gh_busy(false);
                match res {
                    Ok(login) => {
                        st.set_gh_token("".into());
                        st.set_gh_connected(true);
                        st.set_gh_status(ctx2.i18n().tf("gh.status.connected", &[("login", &login)]).into());
                        toast(ui, &ctx2, ctx2.t("gh.connected-toast"));
                    }
                    Err(e) => st.set_gh_status(e.into()),
                }
            },
        );
    });
    on!(on_gh_disconnect, |ui, ctx| {
        let r = ctx.app.lock().unwrap().github_disconnect();
        match r {
            Ok(_) => {
                let st = ui.global::<AppState>();
                st.set_gh_connected(false);
                st.set_gh_status(ctx.t("gh.status.none").into());
                toast(&ui, &ctx, ctx.t("gh.disconnected-toast"));
            }
            Err(e) => toast(&ui, &ctx, format!("{e:#}")),
        }
    });
    on!(on_setting_changed, |ui, ctx, key, shown| {
        let i18n = ctx.i18n();
        let stored = settings::to_stored(&key, &shown, &i18n);
        let result = {
            let mut app = ctx.app.lock().unwrap();
            app.config.set(&key, &stored).map_err(|e| format!("{e:#}")).and_then(|_| app.save_config().map_err(|e| format!("{e:#}")))
        };
        match result {
            Ok(()) => {
                match key.as_str() {
                    "ui.theme" => set_theme(&ui, stored == "dark"),
                    "general.language" => {
                        *ctx.i18n.lock().unwrap() = I18n::new(&stored);
                        let tr = ui.global::<Tr>();
                        tr.set_rev(tr.get_rev() + 1);
                    }
                    _ => {}
                }
                load_settings(&ui, &ctx);
                toast(&ui, &ctx, ctx.t("toast.saved"));
            }
            Err(e) => {
                // Revert the displayed value to what is actually stored.
                load_settings(&ui, &ctx);
                toast(&ui, &ctx, e);
            }
        }
    });

    go(&ui, &ctx, 0);

    // Developer/CI options: `--page N`, `--run ID`, `--lang xx`, `--theme dark|light`,
    // `--size WxH`, `--screenshot out.png` (renders the real UI to a PNG and exits).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    if let Some(l) = opt("--lang") {
        *ctx.i18n.lock().unwrap() = I18n::new(&l);
        let tr = ui.global::<Tr>();
        tr.set_rev(tr.get_rev() + 1);
    }
    if let Some(t) = opt("--theme") {
        set_theme(&ui, t != "light");
    }
    if let Some(id) = opt("--run").and_then(|p| p.parse::<i32>().ok()) {
        open_run(&ui, &ctx, id);
        if args.iter().any(|a| a == "--repro") {
            let run = ctx.run.lock().unwrap().clone();
            if let Some(run) = run {
                data::fill_repro_from_run(&ui, &run, &ctx.i18n());
                ui.global::<AppState>().set_page(13);
            }
        }
    }
    if let Some(sec) = opt("--settings-section").and_then(|p| p.parse::<i32>().ok()) {
        ui.global::<AppState>().set_settings_section(sec);
    }
    if let Some(p) = opt("--page").and_then(|p| p.parse::<i32>().ok()) {
        go(&ui, &ctx, p);
    }
    // Developer aid: start a package-only ShipCheck run immediately (exercises the live screen).
    if let Some(pkg) = opt("--start-package") {
        let opts = PackageOptions {
            package: Some(PathBuf::from(pkg)),
            smoke: opt("--smoke").map(|s| vec![s]).unwrap_or_default(),
            environments: vec!["auto".into()],
            launch: true,
            uninstall: true,
            ..Default::default()
        };
        let target = request::build_shipcheck_target(&opts, &ctx.app.lock().unwrap().config);
        if let Ok(shipcheck) = target {
            let only = ["install", "launch", "smoke", "uninstall"].map(String::from).to_vec();
            start_run(&ui, &ctx, VerifyRequest { shipcheck, only, ..Default::default() });
        }
    }
    if let Some(v) = opt("--wizard-step").and_then(|p| p.parse::<i32>().ok()) {
        let st = ui.global::<AppState>();
        st.set_wiz_step(v);
        if v == 4 {
            st.set_wiz_summary(wizard_summary(&ui, &ctx).into());
        }
    }
    if let Some((w, h)) = opt("--size")
        .and_then(|s| s.split_once('x').map(|(a, b)| (a.parse::<f32>().ok(), b.parse::<f32>().ok())))
        .and_then(|(a, b)| a.zip(b))
    {
        ui.window().set_size(slint::LogicalSize::new(w, h));
    }
    if let Some(path) = opt("--screenshot") {
        ui.show()?;
        let weak = ui.as_weak();
        let delay = opt("--screenshot-delay").and_then(|d| d.parse::<u64>().ok()).unwrap_or(1500);
        slint::Timer::single_shot(std::time::Duration::from_millis(delay), move || {
            if let Some(ui) = weak.upgrade() {
                match ui.window().take_snapshot() {
                    Ok(buf) => {
                        if let Err(e) = write_png(&path, &buf) {
                            eprintln!("screenshot failed: {e}");
                        }
                    }
                    Err(e) => eprintln!("screenshot failed: {e}"),
                }
            }
            let _ = slint::quit_event_loop();
        });
        slint::run_event_loop()?;
        return Ok(());
    }
    ui.run()?;
    Ok(())
}

fn write_png(path: &str, buf: &slint::SharedPixelBuffer<slint::Rgba8Pixel>) -> Result<()> {
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut enc = png::Encoder::new(file, buf.width(), buf.height());
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut w = enc.write_header()?;
    w.write_image_data(buf.as_bytes())?;
    Ok(())
}

#[allow(dead_code)]
fn _status_marker(_: Status) {}
