//! Real end-to-end ShipCheck runs through the host runner: the real agent binary,
//! real process execution inside Job Objects, real exit codes. Windows only.
#![cfg(windows)]

use releaseverity_core::check::{run_checks, Context, ShipKind, ShipcheckTarget, SmokeSpec, VerifyTarget};
use releaseverity_core::config::Config;
use releaseverity_core::logging::Logger;
use releaseverity_core::model::{CheckResult, FailureKind, Status};
use std::path::{Path, PathBuf};
use std::sync::Once;

static BUILD: Once = Once::new();

fn agent() -> PathBuf {
    BUILD.call_once(|| {
        let st = std::process::Command::new(env!("CARGO")).args(["build", "-p", "releaseverity-agent", "--quiet"]).status().unwrap();
        assert!(st.success());
    });
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/releaseverity-agent.exe");
    let root = root.canonicalize().expect("agent built");
    std::env::set_var("RELEASEVERITY_AGENT", &root);
    root
}

/// A "portable app": a directory whose app.exe is a real copy of cmd.exe, so every launch
/// argument set produces a genuinely different real-process behaviour.
fn portable_dir(d: &Path) -> PathBuf {
    let dir = d.join("pkg");
    std::fs::create_dir_all(&dir).unwrap();
    let sys = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32\\cmd.exe");
    std::fs::copy(sys, dir.join("app.exe")).unwrap();
    dir
}

fn smoke(name: &str, args: &[&str], expect_exit: i32, out: Option<&str>) -> SmokeSpec {
    SmokeSpec {
        name: name.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        expect_exit,
        expect_stdout: out.map(Into::into),
        timeout_secs: None,
    }
}

fn target(package: PathBuf, launch: &[&str], smokes: Vec<SmokeSpec>, allow: bool) -> (Config, ShipcheckTarget) {
    let mut cfg = Config::default();
    cfg.security.allow_host_execution = allow;
    cfg.timeouts.launch_secs = 3;
    cfg.timeouts.smoke_secs = 10;
    cfg.timeouts.cleanup_secs = 10;
    let t = ShipcheckTarget {
        kind: ShipKind::Portable,
        package,
        installer_args: vec![],
        exe: Some("app.exe".into()),
        launch_args: launch.iter().map(|s| s.to_string()).collect(),
        gui: false,
        launch: true,
        alive_secs: 2,
        smoke: smokes,
        environments: vec!["host".into()],
        uninstall: true,
    };
    (cfg, t)
}

fn run(cfg: Config, t: ShipcheckTarget) -> Vec<CheckResult> {
    agent();
    let work = tempfile::tempdir().unwrap();
    let vt = VerifyTarget { shipcheck: Some(t.clone()), ..Default::default() };
    let mut ctx = Context::new(cfg, vt, work.path().to_path_buf(), Logger::null());
    run_checks(&releaseverity_shipcheck::checks(&t), &mut ctx).results
}

fn by<'a>(r: &'a [CheckResult], id: &str) -> &'a CheckResult {
    r.iter().find(|x| x.id == id).unwrap_or_else(|| panic!("missing {id}"))
}

#[test]
fn healthy_portable_app_installs_launches_smokes_and_cleans_up() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, t) = target(
        portable_dir(d.path()),
        &["/C", "echo", "started"],
        vec![smoke("prints", &["/C", "echo", "hello-world"], 0, Some("hello-world")), smoke("custom-exit", &["/C", "exit", "5"], 5, None)],
        true,
    );
    let r = run(cfg, t);
    assert_eq!(by(&r, "install.install").status, Status::Pass, "{:?}", by(&r, "install.install"));
    let launch = by(&r, "runtime.launch");
    assert_eq!(launch.status, Status::Pass, "{launch:?}");
    assert_eq!(launch.environment.as_deref(), Some("host"));
    assert!(launch.details.as_deref().unwrap().contains("started"), "real stdout captured");
    let sm = by(&r, "runtime.smoke");
    assert_eq!((sm.status, sm.summary.as_str()), (Status::Pass, "2/2 smoke tests passed"));
    assert_eq!(by(&r, "install.uninstall").status, Status::Pass);
}

#[test]
fn crash_exit_code_is_classified_as_a_crash() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, t) = target(portable_dir(d.path()), &["/C", "exit", "-1073741819"], vec![], true);
    let r = run(cfg, t);
    let l = by(&r, "runtime.launch");
    assert_eq!(l.status, Status::Fail);
    assert_eq!(l.failure_kind, Some(FailureKind::Crashed));
    assert!(l.summary.contains("APPLICATION CRASHED") && l.summary.contains("C0000005"), "{}", l.summary);
    assert_eq!(by(&r, "runtime.smoke").status, Status::Skipped, "no smoke tests were defined");
}

#[test]
fn a_run_that_never_ends_is_a_timeout_and_the_process_tree_is_killed() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, t) = target(portable_dir(d.path()), &["/C", "ping -n 60 127.0.0.1 >nul"], vec![], true);
    let t0 = std::time::Instant::now();
    let r = run(cfg, t);
    let l = by(&r, "runtime.launch");
    assert_eq!(l.failure_kind, Some(FailureKind::Timeout), "{l:?}");
    assert!(l.summary.contains("TEST TIMEOUT"));
    assert!(t0.elapsed().as_secs() < 25, "must not run for the ping's full minute");
    assert_eq!(by(&r, "install.uninstall").status, Status::Pass, "files released after the tree was killed");
}

#[test]
fn smoke_failures_report_exit_code_and_output_mismatches() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, t) = target(
        portable_dir(d.path()),
        &["/C", "exit", "0"],
        vec![smoke("bad-exit", &["/C", "exit", "3"], 0, None), smoke("bad-output", &["/C", "echo", "abc"], 0, Some("zzz"))],
        true,
    );
    let r = run(cfg, t);
    let s = by(&r, "runtime.smoke");
    assert_eq!(s.status, Status::Fail);
    assert!(s.summary.starts_with("0/2"), "{}", s.summary);
    let d = s.details.as_deref().unwrap();
    assert!(d.contains("exit code 3, expected 0") && d.contains("does not contain"), "{d}");
}

#[test]
fn zip_packages_are_extracted_and_run() {
    use std::io::Write;
    let d = tempfile::tempdir().unwrap();
    let zip_path = d.path().join("app.zip");
    let mut z = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
    z.start_file("bin/app.exe", zip::write::SimpleFileOptions::default()).unwrap();
    z.write_all(&std::fs::read(PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32\\cmd.exe")).unwrap()).unwrap();
    z.finish().unwrap();
    let (cfg, t) = target(zip_path, &["/C", "exit", "0"], vec![], true);
    let r = run(cfg, t);
    assert_eq!(by(&r, "install.install").status, Status::Pass, "{:?}", by(&r, "install.install"));
    assert_eq!(by(&r, "runtime.launch").status, Status::Pass);
}

#[test]
fn host_execution_is_refused_unless_explicitly_allowed() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, t) = target(portable_dir(d.path()), &["/C", "exit", "0"], vec![], false);
    let r = run(cfg, t);
    for id in ["install.install", "runtime.launch", "install.uninstall"] {
        let c = by(&r, id);
        assert_eq!(c.status, Status::Error, "{id}");
        assert!(c.summary.contains("host execution is disabled"));
        assert!(c.suggestion.as_deref().unwrap().contains("windows-sandbox"));
    }
}

// ---------------------------------------------------------------------------
// ReleaseVerity's own sandbox (AppContainer)
// ---------------------------------------------------------------------------

#[test]
fn auto_picks_the_builtin_sandbox_for_portable_packages_and_it_really_isolates() {
    let d = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let probe = outside.path().join("escaped.txt");
    let (cfg, mut t) = target(
        portable_dir(d.path()),
        &["/C", "echo", "started"],
        vec![
            smoke("prints", &["/C", "echo", "hello-from-sandbox"], 0, Some("hello-from-sandbox")),
            // Exit code 1 == the OS denied the write. A host run would exit 0.
            smoke("cannot-write-outside", &["/C", &format!("echo x> {}", probe.display())], 1, None),
        ],
        false, // host execution NOT allowed: the sandbox must not need that opt-in
    );
    t.environments = vec!["auto".into()];
    let r = run(cfg, t);
    let launch = by(&r, "runtime.launch");
    assert_eq!(launch.environment.as_deref(), Some("appcontainer"), "auto → appcontainer for portable");
    assert_eq!(launch.status, Status::Pass, "{launch:?}");
    assert_eq!(launch.evidence["isolation"], "appcontainer");
    let sm = by(&r, "runtime.smoke");
    assert_eq!(sm.status, Status::Pass, "{sm:?}");
    assert!(!probe.exists(), "the sandboxed app must not be able to write outside its sandbox");
    assert_eq!(by(&r, "install.uninstall").status, Status::Pass);
}

#[test]
fn the_builtin_sandbox_refuses_installers_with_a_clear_reason() {
    let d = tempfile::tempdir().unwrap();
    let setup = d.path().join("setup.exe");
    std::fs::write(&setup, b"MZ not a real installer").unwrap();
    let (cfg, mut t) = target(setup, &[], vec![], false);
    t.kind = ShipKind::Installer;
    t.environments = vec!["appcontainer".into()];
    let r = run(cfg, t);
    let c = by(&r, "install.install");
    assert_eq!(c.status, Status::Error);
    assert!(c.summary.contains("portable packages only"), "{}", c.summary);
    assert!(c.suggestion.as_deref().unwrap().contains("windows-sandbox"));
}

// ---------------------------------------------------------------------------
// Real crashing / hanging / healthy GUI fixtures (crates/releaseverity-agent/examples)
// ---------------------------------------------------------------------------

fn fixture(name: &str) -> PathBuf {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let st = std::process::Command::new(env!("CARGO"))
            .args(["build", "-p", "releaseverity-agent", "--examples", "--quiet"])
            .status()
            .unwrap();
        assert!(st.success());
    });
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../target/debug/examples/{name}.exe")).canonicalize().expect("fixture built")
}

fn fixture_package(d: &Path, name: &str) -> PathBuf {
    let dir = d.join("pkg");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(fixture(name), dir.join("app.exe")).unwrap();
    dir
}

#[test]
fn a_really_crashing_app_is_reported_as_application_crashed() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, t) = target(fixture_package(d.path(), "crash_app"), &[], vec![], true);
    let r = run(cfg, t);
    let l = by(&r, "runtime.launch");
    assert_eq!(l.failure_kind, Some(FailureKind::Crashed), "{l:?}");
    assert!(l.summary.contains("APPLICATION CRASHED") && l.summary.contains("0xC0000409"), "{}", l.summary);
}

#[test]
fn a_gui_that_stops_pumping_messages_is_reported_as_application_hung() {
    let d = tempfile::tempdir().unwrap();
    let (mut cfg, mut t) = target(fixture_package(d.path(), "hang_app"), &[], vec![], false);
    cfg.timeouts.launch_secs = 25;
    t.gui = true;
    t.alive_secs = 20;
    t.environments = vec!["appcontainer".into()];
    let r = run(cfg, t);
    let l = by(&r, "runtime.launch");
    assert_eq!(l.status, Status::Fail, "{l:?}");
    assert_eq!(l.failure_kind, Some(FailureKind::Hung), "{l:?}");
    assert!(l.summary.contains("APPLICATION HUNG"), "{}", l.summary);
}

#[test]
fn a_healthy_gui_stays_alive_responsive_and_is_terminated_cleanly() {
    let d = tempfile::tempdir().unwrap();
    let (mut cfg, mut t) = target(fixture_package(d.path(), "gui_ok"), &[], vec![], false);
    cfg.timeouts.launch_secs = 20;
    t.gui = true;
    t.alive_secs = 4;
    t.environments = vec!["appcontainer".into()];
    let r = run(cfg, t);
    let l = by(&r, "runtime.launch");
    assert_eq!(l.status, Status::Pass, "{l:?}");
    assert!(l.summary.contains("responsive") && l.summary.contains("window"), "{}", l.summary);
    assert_eq!(by(&r, "install.uninstall").status, Status::Pass, "the GUI process tree was terminated so its files could be removed");
}
