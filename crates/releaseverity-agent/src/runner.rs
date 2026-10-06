//! The agent's plan: install → discover → launch → smoke → uninstall, executed for real.
//! Every step records what was actually observed; nothing is assumed.

use crate::ac::Container;
use crate::winproc::{run_limited, run_supervised, Limits, Mode, Outcome};
use crate::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use winreg::enums::*;
use winreg::RegKey;

const DEFAULT_INNO_ARGS: [&str; 4] = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"];

pub fn crash_like(code: i32) -> bool {
    (code as u32) & 0xF000_0000 == 0xC000_0000
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n.max(1))
}

// ---------------------------------------------------------------------------
// registry / filesystem discovery
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UninstallEntry {
    pub key: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub location: String,
    pub uninstall: String,
    pub quiet_uninstall: String,
    pub icon: String,
}

pub fn read_uninstall_entries() -> Vec<UninstallEntry> {
    let roots = [
        (HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, "HKLM32", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_CURRENT_USER, "HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ];
    let mut out = vec![];
    for (hive, label, path) in roots {
        let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ) else { continue };
        for sub in root.enum_keys().flatten() {
            let Ok(k) = root.open_subkey_with_flags(&sub, KEY_READ) else { continue };
            let g = |n: &str| k.get_value::<String, _>(n).unwrap_or_default();
            let name = g("DisplayName");
            if name.is_empty() {
                continue;
            }
            out.push(UninstallEntry {
                key: format!("{label}\\{sub}"),
                name,
                version: g("DisplayVersion"),
                publisher: g("Publisher"),
                location: g("InstallLocation"),
                uninstall: g("UninstallString"),
                quiet_uninstall: g("QuietUninstallString"),
                icon: g("DisplayIcon"),
            });
        }
    }
    out
}

fn program_dirs() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .chain(std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Programs")))
        .collect()
}

fn snapshot_dirs() -> BTreeSet<PathBuf> {
    let mut s = BTreeSet::new();
    for d in program_dirs() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            s.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
    }
    s
}

fn start_menu_roots() -> Vec<PathBuf> {
    let mut v = vec![];
    if let Some(p) = std::env::var_os("ProgramData") {
        v.push(PathBuf::from(p).join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    if let Some(p) = std::env::var_os("APPDATA") {
        v.push(PathBuf::from(p).join(r"Microsoft\Windows\Start Menu\Programs"));
    }
    v
}

fn find_files(dir: &Path, ext: &str, depth: u32, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if depth > 0 {
                find_files(&p, ext, depth - 1, out);
            }
        } else if p.extension().map(|x| x.eq_ignore_ascii_case(ext)).unwrap_or(false) {
            out.push(p);
        }
    }
}

fn snapshot_shortcuts() -> BTreeSet<PathBuf> {
    let mut v = vec![];
    for r in start_menu_roots() {
        find_files(&r, "lnk", 3, &mut v);
    }
    v.into_iter().collect()
}

fn icon_path(icon: &str) -> Option<PathBuf> {
    let p = icon.trim().trim_matches('"');
    let p = p.rsplit_once(',').filter(|(_, n)| n.trim().parse::<i32>().is_ok()).map(|(a, _)| a).unwrap_or(p);
    let pb = PathBuf::from(p.trim_matches('"'));
    pb.is_file().then_some(pb)
}

/// Pick the application's main executable inside `dir`.
pub fn locate_exe(dir: &Path, wanted: Option<&str>, icon: Option<&str>) -> Option<PathBuf> {
    let mut exes = vec![];
    find_files(dir, "exe", 3, &mut exes);
    if let Some(w) = wanted {
        let w = w.replace('/', "\\").to_ascii_lowercase();
        if let Some(p) = exes.iter().find(|p| {
            let s = p.to_string_lossy().to_ascii_lowercase();
            s.ends_with(&w) && (s.len() == w.len() || s[..s.len() - w.len()].ends_with('\\'))
        }) {
            return Some(p.clone());
        }
    }
    if let Some(p) = icon.and_then(icon_path) {
        if p.starts_with(dir) && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
            return Some(p);
        }
    }
    let skip = |p: &PathBuf| {
        let n = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        n.starts_with("unins") || n.contains("uninstall") || n.starts_with("vc_redist") || n.starts_with("setup")
    };
    exes.into_iter().filter(|p| !skip(p)).max_by_key(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
}

// ---------------------------------------------------------------------------
// agent
// ---------------------------------------------------------------------------

pub struct Agent<'a> {
    spec: &'a Spec,
    out_dir: &'a Path,
    work: PathBuf,
    container: Option<Container>,
    pub steps: Vec<StepReport>,
}

struct Found {
    dir: PathBuf,
    exe: PathBuf,
    entry: Option<UninstallEntry>,
}

impl<'a> Agent<'a> {
    pub fn new(spec: &'a Spec, out_dir: &'a Path, work: PathBuf) -> Self {
        Self { spec, out_dir, work, container: None, steps: vec![] }
    }

    fn limits(&self) -> Limits {
        Limits { memory_mb: self.spec.max_memory_mb, max_processes: self.spec.max_processes }
    }

    fn append(&self, line: &ProgressLine) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(self.out_dir.join(PROGRESS_FILE)) {
            let _ = writeln!(f, "{}", serde_json::to_string(line).unwrap_or_default());
            let _ = f.flush();
        }
    }

    fn start(&self, id: &str, note: &str) {
        self.append(&ProgressLine::Start { id: id.into(), note: note.into() });
    }

    fn end(&mut self, step: StepReport) {
        self.append(&ProgressLine::End { step: step.clone() });
        self.steps.push(step);
    }

    fn skipped(&mut self, id: &str, why: &str) {
        self.end(StepReport {
            id: id.into(),
            status: StepStatus::Skipped,
            fail_kind: None,
            exit_code: None,
            duration_ms: 0,
            message: why.into(),
            log: String::new(),
            facts: Value::Null,
        });
    }

    pub fn run(mut self) -> Vec<StepReport> {
        let _ = std::fs::create_dir_all(&self.work);
        if self.spec.isolation == Isolation::AppContainer {
            if self.spec.kind == PackageKind::Installer {
                self.start("install", "checking isolation");
                self.end(StepReport {
                    id: "install".into(),
                    status: StepStatus::Fail,
                    fail_kind: Some(FailKind::Other),
                    exit_code: None,
                    duration_ms: 0,
                    message: "installers cannot run inside an AppContainer: they must write Program Files and HKLM".into(),
                    log: String::new(),
                    facts: json!({ "isolation": "appcontainer" }),
                });
                for id in ["launch", "uninstall"] {
                    self.skipped(id, "nothing was installed");
                }
                return self.steps;
            }
            match Container::create(&format!("ReleaseVerity.Sandbox.{}", std::process::id())) {
                Ok(c) => self.container = Some(c),
                Err(e) => {
                    self.start("install", "creating the isolated environment");
                    self.end(StepReport {
                        id: "install".into(),
                        status: StepStatus::Fail,
                        fail_kind: Some(FailKind::Other),
                        exit_code: None,
                        duration_ms: 0,
                        message: format!("could not create the AppContainer sandbox: {e}"),
                        log: String::new(),
                        facts: Value::Null,
                    });
                    return self.steps;
                }
            }
        }
        let found = match self.spec.kind {
            PackageKind::Installer => self.installer_phase(),
            PackageKind::Portable => self.portable_phase(),
        };
        let Some(found) = found else {
            self.skipped("launch", "no installed application to run");
            for s in self.spec.smoke.clone() {
                self.skipped(&format!("smoke:{}", s.name), "no installed application to run");
            }
            if self.spec.uninstall {
                self.skipped("uninstall", "nothing was installed");
            }
            return self.steps;
        };
        if self.spec.launch {
            self.launch(&found);
        } else {
            self.skipped("launch", "launch test not requested");
        }
        for s in self.spec.smoke.clone() {
            self.smoke(&found, &s);
        }
        if self.spec.uninstall {
            match self.spec.kind {
                PackageKind::Installer => self.uninstall(&found),
                PackageKind::Portable => self.cleanup_portable(&found),
            }
        } else {
            self.skipped("uninstall", "disabled by configuration");
        }
        self.steps
    }

    // ---- installer ------------------------------------------------------

    fn installer_phase(&mut self) -> Option<Found> {
        let before_entries: BTreeSet<_> = read_uninstall_entries().into_iter().map(|e| e.key).collect();
        let before_dirs = snapshot_dirs();
        let before_lnk = snapshot_shortcuts();
        let pkg = PathBuf::from(&self.spec.package);
        self.start("install", &format!("running {}", pkg.file_name().unwrap_or_default().to_string_lossy()));
        let t = Instant::now();

        let is_msi = pkg.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi"));
        let msi_log = self.work.join("msi-install.log");
        let (mut cmd, tool) = if is_msi {
            let mut c = Command::new("msiexec");
            c.arg("/i").arg(&pkg);
            if self.spec.installer_args.is_empty() {
                c.args(["/qn", "/norestart"]).arg("/l*v").arg(&msi_log);
            } else {
                c.args(&self.spec.installer_args);
            }
            (c, "msiexec")
        } else {
            let mut c = Command::new(&pkg);
            if self.spec.installer_args.is_empty() {
                c.args(DEFAULT_INNO_ARGS);
            } else {
                c.args(&self.spec.installer_args);
            }
            (c, "installer")
        };
        cmd.current_dir(&self.work);
        let res = run_limited(cmd, secs(self.spec.install_timeout_secs), self.limits(), Mode::RunToExit);
        let mut step = self.step_from_result("install", res, t, true);
        if is_msi && msi_log.exists() {
            if let Ok(b) = std::fs::read(&msi_log) {
                // msiexec writes UTF-16LE; fall back to lossy UTF-8.
                let text = if b.len() > 2 && b[1] == 0 {
                    String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
                } else {
                    String::from_utf8_lossy(&b).into_owned()
                };
                step.log = truncate_tail(&format!("{}\n--- msi log ---\n{}", step.log, text), MAX_LOG_BYTES);
            }
        }
        if let Some(c) = step.exit_code {
            if step.status == StepStatus::Fail && step.fail_kind == Some(FailKind::ExitCode) {
                step.message = format!("{tool} returned exit code {c}: {}", exit_code_hint(c, is_msi));
            } else if c == 3010 {
                step.status = StepStatus::Pass;
                step.message = "installed (a reboot is required to finish)".into();
            }
        }
        let install_ok = matches!(step.status, StepStatus::Pass | StepStatus::Warn);
        self.end(step);
        if !install_ok {
            return None;
        }

        // Discover what the installer actually did.
        self.start("files", "inspecting installed files and registry entries");
        let t = Instant::now();
        let new_entries: Vec<_> = read_uninstall_entries().into_iter().filter(|e| !before_entries.contains(&e.key)).collect();
        let new_dirs: Vec<_> = snapshot_dirs().difference(&before_dirs).cloned().collect();
        let new_lnk: Vec<_> = snapshot_shortcuts().difference(&before_lnk).cloned().collect();
        let entry = new_entries.first().cloned();
        let dir = entry
            .as_ref()
            .map(|e| e.location.trim_matches('"').to_string())
            .filter(|l| !l.is_empty() && Path::new(l).is_dir())
            .map(PathBuf::from)
            .or_else(|| entry.as_ref().and_then(|e| icon_path(&e.icon)).and_then(|p| p.parent().map(Path::to_path_buf)))
            .or_else(|| new_dirs.first().cloned());
        let exe = dir.as_ref().and_then(|d| locate_exe(d, self.spec.exe.as_deref(), entry.as_ref().map(|e| e.icon.as_str())));
        let facts = json!({
            "uninstall_entries": new_entries.iter().map(|e| json!({"key": e.key, "name": e.name, "version": e.version, "publisher": e.publisher, "location": e.location})).collect::<Vec<_>>(),
            "new_directories": new_dirs,
            "shortcuts": new_lnk,
            "install_dir": dir,
            "executable": exe,
        });
        let (status, message) = match (&dir, &exe, &entry) {
            (Some(_), Some(e), Some(en)) => (StepStatus::Pass, format!("installed {} {} → {}", en.name, en.version, e.display())),
            (Some(_), Some(e), None) => {
                (StepStatus::Warn, format!("application found at {} but no Add/Remove Programs entry was registered", e.display()))
            }
            _ => (StepStatus::Fail, "the installer reported success but no installed application could be found".into()),
        };
        let rep = StepReport {
            id: "files".into(),
            status,
            fail_kind: (status == StepStatus::Fail).then_some(FailKind::Other),
            exit_code: None,
            duration_ms: t.elapsed().as_millis() as u64,
            message,
            log: String::new(),
            facts,
        };
        self.end(rep);
        match (dir, exe) {
            (Some(dir), Some(exe)) => Some(Found { dir, exe, entry }),
            _ => None,
        }
    }

    // ---- portable ---------------------------------------------------------

    fn portable_phase(&mut self) -> Option<Found> {
        let pkg = PathBuf::from(&self.spec.package);
        let dest = self.work.join("app");
        self.start("install", "extracting portable package");
        let t = Instant::now();
        let res = if pkg.is_dir() { copy_dir(&pkg, &dest).map_err(|e| e.to_string()) } else { extract_zip(&pkg, &dest) };
        let mut rep = StepReport {
            id: "install".into(),
            status: StepStatus::Pass,
            fail_kind: None,
            exit_code: None,
            duration_ms: 0,
            message: String::new(),
            log: String::new(),
            facts: Value::Null,
        };
        let ok = match res {
            Ok(n) => {
                rep.message = format!("extracted {n} files");
                true
            }
            Err(e) => {
                rep.status = StepStatus::Fail;
                rep.fail_kind = Some(FailKind::Other);
                rep.message = format!("could not extract the package: {e}");
                false
            }
        };
        rep.duration_ms = t.elapsed().as_millis() as u64;
        self.end(rep);
        if !ok {
            return None;
        }
        self.start("files", "locating the application executable");
        let t = Instant::now();
        let exe = locate_exe(&dest, self.spec.exe.as_deref(), None);
        let (status, message) = match &exe {
            Some(e) => (StepStatus::Pass, format!("found {}", e.display())),
            None => (StepStatus::Fail, "no executable found in the portable package".into()),
        };
        self.end(StepReport {
            id: "files".into(),
            status,
            fail_kind: (status == StepStatus::Fail).then_some(FailKind::Other),
            exit_code: None,
            duration_ms: t.elapsed().as_millis() as u64,
            message,
            log: String::new(),
            facts: json!({ "executable": exe }),
        });
        if let (Some(c), Some(_)) = (&self.container, &exe) {
            // Read/execute on the package; nothing else on the host is reachable.
            if let Err(e) = c.grant(&dest, false) {
                self.skipped("launch", &format!("could not prepare the sandbox: {e}"));
                return None;
            }
        }
        exe.map(|exe| Found { dir: dest, exe, entry: None })
    }

    fn cleanup_portable(&mut self, f: &Found) {
        self.start("uninstall", "removing the extracted package");
        let t = Instant::now();
        let deadline = Instant::now() + secs(self.spec.cleanup_timeout_secs);
        let mut last = None;
        while Instant::now() < deadline {
            match std::fs::remove_dir_all(&f.dir) {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e.to_string());
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        let gone = !f.dir.exists();
        self.end(StepReport {
            id: "uninstall".into(),
            status: if gone { StepStatus::Pass } else { StepStatus::Fail },
            fail_kind: (!gone).then_some(FailKind::Other),
            exit_code: None,
            duration_ms: t.elapsed().as_millis() as u64,
            message: if gone {
                "portable directory removed cleanly".into()
            } else {
                format!("could not remove the directory: {}", last.unwrap_or_default())
            },
            log: String::new(),
            facts: Value::Null,
        });
    }

    // ---- launch / smoke ---------------------------------------------------

    fn app_command(&self, f: &Found, args: &[String]) -> Command {
        let mut c = Command::new(&f.exe);
        c.args(args).current_dir(f.exe.parent().unwrap_or(&f.dir));
        c
    }

    /// Run the application, inside the AppContainer when isolation is requested.
    fn exec(&self, f: &Found, args: &[String], timeout: Duration, mode: Mode) -> std::io::Result<Outcome> {
        match &self.container {
            Some(c) => {
                let sp = c.spawn(&f.exe, args, f.exe.parent().unwrap_or(&f.dir))?;
                run_supervised(sp, timeout, self.limits(), mode)
            }
            None => run_limited(self.app_command(f, args), timeout, self.limits(), mode),
        }
    }

    fn launch(&mut self, f: &Found) {
        self.start("launch", &format!("starting {}", f.exe.file_name().unwrap_or_default().to_string_lossy()));
        let t = Instant::now();
        let timeout = secs(self.spec.launch_timeout_secs);
        let mode = if self.spec.gui { Mode::GuiAlive { alive: secs(self.spec.alive_secs).min(timeout) } } else { Mode::RunToExit };
        let res = self.exec(f, &self.spec.launch_args, timeout, mode);
        let mut step = self.step_from_result("launch", res, t, !self.spec.gui);
        if self.spec.gui {
            // For GUI apps "still running after the alive window" is success.
            let windows = step.facts["windows_seen"].as_u64().unwrap_or(0);
            let hung = step.facts["hung"].as_bool().unwrap_or(false);
            if hung {
                step.status = StepStatus::Fail;
                step.fail_kind = Some(FailKind::Hung);
                step.message = "APPLICATION HUNG — its window stopped responding".into();
            } else if step.exit_code.is_none() {
                if windows > 0 {
                    step.status = StepStatus::Pass;
                    step.fail_kind = None;
                    step.message = format!("running and responsive after {}s ({windows} window(s))", self.spec.alive_secs);
                } else {
                    step.status = StepStatus::Warn;
                    step.fail_kind = None;
                    step.message = "process stayed alive but no visible window was created".into();
                }
            } else if step.exit_code == Some(0) {
                step.status = StepStatus::Warn;
                step.fail_kind = None;
                step.message = "exited with code 0 before the alive window elapsed (expected a GUI to keep running)".into();
            }
        }
        self.end(step);
    }

    fn smoke(&mut self, f: &Found, s: &Smoke) {
        let id = format!("smoke:{}", s.name);
        self.start(&id, &format!("{} {}", f.exe.file_name().unwrap_or_default().to_string_lossy(), s.args.join(" ")));
        let t = Instant::now();
        let timeout = secs(s.timeout_secs.unwrap_or(self.spec.smoke_timeout_secs));
        let res = self.exec(f, &s.args, timeout, Mode::RunToExit);
        let mut step = self.step_from_result(&id, res, t, false);
        if step.status != StepStatus::Fail || step.fail_kind == Some(FailKind::ExitCode) {
            let code = step.exit_code;
            if code == Some(s.expect_exit) {
                step.status = StepStatus::Pass;
                step.fail_kind = None;
                step.message = format!("exit code {} as expected", s.expect_exit);
                if let Some(want) = &s.expect_stdout {
                    if !step.log.contains(want.as_str()) {
                        step.status = StepStatus::Fail;
                        step.fail_kind = Some(FailKind::Other);
                        step.message = format!("output does not contain {want:?}");
                    }
                }
            } else if let Some(c) = code {
                if !crash_like(c) {
                    step.status = StepStatus::Fail;
                    step.fail_kind = Some(FailKind::ExitCode);
                    step.message = format!("exit code {c}, expected {}", s.expect_exit);
                }
            }
        }
        self.end(step);
    }

    // ---- uninstall --------------------------------------------------------

    fn uninstall(&mut self, f: &Found) {
        self.start("uninstall", "running the registered uninstaller");
        let t = Instant::now();
        let Some(entry) = &f.entry else {
            self.end(StepReport {
                id: "uninstall".into(),
                status: StepStatus::Fail,
                fail_kind: Some(FailKind::Other),
                exit_code: None,
                duration_ms: 0,
                message: "no uninstaller is registered (no Add/Remove Programs entry)".into(),
                log: String::new(),
                facts: Value::Null,
            });
            return;
        };
        let cmdline = if !entry.quiet_uninstall.is_empty() {
            entry.quiet_uninstall.clone()
        } else if entry.uninstall.to_ascii_lowercase().contains("msiexec") {
            format!("{} /qn /norestart", entry.uninstall.replace("/I{", "/X{").replace("/i{", "/x{"))
        } else {
            format!("{} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART", entry.uninstall)
        };
        let (exe, rest) = split_command_line(&cmdline);
        let mut c = Command::new(&exe);
        c.raw_arg(rest);
        let res =
            run_limited(c, secs(self.spec.cleanup_timeout_secs.max(self.spec.install_timeout_secs / 2)), self.limits(), Mode::RunToExit);
        let mut step = self.step_from_result("uninstall", res, t, true);
        // Inno's uninstaller may re-launch itself from %TEMP% and return early; give it a moment.
        std::thread::sleep(Duration::from_secs(2));
        let deadline = Instant::now() + secs(self.spec.cleanup_timeout_secs);
        let still_registered = |key: &str| read_uninstall_entries().iter().any(|e| e.key == key);
        while Instant::now() < deadline && (still_registered(&entry.key) || f.exe.exists()) {
            std::thread::sleep(Duration::from_millis(500));
        }
        let registered = still_registered(&entry.key);
        let exe_left = f.exe.exists();
        let leftovers: Vec<String> = std::fs::read_dir(&f.dir)
            .map(|rd| rd.flatten().take(20).map(|e| e.path().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        step.facts = json!({ "registry_entry_remaining": registered, "executable_remaining": exe_left, "leftovers": leftovers });
        if step.status == StepStatus::Pass || step.status == StepStatus::Warn {
            if registered || exe_left {
                step.status = StepStatus::Fail;
                step.fail_kind = Some(FailKind::Other);
                step.message = format!(
                    "the uninstaller exited successfully but {}",
                    if exe_left { "the application files are still present" } else { "its Add/Remove Programs entry is still registered" }
                );
            } else if !leftovers.is_empty() {
                step.status = StepStatus::Warn;
                step.message = format!("uninstalled, but {} leftover item(s) remain in the install directory", leftovers.len());
            } else {
                step.status = StepStatus::Pass;
                step.message = "uninstalled cleanly (files and registry entry removed)".into();
            }
        }
        self.end(step);
    }

    // ---- shared -----------------------------------------------------------

    /// Map a process outcome to a step. `exit0_ok`: whether exit code 0 means success.
    fn step_from_result(&self, id: &str, res: std::io::Result<Outcome>, t: Instant, exit0_ok: bool) -> StepReport {
        let mut r = StepReport {
            id: id.into(),
            status: StepStatus::Pass,
            fail_kind: None,
            exit_code: None,
            duration_ms: t.elapsed().as_millis() as u64,
            message: String::new(),
            log: String::new(),
            facts: Value::Null,
        };
        let o = match res {
            Ok(o) => o,
            Err(e) => {
                r.status = StepStatus::Fail;
                r.fail_kind = Some(FailKind::Other);
                r.message = format!("could not start the process: {e}");
                return r;
            }
        };
        r.exit_code = o.exit_code;
        r.duration_ms = o.duration_ms;
        r.log = truncate_tail(
            &format!("{}{}{}", o.stdout, if o.stderr.is_empty() { "" } else { "\n--- stderr ---\n" }, o.stderr),
            MAX_LOG_BYTES,
        );
        r.facts = json!({
            "isolation": if self.container.is_some() { "appcontainer" } else { "none" },
            "pids_seen": o.pids_seen, "child_processes": o.pids_seen.len().saturating_sub(1),
            "peak_memory_mb": o.peak_memory_mb, "windows_seen": o.windows_seen, "hung": o.hung,
        });
        if o.timed_out {
            r.status = StepStatus::Fail;
            r.fail_kind = Some(FailKind::Timeout);
            r.message = format!("TEST TIMEOUT — still running after {}s; the process tree was terminated", o.duration_ms / 1000);
        } else if let Some(c) = o.exit_code {
            if crash_like(c) {
                r.status = StepStatus::Fail;
                r.fail_kind = Some(FailKind::Crashed);
                r.message = format!("APPLICATION CRASHED — exit code 0x{:08X}", c as u32);
            } else if c != 0 && exit0_ok {
                r.status = StepStatus::Fail;
                r.fail_kind = Some(FailKind::ExitCode);
                r.message = format!("exit code {c}");
            } else {
                r.message = format!("exit code {c}");
            }
        } else {
            r.message = "still running when stopped".into();
        }
        r
    }
}

pub fn exit_code_hint(code: i32, msi: bool) -> &'static str {
    if msi {
        match code {
            1601 => "Windows Installer service is not accessible",
            1602 => "installation cancelled by the user",
            1603 => "fatal error during installation (see the MSI log)",
            1618 => "another installation is already in progress",
            1619 | 1620 => "the installation package could not be opened",
            1625 => "installation is forbidden by system policy",
            1638 => "another version of this product is already installed",
            1639 => "invalid command line argument",
            _ => "Windows Installer returned an error (see the MSI log)",
        }
    } else {
        match code {
            1 => "installer reported a generic failure or invalid command line (check the silent-install switches)",
            2 => "installation cancelled or setup failed to initialise",
            5 => "access denied (installer needs elevation)",
            _ => "the installer returned a non-zero exit code",
        }
    }
}

/// Split `"C:\Program Files\App\unins000.exe" /SILENT` into program and raw argument text.
pub fn split_command_line(s: &str) -> (String, String) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return (rest[..end].to_string(), rest[end + 1..].trim_start().to_string());
        }
    }
    // Unquoted: the program path may contain spaces; take the longest prefix ending in ".exe".
    if let Some(i) = s.to_ascii_lowercase().find(".exe") {
        let end = i + 4;
        return (s[..end].to_string(), s[end..].trim_start().to_string());
    }
    match s.split_once(' ') {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (s.to_string(), String::new()),
    }
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<usize> {
    std::fs::create_dir_all(dst)?;
    let mut n = 0;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            n += copy_dir(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), &to)?;
            n += 1;
        }
    }
    Ok(n)
}

fn extract_zip(zip_path: &Path, dst: &Path) -> Result<usize, String> {
    let f = std::fs::File::open(zip_path).map_err(|e| e.to_string())?;
    let mut z = zip::ZipArchive::new(f).map_err(|e| format!("not a valid zip archive: {e}"))?;
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    let mut n = 0;
    for i in 0..z.len() {
        let mut e = z.by_index(i).map_err(|e| e.to_string())?;
        // `enclosed_name` rejects zip-slip paths (.., absolute).
        let Some(rel) = e.enclosed_name() else { return Err(format!("unsafe path in archive: {}", e.name())) };
        let out = dst.join(rel);
        if e.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
        } else {
            if let Some(p) = out.parent() {
                std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
            }
            let mut w = std::fs::File::create(&out).map_err(|e| e.to_string())?;
            std::io::copy(&mut e, &mut w).map_err(|e| e.to_string())?;
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_codes_are_recognised() {
        assert!(crash_like(0xC0000005u32 as i32));
        assert!(crash_like(0xC0000409u32 as i32));
        assert!(!crash_like(1) && !crash_like(0) && !crash_like(-1 + 1));
    }

    #[test]
    fn command_lines_split_correctly() {
        assert_eq!(
            split_command_line(r#""C:\Program Files\A\unins000.exe" /SILENT"#),
            (r"C:\Program Files\A\unins000.exe".into(), "/SILENT".into())
        );
        assert_eq!(split_command_line(r"C:\Program Files\A\un.exe /x"), (r"C:\Program Files\A\un.exe".into(), "/x".into()));
        assert_eq!(split_command_line("MsiExec.exe /X{ABC}"), ("MsiExec.exe".into(), "/X{ABC}".into()));
    }

    #[test]
    fn locate_exe_prefers_named_then_largest_and_skips_uninstallers() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("unins000.exe"), vec![0u8; 5000]).unwrap();
        std::fs::write(d.path().join("tool.exe"), vec![0u8; 100]).unwrap();
        std::fs::create_dir(d.path().join("bin")).unwrap();
        std::fs::write(d.path().join("bin").join("app.exe"), vec![0u8; 900]).unwrap();
        assert!(locate_exe(d.path(), None, None).unwrap().ends_with("app.exe"));
        assert!(locate_exe(d.path(), Some("tool.exe"), None).unwrap().ends_with("tool.exe"));
        assert!(locate_exe(d.path(), Some("bin/app.exe"), None).unwrap().ends_with("app.exe"));
    }

    #[test]
    fn zip_slip_is_rejected() {
        use std::io::Write;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("evil.zip");
        let mut z = zip::ZipWriter::new(std::fs::File::create(&p).unwrap());
        z.start_file("../escape.txt", zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(b"x").unwrap();
        z.finish().unwrap();
        assert!(extract_zip(&p, &d.path().join("out")).unwrap_err().contains("unsafe path"));
        assert!(!d.path().join("escape.txt").exists());
    }

    #[test]
    fn msi_hints_are_specific() {
        assert!(exit_code_hint(1603, true).contains("fatal"));
        assert!(exit_code_hint(1618, true).contains("in progress"));
    }
}
