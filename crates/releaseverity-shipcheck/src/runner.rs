//! Environment runners. A runner stages the package, starts the agent inside the
//! environment, streams its real progress, and returns its validated report.

use releaseverity_agent::{
    truncate_tail, AgentReport, Isolation, PackageKind, ProgressLine, Spec, MAX_LOG_BYTES, PROGRESS_FILE, REPORT_FILE,
};
use releaseverity_core::proc;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RunnerError {
    /// English text (derived from the catalog when a key is used).
    pub message: String,
    pub suggestion: Option<String>,
    pub msg: Option<releaseverity_core::model::Msg>,
    pub suggestion_msg: Option<releaseverity_core::model::Msg>,
}

impl RunnerError {
    pub fn new(m: impl Into<String>) -> Self {
        Self { message: m.into(), suggestion: None, msg: None, suggestion_msg: None }
    }
    /// A localized error from a catalog key.
    pub fn key(key: &str, args: &[(&str, &str)]) -> Self {
        let m = releaseverity_core::model::Msg::new(key, args);
        Self { message: m.english(), suggestion: None, msg: Some(m), suggestion_msg: None }
    }
    pub fn hint(mut self, s: impl Into<String>) -> Self {
        self.suggestion = Some(s.into());
        self
    }
    pub fn hint_key(mut self, key: &str) -> Self {
        let m = releaseverity_core::model::Msg::new(key, &[]);
        self.suggestion = Some(m.english());
        self.suggestion_msg = Some(m);
        self
    }
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub struct RunInput<'a> {
    pub spec: &'a Spec,
    /// Installer file, zip, or directory on the host.
    pub package: &'a Path,
    /// Empty working directory for staging.
    pub stage: &'a Path,
    pub agent: &'a Path,
    pub allow_network: bool,
}

pub trait EnvRunner {
    fn id(&self) -> &'static str;
    /// Fail fast, with an actionable message, when the environment can't be used.
    fn availability(&self) -> Result<(), RunnerError>;
    fn run(&self, input: &RunInput, on_progress: &mut dyn FnMut(&ProgressLine), cancel: &AtomicBool) -> Result<AgentReport, RunnerError>;
}

/// Where the agent is installed: `RELEASEVERITY_AGENT`, next to the running exe, or the cargo target dir.
pub fn find_agent() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("RELEASEVERITY_AGENT").map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(p);
    }
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    for _ in 0..3 {
        let c = dir.join("releaseverity-agent.exe");
        if c.is_file() {
            return Some(c);
        }
        dir = dir.parent()?;
    }
    None
}

fn total_timeout(spec: &Spec) -> Duration {
    let smoke: u64 = spec.smoke.iter().map(|s| s.timeout_secs.unwrap_or(spec.smoke_timeout_secs)).sum();
    Duration::from_secs(
        spec.install_timeout_secs + spec.launch_timeout_secs + smoke + spec.cleanup_timeout_secs * 3 + spec.install_timeout_secs / 2 + 30,
    )
}

fn stage_inputs(input: &RunInput) -> Result<(PathBuf, PathBuf, PathBuf, String), RunnerError> {
    let (inp, out) = (input.stage.join("in"), input.stage.join("out"));
    let io = |e: std::io::Error| RunnerError::new(format!("staging failed: {e}"));
    std::fs::create_dir_all(&inp).map_err(io)?;
    std::fs::create_dir_all(&out).map_err(io)?;
    std::fs::copy(input.agent, inp.join("releaseverity-agent.exe")).map_err(io)?;
    let pkg_name = input.package.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "package".into());
    let pkg_dst = inp.join("package").join(&pkg_name);
    std::fs::create_dir_all(pkg_dst.parent().expect("has parent")).map_err(io)?;
    if input.package.is_dir() {
        copy_dir(input.package, &pkg_dst).map_err(io)?;
    } else {
        std::fs::copy(input.package, &pkg_dst).map_err(io)?;
    }
    Ok((inp, out, pkg_dst, pkg_name))
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), to)?;
        }
    }
    Ok(())
}

/// Incremental reader for the agent's progress file.
struct Tail {
    path: PathBuf,
    offset: u64,
    buf: String,
}

impl Tail {
    fn new(path: PathBuf) -> Self {
        Self { path, offset: 0, buf: String::new() }
    }
    fn poll(&mut self) -> Vec<ProgressLine> {
        let Ok(mut f) = std::fs::File::open(&self.path) else { return vec![] };
        if f.seek(SeekFrom::Start(self.offset)).is_err() {
            return vec![];
        }
        let mut chunk = Vec::new();
        // Untrusted writer: never read more than 1 MiB per poll.
        if f.take(1 << 20).read_to_end(&mut chunk).is_err() {
            return vec![];
        }
        self.offset += chunk.len() as u64;
        self.buf.push_str(&String::from_utf8_lossy(&chunk));
        let mut out = vec![];
        while let Some(i) = self.buf.find('\n') {
            let line: String = self.buf.drain(..=i).collect();
            if let Ok(p) = serde_json::from_str::<ProgressLine>(line.trim()) {
                out.push(sanitize_line(p));
            }
        }
        out
    }
}

fn sanitize_line(p: ProgressLine) -> ProgressLine {
    match p {
        ProgressLine::End { mut step } => {
            step.log = truncate_tail(&step.log, MAX_LOG_BYTES);
            step.message.truncate(2000);
            ProgressLine::End { step }
        }
        other => other,
    }
}

/// Parse and bound-check the agent's final report. Everything in it is untrusted data.
pub fn read_report(out_dir: &Path) -> Result<AgentReport, RunnerError> {
    let p = out_dir.join(REPORT_FILE);
    let meta = std::fs::metadata(&p).map_err(|_| RunnerError::key("m.ship.noreport", &[]))?;
    if meta.len() > 4 * 1024 * 1024 {
        return Err(RunnerError::new("the agent report is implausibly large and was rejected"));
    }
    let text = std::fs::read_to_string(&p).map_err(|e| RunnerError::new(format!("cannot read the agent report: {e}")))?;
    let mut r: AgentReport = serde_json::from_str(&text).map_err(|e| RunnerError::new(format!("the agent report is malformed: {e}")))?;
    if r.steps.len() > 200 {
        return Err(RunnerError::new("the agent report has too many steps"));
    }
    for s in &mut r.steps {
        s.id.truncate(120);
        s.message.truncate(2000);
        s.log = truncate_tail(&s.log, MAX_LOG_BYTES);
    }
    Ok(r)
}

// ---------------------------------------------------------------------------
// Host runner — job-limited, but NOT isolated. Requires explicit opt-in.
// ---------------------------------------------------------------------------

pub struct HostRunner {
    pub allowed: bool,
    /// `AppContainer` = ReleaseVerity's own sandbox (needs no opt-in); `None` = host, opt-in only.
    pub isolation: Isolation,
}

impl EnvRunner for HostRunner {
    fn id(&self) -> &'static str {
        match self.isolation {
            Isolation::AppContainer => "appcontainer",
            Isolation::None => "host",
        }
    }

    fn availability(&self) -> Result<(), RunnerError> {
        if !cfg!(windows) {
            return Err(RunnerError::key("m.ship.needs-windows", &[]));
        }
        if self.isolation == Isolation::AppContainer {
            return Ok(());
        }
        if !self.allowed {
            return Err(RunnerError::key("m.ship.host-disabled", &[]).hint_key("m.ship.host-disabled.fix"));
        }
        Ok(())
    }

    fn run(&self, input: &RunInput, on_progress: &mut dyn FnMut(&ProgressLine), cancel: &AtomicBool) -> Result<AgentReport, RunnerError> {
        self.availability()?;
        if self.isolation == Isolation::AppContainer && input.spec.kind == PackageKind::Installer {
            return Err(RunnerError::key("m.ship.ac-installer", &[]).hint_key("m.ship.ac-installer.fix"));
        }
        let (inp, out, pkg, _) = stage_inputs(input)?;
        let mut spec = input.spec.clone();
        spec.isolation = self.isolation;
        spec.package = pkg.to_string_lossy().into_owned();
        let spec_path = inp.join("spec.json");
        std::fs::write(&spec_path, serde_json::to_vec_pretty(&spec).expect("spec serializes"))
            .map_err(|e| RunnerError::new(e.to_string()))?;

        let mut child = Command::new(inp.join("releaseverity-agent.exe"))
            .arg(&spec_path)
            .arg(&out)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| RunnerError::new(format!("could not start the agent: {e}")))?;
        let deadline = Instant::now() + total_timeout(&spec);
        let mut tail = Tail::new(out.join(PROGRESS_FILE));
        let kill = |c: &mut std::process::Child| {
            let _ = c.kill();
            let _ = c.wait();
        };
        loop {
            for l in tail.poll() {
                on_progress(&l);
            }
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(e) => return Err(RunnerError::new(format!("lost the agent process: {e}"))),
            }
            if cancel.load(Ordering::Relaxed) {
                kill(&mut child);
                return Err(RunnerError::key("m.ship.cancelled", &[]));
            }
            if Instant::now() > deadline {
                kill(&mut child);
                return Err(RunnerError::key("m.ship.timeout", &[]));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        for l in tail.poll() {
            on_progress(&l);
        }
        read_report(&out)
    }
}

// ---------------------------------------------------------------------------
// Windows Sandbox runner — disposable VM, no network by default, read-only input.
// ---------------------------------------------------------------------------

pub struct SandboxRunner;

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn sandbox_config(in_dir: &Path, out_dir: &Path, memory_mb: u64, network: bool) -> String {
    format!(
        r#"<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>{net}</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MemoryInMB>{mem}</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{inp}</HostFolder>
      <SandboxFolder>C:\ReleaseVerity\in</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{out}</HostFolder>
      <SandboxFolder>C:\ReleaseVerity\out</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ReleaseVerity\in\launch.ps1</Command>
  </LogonCommand>
</Configuration>
"#,
        net = if network { "Default" } else { "Disable" },
        mem = memory_mb,
        inp = xml(&in_dir.to_string_lossy()),
        out = xml(&out_dir.to_string_lossy()),
    )
}

/// Runs inside the sandbox using only Microsoft-signed tools. If the guest's Application
/// Control policy (Smart App Control) refuses to start our unsigned agent, it records *why*
/// instead of letting the host wait out a timeout. Always shuts the VM down at the end.
pub const LAUNCH_SCRIPT: &str = r#"$out = 'C:\ReleaseVerity\out'
try {
  Start-Process -FilePath 'C:\ReleaseVerity\in\releaseverity-agent.exe' -ArgumentList 'C:\ReleaseVerity\in\spec.json','C:\ReleaseVerity\out' -Wait -ErrorAction Stop
} catch {
  $sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
  [pscustomobject]@{ native_error = $_.Exception.NativeErrorCode; message = $_.Exception.Message; smart_app_control = $sac } |
    ConvertTo-Json -Compress | Set-Content -Path (Join-Path $out 'blocked.json') -Encoding UTF8
}
shutdown /s /t 0 /f
"#;

pub const BLOCKED_FILE: &str = "blocked.json";

/// Turn the guest's `blocked.json` into an actionable error.
pub fn blocked_error(out_dir: &Path) -> Option<RunnerError> {
    let text = std::fs::read_to_string(out_dir.join(BLOCKED_FILE)).ok()?;
    let v: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let sac = v["smart_app_control"].as_u64();
    let why_key = if sac == Some(1) { "m.ship.sandbox-blocked.sac" } else { "m.ship.sandbox-blocked.policy" };
    let why = releaseverity_core::i18n::english().t(why_key);
    let mut e = RunnerError::key("m.ship.sandbox-blocked", &[("why", &why)]).hint_key("m.ship.sandbox-blocked.fix");
    // Keep the localized reason too: the nested catalog key is rendered in the user's language.
    if let Some(m) = &mut e.msg {
        m.args.insert("why".into(), format!("@{why_key}"));
    }
    Some(e)
}

fn sandbox_exe() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    PathBuf::from(root).join("System32\\WindowsSandbox.exe")
}

fn sandbox_running() -> bool {
    ["WindowsSandboxClient.exe", "WindowsSandboxServer.exe", "WindowsSandboxRemoteSession.exe"].iter().any(|n| {
        let mut c = Command::new("tasklist");
        c.args(["/FI", &format!("IMAGENAME eq {n}"), "/NH"]);
        proc::run(&mut c, Duration::from_secs(15)).map(|o| o.stdout.contains(n)).unwrap_or(false)
    })
}

fn kill_sandbox() {
    for n in ["WindowsSandboxClient.exe", "WindowsSandboxRemoteSession.exe", "WindowsSandboxServer.exe"] {
        let mut c = Command::new("taskkill");
        c.args(["/F", "/IM", n]);
        let _ = proc::run(&mut c, Duration::from_secs(20));
    }
}

/// Guarantees the VM is gone on every exit path.
struct SandboxGuard;
impl Drop for SandboxGuard {
    fn drop(&mut self) {
        if sandbox_running() {
            kill_sandbox();
        }
    }
}

impl EnvRunner for SandboxRunner {
    fn id(&self) -> &'static str {
        "windows-sandbox"
    }

    fn availability(&self) -> Result<(), RunnerError> {
        if !cfg!(windows) {
            return Err(RunnerError::key("m.ship.needs-windows", &[]));
        }
        if !sandbox_exe().exists() {
            return Err(RunnerError::key("m.ship.sandbox-missing", &[]).hint_key("m.ship.sandbox-missing.fix"));
        }
        Ok(())
    }

    fn run(&self, input: &RunInput, on_progress: &mut dyn FnMut(&ProgressLine), cancel: &AtomicBool) -> Result<AgentReport, RunnerError> {
        self.availability()?;
        if sandbox_running() {
            return Err(RunnerError::key("m.ship.sandbox-busy", &[]).hint_key("m.ship.sandbox-busy.fix"));
        }
        let (inp, out, pkg_host, pkg_name) = stage_inputs(input)?;
        let mut spec = input.spec.clone();
        spec.package = format!(r"C:\ReleaseVerity\in\package\{pkg_name}");
        let _ = pkg_host;
        std::fs::write(inp.join("spec.json"), serde_json::to_vec_pretty(&spec).expect("spec serializes"))
            .map_err(|e| RunnerError::new(e.to_string()))?;
        std::fs::write(inp.join("launch.ps1"), LAUNCH_SCRIPT).map_err(|e| RunnerError::new(e.to_string()))?;
        let wsb = input.stage.join("releaseverity.wsb");
        let memory = (spec.max_memory_mb * 2).max(2048);
        std::fs::write(&wsb, sandbox_config(&inp, &out, memory, input.allow_network)).map_err(|e| RunnerError::new(e.to_string()))?;

        let _guard = SandboxGuard;
        Command::new(sandbox_exe()).arg(&wsb).spawn().map_err(|e| RunnerError::new(format!("could not start Windows Sandbox: {e}")))?;

        let boot_deadline = Instant::now() + Duration::from_secs(300);
        let mut run_deadline: Option<Instant> = None;
        let mut tail = Tail::new(out.join(PROGRESS_FILE));
        let report_path = out.join(REPORT_FILE);
        on_progress(&ProgressLine::Start { id: "environment".into(), note: "starting a clean Windows Sandbox".into() });
        loop {
            let lines = tail.poll();
            if !lines.is_empty() && run_deadline.is_none() {
                run_deadline = Some(Instant::now() + total_timeout(&spec));
            }
            for l in lines {
                on_progress(&l);
            }
            if out.join(BLOCKED_FILE).exists() {
                std::thread::sleep(Duration::from_millis(300));
                if let Some(e) = blocked_error(&out) {
                    return Err(e);
                }
            }
            if report_path.exists() {
                // Give the agent a moment to finish writing, then read.
                std::thread::sleep(Duration::from_millis(300));
                for l in tail.poll() {
                    on_progress(&l);
                }
                let report = read_report(&out);
                // Let the VM shut itself down; the guard force-closes it otherwise.
                let until = Instant::now() + Duration::from_secs(spec.cleanup_timeout_secs.max(10));
                while sandbox_running() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(500));
                }
                return report;
            }
            if cancel.load(Ordering::Relaxed) {
                return Err(RunnerError::key("m.ship.cancelled", &[]));
            }
            match run_deadline {
                Some(d) if Instant::now() > d => {
                    return Err(RunnerError::key("m.ship.timeout", &[]));
                }
                None if Instant::now() > boot_deadline => {
                    return Err(RunnerError::key("m.ship.sandbox-noboot", &[]).hint_key("m.ship.sandbox-noboot.fix"));
                }
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_config_is_locked_down_and_escaped() {
        let x = sandbox_config(Path::new(r"C:\a&b\in"), Path::new(r"C:\a&b\out"), 4096, false);
        assert!(x.contains("<Networking>Disable</Networking>"));
        assert!(x.contains("<ReadOnly>true</ReadOnly>") && x.contains("C:\\a&amp;b\\in"));
        assert!(x.contains("launch.ps1"));
        assert!(sandbox_config(Path::new("a"), Path::new("b"), 1, true).contains("<Networking>Default</Networking>"));
    }

    #[test]
    fn guest_policy_block_becomes_an_actionable_error() {
        let d = tempfile::tempdir().unwrap();
        assert!(blocked_error(d.path()).is_none());
        std::fs::write(d.path().join(BLOCKED_FILE), "\u{feff}{\"native_error\":1260,\"message\":\"blocked\",\"smart_app_control\":1}")
            .unwrap();
        let e = blocked_error(d.path()).unwrap();
        assert!(e.message.contains("Smart App Control"), "{}", e.message);
        assert!(e.suggestion.unwrap().contains("appcontainer"));
    }

    #[test]
    fn untrusted_report_is_bounded_and_validated() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_report(d.path()).is_err());
        std::fs::write(d.path().join(REPORT_FILE), "not json").unwrap();
        assert!(read_report(d.path()).unwrap_err().message.contains("malformed"));
        let step = |log: String| serde_json::json!({"id":"install","status":"pass","duration_ms":1,"message":"m","log":log});
        let rep = serde_json::json!({"agent_version":"0","os":"windows","finished":true,"steps":[step("x".repeat(500_000))]});
        std::fs::write(d.path().join(REPORT_FILE), rep.to_string()).unwrap();
        let r = read_report(d.path()).unwrap();
        assert!(r.steps[0].log.len() <= MAX_LOG_BYTES + 32);
    }

    #[test]
    fn tail_reads_incrementally_and_ignores_garbage() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(PROGRESS_FILE);
        let mut t = Tail::new(p.clone());
        assert!(t.poll().is_empty());
        std::fs::write(&p, "{\"event\":\"start\",\"id\":\"install\",\"note\":\"n\"}\ngarbage\n{\"event\":\"sta").unwrap();
        assert_eq!(t.poll().len(), 1);
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        use std::io::Write;
        writeln!(f, "rt\",\"id\":\"launch\",\"note\":\"\"}}").unwrap();
        let more = t.poll();
        assert_eq!(more.len(), 1, "a line split across polls is completed: {more:?}");
    }
}
