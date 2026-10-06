//! The verification pipeline contract. Engines implement [`Check`]; the
//! orchestrator runs them and emits real events as each step starts and ends.

use crate::config::Config;
use crate::logging::Logger;
use crate::model::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RunEvent {
    Started {
        total: usize,
    },
    StepStarted {
        index: usize,
        total: usize,
        id: String,
    },
    /// Free-form progress message emitted *by a check while it works*
    /// (e.g. "cloning repository"). Never synthesized by the orchestrator.
    Progress {
        id: String,
        message: String,
    },
    StepFinished {
        index: usize,
        total: usize,
        result: CheckResult,
    },
    Finished {
        score: Option<u8>,
        verdict: Verdict,
        cancelled: bool,
    },
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: &RunEvent);
}

pub struct NullSink;
impl EventSink for NullSink {
    fn emit(&self, _: &RunEvent) {}
}

impl<F: Fn(&RunEvent) + Send + Sync> EventSink for F {
    fn emit(&self, e: &RunEvent) {
        self(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShipKind {
    Installer,
    Portable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SmokeSpec {
    pub name: String,
    pub args: Vec<String>,
    pub expect_exit: i32,
    pub expect_stdout: Option<String>,
    pub timeout_secs: Option<u64>,
}

/// What ShipCheck installs/runs and where.
#[derive(Debug, Clone)]
pub struct ShipcheckTarget {
    pub kind: ShipKind,
    /// Installer file, portable zip, or portable directory.
    pub package: PathBuf,
    pub installer_args: Vec<String>,
    pub exe: Option<String>,
    pub launch_args: Vec<String>,
    pub gui: bool,
    /// Start the application after installing (otherwise only install/uninstall are tested).
    pub launch: bool,
    pub alive_secs: u64,
    pub smoke: Vec<SmokeSpec>,
    /// Environment ids: `windows-sandbox`, `host`.
    pub environments: Vec<String>,
    pub uninstall: bool,
}

/// What is being verified.
#[derive(Debug, Clone, Default)]
pub struct VerifyTarget {
    pub project_name: String,
    /// Remote URL or local path, as given by the user (for display and reports).
    pub repo: String,
    /// Local checkout to verify against. For remote repos the source check clones into the work dir.
    pub local_repo: Option<PathBuf>,
    pub tag: String,
    /// Release assets on disk: installers, archives, checksum files, signatures, SBOMs, attestations.
    pub assets: Vec<PathBuf>,
    /// A locally rebuilt artifact to compare with the release artifact (Repro Engine).
    pub rebuilt: Option<PathBuf>,
    /// Installation/runtime testing request (ShipCheck Engine).
    pub shipcheck: Option<ShipcheckTarget>,
}

/// Facts discovered by earlier checks and consumed by later ones.
#[derive(Debug, Default, Clone)]
pub struct State {
    pub repo_dir: Option<PathBuf>,
    pub commit: Option<String>,
    pub artifacts: Vec<ArtifactInfo>,
    /// Engine-private cache shared between that engine's checks (e.g. one agent run per environment).
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

pub struct Context {
    pub config: Config,
    pub target: VerifyTarget,
    pub work_dir: PathBuf,
    pub logger: Logger,
    pub cancel: Arc<AtomicBool>,
    pub state: State,
    pub sink: Arc<dyn EventSink>,
    current: String,
}

impl Context {
    pub fn new(config: Config, target: VerifyTarget, work_dir: PathBuf, logger: Logger) -> Self {
        Self {
            config,
            target,
            work_dir,
            logger,
            cancel: Arc::new(AtomicBool::new(false)),
            state: State::default(),
            sink: Arc::new(NullSink),
            current: String::new(),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Report real progress from inside a check.
    pub fn progress(&self, message: impl Into<String>) {
        self.sink.emit(&RunEvent::Progress { id: self.current.clone(), message: message.into() });
    }
}

pub trait Check: Send + Sync {
    fn id(&self) -> &'static str;
    fn category(&self) -> Category;
    /// Environment this check runs in (ShipCheck per-environment checks).
    fn environment(&self) -> Option<String> {
        None
    }
    fn run(&self, ctx: &mut Context) -> CheckResult;
}

pub struct Outcome {
    pub results: Vec<CheckResult>,
    pub cancelled: bool,
}

/// Run checks in order. Stops early (and marks the rest skipped) only on cancellation.
pub fn run_checks(checks: &[Box<dyn Check>], ctx: &mut Context) -> Outcome {
    let total = checks.len();
    let sink = ctx.sink.clone();
    sink.emit(&RunEvent::Started { total });
    let mut results = Vec::with_capacity(total);
    let mut cancelled = false;
    for (i, c) in checks.iter().enumerate() {
        let index = i + 1;
        if ctx.is_cancelled() {
            cancelled = true;
            results.push(CheckResult::new(c.id(), c.category(), Status::Skipped, "cancelled"));
            continue;
        }
        ctx.current = c.id().to_string();
        sink.emit(&RunEvent::StepStarted { index, total, id: c.id().into() });
        let t = Instant::now();
        let mut r = c.run(ctx);
        r.duration_ms = t.elapsed().as_millis() as u64;
        ctx.logger.log(
            crate::logging::Category::Verification,
            crate::logging::Level::Info,
            &format!("{} -> {}", r.id, r.status.as_str()),
            serde_json::json!({ "summary": r.summary, "duration_ms": r.duration_ms }),
        );
        sink.emit(&RunEvent::StepFinished { index, total, result: r.clone() });
        results.push(r);
    }
    let verdict = crate::scoring::verdict(&results);
    sink.emit(&RunEvent::Finished { score: crate::scoring::score(&results), verdict, cancelled });
    Outcome { results, cancelled }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fixed(&'static str, Status);
    impl Check for Fixed {
        fn id(&self) -> &'static str {
            self.0
        }
        fn category(&self) -> Category {
            Category::Trust
        }
        fn run(&self, ctx: &mut Context) -> CheckResult {
            ctx.progress("working");
            CheckResult::new(self.0, Category::Trust, self.1, "x")
        }
    }

    #[test]
    fn emits_ordered_events_and_honours_cancellation() {
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let e2 = events.clone();
        let mut ctx = Context::new(Config::default(), VerifyTarget::default(), PathBuf::new(), Logger::null());
        ctx.sink = Arc::new(move |e: &RunEvent| {
            e2.lock().unwrap().push(match e {
                RunEvent::Started { .. } => "start".into(),
                RunEvent::StepStarted { id, .. } => format!("begin:{id}"),
                RunEvent::Progress { id, message } => format!("progress:{id}:{message}"),
                RunEvent::StepFinished { result, .. } => format!("end:{}", result.id),
                RunEvent::Finished { .. } => "finish".into(),
            });
        });
        let checks: Vec<Box<dyn Check>> = vec![Box::new(Fixed("a", Status::Pass)), Box::new(Fixed("b", Status::Pass))];
        let out = run_checks(&checks, &mut ctx);
        assert_eq!(out.results.len(), 2);
        assert_eq!(events.lock().unwrap().join(","), "start,begin:a,progress:a:working,end:a,begin:b,progress:b:working,end:b,finish");

        ctx.cancel.store(true, Ordering::Relaxed);
        let out = run_checks(&checks, &mut ctx);
        assert!(out.cancelled);
        assert!(out.results.iter().all(|r| r.status == Status::Skipped));
    }
}
