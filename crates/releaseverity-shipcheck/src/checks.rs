//! ShipCheck checks. One agent run per environment feeds the install / launch /
//! smoke / uninstall checks of that environment (the Environment Matrix rows).

use crate::runner::{find_agent, EnvRunner, HostRunner, RunInput, SandboxRunner};
use releaseverity_agent::{AgentReport, FailKind, PackageKind, ProgressLine, Smoke, Spec, StepReport, StepStatus};
use releaseverity_core::check::{Check, Context, ShipKind, ShipcheckTarget};
use releaseverity_core::model::{Category, CheckResult, FailureKind, Status};
use serde_json::{json, Value};

fn cache_key(env: &str) -> String {
    format!("shipcheck:{env}")
}

pub fn build_spec(t: &ShipcheckTarget, cfg: &releaseverity_core::config::Config) -> Spec {
    Spec {
        kind: match t.kind {
            ShipKind::Installer => PackageKind::Installer,
            ShipKind::Portable => PackageKind::Portable,
        },
        package: t.package.to_string_lossy().into_owned(),
        installer_args: t.installer_args.clone(),
        exe: t.exe.clone(),
        launch_args: t.launch_args.clone(),
        gui: t.gui,
        launch: t.launch,
        isolation: releaseverity_agent::Isolation::None, // set by the runner
        alive_secs: t.alive_secs.min(cfg.timeouts.launch_secs),
        install_timeout_secs: cfg.timeouts.install_secs,
        launch_timeout_secs: cfg.timeouts.launch_secs,
        smoke_timeout_secs: cfg.timeouts.smoke_secs,
        cleanup_timeout_secs: cfg.timeouts.cleanup_secs,
        smoke: t
            .smoke
            .iter()
            .map(|s| Smoke {
                name: s.name.clone(),
                args: s.args.clone(),
                expect_exit: s.expect_exit,
                expect_stdout: s.expect_stdout.clone(),
                timeout_secs: s.timeout_secs,
            })
            .collect(),
        uninstall: t.uninstall,
        max_memory_mb: cfg.security.max_memory_mb,
        max_processes: cfg.security.max_processes,
    }
}

/// Run the agent in `env` once and cache the outcome (report or error) in the context.
fn ensure_run(ctx: &mut Context, env: &str) -> Value {
    let key = cache_key(env);
    if let Some(v) = ctx.state.extra.get(&key) {
        return v.clone();
    }
    let outcome = execute(ctx, env);
    let v = match outcome {
        Ok(r) => json!({ "report": r }),
        Err(e) => json!({ "error": e.message, "suggestion": e.suggestion, "msg": e.msg, "suggestion_msg": e.suggestion_msg }),
    };
    ctx.state.extra.insert(key, v.clone());
    v
}

fn execute(ctx: &mut Context, env: &str) -> Result<AgentReport, crate::runner::RunnerError> {
    use crate::runner::RunnerError;
    let target = ctx.target.shipcheck.clone().ok_or_else(|| RunnerError::key("m.ship.nopackage", &[]))?;
    let runner: Box<dyn EnvRunner> = match env {
        "host" => {
            Box::new(HostRunner { allowed: ctx.config.security.allow_host_execution, isolation: releaseverity_agent::Isolation::None })
        }
        "appcontainer" => Box::new(HostRunner { allowed: true, isolation: releaseverity_agent::Isolation::AppContainer }),
        "windows-sandbox" => Box::new(SandboxRunner),
        other => return Err(RunnerError::key("m.ship.badenv", &[("env", other)]).hint_key("m.ship.badenv.fix")),
    };
    runner.availability()?;
    let agent = find_agent().ok_or_else(|| RunnerError::key("m.ship.noagent", &[]).hint_key("m.ship.noagent.fix"))?;
    let spec = build_spec(&target, &ctx.config);
    let stage = ctx.work_dir.join(format!("shipcheck-{env}"));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|e| RunnerError::new(e.to_string()))?;
    let input = RunInput {
        spec: &spec,
        package: &target.package,
        stage: &stage,
        agent: &agent,
        allow_network: ctx.config.security.allow_network_in_sandbox,
    };
    let sink = ctx.sink.clone();
    let current = format!("shipcheck.{env}");
    let logger = ctx.logger.clone();
    let mut on_progress = |l: &ProgressLine| {
        let msg = match l {
            ProgressLine::Start { id, note } => format!("[{env}] {id}: {note}"),
            ProgressLine::End { step } => format!("[{env}] {} → {}", step.id, step_word(step.status)),
        };
        logger.info(releaseverity_core::logging::Category::Shipcheck, &msg);
        sink.emit(&releaseverity_core::check::RunEvent::Progress { id: current.clone(), message: msg });
    };
    let r = runner.run(&input, &mut on_progress, &ctx.cancel);
    // Cleanup guarantee: the staging directory never outlives the run.
    let _ = std::fs::remove_dir_all(&stage);
    r
}

fn step_word(s: StepStatus) -> &'static str {
    match s {
        StepStatus::Pass => "pass",
        StepStatus::Warn => "warn",
        StepStatus::Fail => "fail",
        StepStatus::Skipped => "skipped",
    }
}

fn status_of(s: StepStatus) -> Status {
    match s {
        StepStatus::Pass => Status::Pass,
        StepStatus::Warn => Status::Warn,
        StepStatus::Fail => Status::Fail,
        StepStatus::Skipped => Status::Skipped,
    }
}

fn failure_of(k: FailKind) -> FailureKind {
    match k {
        FailKind::Crashed => FailureKind::Crashed,
        FailKind::Hung => FailureKind::Hung,
        FailKind::Timeout => FailureKind::Timeout,
        FailKind::ExitCode => FailureKind::ExitCode,
        FailKind::Other => FailureKind::Other,
    }
}

fn from_step(id: &str, cat: Category, env: &str, s: &StepReport) -> CheckResult {
    let mut r = CheckResult::new(id, cat, status_of(s.status), s.message.clone());
    if let Some(m) = crate::agent_msgs::localize(&s.message) {
        let args: Vec<(&str, &str)> = m.args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        r = r.summary_key(&m.key, &args);
    }
    r.environment = Some(env.into());
    r.exit_code = s.exit_code;
    r.failure_kind = s.fail_kind.map(failure_of);
    r.evidence = s.facts.clone();
    if !s.log.trim().is_empty() {
        r.details = Some(s.log.clone());
    }
    if s.status == StepStatus::Fail {
        let (cause, hint, cargs) = diagnose(id, s);
        let cargs: Vec<(&str, &str)> = cargs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        r = r.cause_key(cause, &cargs).suggestion_key(hint, &[]);
    }
    r
}

/// (cause key, suggestion key, cause args) for a failed step.
fn diagnose(id: &str, s: &StepReport) -> (&'static str, &'static str, Vec<(&'static str, String)>) {
    match (id, s.fail_kind) {
        ("install.install", Some(FailKind::ExitCode)) => {
            ("m.ship.diag.install-exit", "m.ship.diag.install-exit.fix", vec![("code", s.exit_code.unwrap_or(-1).to_string())])
        }
        (_, Some(FailKind::Crashed)) => ("m.ship.diag.crash", "m.ship.diag.crash.fix", vec![]),
        (_, Some(FailKind::Hung)) => ("m.ship.diag.hung", "m.ship.diag.hung.fix", vec![]),
        (_, Some(FailKind::Timeout)) => ("m.ship.diag.timeout", "m.ship.diag.timeout.fix", vec![]),
        (_, Some(FailKind::ExitCode)) => ("m.ship.diag.exitcode", "m.ship.diag.exitcode.fix", vec![]),
        _ => ("m.ship.diag.other", "m.ship.diag.other.fix", vec![]),
    }
}

fn env_error(id: &str, cat: Category, env: &str, v: &Value) -> CheckResult {
    let mut r = CheckResult::new(id, cat, Status::Error, v["error"].as_str().unwrap_or("environment failed").to_string());
    if let Ok(m) = serde_json::from_value::<releaseverity_core::model::Msg>(v["msg"].clone()) {
        r.summary_msg = Some(m);
    }
    r.environment = Some(env.into());
    r.suggestion = v["suggestion"].as_str().map(str::to_string);
    if let Ok(m) = serde_json::from_value::<releaseverity_core::model::Msg>(v["suggestion_msg"].clone()) {
        r.suggestion_msg = Some(m);
    }
    r
}

fn report_of(v: &Value) -> Option<AgentReport> {
    serde_json::from_value(v["report"].clone()).ok()
}

fn step<'a>(r: &'a AgentReport, id: &str) -> Option<&'a StepReport> {
    r.steps.iter().find(|s| s.id == id)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Install,
    Launch,
    Smoke,
    Uninstall,
}

pub struct EnvCheck {
    env: String,
    kind: Kind,
    id: &'static str,
}

impl Check for EnvCheck {
    fn id(&self) -> &'static str {
        self.id
    }
    fn environment(&self) -> Option<String> {
        Some(self.env.clone())
    }
    fn category(&self) -> Category {
        match self.kind {
            Kind::Install | Kind::Uninstall => Category::Installation,
            _ => Category::Runtime,
        }
    }
    fn run(&self, ctx: &mut Context) -> CheckResult {
        let env = self.env.clone();
        let cat = self.category();
        if self.kind == Kind::Uninstall && ctx.target.shipcheck.as_ref().is_some_and(|t| !t.uninstall) {
            let mut r = CheckResult::msg(self.id, cat, Status::Skipped, "m.ship.disabled-uninstall", &[]);
            r.environment = Some(env);
            return r;
        }
        if self.kind == Kind::Install {
            ctx.progress(format!("preparing a clean {env} environment"));
        }
        let v = ensure_run(ctx, &env);
        let Some(rep) = report_of(&v) else {
            return env_error(self.id, cat, &env, &v);
        };
        let r = match self.kind {
            Kind::Install => {
                let inst = step(&rep, "install");
                let files = step(&rep, "files");
                match (inst, files) {
                    (Some(i), _) if i.status != StepStatus::Pass => from_step(self.id, cat, &env, i),
                    (_, Some(f)) if f.status != StepStatus::Pass => {
                        let mut r = from_step(self.id, cat, &env, f);
                        if let Some(i) = inst {
                            r.exit_code = i.exit_code;
                        }
                        r
                    }
                    (Some(i), Some(f)) => {
                        let mut r = from_step(self.id, cat, &env, f);
                        r.exit_code = i.exit_code;
                        r.details = Some(i.log.clone()).filter(|l| !l.trim().is_empty());
                        r
                    }
                    (Some(i), None) => from_step(self.id, cat, &env, i),
                    _ => return incomplete(self.id, cat, &env),
                }
            }
            Kind::Launch => match step(&rep, "launch") {
                Some(s) => from_step(self.id, cat, &env, s),
                None => return incomplete(self.id, cat, &env),
            },
            Kind::Uninstall => match step(&rep, "uninstall") {
                Some(s) => from_step(self.id, cat, &env, s),
                None => return incomplete(self.id, cat, &env),
            },
            Kind::Smoke => {
                let smokes: Vec<&StepReport> = rep.steps.iter().filter(|s| s.id.starts_with("smoke:")).collect();
                if smokes.is_empty() {
                    let mut r =
                        CheckResult::msg(self.id, cat, Status::Skipped, "m.ship.nosmoke", &[]).suggestion_key("m.ship.nosmoke.fix", &[]);
                    r.environment = Some(env);
                    return r;
                }
                let pass = smokes.iter().filter(|s| s.status == StepStatus::Pass).count();
                let failed: Vec<_> = smokes.iter().filter(|s| s.status == StepStatus::Fail).collect();
                let all_skipped = smokes.iter().all(|s| s.status == StepStatus::Skipped);
                let lines: Vec<String> = smokes
                    .iter()
                    .map(|s| format!("{} {} — {}", step_word(s.status), s.id.trim_start_matches("smoke:"), s.message))
                    .collect();
                let (pass_s, total_s) = (pass.to_string(), smokes.len().to_string());
                let mut r = if let Some(f) = failed.first() {
                    let mut r = from_step(self.id, cat, &env, f);
                    r = r.summary_key("m.ship.smoke-fail", &[("pass", &pass_s), ("total", &total_s)]);
                    r
                } else if all_skipped {
                    CheckResult::msg(self.id, cat, Status::Skipped, "m.ship.smoke-notrun", &[])
                } else {
                    CheckResult::msg(self.id, cat, Status::Pass, "m.ship.smoke-ok", &[("pass", &pass_s), ("total", &total_s)])
                };
                r.environment = Some(env);
                r.details = Some(lines.join("\n"));
                r.evidence = json!(smokes
                    .iter()
                    .map(|s| json!({"id": s.id, "status": step_word(s.status), "exit_code": s.exit_code, "message": s.message}))
                    .collect::<Vec<_>>());
                r
            }
        };
        r
    }
}

fn incomplete(id: &str, cat: Category, env: &str) -> CheckResult {
    let mut r = CheckResult::msg(id, cat, Status::Error, "m.ship.incomplete", &[]);
    r.environment = Some(env.into());
    r
}

/// All ShipCheck checks for the requested environments (+ documentation checks).
pub fn checks(target: &ShipcheckTarget) -> Vec<Box<dyn Check>> {
    let mut v: Vec<Box<dyn Check>> = crate::docs::checks();
    v.extend(env_checks(target));
    v
}

/// Only the per-environment install/runtime checks.
/// `auto` picks the strongest isolation that can run this package on this machine:
/// portable → ReleaseVerity's own AppContainer sandbox (every Windows edition);
/// installer → Windows Sandbox (a VM; the only built-in option that can host an installer).
pub fn resolve_env(env: &str, kind: ShipKind) -> String {
    if env != "auto" {
        return env.to_string();
    }
    match kind {
        ShipKind::Portable => "appcontainer".into(),
        ShipKind::Installer => "windows-sandbox".into(),
    }
}

pub fn env_checks(target: &ShipcheckTarget) -> Vec<Box<dyn Check>> {
    let mut v: Vec<Box<dyn Check>> = vec![];
    let mut seen: Vec<String> = vec![];
    for env in target.environments.iter().map(|e| resolve_env(e, target.kind)) {
        if seen.contains(&env) {
            continue;
        }
        seen.push(env.clone());
        for (kind, id) in [
            (Kind::Install, "install.install"),
            (Kind::Launch, "runtime.launch"),
            (Kind::Smoke, "runtime.smoke"),
            (Kind::Uninstall, "install.uninstall"),
        ] {
            v.push(Box::new(EnvCheck { env: env.clone(), kind, id }));
        }
    }
    v
}

pub fn _use_repro_for_docs() -> bool {
    releaseverity_repro::git::available()
}
