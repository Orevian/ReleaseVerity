//! `releaseverity` — command line front end. Contains no business logic: every
//! operation goes through `releaseverity-services`, exactly like the desktop app.

mod ui;

use anyhow::{bail, Context as _, Result};
use clap::{Args, Parser, Subcommand};
use releaseverity_services::core::check::RunEvent;
use releaseverity_services::core::check::ShipcheckTarget;
use releaseverity_services::core::config::{Config, Paths};
use releaseverity_services::core::i18n::I18n;
use releaseverity_services::core::model::*;
use releaseverity_services::core::report::{check_title, environment_matrix, verdict_label, Format};
use releaseverity_services::repro::{self, assets, diff, inspect, sbom};
use releaseverity_services::request::{self, PackageOptions};
use releaseverity_services::{environments, App, VerifyRequest};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use ui::{pad, table, Style};

#[derive(Parser)]
#[command(name = "releaseverity", version, about = "Release verification & software quality platform", propagate_version = true)]
struct Cli {
    /// Disable coloured output (also honours NO_COLOR).
    #[arg(long, global = true)]
    no_color: bool,
    /// Use ASCII symbols instead of ✓ ⚠ ✗.
    #[arg(long, global = true)]
    ascii: bool,
    /// Machine-readable JSON output where supported.
    #[arg(long, global = true)]
    json: bool,
    /// Data directory (default: %APPDATA%\ReleaseVerity, or ./data in portable mode).
    #[arg(long, global = true, env = "RELEASEVERITY_HOME")]
    home: Option<PathBuf>,
    /// Output language: en | tr (default: from config).
    #[arg(long, global = true)]
    lang: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the data directory, default config and database.
    Init,
    /// Manage registered projects.
    #[command(subcommand)]
    Project(ProjectCmd),
    /// Verify a release with all available engines.
    Verify(VerifyArgs),
    /// Repro Engine: supply-chain and reproducibility verification.
    #[command(subcommand)]
    Repro(ReproCmd),
    /// ShipCheck Engine: installation and runtime testing.
    #[command(subcommand)]
    Shipcheck(ShipCmd),
    /// Inspect release artifacts.
    #[command(subcommand)]
    Artifact(ArtifactCmd),
    /// Inspect SBOM files.
    #[command(subcommand)]
    Sbom(SbomCmd),
    /// Generate and export verification reports.
    #[command(subcommand)]
    Report(ReportCmd),
    /// List and inspect execution environments.
    #[command(subcommand)]
    Environment(EnvCmd),
    /// GitHub account, releases and check publishing.
    #[command(subcommand)]
    Github(GithubCmd),
    /// Check that ReleaseVerity's tools and storage work.
    Doctor,
    /// View or change configuration.
    Config {
        #[command(subcommand)]
        action: Option<ConfigCmd>,
    },
    /// Print version information.
    Version,
}

#[derive(Subcommand)]
enum ProjectCmd {
    /// Register a project.
    Add {
        name: String,
        /// Repository URL (e.g. https://github.com/owner/repo).
        #[arg(long)]
        repo: Option<String>,
        /// Local repository path.
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value = "main")]
        branch: String,
    },
    List,
    Remove {
        name: String,
    },
}

/// What ShipCheck installs and runs in a clean environment.
#[derive(Args, Clone, Default)]
struct PackageArgs {
    /// Installer (.exe/.msi), portable zip, or portable directory to test in a clean environment.
    #[arg(long)]
    package: Option<PathBuf>,
    /// installer | portable (default: guessed from the package).
    #[arg(long, value_parser = ["installer", "portable"])]
    package_kind: Option<String>,
    /// Silent-install switches for .exe installers (default: Inno Setup style; .msi uses /qn).
    #[arg(long, allow_hyphen_values = true)]
    installer_args: Option<String>,
    /// Main executable inside the install/portable directory (auto-detected).
    #[arg(long)]
    exe: Option<String>,
    /// Arguments for the launch test.
    #[arg(long, allow_hyphen_values = true)]
    launch_args: Option<String>,
    /// The app is a GUI: it must stay running and responsive instead of exiting 0.
    #[arg(long)]
    gui: bool,
    /// Smoke test (repeatable): "<args>" or "<args> => <expected output text>". Exit code 0 is expected.
    #[arg(long, allow_hyphen_values = true)]
    smoke: Vec<String>,
    /// Environments: auto (default), appcontainer (built-in sandbox, portable), windows-sandbox (VM), host (no isolation).
    #[arg(long = "env", value_delimiter = ',')]
    envs: Vec<String>,
    /// Skip the uninstall test.
    #[arg(long)]
    no_uninstall: bool,
    /// Seconds a GUI app must stay alive.
    #[arg(long, default_value_t = 5)]
    alive: u64,
}

#[derive(Args, Clone)]
struct VerifyArgs {
    #[command(flatten)]
    pkg: PackageArgs,
    /// Optional literal `release` (so `releaseverity verify release …` reads naturally).
    #[arg(value_parser = ["release"])]
    kind: Option<String>,
    /// Repository URL or local path.
    #[arg(long)]
    repo: Option<String>,
    /// Registered project name.
    #[arg(long, short = 'p')]
    project: Option<String>,
    /// Release tag, e.g. v1.4.0.
    #[arg(long, alias = "tag", short = 'r')]
    release: Option<String>,
    /// Release asset file or directory (repeatable): artifacts, SHA256SUMS, signatures, SBOMs, attestations.
    #[arg(long, short = 'a')]
    asset: Vec<PathBuf>,
    /// A local rebuild of the artifact to compare bit-for-bit with the release artifact.
    #[arg(long)]
    rebuilt: Option<PathBuf>,
    /// Only run these checks: source, checksum, signature, provenance, sbom, repro.
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Also write reports in these formats: html, json, markdown.
    #[arg(long, value_delimiter = ',')]
    report: Vec<String>,
    /// Directory for --report output (default: the ReleaseVerity reports directory).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Treat warnings as failure (exit code 1).
    #[arg(long)]
    strict: bool,
    /// Publish the verdict on the release commit as a GitHub Check (needs a token).
    #[arg(long)]
    publish: bool,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ReproCmd {
    /// Run the Repro Engine checks only.
    Verify(VerifyArgs),
    /// Compare a release artifact with a local build and explain the differences.
    Compare { release: PathBuf, local: PathBuf },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ShipCmd {
    /// Install, launch, smoke-test and uninstall a package in a clean environment.
    Run(VerifyArgs),
    /// Test only installation and uninstallation.
    Install(VerifyArgs),
    /// Install, launch and run the smoke tests (requires --smoke).
    Smoke(VerifyArgs),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Verify,
    Repro,
    ShipRun,
    ShipInstall,
    ShipSmoke,
}

#[derive(Subcommand)]
enum ArtifactCmd {
    Inspect { path: PathBuf },
}

#[derive(Subcommand)]
enum SbomCmd {
    Inspect { path: PathBuf },
}

#[derive(Subcommand)]
enum ReportCmd {
    /// Render a stored run (default: the latest) to the reports directory.
    Generate {
        #[arg(long)]
        run: Option<i64>,
        #[arg(long, default_value = "html")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Export a stored run to a specific file.
    Export {
        #[arg(long)]
        run: Option<i64>,
        #[arg(long, default_value = "html")]
        format: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// List recent verification runs.
    List {
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
}

#[derive(Subcommand)]
enum GithubCmd {
    /// Store a personal access token in Windows Credential Manager.
    Login {
        /// The token (prefer --stdin so it does not appear in shell history).
        #[arg(long)]
        token: Option<String>,
        /// Read the token from standard input.
        #[arg(long)]
        stdin: bool,
    },
    /// Remove the stored token.
    Logout,
    /// Show whether a token is available and which account it belongs to.
    Status,
    /// List the releases of a repository.
    Releases { repo: String },
}

#[derive(Subcommand)]
enum EnvCmd {
    List,
    Inspect { id: String },
}

#[derive(Subcommand)]
enum ConfigCmd {
    List,
    Path,
    Get { key: String },
    Set { key: String, value: String },
}

const EXIT_FAILED: u8 = 1;
const EXIT_ERROR: u8 = 2;
const EXIT_INCONCLUSIVE: u8 = 3;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let style = Style::detect(cli.no_color, cli.ascii);
    match run(cli, style) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{} {e:#}", if style.color { "\x1b[31merror:\x1b[0m" } else { "error:" });
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn open_app(cli: &Cli) -> Result<App> {
    let paths = cli.home.clone().map(Paths::new).unwrap_or_else(Paths::discover);
    let mut app = App::open(paths).context("opening ReleaseVerity data directory")?;
    if let Some(l) = &cli.lang {
        anyhow::ensure!(matches!(l.as_str(), "en" | "tr"), "--lang must be en or tr");
        app.i18n = I18n::new(l);
    }
    Ok(app)
}

fn run(cli: Cli, st: Style) -> Result<u8> {
    match &cli.cmd {
        Cmd::Version => {
            println!("releaseverity {}", releaseverity_services::core::VERSION);
            return Ok(0);
        }
        // These need no storage and must keep working when the data directory is not writable
        // (read-only media, sandboxes, locked-down machines).
        Cmd::Environment(e) => {
            return environment(
                match e {
                    EnvCmd::List => EnvCmd::List,
                    EnvCmd::Inspect { id } => EnvCmd::Inspect { id: id.clone() },
                },
                cli.json,
                st,
            );
        }
        Cmd::Doctor => return doctor(&cli, st),
        Cmd::Artifact(ArtifactCmd::Inspect { path }) => return artifact_inspect(path, cli.json, st),
        Cmd::Sbom(SbomCmd::Inspect { path }) => return sbom_inspect(path, cli.json, st),
        Cmd::Repro(ReproCmd::Compare { release, local }) => {
            let app = open_app(&cli).ok();
            let i18n = app.map(|a| a.i18n).unwrap_or_else(|| I18n::new(cli.lang.as_deref().unwrap_or("en")));
            return repro_compare(release, local, cli.json, st, &i18n);
        }
        _ => {}
    }
    let app = open_app(&cli)?;
    match cli.cmd {
        Cmd::Init => init(&app),
        Cmd::Project(p) => project(&app, p, cli.json),
        Cmd::Verify(a) => verify(&app, a, Mode::Verify, cli.json, st),
        Cmd::Repro(ReproCmd::Verify(a)) => verify(&app, a, Mode::Repro, cli.json, st),
        Cmd::Shipcheck(ShipCmd::Run(a)) => verify(&app, a, Mode::ShipRun, cli.json, st),
        Cmd::Shipcheck(ShipCmd::Install(a)) => verify(&app, a, Mode::ShipInstall, cli.json, st),
        Cmd::Shipcheck(ShipCmd::Smoke(a)) => verify(&app, a, Mode::ShipSmoke, cli.json, st),
        Cmd::Report(r) => report(&app, r, cli.json, st),
        Cmd::Github(g) => github(&app, g, cli.json, st),
        Cmd::Config { action } => config(app, action),
        Cmd::Version | Cmd::Doctor | Cmd::Environment(_) | Cmd::Artifact(_) | Cmd::Sbom(_) | Cmd::Repro(ReproCmd::Compare { .. }) => {
            unreachable!()
        }
    }
}

fn init(app: &App) -> Result<u8> {
    if !app.paths.config_file().exists() {
        app.config.save(&app.paths.config_file())?;
    }
    println!("ReleaseVerity initialised");
    println!("  data     {}", app.paths.root.display());
    println!("  config   {}", app.paths.config_file().display());
    println!("  database {}", app.paths.database().display());
    println!("  logs     {}", app.paths.logs_dir().display());
    Ok(0)
}

fn project(app: &App, cmd: ProjectCmd, json: bool) -> Result<u8> {
    match cmd {
        ProjectCmd::Add { name, repo, path, branch } => {
            if let Some(p) = &path {
                anyhow::ensure!(repro::git::is_repo(p), "{} is not a git repository", p.display());
            }
            let abs = path.map(|p| std::fs::canonicalize(&p).unwrap_or(p).to_string_lossy().trim_start_matches(r"\\?\").to_string());
            let p = app.db.add_project(&name, repo.as_deref(), abs.as_deref(), &branch)?;
            println!("Added project {} (#{})", p.name, p.id);
        }
        ProjectCmd::List => {
            let ps = app.db.list_projects()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ps)?);
                return Ok(0);
            }
            if ps.is_empty() {
                println!("No projects yet. Add one: releaseverity project add <name> --repo <url>");
                return Ok(0);
            }
            let mut rows = vec![vec!["NAME".into(), "REPOSITORY".into(), "BRANCH".into(), "LAST RUN".into(), "SCORE".into()]];
            for p in ps {
                let last = app.db.list_runs(1, Some(p.id))?.into_iter().next();
                rows.push(vec![
                    p.name.clone(),
                    p.repo_url.clone().or(p.local_path.clone()).unwrap_or_default(),
                    p.default_branch.clone(),
                    last.as_ref().map(|r| format!("{} {}", r.tag, verdict_label(&app.i18n, r.verdict))).unwrap_or_else(|| "-".into()),
                    last.and_then(|r| r.score).map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                ]);
            }
            println!("{}", table(&rows));
        }
        ProjectCmd::Remove { name } => {
            if app.db.remove_project(&name)? {
                println!("Removed project {name}");
            } else {
                bail!("no project named {name:?}");
            }
        }
    }
    Ok(0)
}

fn build_shipcheck(p: &PackageArgs, cfg: &Config, mode: Mode) -> Result<Option<ShipcheckTarget>> {
    if p.package.is_none() {
        if matches!(mode, Mode::ShipRun | Mode::ShipInstall | Mode::ShipSmoke) {
            bail!("--package <installer|zip|dir> is required for ShipCheck");
        }
        return Ok(None);
    }
    if mode == Mode::ShipSmoke {
        anyhow::ensure!(!p.smoke.is_empty(), "`shipcheck smoke` needs at least one --smoke \"<args>\"");
    }
    let opts = PackageOptions {
        package: p.package.clone(),
        kind: p.package_kind.clone(),
        installer_args: p.installer_args.clone(),
        exe: p.exe.clone(),
        launch_args: p.launch_args.clone(),
        gui: p.gui,
        smoke: if mode == Mode::ShipInstall { vec![] } else { p.smoke.clone() },
        environments: p.envs.clone(),
        launch: mode != Mode::ShipInstall,
        uninstall: !p.no_uninstall,
        alive_secs: p.alive,
    };
    request::build_shipcheck_target(&opts, cfg)
}

fn verify(app: &App, a: VerifyArgs, mode: Mode, json: bool, st: Style) -> Result<u8> {
    let shipcheck = build_shipcheck(&a.pkg, &app.config, mode)?;
    let package_only = shipcheck.is_some() && a.repo.is_none() && a.project.is_none();
    let tag = a.release.clone().unwrap_or_default();
    if tag.is_empty() && !package_only {
        bail!("--release <tag> is required (e.g. --release v1.4.0)");
    }
    let mut only = a.only.clone();
    if only.is_empty() {
        match mode {
            Mode::Repro => only = App::repro_names(),
            Mode::ShipRun | Mode::ShipSmoke => {
                only = ["install", "launch", "smoke", "uninstall"].map(String::from).to_vec();
                if mode == Mode::ShipRun && !package_only {
                    only.push("docs".into());
                }
            }
            Mode::ShipInstall => {
                only = vec!["install".into(), "uninstall".into()];
                if !package_only {
                    only.push("docs".into());
                }
            }
            Mode::Verify => {}
        }
    }
    let formats: Vec<Format> = a.report.iter().map(|f| Format::parse(f)).collect::<Result<_>>()?;
    let req = VerifyRequest {
        project: a.project.clone(),
        repo: a.repo.clone(),
        tag: tag.clone(),
        assets: request::expand_assets(&a.asset)?,
        rebuilt: a.rebuilt.clone(),
        shipcheck,
        only,
    };

    let i18n = app.i18n.clone();
    let repo_display = a
        .repo
        .clone()
        .or_else(|| a.project.clone())
        .or_else(|| a.pkg.package.as_ref().map(|p| p.display().to_string()))
        .unwrap_or_default();
    if !json {
        println!("{}", st.bold(&i18n.t("app.name")));
        println!("{}\n", i18n.t("app.tagline"));
        println!("{}{}", pad(&i18n.t("cli.repository"), 16), repo_display);
        if tag.is_empty() {
            println!();
        } else {
            println!("{}{}\n", pad(&i18n.t("cli.release"), 16), tag);
        }
    }
    let live = Mutex::new(());
    let sink: Arc<dyn releaseverity_services::core::check::EventSink> = if json {
        App::null_sink()
    } else {
        let i18n = i18n.clone();
        Arc::new(move |e: &RunEvent| {
            let _g = live.lock().unwrap_or_else(|p| p.into_inner());
            match e {
                RunEvent::StepStarted { index, total, id } if st.tty && st.color => {
                    use std::io::Write;
                    print!("[{index}/{total}] {} {}", pad(&check_title(&i18n, id), 26), st.dim("…"));
                    let _ = std::io::stdout().flush();
                }
                RunEvent::Progress { message, .. } if st.tty && st.color => {
                    use std::io::Write;
                    print!("\r\x1b[K  {}", st.dim(message));
                    let _ = std::io::stdout().flush();
                }
                RunEvent::StepFinished { index, total, result } => {
                    let prefix = if st.tty && st.color { "\r\x1b[K" } else { "" };
                    let env = result.environment.as_deref().map(|e| format!(" {}", st.dim(&format!("[{e}]")))).unwrap_or_default();
                    println!(
                        "{prefix}[{index}/{total}] {} {}{env}",
                        pad(&check_title(&i18n, &result.id), 26),
                        st.status_symbol(result.status)
                    );
                }
                _ => {}
            }
        })
    };
    let run = app.verify(req, sink, Arc::new(AtomicBool::new(false)))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&run)?);
    } else {
        print_findings(&run, &i18n, st);
        print_matrix(&run, &i18n, st);
        println!();
        println!("{}{}", pad(&i18n.t("cli.commit"), 16), run.commit.as_deref().unwrap_or("-"));
        println!("{}", i18n.tf("cli.score", &[("score", &run.score.map(|s| s.to_string()).unwrap_or_else(|| "-".into()))]));
        let v = run.verdict.unwrap_or(Verdict::Inconclusive);
        println!("{}", i18n.tf("cli.status", &[("status", &st.verdict(v, &verdict_label(&i18n, Some(v))))]));
    }
    if a.publish {
        match app.publish_check(run.id) {
            Ok(releaseverity_services::github::client::Published::CheckRun(u)) => println!("GitHub check published: {u}"),
            Ok(releaseverity_services::github::client::Published::Status(u)) => {
                println!("GitHub commit status published (the token cannot create check runs): {u}")
            }
            Err(e) => eprintln!("could not publish the GitHub check: {e:#}"),
        }
    }
    for f in formats {
        let out = a.out.as_ref().map(|d| d.join(format!("releaseverity-run-{}.{}", run.id, f.extension())));
        let p = app.generate_report(run.id, f, out.as_deref())?;
        if !json {
            println!("{}", i18n.tf("cli.report_written", &[("path", &p.display().to_string())]));
        }
    }
    Ok(match run.verdict {
        Some(Verdict::Failed) => EXIT_FAILED,
        Some(Verdict::VerifiedWithWarnings) if a.strict => EXIT_FAILED,
        Some(Verdict::Inconclusive) | None => EXIT_INCONCLUSIVE,
        _ => 0,
    })
}

fn print_matrix(run: &Run, i18n: &I18n, st: Style) {
    let Some(m) = environment_matrix(&run.results) else { return };
    println!("\n{}", st.bold("Environment Matrix"));
    let mut header = vec![String::new()];
    header.extend(m.environments.iter().cloned());
    let mut rows = vec![header];
    for (id, cells) in &m.rows {
        let mut row = vec![check_title(i18n, id)];
        row.extend(cells.iter().map(|c| c.as_ref().map(|r| r.status.symbol().to_string()).unwrap_or_else(|| "-".into())));
        rows.push(row);
    }
    // Symbols are width-1; colour them after alignment.
    let colored = table(&rows)
        .replace('✓', &st.status_symbol(Status::Pass))
        .replace('⚠', &st.status_symbol(Status::Warn))
        .replace('✗', &st.status_symbol(Status::Fail));
    println!("{colored}");
}

fn print_findings(run: &Run, i18n: &I18n, st: Style) {
    let notable: Vec<_> = run.results.iter().filter(|r| matches!(r.status, Status::Warn | Status::Fail | Status::Error)).collect();
    if notable.is_empty() {
        return;
    }
    println!();
    for r in notable {
        let head = match r.failure_kind {
            Some(k) => k.label().to_string(),
            None => match r.status {
                Status::Fail => "Verification failed".into(),
                Status::Error => "Could not verify".into(),
                _ => "Warning".into(),
            },
        };
        println!("{} {} — {}", st.status_symbol(r.status), st.bold(&check_title(i18n, &r.id)), head);
        println!("    {}", r.summary_text(i18n));
        if let Some(c) = r.cause_text(i18n) {
            println!("    {}: {c}", i18n.t("error.cause"));
        }
        if let Some(c) = r.exit_code {
            println!("    Exit code: {c}");
        }
        if let Some(d) = &r.details {
            for l in d.lines().take(12) {
                println!("      {}", st.dim(l));
            }
            if d.lines().count() > 12 {
                println!("      {}", st.dim("… (full details in the report)"));
            }
        }
        if let Some(s) = r.suggestion_text(i18n) {
            println!("    {}: {s}", i18n.t("error.suggestion"));
        }
    }
}

fn repro_compare(release: &Path, local: &Path, json: bool, st: Style, i18n: &I18n) -> Result<u8> {
    let (ha, hb) = (releaseverity_services::core::hash::hash_file(release)?, releaseverity_services::core::hash::hash_file(local)?);
    let same = ha.sha256 == hb.sha256;
    let rep = if same { None } else { Some(diff::compare(release, local)?) };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "reproducible": same,
                "release": {"file": release, "sha256": ha.sha256, "size": ha.size},
                "local": {"file": local, "sha256": hb.sha256, "size": hb.size},
                "diff": rep,
            }))?
        );
        return Ok(if same { 0 } else { EXIT_FAILED });
    }
    println!("{}\n  SHA256: {}\n", st.bold("Release Artifact"), ha.sha256);
    println!("{}\n  SHA256: {}\n", st.bold("Local Build"), hb.sha256);
    let key = if same { "repro.result.reproducible" } else { "repro.result.not_reproducible" };
    println!("Result: {}", st.verdict(if same { Verdict::Verified } else { Verdict::Failed }, &i18n.t(key)));
    if let Some(r) = rep {
        println!("\nDifferences ({} of {} bytes, kind: {})", r.total_diff_bytes, r.size_a.max(r.size_b), r.kind);
        let mut rows = vec![vec!["REGION".into(), "OF DIFF".into(), "REGION CHANGED".into(), "BYTES".into()]];
        for x in r.regions.iter().filter(|x| x.diff_bytes > 0 || r.kind == "zip") {
            rows.push(vec![x.name.clone(), format!("{:.2}%", x.share_pct), format!("{:.2}%", x.changed_pct), x.diff_bytes.to_string()]);
        }
        println!("{}", table(&rows));
        if r.causes.is_empty() {
            println!("\nNo specific cause could be determined from the file structure.");
        } else {
            println!("\nProbable causes (derived from the bytes):");
            for c in &r.causes {
                println!(
                    "  • {}",
                    releaseverity_services::core::report::diff_cause_text(i18n, &serde_json::to_value(c).unwrap_or_default())
                );
                if !c.evidence.is_null() {
                    println!("    {}", st.dim(&c.evidence.to_string().chars().take(300).collect::<String>()));
                }
            }
        }
    }
    Ok(if same { 0 } else { EXIT_FAILED })
}

fn artifact_inspect(path: &Path, json: bool, st: Style) -> Result<u8> {
    let i = inspect::inspect(path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"artifact": i.info, "details": i.details}))?);
        return Ok(0);
    }
    println!("{}", st.bold(&i.info.name));
    println!("  kind    {}", i.info.kind);
    println!("  size    {} bytes", i.info.size);
    println!("  sha256  {}", i.info.sha256);
    println!("  sha512  {}", i.info.sha512);
    if let Some(o) = i.details.as_object() {
        for (k, v) in o.iter().filter(|(k, _)| !matches!(k.as_str(), "sections" | "sample")) {
            println!(
                "  {:<7} {}",
                k,
                match v {
                    serde_json::Value::String(s) => s.clone(),
                    o => o.to_string(),
                }
            );
        }
        if let Some(secs) = o.get("sections").and_then(|s| s.as_array()) {
            println!("  sections");
            for s in secs {
                println!(
                    "    {:<12} {}",
                    s["name"].as_str().unwrap_or("?"),
                    s.get("raw_size").or(s.get("size")).map(|v| v.to_string()).unwrap_or_default()
                );
            }
        }
    }
    Ok(0)
}

fn sbom_inspect(path: &Path, json: bool, st: Style) -> Result<u8> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let s = sbom::parse(&text).with_context(|| format!("{} is not a valid SBOM", path.display()))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
    } else {
        println!("{}", st.bold(&assets::file_name(path)));
        println!("  format      {} {}", s.format, s.spec_version);
        println!("  components  {} ({} with version, {} with license)", s.components, s.with_version, s.with_license);
        for i in &s.issues {
            println!("  {} {i}", st.status_symbol(Status::Warn));
        }
    }
    Ok(if s.issues.is_empty() { 0 } else { EXIT_FAILED })
}

fn report(app: &App, cmd: ReportCmd, json: bool, st: Style) -> Result<u8> {
    let latest = || -> Result<i64> { Ok(app.db.list_runs(1, None)?.into_iter().next().context("no verification runs yet")?.id) };
    match cmd {
        ReportCmd::Generate { run, format, out } => {
            let p = app.generate_report(run.map_or_else(latest, Ok)?, Format::parse(&format)?, out.as_deref())?;
            println!("{}", p.display());
        }
        ReportCmd::Export { run, format, out } => {
            let p = app.generate_report(run.map_or_else(latest, Ok)?, Format::parse(&format)?, Some(&out))?;
            println!("{}", p.display());
        }
        ReportCmd::List { limit } => {
            let runs = app.db.list_runs(limit, None)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&runs)?);
                return Ok(0);
            }
            let mut rows = vec![vec!["RUN".into(), "PROJECT".into(), "RELEASE".into(), "SCORE".into(), "STATUS".into(), "STARTED".into()]];
            for r in runs {
                let v = r.verdict;
                rows.push(vec![
                    format!("#{}", r.id),
                    r.project_name,
                    r.tag,
                    r.score.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                    match v {
                        Some(v) => st.verdict(v, &verdict_label(&app.i18n, Some(v))),
                        None => r.status.as_str().into(),
                    },
                    r.started_at.format("%Y-%m-%d %H:%M").to_string(),
                ]);
            }
            println!("{}", table(&rows));
        }
    }
    Ok(0)
}

fn environment(cmd: EnvCmd, json: bool, st: Style) -> Result<u8> {
    let envs = environments::list();
    match cmd {
        EnvCmd::List => {
            if json {
                println!("{}", serde_json::to_string_pretty(&envs)?);
                return Ok(0);
            }
            let mut rows = vec![vec!["ID".into(), "NAME".into(), "ISOLATION".into(), "AVAILABLE".into()]];
            for e in &envs {
                rows.push(vec![
                    e.id.into(),
                    e.name.into(),
                    format!("{:?}", e.isolation).to_lowercase(),
                    st.status_symbol(if e.available { Status::Pass } else { Status::Skipped }),
                ]);
            }
            println!("{}", table(&rows));
        }
        EnvCmd::Inspect { id } => {
            let e = envs
                .iter()
                .find(|e| e.id == id)
                .with_context(|| format!("unknown environment {id:?}; see `releaseverity environment list`"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(e)?);
            } else {
                println!("{} ({})", st.bold(e.name), e.id);
                println!("  isolation  {:?}", e.isolation);
                println!("  available  {}", e.available);
                println!("  detail     {}", e.detail);
            }
        }
    }
    Ok(0)
}

fn github(app: &App, cmd: GithubCmd, json: bool, st: Style) -> Result<u8> {
    use releaseverity_services::github::client::credstore;
    match cmd {
        GithubCmd::Login { token, stdin } => {
            let token = match (token, stdin) {
                (Some(t), _) => t,
                (None, true) => {
                    let mut l = String::new();
                    std::io::stdin().read_line(&mut l)?;
                    l
                }
                (None, false) => bail!("pass --stdin (recommended) or --token <token>"),
            };
            let login = app.github_connect(&token)?;
            println!("Connected to GitHub as {login}. The token is stored in Windows Credential Manager.");
        }
        GithubCmd::Logout => {
            if app.github_disconnect()? {
                println!("Stored GitHub token removed.");
            } else {
                println!("No stored GitHub token.");
            }
        }
        GithubCmd::Status => {
            let stored = credstore::load(&app.config.github.credential_name).is_some();
            if !stored {
                println!("{} not connected (public repositories still work, with a lower rate limit)", st.status_symbol(Status::Skipped));
                return Ok(0);
            }
            match app.github().login() {
                Ok(l) => println!("{} connected as {l}", st.status_symbol(Status::Pass)),
                Err(e) => {
                    println!("{} token present but not usable: {e}", st.status_symbol(Status::Fail));
                    return Ok(EXIT_FAILED);
                }
            }
        }
        GithubCmd::Releases { repo } => {
            let (o, r) = releaseverity_services::github::client::parse_repo(&repo)
                .with_context(|| format!("{repo:?} is not a GitHub repository"))?;
            let rels = app.github().releases(&o, &r).map_err(|e| anyhow::anyhow!("{e}"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rels.iter().map(|x| serde_json::json!({"tag": x.tag, "name": x.name, "prerelease": x.prerelease, "draft": x.draft, "assets": x.assets.iter().map(|a| &a.name).collect::<Vec<_>>()})).collect::<Vec<_>>())?);
                return Ok(0);
            }
            let mut rows = vec![vec!["TAG".into(), "NAME".into(), "ASSETS".into(), "PUBLISHED".into(), "".into()]];
            for x in rels {
                let flag = if x.draft {
                    "draft"
                } else if x.prerelease {
                    "pre-release"
                } else {
                    ""
                };
                rows.push(vec![x.tag, x.name, x.assets.len().to_string(), x.published_at.chars().take(10).collect(), flag.into()]);
            }
            println!("{}", table(&rows));
        }
    }
    Ok(0)
}

fn doctor(cli: &Cli, st: Style) -> Result<u8> {
    let paths = cli.home.clone().map(Paths::new).unwrap_or_else(Paths::discover);
    println!("{}", st.bold("ReleaseVerity doctor"));
    println!("  version    {}", releaseverity_services::core::VERSION);
    println!("  platform   {}", environments::host_description());
    println!("  data dir   {}", paths.root.display());
    // Storage is checked, not assumed: report why it fails instead of failing the whole command.
    let storage_ok = match App::open(paths.clone()) {
        Ok(_) => {
            println!("  storage    {} database opens ({})", st.status_symbol(Status::Pass), paths.database().display());
            true
        }
        Err(e) => {
            println!("  storage    {} {e:#}", st.status_symbol(Status::Fail));
            println!(
                "             {}",
                st.dim("ReleaseVerity needs a writable data directory (set RELEASEVERITY_HOME or use the portable layout).")
            );
            false
        }
    };
    println!(
        "
Tools"
    );
    let mut git_ok = true;
    for t in environments::tools() {
        let required = t.name == "git";
        let s = if t.found {
            Status::Pass
        } else if required {
            Status::Fail
        } else {
            Status::Skipped
        };
        if required && !t.found {
            git_ok = false;
        }
        println!(
            "  {} {:<8} {:<28} {}",
            st.status_symbol(s),
            t.name,
            t.version.clone().unwrap_or_else(|| "not found".into()),
            st.dim(t.purpose)
        );
    }
    println!(
        "
Execution environments"
    );
    for e in environments::list() {
        println!("  {} {:<17} {}", st.status_symbol(if e.available { Status::Pass } else { Status::Skipped }), e.id, st.dim(&e.detail));
    }
    Ok(if git_ok && storage_ok { 0 } else { EXIT_FAILED })
}

fn config(mut app: App, action: Option<ConfigCmd>) -> Result<u8> {
    match action.unwrap_or(ConfigCmd::List) {
        ConfigCmd::Path => println!("{}", app.paths.config_file().display()),
        ConfigCmd::List => print!("{}", toml_text(&app)?),
        ConfigCmd::Get { key } => println!("{}", app.config.get(&key).with_context(|| format!("unknown setting {key:?}"))?),
        ConfigCmd::Set { key, value } => {
            app.config.set(&key, &value)?;
            app.save_config()?;
            println!("{key} = {}", app.config.get(&key).unwrap_or_default());
        }
    }
    Ok(0)
}

fn toml_text(app: &App) -> Result<String> {
    releaseverity_services::core::config::to_toml(&app.config)
}
