//! `releaseverity-agent <spec.json> <out-dir> [--shutdown]`
//!
//! Runs the ShipCheck plan inside the clean environment and writes
//! `progress.jsonl` (live) and `report.json` (final) into `<out-dir>`.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use releaseverity_agent::{runner::Agent, AgentReport, Spec, REPORT_FILE};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let shutdown = args.iter().any(|a| a == "--shutdown");
    let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let (Some(spec_path), Some(out_dir)) = (pos.first(), pos.get(1)) else {
        eprintln!("usage: releaseverity-agent <spec.json> <out-dir> [--shutdown]");
        return std::process::ExitCode::from(2);
    };
    let out = std::path::PathBuf::from(out_dir);
    let _ = std::fs::create_dir_all(&out);

    let result = std::fs::read_to_string(spec_path)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str::<Spec>(&t).map_err(|e| e.to_string()));
    let code = match result {
        Err(e) => {
            eprintln!("invalid spec: {e}");
            2
        }
        Ok(spec) => {
            let work = std::env::temp_dir().join(format!("releaseverity-agent-{}", std::process::id()));
            let steps = Agent::new(&spec, &out, work.clone()).run();
            let report =
                AgentReport { agent_version: env!("CARGO_PKG_VERSION").into(), os: std::env::consts::OS.into(), steps, finished: true };
            let _ = std::fs::write(out.join(REPORT_FILE), serde_json::to_string_pretty(&report).unwrap_or_default());
            let _ = std::fs::remove_dir_all(&work);
            0
        }
    };
    if shutdown {
        // Inside Windows Sandbox: closing the VM is what makes it single-use.
        let _ = std::process::Command::new("shutdown").args(["/s", "/t", "0", "/f"]).status();
    }
    std::process::ExitCode::from(code)
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("releaseverity-agent runs on Windows only");
    std::process::ExitCode::from(2)
}
