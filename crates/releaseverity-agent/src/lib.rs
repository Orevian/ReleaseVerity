//! Wire protocol between the host (ShipCheck engine) and the agent that runs
//! inside the clean environment. The agent is untrusted-adjacent: the host
//! treats everything it writes as *data* and validates it.

use serde::{Deserialize, Serialize};

#[cfg(windows)]
pub mod ac;
#[cfg(windows)]
pub mod runner;
#[cfg(windows)]
pub mod winproc;

pub const PROGRESS_FILE: &str = "progress.jsonl";
pub const REPORT_FILE: &str = "report.json";
/// Hard cap on any text field the agent reports (the host enforces it again).
pub const MAX_LOG_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageKind {
    /// An installer (`.exe` / `.msi`) that must install, run and uninstall.
    Installer,
    /// A zip archive or directory that is run in place.
    Portable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Smoke {
    pub name: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub expect_exit: i32,
    #[serde(default)]
    pub expect_stdout: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// How the application under test is confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// Job-limited only. Never used for untrusted code without explicit opt-in.
    #[default]
    None,
    /// ReleaseVerity's own sandbox: a Windows AppContainer (portable packages only).
    AppContainer,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Spec {
    #[serde(default)]
    pub isolation: Isolation,
    pub kind: PackageKind,
    /// Path to the installer file, zip, or directory (inside the environment).
    pub package: String,
    #[serde(default)]
    pub installer_args: Vec<String>,
    /// Executable to run, relative name or file name (auto-detected when absent).
    #[serde(default)]
    pub exe: Option<String>,
    #[serde(default)]
    pub launch_args: Vec<String>,
    /// GUI apps must stay alive and responsive; console apps must exit 0.
    #[serde(default)]
    pub gui: bool,
    #[serde(default = "yes")]
    pub launch: bool,
    pub alive_secs: u64,
    pub install_timeout_secs: u64,
    pub launch_timeout_secs: u64,
    pub smoke_timeout_secs: u64,
    pub cleanup_timeout_secs: u64,
    #[serde(default)]
    pub smoke: Vec<Smoke>,
    #[serde(default = "yes")]
    pub uninstall: bool,
    pub max_memory_mb: u64,
    pub max_processes: u32,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pass,
    Warn,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailKind {
    Crashed,
    Hung,
    Timeout,
    ExitCode,
    Other,
}

/// Step ids: `install`, `files`, `launch`, `smoke:<name>`, `uninstall`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StepReport {
    pub id: String,
    pub status: StepStatus,
    #[serde(default)]
    pub fail_kind: Option<FailKind>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub message: String,
    #[serde(default)]
    pub log: String,
    #[serde(default)]
    pub facts: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ProgressLine {
    Start { id: String, note: String },
    End { step: StepReport },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentReport {
    pub agent_version: String,
    pub os: String,
    pub steps: Vec<StepReport>,
    /// False if the agent terminated before completing its plan.
    pub finished: bool,
}

pub fn truncate_tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    format!("…[truncated]\n{}", &s[start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_round_trips_and_defaults_apply() {
        let j = r#"{"kind":"installer","package":"a.exe","alive_secs":5,"install_timeout_secs":1,"launch_timeout_secs":1,
          "smoke_timeout_secs":1,"cleanup_timeout_secs":1,"max_memory_mb":512,"max_processes":8}"#;
        let s: Spec = serde_json::from_str(j).unwrap();
        assert!(s.uninstall && s.launch && s.smoke.is_empty() && !s.gui);
        assert_eq!(s.isolation, Isolation::None);
        assert_eq!(serde_json::from_str::<Spec>(&serde_json::to_string(&s).unwrap()).unwrap(), s);
    }

    #[test]
    fn truncation_keeps_the_tail_on_char_boundaries() {
        let t = truncate_tail(&"ğ".repeat(100), 11);
        assert!(t.starts_with("…[truncated]") && t.ends_with('ğ'));
        assert_eq!(truncate_tail("short", 100), "short");
    }
}
