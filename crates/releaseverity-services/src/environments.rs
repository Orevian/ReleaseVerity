//! Detection of the execution environments ReleaseVerity could use. Detection only:
//! nothing here fakes availability — each probe runs the real tool.

use releaseverity_core::proc;
use serde::Serialize;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// Runs directly on the host. Never used for untrusted code without explicit opt-in.
    None,
    /// OS-enforced process isolation (ReleaseVerity's built-in AppContainer sandbox).
    Process,
    Container,
    VirtualMachine,
}

#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub id: &'static str,
    pub name: &'static str,
    pub isolation: Isolation,
    pub available: bool,
    /// Why it is (un)available, from the actual probe.
    pub detail: String,
}

fn probe(cmd: &str, args: &[&str], secs: u64) -> Option<String> {
    let mut c = Command::new(cmd);
    c.args(args);
    let o = proc::run(&mut c, Duration::from_secs(secs)).ok()?;
    o.success().then(|| o.stdout.trim().to_string())
}

pub fn host_description() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

pub fn list() -> Vec<Environment> {
    let mut v = vec![Environment {
        id: "host",
        name: "Host (no isolation)",
        isolation: Isolation::None,
        available: true,
        detail: format!("{} — only for trusted software; requires security.allow_host_execution", host_description()),
    }];

    v.insert(
        0,
        Environment {
            id: "appcontainer",
            name: "ReleaseVerity built-in sandbox (AppContainer)",
            isolation: Isolation::Process,
            available: cfg!(windows),
            detail: if cfg!(windows) {
                "works on every Windows edition; portable packages only; no network, no access outside its sandbox".into()
            } else {
                "Windows only".into()
            },
        },
    );

    let docker = if proc::exists_on_path("docker") {
        match probe("docker", &["info", "--format", "{{.OSType}}/{{.ServerVersion}}"], 15) {
            Some(i) => (true, format!("Docker engine {i}")),
            None => (false, "docker is installed but the engine is not running".into()),
        }
    } else {
        (false, "docker not found on PATH".into())
    };
    v.push(Environment { id: "docker", name: "Docker container", isolation: Isolation::Container, available: docker.0, detail: docker.1 });

    let sandbox = windows_sandbox();
    v.push(Environment {
        id: "windows-sandbox",
        name: "Windows Sandbox",
        isolation: Isolation::VirtualMachine,
        available: sandbox.0,
        detail: sandbox.1,
    });
    v
}

fn windows_sandbox() -> (bool, String) {
    if !cfg!(windows) {
        return (false, "Windows only".into());
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let exe = std::path::Path::new(&root).join("System32\\WindowsSandbox.exe");
    if exe.exists() {
        (true, "Windows Sandbox feature is enabled (requires Windows 10/11 Pro or Enterprise)".into())
    } else {
        (false, "Windows Sandbox is not enabled (Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM)".into())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub found: bool,
    pub version: Option<String>,
    pub purpose: &'static str,
}

/// Tools ReleaseVerity shells out to, with versions where available.
pub fn tools() -> Vec<Tool> {
    let t = |name: &'static str, args: &[&str], purpose: &'static str| {
        let found = proc::exists_on_path(name);
        let version = if found { probe(name, args, 10).map(|s| s.lines().next().unwrap_or("").to_string()) } else { None };
        Tool { name, found, version, purpose }
    };
    vec![
        t("git", &["--version"], "source and tag verification (required)"),
        t("gh", &["--version"], "GitHub attestation verification (optional)"),
        t("gpg", &["--version"], "detached/tag signature verification (optional)"),
        t("docker", &["--version"], "container isolation for ShipCheck (optional)"),
        t("iscc", &["/?"], "building the Windows installer (build-time only)"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_sandbox_and_host_are_listed_and_host_is_flagged_unisolated() {
        let l = list();
        assert_eq!(l[0].id, "appcontainer");
        assert_eq!(l[0].available, cfg!(windows));
        let host = l.iter().find(|e| e.id == "host").unwrap();
        assert_eq!(host.isolation, Isolation::None);
        assert!(l.iter().any(|e| e.id == "docker") && l.iter().any(|e| e.id == "windows-sandbox"));
    }

    #[test]
    fn git_is_detected_with_a_version() {
        let g = tools().into_iter().find(|t| t.name == "git").unwrap();
        assert!(g.found && g.version.unwrap().contains("git version"));
    }
}
