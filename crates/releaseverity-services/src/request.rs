//! Building verification requests from user input. Shared by the CLI (flags) and the
//! desktop wizard (form fields) so both interpret the same text the same way.

use anyhow::{bail, ensure, Result};
use releaseverity_core::check::{ShipKind, ShipcheckTarget, SmokeSpec};
use releaseverity_core::config::Config;
use std::path::{Path, PathBuf};

/// Split a command line into arguments, honouring double quotes.
pub fn split_args(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted, mut any) = (vec![], String::new(), false, false);
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `"<args>"` or `"<args> => <expected output text>"`; blank lines and `#` comments are ignored.
pub fn parse_smoke(line: &str) -> Option<SmokeSpec> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (args, expect) = match line.split_once("=>") {
        Some((a, e)) => (a.trim(), Some(e.trim().to_string()).filter(|e| !e.is_empty())),
        None => (line, None),
    };
    Some(SmokeSpec { name: args.to_string(), args: split_args(args), expect_exit: 0, expect_stdout: expect, timeout_secs: None })
}

/// Files of a directory (non-recursive, sorted), or the file itself.
pub fn expand_assets(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = vec![];
    for p in paths {
        if p.is_dir() {
            let mut files: Vec<_> = std::fs::read_dir(p)?.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
            files.sort();
            out.extend(files);
        } else if p.is_file() {
            out.push(p.clone());
        } else {
            bail!("asset not found: {}", p.display());
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct PackageOptions {
    pub package: Option<PathBuf>,
    /// `installer` | `portable`; guessed from the package when `None`.
    pub kind: Option<String>,
    pub installer_args: Option<String>,
    pub exe: Option<String>,
    pub launch_args: Option<String>,
    pub gui: bool,
    /// One smoke test per entry (see [`parse_smoke`]).
    pub smoke: Vec<String>,
    /// `auto`, `appcontainer`, `windows-sandbox`, `host`; empty = config default.
    pub environments: Vec<String>,
    pub launch: bool,
    pub uninstall: bool,
    pub alive_secs: u64,
}

pub const ENVIRONMENT_IDS: [&str; 4] = ["auto", "appcontainer", "windows-sandbox", "host"];

pub fn build_shipcheck_target(o: &PackageOptions, cfg: &Config) -> Result<Option<ShipcheckTarget>> {
    let Some(package) = &o.package else { return Ok(None) };
    ensure!(package.exists(), "package not found: {}", package.display());
    let kind = match o.kind.as_deref() {
        Some("installer") => ShipKind::Installer,
        Some("portable") => ShipKind::Portable,
        _ => {
            let ext = package.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
            if package.is_dir() || ext == "zip" {
                ShipKind::Portable
            } else {
                ShipKind::Installer
            }
        }
    };
    let envs = if o.environments.is_empty() { cfg.environments.default.clone() } else { o.environments.clone() };
    for e in &envs {
        ensure!(ENVIRONMENT_IDS.contains(&e.as_str()), "unknown environment {e:?} (use auto, appcontainer, windows-sandbox or host)");
    }
    let abs = std::fs::canonicalize(package)
        .map(|c| PathBuf::from(c.to_string_lossy().trim_start_matches(r"\\?\")))
        .unwrap_or_else(|_| package.clone());
    Ok(Some(ShipcheckTarget {
        kind,
        package: abs,
        installer_args: o.installer_args.as_deref().map(split_args).unwrap_or_default(),
        exe: o.exe.clone().filter(|e| !e.trim().is_empty()),
        launch_args: o.launch_args.as_deref().map(split_args).unwrap_or_default(),
        gui: o.gui,
        launch: o.launch,
        alive_secs: if o.alive_secs == 0 { 5 } else { o.alive_secs },
        smoke: o.smoke.iter().filter_map(|s| parse_smoke(s)).collect(),
        environments: envs,
        uninstall: o.uninstall,
    }))
}

pub fn path_exists(p: &str) -> bool {
    !p.trim().is_empty() && Path::new(p.trim()).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_arguments() {
        assert_eq!(split_args(r#"--name "John Smith" -v"#), ["--name", "John Smith", "-v"]);
        assert_eq!(split_args(r#""" x"#), ["", "x"]);
        assert!(split_args("   ").is_empty());
    }

    #[test]
    fn parses_smoke_lines() {
        let s = parse_smoke("--version => 1.2.3").unwrap();
        assert_eq!((s.args.as_slice(), s.expect_stdout.as_deref()), (&["--version".to_string()][..], Some("1.2.3")));
        assert!(parse_smoke("# comment").is_none() && parse_smoke("  ").is_none());
        assert_eq!(parse_smoke("--help").unwrap().expect_stdout, None);
    }

    #[test]
    fn builds_targets_and_rejects_bad_input() {
        let d = tempfile::tempdir().unwrap();
        let cfg = Config::default();
        let o = PackageOptions {
            package: Some(d.path().to_path_buf()),
            smoke: vec!["--version".into()],
            launch: true,
            uninstall: true,
            ..Default::default()
        };
        let t = build_shipcheck_target(&o, &cfg).unwrap().unwrap();
        assert_eq!(t.kind, ShipKind::Portable);
        assert_eq!(t.environments, ["auto"]);
        assert_eq!(t.smoke.len(), 1);
        assert!(build_shipcheck_target(&PackageOptions { package: Some(d.path().join("nope")), ..Default::default() }, &cfg).is_err());
        let bad = PackageOptions { package: Some(d.path().to_path_buf()), environments: vec!["vmware".into()], ..Default::default() };
        assert!(build_shipcheck_target(&bad, &cfg).is_err());
        assert!(build_shipcheck_target(&PackageOptions::default(), &cfg).unwrap().is_none());
    }
}
