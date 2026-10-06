//! `config.toml` handling and application directories.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where ReleaseVerity keeps its data.
///
/// Resolution order:
/// 1. `RELEASEVERITY_HOME` environment variable
/// 2. portable mode: a `config` directory next to the executable (or one level above, for
///    `clieriforge.exe`) → `<that dir>/data`
/// 3. `%APPDATA%\ReleaseVerity` (Windows) / `$XDG_DATA_HOME/releaseverity` / `~/.local/share/releaseverity`
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn discover() -> Self {
        if let Some(h) = std::env::var_os("RELEASEVERITY_HOME") {
            return Self::new(h);
        }
        // Portable layout: a `config` folder beside ReleaseVerity.exe (or one level above `clieriforge.exe`).
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                for base in [Some(dir), dir.parent()].into_iter().flatten() {
                    if base.join("config").is_dir() {
                        return Self::new(base.join("data"));
                    }
                }
            }
        }
        #[cfg(windows)]
        let base = std::env::var_os("APPDATA").map(PathBuf::from);
        #[cfg(not(windows))]
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
        let name = if cfg!(windows) { "ReleaseVerity" } else { "releaseverity" };
        Self::new(base.unwrap_or_else(std::env::temp_dir).join(name))
    }

    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn database(&self) -> PathBuf {
        self.root.join("releaseverity.db")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }
    pub fn reports_dir(&self) -> PathBuf {
        self.root.join("reports")
    }
    pub fn work_dir(&self) -> PathBuf {
        self.root.join("work")
    }
    pub fn ensure(&self) -> Result<()> {
        for d in [&self.root, &self.logs_dir(), &self.reports_dir(), &self.work_dir()] {
            std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
        }
        Ok(())
    }
}

/// Pretty TOML for display and saving.
pub fn to_toml(cfg: &Config) -> Result<String> {
    toml::to_string_pretty(cfg).map_err(Into::into)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub general: General,
    pub timeouts: Timeouts,
    pub verification: Verification,
    pub environments: Environments,
    pub github: GitHub,
    pub security: Security,
    pub logging: Logging,
    pub ui: Ui,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct General {
    /// `en` or `tr`.
    pub language: String,
}

/// All values in seconds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Timeouts {
    pub install_secs: u64,
    pub launch_secs: u64,
    pub smoke_secs: u64,
    pub cleanup_secs: u64,
    pub build_secs: u64,
    pub network_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Verification {
    /// `quick`, `standard` or `full`.
    pub profile: String,
    /// Treat warnings as failures (useful for CI gates).
    pub warnings_as_errors: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Environments {
    pub default: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GitHub {
    pub api_url: String,
    /// Name of the secret in the OS credential store. The token itself is
    /// never written to this file.
    pub credential_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Security {
    /// Allow running untrusted build/install commands directly on the host.
    /// Off by default; sandboxed execution is preferred.
    pub allow_host_execution: bool,
    pub allow_network_in_sandbox: bool,
    pub max_memory_mb: u64,
    pub max_processes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Logging {
    /// trace | debug | info | warn | error
    pub level: String,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Ui {
    /// `dark` or `light`.
    pub theme: String,
}

impl Default for General {
    fn default() -> Self {
        Self { language: "en".into() }
    }
}
impl Default for Timeouts {
    fn default() -> Self {
        Self { install_secs: 120, launch_secs: 30, smoke_secs: 60, cleanup_secs: 30, build_secs: 1800, network_secs: 60 }
    }
}
impl Default for Verification {
    fn default() -> Self {
        Self { profile: "standard".into(), warnings_as_errors: false }
    }
}
impl Default for Environments {
    fn default() -> Self {
        Self { default: vec!["auto".into()] }
    }
}
impl Default for GitHub {
    fn default() -> Self {
        Self { api_url: "https://api.github.com".into(), credential_name: "ReleaseVerity/github".into() }
    }
}
impl Default for Security {
    fn default() -> Self {
        Self { allow_host_execution: false, allow_network_in_sandbox: false, max_memory_mb: 2048, max_processes: 64 }
    }
}
impl Default for Logging {
    fn default() -> Self {
        Self { level: "info".into(), retention_days: 30 }
    }
}
impl Default for Ui {
    fn default() -> Self {
        Self { theme: "dark".into() }
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text).context("invalid config.toml")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(t) => Self::parse(&t).with_context(|| format!("in {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let text = toml::to_string_pretty(self)?;
        // Write-then-rename so a crash never leaves a truncated config.
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            matches!(self.general.language.as_str(), "en" | "tr"),
            "general.language must be \"en\" or \"tr\", got {:?}",
            self.general.language
        );
        anyhow::ensure!(matches!(self.ui.theme.as_str(), "dark" | "light"), "ui.theme must be \"dark\" or \"light\"");
        anyhow::ensure!(
            matches!(self.logging.level.as_str(), "trace" | "debug" | "info" | "warn" | "error"),
            "logging.level must be trace|debug|info|warn|error"
        );
        anyhow::ensure!(
            matches!(self.verification.profile.as_str(), "quick" | "standard" | "full"),
            "verification.profile must be quick|standard|full"
        );
        for (name, v) in [
            ("install_secs", self.timeouts.install_secs),
            ("launch_secs", self.timeouts.launch_secs),
            ("smoke_secs", self.timeouts.smoke_secs),
            ("cleanup_secs", self.timeouts.cleanup_secs),
            ("build_secs", self.timeouts.build_secs),
            ("network_secs", self.timeouts.network_secs),
        ] {
            anyhow::ensure!(v > 0, "timeouts.{name} must be greater than 0");
        }
        Ok(())
    }

    /// Get a value by dotted key (`timeouts.install_secs`) for `releaseverity config get`.
    pub fn get(&self, key: &str) -> Option<String> {
        let v = toml::Value::try_from(self).ok()?;
        let mut cur = &v;
        for part in key.split('.') {
            cur = cur.get(part)?;
        }
        Some(match cur {
            toml::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }

    /// Set a value by dotted key, keeping the existing value's type.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let mut v = toml::Value::try_from(&*self)?;
        let parts: Vec<&str> = key.split('.').collect();
        let (last, parents) = parts.split_last().context("empty key")?;
        let mut cur = &mut v;
        for p in parents {
            cur = cur.get_mut(*p).with_context(|| format!("unknown setting {key}"))?;
        }
        let slot = cur.get_mut(*last).with_context(|| format!("unknown setting {key}"))?;
        *slot = match slot {
            toml::Value::Integer(_) => toml::Value::Integer(value.parse().context("expected an integer")?),
            toml::Value::Boolean(_) => toml::Value::Boolean(value.parse().context("expected true or false")?),
            toml::Value::Array(_) => toml::Value::Array(value.split(',').map(|s| toml::Value::String(s.trim().to_string())).collect()),
            _ => toml::Value::String(value.to_string()),
        };
        let new: Config = v.try_into().context("invalid value")?;
        new.validate()?;
        *self = new;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_through_toml() {
        let c = Config::default();
        let text = toml::to_string_pretty(&c).unwrap();
        assert_eq!(Config::parse(&text).unwrap(), c);
    }

    #[test]
    fn partial_file_falls_back_to_defaults() {
        let c = Config::parse("[timeouts]\ninstall_secs = 300\n").unwrap();
        assert_eq!(c.timeouts.install_secs, 300);
        assert_eq!(c.timeouts.launch_secs, 30);
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(Config::parse("[general]\nlanguage = \"xx\"\n").is_err());
        assert!(Config::parse("[timeouts]\nlaunch_secs = 0\n").is_err());
        assert!(Config::parse("[timeouts]\nlaunch_secs = \"x\"\n").is_err());
    }

    #[test]
    fn get_and_set_by_dotted_key() {
        let mut c = Config::default();
        c.set("timeouts.install_secs", "99").unwrap();
        assert_eq!(c.get("timeouts.install_secs").as_deref(), Some("99"));
        c.set("general.language", "tr").unwrap();
        assert_eq!(c.general.language, "tr");
        assert!(c.set("general.language", "zz").is_err());
        assert!(c.set("nope.key", "1").is_err());
        assert!(c.set("timeouts.install_secs", "abc").is_err());
    }

    #[test]
    fn save_and_load() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        let mut c = Config::default();
        c.ui.theme = "light".into();
        c.save(&p).unwrap();
        assert_eq!(Config::load(&p).unwrap().ui.theme, "light");
        assert_eq!(Config::load(&d.path().join("missing.toml")).unwrap(), Config::default());
    }
}
