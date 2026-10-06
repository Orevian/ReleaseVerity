//! Structured (JSON Lines) logging shared by CLI and GUI.
//!
//! Layout: `logs/{application,verification,shipcheck,repro}/releaseverity-YYYY-MM-DD.jsonl`

use chrono::Utc;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "trace" => Level::Trace,
            "debug" => Level::Debug,
            "info" => Level::Info,
            "warn" => Level::Warn,
            "error" => Level::Error,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Application,
    Verification,
    Shipcheck,
    Repro,
}

impl Category {
    pub fn dir(self) -> &'static str {
        match self {
            Category::Application => "application",
            Category::Verification => "verification",
            Category::Shipcheck => "shipcheck",
            Category::Repro => "repro",
        }
    }
}

struct Inner {
    root: Option<PathBuf>,
    min: Level,
    /// Also mirror to stderr (CLI `--verbose`).
    stderr: bool,
    lock: Mutex<()>,
}

#[derive(Clone)]
pub struct Logger(Arc<Inner>);

impl Logger {
    pub fn new(logs_dir: impl Into<PathBuf>, min: Level) -> Self {
        Self(Arc::new(Inner { root: Some(logs_dir.into()), min, stderr: false, lock: Mutex::new(()) }))
    }
    /// A logger that discards everything (tests, library use).
    pub fn null() -> Self {
        Self(Arc::new(Inner { root: None, min: Level::Error, stderr: false, lock: Mutex::new(()) }))
    }
    pub fn with_stderr(self, on: bool) -> Self {
        let i = &*self.0;
        Self(Arc::new(Inner { root: i.root.clone(), min: i.min, stderr: on, lock: Mutex::new(()) }))
    }

    pub fn log(&self, cat: Category, level: Level, msg: &str, fields: Value) {
        let i = &*self.0;
        if level < i.min {
            return;
        }
        let now = Utc::now();
        let line = json!({
            "ts": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "level": level.as_str(),
            "category": cat.dir(),
            "msg": msg,
            "fields": fields,
        });
        if i.stderr {
            eprintln!("[{}] {}", level.as_str(), msg);
        }
        let Some(root) = &i.root else { return };
        let _g = i.lock.lock().unwrap_or_else(|e| e.into_inner());
        let dir = root.join(cat.dir());
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let file = dir.join(format!("releaseverity-{}.jsonl", now.format("%Y-%m-%d")));
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(file) {
            let _ = writeln!(f, "{line}");
        }
    }

    pub fn trace(&self, c: Category, m: &str) {
        self.log(c, Level::Trace, m, Value::Null)
    }
    pub fn debug(&self, c: Category, m: &str) {
        self.log(c, Level::Debug, m, Value::Null)
    }
    pub fn info(&self, c: Category, m: &str) {
        self.log(c, Level::Info, m, Value::Null)
    }
    pub fn warn(&self, c: Category, m: &str) {
        self.log(c, Level::Warn, m, Value::Null)
    }
    pub fn error(&self, c: Category, m: &str) {
        self.log(c, Level::Error, m, Value::Null)
    }

    /// Delete log files older than `days`. Returns number removed.
    pub fn prune(&self, days: u32) -> usize {
        let Some(root) = &self.0.root else { return 0 };
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(days as u64 * 86_400);
        let mut n = 0;
        for cat in ["application", "verification", "shipcheck", "repro"] {
            let Ok(rd) = std::fs::read_dir(root.join(cat)) else { continue };
            for e in rd.flatten() {
                let old = e.metadata().and_then(|m| m.modified()).map(|t| t < cutoff).unwrap_or(false);
                if old && std::fs::remove_file(e.path()).is_ok() {
                    n += 1;
                }
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_lines_per_category_and_respects_level() {
        let d = tempfile::tempdir().unwrap();
        let l = Logger::new(d.path(), Level::Info);
        l.debug(Category::Repro, "hidden");
        l.log(Category::Repro, Level::Warn, "shown", json!({"k": 1}));
        let dir = d.path().join("repro");
        let f = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        let text = std::fs::read_to_string(f).unwrap();
        assert_eq!(text.lines().count(), 1);
        let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["level"], "WARN");
        assert_eq!(v["msg"], "shown");
        assert_eq!(v["fields"]["k"], 1);
    }
}
