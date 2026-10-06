//! Domain model shared by CLI, GUI, engines and reports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Outcome of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    /// The check was not applicable or not requested. Excluded from scoring.
    Skipped,
    /// The check could not be carried out (tooling missing, I/O failure…).
    /// This is *not* a pass: the property is unverified.
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Warn => "warn",
            Status::Fail => "fail",
            Status::Skipped => "skipped",
            Status::Error => "error",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pass" => Status::Pass,
            "warn" => Status::Warn,
            "fail" => Status::Fail,
            "skipped" => Status::Skipped,
            "error" => Status::Error,
            _ => return None,
        })
    }
    pub fn symbol(self) -> &'static str {
        match self {
            Status::Pass => "✓",
            Status::Warn => "⚠",
            Status::Fail => "✗",
            Status::Skipped => "-",
            Status::Error => "!",
        }
    }
    pub fn ascii_symbol(self) -> &'static str {
        match self {
            Status::Pass => "OK",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Skipped => "-",
            Status::Error => "ERR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Trust,
    Build,
    Installation,
    Runtime,
    Documentation,
}

impl Category {
    pub const ALL: [Category; 5] = [Category::Trust, Category::Build, Category::Installation, Category::Runtime, Category::Documentation];
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Trust => "trust",
            Category::Build => "build",
            Category::Installation => "installation",
            Category::Runtime => "runtime",
            Category::Documentation => "documentation",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// Distinguishes *why* something failed at runtime (ShipCheck).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Crashed,
    Hung,
    Timeout,
    ExitCode,
    Other,
}

impl FailureKind {
    pub fn label(self) -> &'static str {
        match self {
            FailureKind::Crashed => "APPLICATION CRASHED",
            FailureKind::Hung => "APPLICATION HUNG",
            FailureKind::Timeout => "TEST TIMEOUT",
            FailureKind::ExitCode => "UNEXPECTED EXIT CODE",
            FailureKind::Other => "FAILED",
        }
    }
}

/// A translatable message: a catalog key plus its `{placeholder}` arguments.
/// The English text is always derived from the same catalog, so there is a single source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Msg {
    pub key: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub args: std::collections::BTreeMap<String, String>,
}

impl Msg {
    pub fn new(key: &str, args: &[(&str, &str)]) -> Self {
        Self { key: key.to_string(), args: args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
    }
    /// Render in `i18n`'s language. An argument value starting with `@` is itself a catalog key.
    pub fn render(&self, i18n: &crate::i18n::I18n) -> String {
        let resolved: Vec<(String, String)> =
            self.args.iter().map(|(k, v)| (k.clone(), v.strip_prefix('@').map(|key| i18n.t(key)).unwrap_or_else(|| v.clone()))).collect();
        let args: Vec<(&str, &str)> = resolved.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        i18n.tf(&self.key, &args)
    }
    /// English rendering (used for the plain-text fallback fields).
    pub fn english(&self) -> String {
        self.render(crate::i18n::english())
    }
}

/// Result of one check. `evidence` holds machine-readable facts that back the
/// verdict (hashes, commit ids, section tables…). Nothing here is synthesized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub category: Category,
    pub status: Status,
    /// English text. When `summary_msg` is present it is rendered in the user's language instead.
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_msg: Option<Msg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub evidence: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause_msg: Option<Msg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_msg: Option<Msg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<FailureKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub duration_ms: u64,
}

impl CheckResult {
    pub fn new(id: &str, category: Category, status: Status, summary: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            category,
            status,
            summary: summary.into(),
            summary_msg: None,
            details: None,
            evidence: serde_json::Value::Null,
            cause: None,
            cause_msg: None,
            suggestion: None,
            suggestion_msg: None,
            failure_kind: None,
            exit_code: None,
            environment: None,
            duration_ms: 0,
        }
    }
    pub fn details(mut self, d: impl Into<String>) -> Self {
        self.details = Some(d.into());
        self
    }
    pub fn evidence(mut self, v: serde_json::Value) -> Self {
        self.evidence = v;
        self
    }
    pub fn cause(mut self, c: impl Into<String>) -> Self {
        self.cause = Some(c.into());
        self
    }
    pub fn suggestion(mut self, s: impl Into<String>) -> Self {
        self.suggestion = Some(s.into());
        self
    }
    /// Set the summary from a catalog key (English text derived from the catalog).
    pub fn summary_key(mut self, key: &str, args: &[(&str, &str)]) -> Self {
        let m = Msg::new(key, args);
        self.summary = m.english();
        self.summary_msg = Some(m);
        self
    }
    pub fn cause_key(mut self, key: &str, args: &[(&str, &str)]) -> Self {
        let m = Msg::new(key, args);
        self.cause = Some(m.english());
        self.cause_msg = Some(m);
        self
    }
    pub fn suggestion_key(mut self, key: &str, args: &[(&str, &str)]) -> Self {
        let m = Msg::new(key, args);
        self.suggestion = Some(m.english());
        self.suggestion_msg = Some(m);
        self
    }
    /// Constructor for fully key-based results.
    pub fn msg(id: &str, category: Category, status: Status, key: &str, args: &[(&str, &str)]) -> Self {
        Self::new(id, category, status, "").summary_key(key, args)
    }
    /// Summary in the user's language (falls back to the stored English text).
    pub fn summary_text(&self, i18n: &crate::i18n::I18n) -> String {
        self.summary_msg.as_ref().map(|m| m.render(i18n)).unwrap_or_else(|| self.summary.clone())
    }
    pub fn cause_text(&self, i18n: &crate::i18n::I18n) -> Option<String> {
        self.cause_msg.as_ref().map(|m| m.render(i18n)).or_else(|| self.cause.clone())
    }
    pub fn suggestion_text(&self, i18n: &crate::i18n::I18n) -> Option<String> {
        self.suggestion_msg.as_ref().map(|m| m.render(i18n)).or_else(|| self.suggestion.clone())
    }
}

/// Overall release verdict derived from the results (see `scoring`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Verified,
    VerifiedWithWarnings,
    Failed,
    /// Nothing failed, but required properties could not be checked.
    Inconclusive,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::VerifiedWithWarnings => "verified_with_warnings",
            Verdict::Failed => "failed",
            Verdict::Inconclusive => "inconclusive",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "verified" => Verdict::Verified,
            "verified_with_warnings" => Verdict::VerifiedWithWarnings,
            "failed" => Verdict::Failed,
            "inconclusive" => Verdict::Inconclusive,
            _ => return None,
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Verified => "VERIFIED",
            Verdict::VerifiedWithWarnings => "VERIFIED WITH WARNINGS",
            Verdict::Failed => "FAILED",
            Verdict::Inconclusive => "INCONCLUSIVE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub repo_url: Option<String>,
    pub local_path: Option<String>,
    pub default_branch: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub id: i64,
    pub project_id: i64,
    pub tag: String,
    pub commit_sha: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub sha512: String,
    pub kind: String,
}

/// A finished (or running) verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: i64,
    pub project_id: Option<i64>,
    pub project_name: String,
    pub repo: String,
    pub tag: String,
    pub commit: Option<String>,
    pub status: RunState,
    pub score: Option<u8>,
    pub verdict: Option<Verdict>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub tool_version: String,
    pub results: Vec<CheckResult>,
    pub artifacts: Vec<ArtifactInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Running,
    Finished,
    Cancelled,
}

impl RunState {
    pub fn as_str(self) -> &'static str {
        match self {
            RunState::Running => "running",
            RunState::Finished => "finished",
            RunState::Cancelled => "cancelled",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "finished" => RunState::Finished,
            "cancelled" => RunState::Cancelled,
            _ => RunState::Running,
        }
    }
}
