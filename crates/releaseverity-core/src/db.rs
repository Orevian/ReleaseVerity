//! Local SQLite storage. Secrets are never stored here (see `Config::github.credential_name`).

use crate::model::*;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE projects (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  repo_url TEXT,
  local_path TEXT,
  default_branch TEXT NOT NULL DEFAULT 'main',
  created_at TEXT NOT NULL
);
CREATE TABLE releases (
  id INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  commit_sha TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(project_id, tag)
);
CREATE TABLE runs (
  id INTEGER PRIMARY KEY,
  project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
  project_name TEXT NOT NULL,
  repo TEXT NOT NULL,
  tag TEXT NOT NULL,
  commit_sha TEXT,
  state TEXT NOT NULL,
  score INTEGER,
  verdict TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  tool_version TEXT NOT NULL
);
CREATE TABLE results (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  check_id TEXT NOT NULL,
  category TEXT NOT NULL,
  status TEXT NOT NULL,
  environment TEXT,
  duration_ms INTEGER NOT NULL,
  body TEXT NOT NULL
);
CREATE INDEX results_run ON results(run_id);
CREATE TABLE artifacts (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  sha512 TEXT NOT NULL,
  kind TEXT NOT NULL
);
CREATE TABLE reports (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  format TEXT NOT NULL,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"#,
    // 2: remember which process owns a running run so crash recovery never touches live runs.
    "ALTER TABLE runs ADD COLUMN pid INTEGER;",
];

#[derive(Debug, Clone)]
pub struct ReportRow {
    pub id: i64,
    pub run_id: i64,
    pub project: String,
    pub tag: String,
    pub format: String,
    pub path: String,
    pub created_at: DateTime<Utc>,
}

pub struct Db {
    conn: Connection,
}

fn ts(s: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).unwrap_or_default()
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;")?;
        let mut db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&mut self) -> Result<()> {
        let current: usize = self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
            tx.commit()?;
        }
        Ok(())
    }

    // ---- projects ----------------------------------------------------

    pub fn add_project(&self, name: &str, repo_url: Option<&str>, local_path: Option<&str>, branch: &str) -> Result<Project> {
        anyhow::ensure!(!name.trim().is_empty(), "project name must not be empty");
        anyhow::ensure!(repo_url.is_some() || local_path.is_some(), "a project needs a repository URL or a local path");
        let now = Utc::now();
        self.conn
            .execute(
                "INSERT INTO projects(name, repo_url, local_path, default_branch, created_at) VALUES (?,?,?,?,?)",
                params![name, repo_url, local_path, branch, now.to_rfc3339()],
            )
            .with_context(|| format!("project {name:?} already exists or could not be saved"))?;
        Ok(Project {
            id: self.conn.last_insert_rowid(),
            name: name.into(),
            repo_url: repo_url.map(Into::into),
            local_path: local_path.map(Into::into),
            default_branch: branch.into(),
            created_at: now,
        })
    }

    fn project_from_row(r: &rusqlite::Row) -> rusqlite::Result<Project> {
        Ok(Project {
            id: r.get(0)?,
            name: r.get(1)?,
            repo_url: r.get(2)?,
            local_path: r.get(3)?,
            default_branch: r.get(4)?,
            created_at: ts(r.get(5)?),
        })
    }

    pub fn list_projects(&self) -> Result<Vec<Project>> {
        let mut st =
            self.conn.prepare("SELECT id,name,repo_url,local_path,default_branch,created_at FROM projects ORDER BY name COLLATE NOCASE")?;
        let rows = st.query_map([], Self::project_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn find_project(&self, name: &str) -> Result<Option<Project>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id,name,repo_url,local_path,default_branch,created_at FROM projects WHERE name = ? COLLATE NOCASE",
                [name],
                Self::project_from_row,
            )
            .optional()?)
    }

    /// Returns whether a project was removed.
    pub fn remove_project(&self, name: &str) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM projects WHERE name = ? COLLATE NOCASE", [name])? > 0)
    }

    // ---- releases ----------------------------------------------------

    pub fn upsert_release(&self, project_id: i64, tag: &str, commit: Option<&str>) -> Result<Release> {
        let now = Utc::now();
        self.conn.execute(
            "INSERT INTO releases(project_id, tag, commit_sha, created_at) VALUES (?,?,?,?)
             ON CONFLICT(project_id, tag) DO UPDATE SET commit_sha = COALESCE(excluded.commit_sha, commit_sha)",
            params![project_id, tag, commit, now.to_rfc3339()],
        )?;
        self.conn
            .query_row(
                "SELECT id, project_id, tag, commit_sha, created_at FROM releases WHERE project_id=? AND tag=?",
                params![project_id, tag],
                |r| Ok(Release { id: r.get(0)?, project_id: r.get(1)?, tag: r.get(2)?, commit_sha: r.get(3)?, created_at: ts(r.get(4)?) }),
            )
            .map_err(Into::into)
    }

    pub fn list_releases(&self, project_id: i64) -> Result<Vec<Release>> {
        let mut st =
            self.conn.prepare("SELECT id, project_id, tag, commit_sha, created_at FROM releases WHERE project_id=? ORDER BY id DESC")?;
        let rows = st.query_map([project_id], |r| {
            Ok(Release { id: r.get(0)?, project_id: r.get(1)?, tag: r.get(2)?, commit_sha: r.get(3)?, created_at: ts(r.get(4)?) })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    // ---- runs --------------------------------------------------------

    pub fn start_run(&self, project_id: Option<i64>, project_name: &str, repo: &str, tag: &str, tool_version: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO runs(project_id, project_name, repo, tag, state, started_at, tool_version, pid)
             VALUES (?,?,?,?,?,?,?,?)",
            params![
                project_id,
                project_name,
                repo,
                tag,
                RunState::Running.as_str(),
                Utc::now().to_rfc3339(),
                tool_version,
                std::process::id()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn add_result(&self, run_id: i64, r: &CheckResult) -> Result<()> {
        self.conn.execute(
            "INSERT INTO results(run_id, check_id, category, status, environment, duration_ms, body)
             VALUES (?,?,?,?,?,?,?)",
            params![run_id, r.id, r.category.as_str(), r.status.as_str(), r.environment, r.duration_ms as i64, serde_json::to_string(r)?],
        )?;
        Ok(())
    }

    pub fn add_artifact(&self, run_id: i64, a: &ArtifactInfo) -> Result<()> {
        self.conn.execute(
            "INSERT INTO artifacts(run_id, name, path, size, sha256, sha512, kind) VALUES (?,?,?,?,?,?,?)",
            params![run_id, a.name, a.path, a.size as i64, a.sha256, a.sha512, a.kind],
        )?;
        Ok(())
    }

    pub fn finish_run(
        &self,
        run_id: i64,
        state: RunState,
        commit: Option<&str>,
        score: Option<u8>,
        verdict: Option<Verdict>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET state=?, commit_sha=?, score=?, verdict=?, finished_at=? WHERE id=?",
            params![state.as_str(), commit, score.map(i64::from), verdict.map(|v| v.as_str()), Utc::now().to_rfc3339(), run_id],
        )?;
        Ok(())
    }

    fn run_header(r: &rusqlite::Row) -> rusqlite::Result<Run> {
        Ok(Run {
            id: r.get(0)?,
            project_id: r.get(1)?,
            project_name: r.get(2)?,
            repo: r.get(3)?,
            tag: r.get(4)?,
            commit: r.get(5)?,
            status: RunState::parse(&r.get::<_, String>(6)?),
            score: r.get::<_, Option<i64>>(7)?.map(|s| s as u8),
            verdict: r.get::<_, Option<String>>(8)?.and_then(|v| Verdict::parse(&v)),
            started_at: ts(r.get(9)?),
            finished_at: r.get::<_, Option<String>>(10)?.map(ts),
            tool_version: r.get(11)?,
            results: vec![],
            artifacts: vec![],
        })
    }

    const RUN_COLS: &'static str =
        "id, project_id, project_name, repo, tag, commit_sha, state, score, verdict, started_at, finished_at, tool_version";

    /// Full run including results and artifacts.
    pub fn get_run(&self, id: i64) -> Result<Option<Run>> {
        let Some(mut run) =
            self.conn.query_row(&format!("SELECT {} FROM runs WHERE id=?", Self::RUN_COLS), [id], Self::run_header).optional()?
        else {
            return Ok(None);
        };
        let mut st = self.conn.prepare("SELECT body FROM results WHERE run_id=? ORDER BY id")?;
        for body in st.query_map([id], |r| r.get::<_, String>(0))? {
            run.results.push(serde_json::from_str(&body?)?);
        }
        let mut st = self.conn.prepare("SELECT name, path, size, sha256, sha512, kind FROM artifacts WHERE run_id=? ORDER BY id")?;
        let rows = st.query_map([id], |r| {
            Ok(ArtifactInfo {
                name: r.get(0)?,
                path: r.get(1)?,
                size: r.get::<_, i64>(2)? as u64,
                sha256: r.get(3)?,
                sha512: r.get(4)?,
                kind: r.get(5)?,
            })
        })?;
        run.artifacts = rows.collect::<rusqlite::Result<_>>()?;
        Ok(Some(run))
    }

    /// Newest-first run headers (without results).
    pub fn list_runs(&self, limit: u32, project_id: Option<i64>) -> Result<Vec<Run>> {
        let sql = format!("SELECT {} FROM runs WHERE (?1 IS NULL OR project_id = ?1) ORDER BY id DESC LIMIT ?2", Self::RUN_COLS);
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(params![project_id, limit], Self::run_header)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Runs left in `running` state by a process that no longer exists become `cancelled`.
    /// Runs owned by a live process (including this one) are never touched.
    pub fn recover_interrupted_runs(&self) -> Result<usize> {
        let mut st = self.conn.prepare("SELECT id, pid FROM runs WHERE state='running'")?;
        let rows: Vec<(i64, Option<i64>)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut n = 0;
        for (id, pid) in rows {
            let alive = pid.map(|p| crate::proc::pid_alive(p as u32)).unwrap_or(false);
            if !alive {
                n += self
                    .conn
                    .execute("UPDATE runs SET state='cancelled', finished_at=? WHERE id=?", params![Utc::now().to_rfc3339(), id])?;
            }
        }
        Ok(n)
    }

    /// Artifacts recorded across runs, newest first: (run id, project, tag, artifact).
    pub fn list_artifacts(&self, limit: u32) -> Result<Vec<(i64, String, String, ArtifactInfo)>> {
        let mut st = self.conn.prepare(
            "SELECT a.run_id, r.project_name, r.tag, a.name, a.path, a.size, a.sha256, a.sha512, a.kind
             FROM artifacts a JOIN runs r ON r.id = a.run_id ORDER BY a.id DESC LIMIT ?",
        )?;
        let rows = st.query_map([limit], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                ArtifactInfo {
                    name: r.get(3)?,
                    path: r.get(4)?,
                    size: r.get::<_, i64>(5)? as u64,
                    sha256: r.get(6)?,
                    sha512: r.get(7)?,
                    kind: r.get(8)?,
                },
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// All generated reports, newest first.
    pub fn list_all_reports(&self, limit: u32) -> Result<Vec<ReportRow>> {
        let mut st = self.conn.prepare(
            "SELECT p.id, p.run_id, r.project_name, r.tag, p.format, p.path, p.created_at
             FROM reports p JOIN runs r ON r.id = p.run_id ORDER BY p.id DESC LIMIT ?",
        )?;
        let rows = st.query_map([limit], |r| {
            Ok(ReportRow {
                id: r.get(0)?,
                run_id: r.get(1)?,
                project: r.get(2)?,
                tag: r.get(3)?,
                format: r.get(4)?,
                path: r.get(5)?,
                created_at: ts(r.get(6)?),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    // ---- reports / settings -------------------------------------------

    pub fn add_report(&self, run_id: i64, format: &str, path: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO reports(run_id, format, path, created_at) VALUES (?,?,?,?)",
            params![run_id, format, path, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn list_reports(&self, run_id: i64) -> Result<Vec<(String, String)>> {
        let mut st = self.conn.prepare("SELECT format, path FROM reports WHERE run_id=? ORDER BY id")?;
        let rows = st.query_map([run_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn
            .execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [key, value])?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM settings WHERE key=?", [key], |r| r.get(0)).optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_crud_and_uniqueness() {
        let db = Db::open_in_memory().unwrap();
        let p = db.add_project("Astra", Some("https://github.com/x/astra"), None, "main").unwrap();
        assert!(db.add_project("astra", None, Some("C:/a"), "main").is_err(), "names are case-insensitive unique");
        assert!(db.add_project("Empty", None, None, "main").is_err());
        assert_eq!(db.find_project("ASTRA").unwrap().unwrap().id, p.id);
        assert_eq!(db.list_projects().unwrap().len(), 1);
        assert!(db.remove_project("Astra").unwrap());
        assert!(!db.remove_project("Astra").unwrap());
    }

    #[test]
    fn run_lifecycle_round_trips_results_and_artifacts() {
        let db = Db::open_in_memory().unwrap();
        let p = db.add_project("A", None, Some("C:/a"), "main").unwrap();
        let run = db.start_run(Some(p.id), "A", "C:/a", "v1", "0.1.0").unwrap();
        let r = CheckResult::new("source.tag", Category::Trust, Status::Pass, "ok").evidence(serde_json::json!({"commit": "abc"}));
        db.add_result(run, &r).unwrap();
        db.add_artifact(
            run,
            &ArtifactInfo {
                name: "a.exe".into(),
                path: "x/a.exe".into(),
                size: 3,
                sha256: "s".into(),
                sha512: "t".into(),
                kind: "pe".into(),
            },
        )
        .unwrap();
        db.finish_run(run, RunState::Finished, Some("abc"), Some(100), Some(Verdict::Verified)).unwrap();

        let got = db.get_run(run).unwrap().unwrap();
        assert_eq!(got.score, Some(100));
        assert_eq!(got.verdict, Some(Verdict::Verified));
        assert_eq!(got.results[0].evidence["commit"], "abc");
        assert_eq!(got.artifacts[0].name, "a.exe");
        assert_eq!(db.list_runs(10, Some(p.id)).unwrap().len(), 1);
        assert_eq!(db.list_runs(10, Some(p.id + 99)).unwrap().len(), 0);
    }

    #[test]
    fn only_runs_of_dead_processes_are_recovered() {
        let db = Db::open_in_memory().unwrap();
        let live = db.start_run(None, "x", "r", "v", "0").unwrap(); // owned by this (live) process
        let dead = db.start_run(None, "y", "r", "v", "0").unwrap();
        db.conn.execute("UPDATE runs SET pid = 2147483000 WHERE id = ?", [dead]).unwrap();
        assert_eq!(db.recover_interrupted_runs().unwrap(), 1);
        assert_eq!(db.get_run(dead).unwrap().unwrap().status, RunState::Cancelled);
        assert_eq!(db.get_run(live).unwrap().unwrap().status, RunState::Running, "a live run must survive other connections opening");
    }

    #[test]
    fn artifacts_and_reports_are_listed_with_their_run_context() {
        let db = Db::open_in_memory().unwrap();
        let run = db.start_run(None, "Astra", "r", "v1", "0").unwrap();
        db.add_artifact(
            run,
            &ArtifactInfo { name: "a.exe".into(), path: "p".into(), size: 5, sha256: "s".into(), sha512: "t".into(), kind: "pe".into() },
        )
        .unwrap();
        db.add_report(run, "html", "C:/r.html").unwrap();
        let a = db.list_artifacts(10).unwrap();
        assert_eq!((a[0].1.as_str(), a[0].2.as_str(), a[0].3.name.as_str()), ("Astra", "v1", "a.exe"));
        let r = db.list_all_reports(10).unwrap();
        assert_eq!((r[0].project.as_str(), r[0].format.as_str()), ("Astra", "html"));
    }

    #[test]
    fn settings_upsert() {
        let db = Db::open_in_memory().unwrap();
        db.set_setting("k", "1").unwrap();
        db.set_setting("k", "2").unwrap();
        assert_eq!(db.get_setting("k").unwrap().as_deref(), Some("2"));
        assert_eq!(db.get_setting("zz").unwrap(), None);
    }
}
