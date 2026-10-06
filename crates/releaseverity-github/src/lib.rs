//! GitHub integration: repositories, branches, tags, releases and their assets,
//! commits, Actions runs, pull requests, checks — and publishing a verification
//! result back as a Check Run (or a commit status when a check cannot be created).

pub mod credstore;

use serde::Serialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("could not reach GitHub: {0}")]
    Network(String),
    #[error("{message}")]
    Status { code: u16, message: String, rate_limited: bool },
    #[error("unexpected response from GitHub: {0}")]
    Parse(String),
    #[error("{0}")]
    Io(String),
}

impl ApiError {
    pub fn code(&self) -> Option<u16> {
        match self {
            ApiError::Status { code, .. } => Some(*code),
            _ => None,
        }
    }
}

type Result<T> = std::result::Result<T, ApiError>;

/// `https://github.com/o/r(.git)`, `git@github.com:o/r.git`, or `o/r` → (owner, repo).
pub fn parse_repo(s: &str) -> Option<(String, String)> {
    let s = s.trim().trim_end_matches('/').trim_end_matches(".git");
    let rest = if let Some(i) = s.find("github.com") {
        s[i + "github.com".len()..].trim_start_matches(['/', ':'])
    } else if s.matches('/').count() == 1 && !s.contains(['\\', ':', ' ']) {
        s
    } else {
        return None;
    };
    let mut it = rest.split('/');
    let (o, r) = (it.next()?, it.next()?);
    (!o.is_empty() && !r.is_empty()).then(|| (o.to_string(), r.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoInfo {
    pub full_name: String,
    pub default_branch: String,
    pub private: bool,
    pub description: String,
    pub html_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetInfo {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub content_type: String,
    /// API URL (works for private repositories with a token).
    pub api_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub id: u64,
    pub tag: String,
    pub name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub published_at: String,
    pub body: String,
    pub assets: Vec<AssetInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub sha: String,
    pub message: String,
    pub author: String,
    pub date: String,
    /// GitHub's verdict on the commit signature.
    pub signature_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowRun {
    pub id: u64,
    pub name: String,
    pub status: String,
    pub conclusion: String,
    pub head_sha: String,
    pub html_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequest {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub author: String,
    pub head_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRunInfo {
    pub name: String,
    pub status: String,
    pub conclusion: String,
    pub app: String,
}

/// What to publish for a verified release.
#[derive(Debug, Clone, Serialize)]
pub struct CheckOutput {
    /// success | neutral | failure
    pub conclusion: String,
    pub title: String,
    pub summary: String,
    pub details_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    CheckRun(String),
    /// A commit status, used when the token cannot create check runs.
    Status(String),
}

pub struct GitHub {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl GitHub {
    pub fn new(api_url: &str, token: Option<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("ReleaseVerity/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { base: api_url.trim_end_matches('/').to_string(), token: token.filter(|t| !t.is_empty()), agent }
    }

    pub fn authenticated(&self) -> bool {
        self.token.is_some()
    }

    fn request(&self, method: &str, url: &str) -> ureq::Request {
        let mut r = self.agent.request(method, url).set("Accept", "application/vnd.github+json").set("X-GitHub-Api-Version", "2022-11-28");
        if let Some(t) = &self.token {
            r = r.set("Authorization", &format!("Bearer {t}"));
        }
        r
    }

    fn map_err(e: ureq::Error) -> ApiError {
        match e {
            ureq::Error::Status(code, resp) => {
                let remaining = resp.header("x-ratelimit-remaining").map(str::to_string);
                let reset = resp.header("x-ratelimit-reset").map(str::to_string);
                let body: Value = resp.into_json().unwrap_or(Value::Null);
                let api_msg = body["message"].as_str().unwrap_or("").to_string();
                let rate_limited =
                    (code == 403 || code == 429) && (remaining.as_deref() == Some("0") || api_msg.to_lowercase().contains("rate limit"));
                let message = match code {
                    401 => "GitHub rejected the token (invalid or expired). Reconnect your account in Settings → GitHub.".to_string(),
                    403 if rate_limited => format!(
                        "GitHub rate limit exceeded{}. Connect a token to raise the limit.",
                        reset.map(|r| format!(" (resets at unix time {r})")).unwrap_or_default()
                    ),
                    403 => format!("GitHub denied access: {api_msg}"),
                    404 => "Not found on GitHub. If the repository is private, connect a token that can read it.".to_string(),
                    _ => format!("GitHub returned HTTP {code}: {api_msg}"),
                };
                ApiError::Status { code, message, rate_limited }
            }
            ureq::Error::Transport(t) => ApiError::Network(t.to_string()),
        }
    }

    fn get(&self, path: &str) -> Result<Value> {
        let url = if path.starts_with("http") { path.to_string() } else { format!("{}{}", self.base, path) };
        self.request("GET", &url).call().map_err(Self::map_err)?.into_json::<Value>().map_err(|e| ApiError::Parse(e.to_string()))
    }

    /// Follow `?page=` pagination (max `pages` pages of 100).
    fn list(&self, path: &str, pages: u32) -> Result<Vec<Value>> {
        let mut out = vec![];
        for page in 1..=pages {
            let sep = if path.contains('?') { '&' } else { '?' };
            let v = self.get(&format!("{path}{sep}per_page=100&page={page}"))?;
            let arr = match v {
                Value::Array(a) => a,
                other => other.as_object().and_then(|o| o.values().find_map(|x| x.as_array().cloned())).unwrap_or_default(),
            };
            let n = arr.len();
            out.extend(arr);
            if n < 100 {
                break;
            }
        }
        Ok(out)
    }

    pub fn login(&self) -> Result<String> {
        Ok(self.get("/user")?["login"].as_str().unwrap_or("").to_string())
    }

    pub fn repo(&self, o: &str, r: &str) -> Result<RepoInfo> {
        let v = self.get(&format!("/repos/{o}/{r}"))?;
        Ok(RepoInfo {
            full_name: v["full_name"].as_str().unwrap_or("").into(),
            default_branch: v["default_branch"].as_str().unwrap_or("main").into(),
            private: v["private"].as_bool().unwrap_or(false),
            description: v["description"].as_str().unwrap_or("").into(),
            html_url: v["html_url"].as_str().unwrap_or("").into(),
        })
    }

    pub fn branches(&self, o: &str, r: &str) -> Result<Vec<String>> {
        Ok(self.list(&format!("/repos/{o}/{r}/branches"), 3)?.iter().filter_map(|b| b["name"].as_str().map(str::to_string)).collect())
    }

    pub fn tags(&self, o: &str, r: &str) -> Result<Vec<String>> {
        Ok(self.list(&format!("/repos/{o}/{r}/tags"), 3)?.iter().filter_map(|b| b["name"].as_str().map(str::to_string)).collect())
    }

    fn release_from(v: &Value) -> ReleaseInfo {
        ReleaseInfo {
            id: v["id"].as_u64().unwrap_or(0),
            tag: v["tag_name"].as_str().unwrap_or("").into(),
            name: v["name"].as_str().unwrap_or("").into(),
            draft: v["draft"].as_bool().unwrap_or(false),
            prerelease: v["prerelease"].as_bool().unwrap_or(false),
            published_at: v["published_at"].as_str().unwrap_or("").into(),
            body: v["body"].as_str().unwrap_or("").into(),
            assets: v["assets"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|x| AssetInfo {
                            id: x["id"].as_u64().unwrap_or(0),
                            name: x["name"].as_str().unwrap_or("").into(),
                            size: x["size"].as_u64().unwrap_or(0),
                            content_type: x["content_type"].as_str().unwrap_or("").into(),
                            api_url: x["url"].as_str().unwrap_or("").into(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    pub fn releases(&self, o: &str, r: &str) -> Result<Vec<ReleaseInfo>> {
        Ok(self.list(&format!("/repos/{o}/{r}/releases"), 2)?.iter().map(Self::release_from).collect())
    }

    pub fn release_by_tag(&self, o: &str, r: &str, tag: &str) -> Result<ReleaseInfo> {
        Ok(Self::release_from(&self.get(&format!("/repos/{o}/{r}/releases/tags/{tag}"))?))
    }

    pub fn commit(&self, o: &str, r: &str, rev: &str) -> Result<CommitInfo> {
        let v = self.get(&format!("/repos/{o}/{r}/commits/{rev}"))?;
        Ok(CommitInfo {
            sha: v["sha"].as_str().unwrap_or("").into(),
            message: v["commit"]["message"].as_str().unwrap_or("").lines().next().unwrap_or("").into(),
            author: v["commit"]["author"]["name"].as_str().unwrap_or("").into(),
            date: v["commit"]["author"]["date"].as_str().unwrap_or("").into(),
            signature_verified: v["commit"]["verification"]["verified"].as_bool().unwrap_or(false),
        })
    }

    pub fn workflow_runs(&self, o: &str, r: &str, head_sha: Option<&str>) -> Result<Vec<WorkflowRun>> {
        let q = head_sha.map(|s| format!("?head_sha={s}")).unwrap_or_default();
        let v = self.get(&format!("/repos/{o}/{r}/actions/runs{q}"))?;
        Ok(v["workflow_runs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| WorkflowRun {
                        id: x["id"].as_u64().unwrap_or(0),
                        name: x["name"].as_str().unwrap_or("").into(),
                        status: x["status"].as_str().unwrap_or("").into(),
                        conclusion: x["conclusion"].as_str().unwrap_or("").into(),
                        head_sha: x["head_sha"].as_str().unwrap_or("").into(),
                        html_url: x["html_url"].as_str().unwrap_or("").into(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn pull_requests(&self, o: &str, r: &str, state: &str) -> Result<Vec<PullRequest>> {
        Ok(self
            .list(&format!("/repos/{o}/{r}/pulls?state={state}"), 1)?
            .iter()
            .map(|x| PullRequest {
                number: x["number"].as_u64().unwrap_or(0),
                title: x["title"].as_str().unwrap_or("").into(),
                state: x["state"].as_str().unwrap_or("").into(),
                author: x["user"]["login"].as_str().unwrap_or("").into(),
                head_sha: x["head"]["sha"].as_str().unwrap_or("").into(),
            })
            .collect())
    }

    pub fn check_runs(&self, o: &str, r: &str, rev: &str) -> Result<Vec<CheckRunInfo>> {
        let v = self.get(&format!("/repos/{o}/{r}/commits/{rev}/check-runs"))?;
        Ok(v["check_runs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| CheckRunInfo {
                        name: x["name"].as_str().unwrap_or("").into(),
                        status: x["status"].as_str().unwrap_or("").into(),
                        conclusion: x["conclusion"].as_str().unwrap_or("").into(),
                        app: x["app"]["name"].as_str().unwrap_or("").into(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Download a release asset into `dir` (streamed; `progress(done, total)`).
    pub fn download_asset(&self, asset: &AssetInfo, dir: &Path, progress: &mut dyn FnMut(u64, Option<u64>)) -> Result<PathBuf> {
        // Never let a hostile asset name escape the destination directory.
        let name = Path::new(&asset.name)
            .file_name()
            .map(|n| n.to_owned())
            .ok_or_else(|| ApiError::Io(format!("unsafe asset name {:?}", asset.name)))?;
        std::fs::create_dir_all(dir).map_err(|e| ApiError::Io(e.to_string()))?;
        let dest = dir.join(name);
        let resp = self.request("GET", &asset.api_url).set("Accept", "application/octet-stream").call().map_err(Self::map_err)?;
        let total = resp.header("content-length").and_then(|s| s.parse::<u64>().ok()).or(Some(asset.size).filter(|s| *s > 0));
        let mut reader = resp.into_reader();
        let mut file = std::fs::File::create(&dest).map_err(|e| ApiError::Io(format!("{}: {e}", dest.display())))?;
        let (mut buf, mut done) = (vec![0u8; 256 * 1024], 0u64);
        loop {
            let n = reader.read(&mut buf).map_err(|e| ApiError::Network(e.to_string()))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).map_err(|e| ApiError::Io(e.to_string()))?;
            done += n as u64;
            progress(done, total);
        }
        if let Some(t) = total {
            if t != done {
                return Err(ApiError::Network(format!("download of {} was truncated ({done} of {t} bytes)", asset.name)));
            }
        }
        Ok(dest)
    }

    /// Publish a verification result on `sha`. Creates a Check Run (needs a GitHub App or
    /// Actions `GITHUB_TOKEN` with `checks: write`); if GitHub refuses, falls back to a
    /// commit status, which a personal access token with `repo:status` can create.
    pub fn publish(&self, o: &str, r: &str, sha: &str, out: &CheckOutput) -> Result<Published> {
        let body = json!({
            "name": "ReleaseVerity",
            "head_sha": sha,
            "status": "completed",
            "conclusion": out.conclusion,
            "details_url": out.details_url,
            "output": { "title": out.title, "summary": out.summary },
        });
        let url = format!("{}/repos/{o}/{r}/check-runs", self.base);
        match self.request("POST", &url).send_json(body).map_err(Self::map_err) {
            Ok(resp) => {
                let v: Value = resp.into_json().map_err(|e| ApiError::Parse(e.to_string()))?;
                Ok(Published::CheckRun(v["html_url"].as_str().unwrap_or("").to_string()))
            }
            Err(ApiError::Status { code: 401 | 403 | 404 | 422, .. }) => {
                let state = match out.conclusion.as_str() {
                    "success" => "success",
                    "failure" => "failure",
                    _ => "error",
                };
                let desc: String = out.title.chars().take(140).collect();
                let url = format!("{}/repos/{o}/{r}/statuses/{sha}", self.base);
                let resp = self
                    .request("POST", &url)
                    .send_json(json!({ "state": state, "context": "ReleaseVerity", "description": desc, "target_url": out.details_url }))
                    .map_err(Self::map_err)?;
                let v: Value = resp.into_json().map_err(|e| ApiError::Parse(e.to_string()))?;
                Ok(Published::Status(v["url"].as_str().unwrap_or("").to_string()))
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn parses_repo_references() {
        let p = |s: &str| parse_repo(s);
        assert_eq!(p("https://github.com/o/r"), Some(("o".into(), "r".into())));
        assert_eq!(p("https://github.com/o/r.git/"), Some(("o".into(), "r".into())));
        assert_eq!(p("git@github.com:o/r.git"), Some(("o".into(), "r".into())));
        assert_eq!(p("o/r"), Some(("o".into(), "r".into())));
        assert_eq!(p("https://gitlab.com/o/r"), None);
        assert_eq!(p("C:\\repo"), None);
        assert_eq!(p("justaname"), None);
    }

    /// A tiny HTTP server speaking just enough of the GitHub REST API. It records every
    /// request line + auth header so tests can assert on what the client really sent.
    struct Server {
        base: String,
        log: Arc<Mutex<Vec<(String, String, String)>>>, // (method+path, auth, body)
    }

    type Route = (&'static str, u16, String, Vec<(&'static str, String)>);

    fn serve(routes: Vec<Route>) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log = Arc::new(Mutex::new(vec![]));
        let log2 = log.clone();
        let routes = Arc::new(routes);
        std::thread::spawn(move || {
            for stream in l.incoming().flatten() {
                let (routes, log2) = (routes.clone(), log2.clone());
                std::thread::spawn(move || {
                    let mut rd = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if rd.read_line(&mut line).is_err() {
                        return;
                    }
                    let (mut auth, mut len) = (String::new(), 0usize);
                    loop {
                        let mut h = String::new();
                        rd.read_line(&mut h).unwrap();
                        if h.trim().is_empty() {
                            break;
                        }
                        let lower = h.to_lowercase();
                        if let Some(v) = lower.strip_prefix("authorization:") {
                            auth = v.trim().to_string();
                        }
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; len];
                    std::io::Read::read_exact(&mut rd, &mut body).unwrap();
                    let req = line.trim().to_string();
                    let path = req.split(' ').take(2).collect::<Vec<_>>().join(" ");
                    log2.lock().unwrap().push((path.clone(), auth, String::from_utf8_lossy(&body).into_owned()));
                    let hit = routes
                        .iter()
                        .find(|(p, ..)| path == *p || path.starts_with(&format!("{p}?")) || path.starts_with(&format!("{p}&")));
                    let (status, payload, headers) = match hit {
                        Some((_, s, b, h)) => (*s, b.clone(), h.clone()),
                        None => (404, r#"{"message":"Not Found"}"#.to_string(), vec![]),
                    };
                    let mut out = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                        payload.len()
                    );
                    for (k, v) in headers {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    out.push_str("\r\n");
                    out.push_str(&payload);
                    let mut s = stream;
                    let _ = s.write_all(out.as_bytes());
                    let _ = s.flush();
                    // Send FIN, then give the client time to drain the response before the socket is dropped
                    // (closing with data still in flight can reset the connection on Windows).
                    let _ = s.shutdown(std::net::Shutdown::Write);
                    std::thread::sleep(Duration::from_millis(400));
                });
            }
        });
        Server { base, log }
    }

    fn ok(path: &'static str, body: Value) -> Route {
        (path, 200, body.to_string(), vec![])
    }

    #[test]
    fn lists_releases_with_assets_and_sends_the_token() {
        let rel = json!({"id": 7, "tag_name": "v1.4.0", "name": "1.4.0", "draft": false, "prerelease": true, "published_at": "2026-01-02T00:00:00Z", "body": "notes",
            "assets": [{"id": 9, "name": "app.zip", "size": 12, "content_type": "application/zip", "url": "http://x/assets/9"}]});
        let s = serve(vec![
            ok("GET /repos/o/r/releases", json!([rel.clone()])),
            ok("GET /repos/o/r/releases/tags/v1.4.0", rel),
            ok("GET /user", json!({"login": "octo"})),
        ]);
        let gh = GitHub::new(&s.base, Some("tok123".into()));
        let rs = gh.releases("o", "r").unwrap();
        assert_eq!(
            (rs[0].tag.as_str(), rs[0].prerelease, rs[0].assets[0].name.as_str(), rs[0].assets[0].size),
            ("v1.4.0", true, "app.zip", 12)
        );
        assert_eq!(gh.release_by_tag("o", "r", "v1.4.0").unwrap().assets.len(), 1);
        assert_eq!(gh.login().unwrap(), "octo");
        assert!(s.log.lock().unwrap().iter().all(|(_, auth, _)| auth == "bearer tok123"));
        assert!(gh.authenticated());
    }

    #[test]
    fn maps_http_errors_to_actionable_messages() {
        let s = serve(vec![
            (
                "GET /repos/o/limited",
                403,
                r#"{"message":"API rate limit exceeded"}"#.into(),
                vec![("X-RateLimit-Remaining", "0".into()), ("X-RateLimit-Reset", "1700000000".into())],
            ),
            ("GET /repos/o/badtoken", 401, r#"{"message":"Bad credentials"}"#.into(), vec![]),
        ]);
        let gh = GitHub::new(&s.base, None);
        match gh.repo("o", "limited").unwrap_err() {
            ApiError::Status { rate_limited: true, message, .. } => {
                assert!(message.contains("rate limit") && message.contains("Connect a token"))
            }
            e => panic!("{e:?}"),
        }
        let e = gh.repo("o", "missing").unwrap_err();
        assert_eq!(e.code(), Some(404));
        assert!(e.to_string().contains("private"));
        assert!(gh.repo("o", "badtoken").unwrap_err().to_string().contains("Reconnect"));
        assert!(matches!(GitHub::new("http://127.0.0.1:1", None).login().unwrap_err(), ApiError::Network(_)));
    }

    #[test]
    fn downloads_assets_with_progress_and_rejects_path_traversal() {
        let payload = "x".repeat(60_000);
        let s = serve(vec![("GET /assets/9", 200, payload.clone(), vec![])]);
        let gh = GitHub::new(&s.base, None);
        let asset = AssetInfo {
            id: 9,
            name: "app.zip".into(),
            size: payload.len() as u64,
            content_type: "".into(),
            api_url: format!("{}/assets/9", s.base),
        };
        let d = tempfile::tempdir().unwrap();
        let (mut calls, mut last) = (0, 0);
        let p = gh
            .download_asset(&asset, d.path(), &mut |done, total| {
                calls += 1;
                last = done;
                assert_eq!(total, Some(60_000));
            })
            .unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap().len(), 60_000);
        assert!(calls >= 2 && last == 60_000);

        let evil = AssetInfo { name: "../../escape.txt".into(), ..asset.clone() };
        // The fake server answers one request per connection, so use a fresh client (fresh connection) each time.
        let gh = GitHub::new(&s.base, None);
        let p = gh.download_asset(&evil, d.path(), &mut |_, _| {}).unwrap();
        assert_eq!(p.parent().unwrap(), d.path(), "directory components are stripped");
        assert!(!d.path().parent().unwrap().join("escape.txt").exists());
        // Rejected before any request is made.
        assert!(GitHub::new(&s.base, None).download_asset(&AssetInfo { name: "..".into(), ..asset }, d.path(), &mut |_, _| {}).is_err());
    }

    #[test]
    fn publishes_a_check_run_and_falls_back_to_a_commit_status() {
        let out = CheckOutput {
            conclusion: "success".into(),
            title: "Release verification passed — 94/100".into(),
            summary: "ok".into(),
            details_url: None,
        };
        let s = serve(vec![("POST /repos/o/r/check-runs", 201, r#"{"html_url":"https://github.com/o/r/runs/1"}"#.into(), vec![])]);
        let gh = GitHub::new(&s.base, Some("t".into()));
        assert_eq!(gh.publish("o", "r", "abc", &out).unwrap(), Published::CheckRun("https://github.com/o/r/runs/1".into()));
        let body = s.log.lock().unwrap()[0].2.clone();
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            (v["name"].as_str(), v["head_sha"].as_str(), v["conclusion"].as_str()),
            (Some("ReleaseVerity"), Some("abc"), Some("success"))
        );

        // A PAT cannot create check runs (403) → commit status instead.
        let s = serve(vec![
            ("POST /repos/o/r/check-runs", 403, r#"{"message":"Resource not accessible by personal access token"}"#.into(), vec![]),
            ("POST /repos/o/r/statuses/abc", 201, r#"{"url":"https://api.github.com/repos/o/r/statuses/abc"}"#.into(), vec![]),
        ]);
        let gh = GitHub::new(&s.base, Some("pat".into()));
        let p = gh.publish("o", "r", "abc", &CheckOutput { conclusion: "failure".into(), ..out.clone() }).unwrap();
        assert!(matches!(p, Published::Status(_)));
        let log = s.log.lock().unwrap();
        let status_body: Value = serde_json::from_str(&log[1].2).unwrap();
        assert_eq!((status_body["state"].as_str(), status_body["context"].as_str()), (Some("failure"), Some("ReleaseVerity")));
    }

    #[test]
    fn parses_commits_runs_prs_and_checks() {
        let s = serve(vec![
            ok(
                "GET /repos/o/r/commits/abc",
                json!({"sha":"abc","commit":{"message":"fix\n\nbody","author":{"name":"A","date":"d"},"verification":{"verified":true}}}),
            ),
            ok(
                "GET /repos/o/r/actions/runs",
                json!({"workflow_runs":[{"id":1,"name":"CI","status":"completed","conclusion":"success","head_sha":"abc","html_url":"u"}]}),
            ),
            ok("GET /repos/o/r/pulls", json!([{"number":3,"title":"T","state":"open","user":{"login":"u"},"head":{"sha":"abc"}}])),
            ok(
                "GET /repos/o/r/commits/abc/check-runs",
                json!({"check_runs":[{"name":"build","status":"completed","conclusion":"success","app":{"name":"GitHub Actions"}}]}),
            ),
        ]);
        let gh = GitHub::new(&s.base, None);
        let c = gh.commit("o", "r", "abc").unwrap();
        assert_eq!((c.message.as_str(), c.signature_verified), ("fix", true));
        assert_eq!(gh.workflow_runs("o", "r", Some("abc")).unwrap()[0].conclusion, "success");
        assert_eq!(gh.pull_requests("o", "r", "open").unwrap()[0].number, 3);
        assert_eq!(gh.check_runs("o", "r", "abc").unwrap()[0].app, "GitHub Actions");
    }
}
