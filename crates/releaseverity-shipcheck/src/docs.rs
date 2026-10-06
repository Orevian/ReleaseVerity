//! Documentation checks: does the release ship installation, usage and upgrade
//! instructions? Reads the real README at the release tag.

use releaseverity_core::check::{Check, Context};
use releaseverity_core::model::{Category, CheckResult, Status};
use releaseverity_repro::git;

#[derive(Clone, Copy)]
pub enum Topic {
    Installation,
    Usage,
    Upgrade,
}

impl Topic {
    fn id(self) -> &'static str {
        match self {
            Topic::Installation => "docs.installation",
            Topic::Usage => "docs.usage",
            Topic::Upgrade => "docs.upgrade",
        }
    }
    fn words(self) -> &'static [&'static str] {
        match self {
            Topic::Installation => &["install", "setup", "getting started", "kurulum", "yükleme"],
            Topic::Usage => &["usage", "how to use", "quick start", "quickstart", "getting started", "examples", "kullanım", "örnek"],
            Topic::Upgrade => &["upgrad", "updating", "migrat", "yükselt", "güncelle", "breaking change"],
        }
    }
}

pub struct DocCheck(pub Topic);

/// Markdown headings of a document, lowercased.
pub fn headings(md: &str) -> Vec<String> {
    let mut in_code = false;
    let mut out = vec![];
    let lines: Vec<&str> = md.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            continue;
        }
        if t.starts_with('#') {
            out.push(t.trim_start_matches('#').trim().to_lowercase());
        } else if let Some(next) = lines.get(i + 1) {
            // Setext heading underline.
            let n = next.trim();
            if !t.is_empty() && !n.is_empty() && (n.chars().all(|c| c == '=') || n.chars().all(|c| c == '-')) && n.len() >= 3 {
                out.push(t.trim().to_lowercase());
            }
        }
    }
    out
}

fn doc_candidates(files: &[String]) -> Vec<&String> {
    files
        .iter()
        .filter(|f| {
            let l = f.to_ascii_lowercase();
            let base = l.rsplit('/').next().unwrap_or(&l);
            (base.starts_with("readme")
                || base.starts_with("install")
                || base.starts_with("upgrad")
                || base.starts_with("usage")
                || base.starts_with("changelog")
                || base.starts_with("migrat"))
                && (l.ends_with(".md") || l.ends_with(".txt") || l.ends_with(".rst") || !base.contains('.'))
        })
        .filter(|f| f.matches('/').count() <= 2)
        .collect()
}

pub fn find_topic(docs: &[(String, String)], topic: Topic) -> Option<String> {
    for (file, text) in docs {
        let fname = file.to_ascii_lowercase();
        let base = fname.rsplit('/').next().unwrap_or(&fname);
        let file_hit = match topic {
            Topic::Installation => base.starts_with("install"),
            Topic::Usage => base.starts_with("usage"),
            Topic::Upgrade => base.starts_with("upgrad") || base.starts_with("migrat"),
        };
        if file_hit {
            return Some(format!("{file} (dedicated file)"));
        }
        for h in headings(text) {
            if topic.words().iter().any(|w| h.contains(w)) {
                return Some(format!("{file} → \"{h}\""));
            }
        }
    }
    None
}

impl Check for DocCheck {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn category(&self) -> Category {
        Category::Documentation
    }
    fn run(&self, ctx: &mut Context) -> CheckResult {
        let id = self.id();
        let Some(dir) = ctx.state.repo_dir.clone() else {
            return CheckResult::msg(id, Category::Documentation, Status::Skipped, "m.docs.unavailable", &[]);
        };
        let rev = if ctx.target.tag.is_empty() { "HEAD".to_string() } else { ctx.target.tag.clone() };
        let files = match git::list_files(&dir, &rev) {
            Ok(f) => f,
            Err(e) => return CheckResult::new(id, Category::Documentation, Status::Error, format!("{e:#}")),
        };
        let docs: Vec<(String, String)> =
            doc_candidates(&files).into_iter().filter_map(|f| git::show_file(&dir, &rev, f).ok().map(|t| (f.clone(), t))).collect();
        match find_topic(&docs, self.0) {
            Some(hit) => CheckResult::msg(id, Category::Documentation, Status::Pass, "m.docs.found", &[("where", &hit)]),
            None => CheckResult::msg(id, Category::Documentation, Status::Fail, "m.docs.missing", &[]).suggestion_key(
                match self.0 {
                    Topic::Installation => "m.docs.fix.install",
                    Topic::Usage => "m.docs.fix.usage",
                    Topic::Upgrade => "m.docs.fix.upgrade",
                },
                &[],
            ),
        }
    }
}

pub fn checks() -> Vec<Box<dyn Check>> {
    vec![Box::new(DocCheck(Topic::Installation)), Box::new(DocCheck(Topic::Usage)), Box::new(DocCheck(Topic::Upgrade))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_atx_and_setext_headings_and_ignores_code_blocks() {
        let md = "Title\n=====\n\n## Installation\n\n```\n# Upgrade is a shell comment here\n```\n\nUsage\n-----\n";
        let h = headings(md);
        assert!(h.contains(&"installation".to_string()) && h.contains(&"usage".to_string()));
        assert!(!h.iter().any(|x| x.contains("upgrade")));
    }

    #[test]
    fn topics_match_english_and_turkish_headings() {
        let docs = vec![("README.md".to_string(), "# X\n## Kurulum\n## Kullanım\n".to_string())];
        assert!(find_topic(&docs, Topic::Installation).is_some());
        assert!(find_topic(&docs, Topic::Usage).is_some());
        assert!(find_topic(&docs, Topic::Upgrade).is_none());
        let with_file = vec![("docs/UPGRADING.md".to_string(), "text".to_string())];
        assert!(find_topic(&with_file, Topic::Upgrade).unwrap().contains("dedicated"));
    }
}
