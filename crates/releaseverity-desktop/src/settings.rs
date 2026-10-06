//! Settings page: rows are generated from the real `Config`, edits go back through
//! `Config::set` (which validates) and are saved to `config.toml`.

use crate::SettingRow;
use releaseverity_services::core::config::Config;
use releaseverity_services::core::i18n::I18n;
use slint::SharedString;

#[cfg(test)]
pub const SECTIONS: usize = 11;

/// kind: 0 text · 1 switch · 2 choice · 3 number
struct Spec {
    key: &'static str,
    label: &'static str,
    hint: &'static str,
    kind: i32,
}

const fn s(key: &'static str, label: &'static str, hint: &'static str, kind: i32) -> Spec {
    Spec { key, label, hint, kind }
}

fn section_specs(section: usize) -> Vec<Spec> {
    match section {
        1 => vec![s("general.language", "set.language", "set.language.hint", 2)],
        2 => vec![s("ui.theme", "set.theme", "", 2)],
        3 => vec![
            s("verification.profile", "set.profile", "set.profile.hint", 2),
            s("verification.warnings_as_errors", "set.warn-errors", "set.warn-errors.hint", 1),
        ],
        4 => vec![s("environments.default", "set.default-env", "set.default-env.hint", 2)],
        5 => vec![s("github.api_url", "set.gh-api", "", 0), s("github.credential_name", "set.gh-cred", "set.gh-cred.hint", 0)],
        6 => vec![
            s("security.allow_host_execution", "set.allow-host", "set.allow-host.hint", 1),
            s("security.allow_network_in_sandbox", "set.allow-net", "set.allow-net.hint", 1),
            s("security.max_memory_mb", "set.max-mem", "set.max-mem.hint", 3),
            s("security.max_processes", "set.max-proc", "set.max-proc.hint", 3),
        ],
        8 => vec![s("logging.level", "set.log-level", "", 2), s("logging.retention_days", "set.log-retention", "", 3)],
        10 => vec![
            s("timeouts.install_secs", "set.t-install", "set.t-unit", 3),
            s("timeouts.launch_secs", "set.t-launch", "set.t-unit", 3),
            s("timeouts.smoke_secs", "set.t-smoke", "set.t-unit", 3),
            s("timeouts.cleanup_secs", "set.t-cleanup", "set.t-unit", 3),
            s("timeouts.build_secs", "set.t-build", "set.t-unit", 3),
            s("timeouts.network_secs", "set.t-network", "set.t-unit", 3),
        ],
        _ => vec![],
    }
}

/// (stored value, label to display)
fn choices(key: &str, i18n: &I18n) -> Vec<(&'static str, String)> {
    match key {
        "general.language" => vec![("en", "English".into()), ("tr", "Türkçe".into())],
        "ui.theme" => vec![("dark", i18n.t("set.theme.dark")), ("light", i18n.t("set.theme.light"))],
        "verification.profile" => {
            vec![("quick", i18n.t("set.profile.quick")), ("standard", i18n.t("set.profile.standard")), ("full", i18n.t("set.profile.full"))]
        }
        "environments.default" => vec![
            ("auto", "auto".into()),
            ("appcontainer", "appcontainer".into()),
            ("windows-sandbox", "windows-sandbox".into()),
            ("host", "host".into()),
        ],
        "logging.level" => ["trace", "debug", "info", "warn", "error"].iter().map(|l| (*l, l.to_string())).collect(),
        _ => vec![],
    }
}

pub fn note(section: usize, i18n: &I18n, version: &str) -> String {
    match section {
        0 => format!("ReleaseVerity {version}\n{}", i18n.t("set.general.note")),
        5 => i18n.t("set.github.note"),
        7 => i18n.t("set.storage.note"),
        9 => i18n.t("set.cli.note"),
        10 => i18n.t("set.advanced.note"),
        _ => String::new(),
    }
}

pub fn rows(section: usize, cfg: &Config, i18n: &I18n) -> Vec<SettingRow> {
    section_specs(section)
        .into_iter()
        .map(|sp| {
            let raw = cfg.get(sp.key).unwrap_or_default();
            let raw = raw.trim_matches(|c| c == '[' || c == ']' || c == '"').to_string();
            let opts = choices(sp.key, i18n);
            let value = if sp.kind == 2 { opts.iter().find(|(code, _)| *code == raw).map(|(_, l)| l.clone()).unwrap_or(raw) } else { raw };
            SettingRow {
                section: section.to_string().into(),
                key: sp.key.into(),
                label: i18n.t(sp.label).into(),
                hint: if sp.hint.is_empty() { "".into() } else { i18n.t(sp.hint).into() },
                kind: sp.kind,
                value: value.into(),
                options: crate::data::rows(opts.iter().map(|(_, l)| SharedString::from(l.as_str())).collect()),
            }
        })
        .collect()
}

/// Translate what the UI sent (a label for choices) back to the stored value.
pub fn to_stored(key: &str, shown: &str, i18n: &I18n) -> String {
    choices(key, i18n).into_iter().find(|(_, l)| l == shown).map(|(c, _)| c.to_string()).unwrap_or_else(|| shown.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_is_a_real_config_key_and_labels_exist_in_both_languages() {
        let cfg = Config::default();
        for lang in ["en", "tr"] {
            let i18n = I18n::new(lang);
            for sec in 0..SECTIONS {
                for sp in section_specs(sec) {
                    assert!(cfg.get(sp.key).is_some(), "unknown config key {}", sp.key);
                    assert_ne!(i18n.t(sp.label), sp.label, "missing {lang} label {}", sp.label);
                    if !sp.hint.is_empty() {
                        assert_ne!(i18n.t(sp.hint), sp.hint, "missing {lang} hint {}", sp.hint);
                    }
                }
            }
        }
    }

    #[test]
    fn choice_labels_map_back_to_stored_values_in_both_languages() {
        for lang in ["en", "tr"] {
            let i18n = I18n::new(lang);
            assert_eq!(to_stored("ui.theme", &i18n.t("set.theme.light"), &i18n), "light");
            assert_eq!(to_stored("general.language", "Türkçe", &i18n), "tr");
            assert_eq!(to_stored("security.max_memory_mb", "512", &i18n), "512");
        }
    }
}

#[cfg(test)]
mod catalog_usage {
    use releaseverity_services::core::i18n::I18n;
    use std::collections::BTreeSet;

    fn files(dir: &std::path::Path, ext: &str, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                files(&p, ext, out);
            } else if p.extension().is_some_and(|x| x == ext) {
                out.push(p);
            }
        }
    }

    /// Every string key the UI can ask for must exist in both catalogs, so no screen ever
    /// shows a raw key in either language.
    #[test]
    fn every_key_used_by_the_ui_exists_in_english_and_turkish() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut keys = BTreeSet::new();
        let mut slint = vec![];
        files(&root.join("ui"), "slint", &mut slint);
        for f in slint {
            let t = std::fs::read_to_string(&f).unwrap();
            for part in t.split("Tr.t(\"").skip(1) {
                let k = part.split('"').next().unwrap();
                if k.contains('.') && !k.ends_with('\\') {
                    keys.insert(k.to_string());
                }
            }
        }
        let mut rs = vec![];
        files(&root.join("src"), "rs", &mut rs);
        for f in rs {
            let t = std::fs::read_to_string(&f).unwrap();
            // `t("key")`, `ctx.t("key")`, `i18n.t("key")`, `i18n.tf("key", …)` — but not `get("x")`.
            for marker in ["t(\"", "tf(\""] {
                for (i, _) in t.match_indices(marker) {
                    let before = t[..i].chars().last().unwrap_or(' ');
                    if before.is_alphanumeric() || before == '_' {
                        continue;
                    }
                    let k = t[i + marker.len()..].split('"').next().unwrap();
                    if k.contains('.') && !k.contains(' ') && k.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c == '-') {
                        keys.insert(k.to_string());
                    }
                }
            }
        }
        assert!(keys.len() > 100, "scan found only {} keys", keys.len());
        let (en, tr) = (I18n::new("en"), I18n::new("tr"));
        let missing: Vec<_> = keys.iter().filter(|k| en.t(k) == **k || tr.t(k) == **k).collect();
        assert!(missing.is_empty(), "keys missing from en.json/tr.json: {missing:?}");
    }
}
