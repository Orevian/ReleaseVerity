//! Localization. Catalogs live in `locales/*.json` (repo root) and are embedded
//! at compile time so CLI and GUI share them and portable builds need no extra files.

use std::collections::HashMap;

const EN: &str = include_str!("../../../locales/en.json");
const TR: &str = include_str!("../../../locales/tr.json");

pub const LANGUAGES: [(&str, &str); 2] = [("en", "English"), ("tr", "Türkçe")];

/// The English catalog, loaded once (source of every message's English text).
pub fn english() -> &'static I18n {
    static EN_CATALOG: std::sync::OnceLock<I18n> = std::sync::OnceLock::new();
    EN_CATALOG.get_or_init(|| I18n::new("en"))
}

#[derive(Clone)]
pub struct I18n {
    lang: String,
    primary: HashMap<String, String>,
    fallback: HashMap<String, String>,
}

fn load(text: &str) -> HashMap<String, String> {
    serde_json::from_str(text).expect("embedded locale catalog is valid JSON")
}

impl I18n {
    pub fn new(lang: &str) -> Self {
        let fallback = load(EN);
        let primary = match lang {
            "tr" => load(TR),
            _ => fallback.clone(),
        };
        Self { lang: if lang == "tr" { "tr".into() } else { "en".into() }, primary, fallback }
    }

    pub fn lang(&self) -> &str {
        &self.lang
    }

    /// Translate `key`; falls back to English, then to the key itself.
    pub fn t(&self, key: &str) -> String {
        self.primary.get(key).or_else(|| self.fallback.get(key)).cloned().unwrap_or_else(|| key.to_string())
    }

    /// Translate and substitute `{name}` placeholders.
    pub fn tf(&self, key: &str, args: &[(&str, &str)]) -> String {
        let mut s = self.t(key);
        for (k, v) in args {
            s = s.replace(&format!("{{{k}}}"), v);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogs_have_identical_keys() {
        let en = load(EN);
        let tr = load(TR);
        let mut missing: Vec<_> = en.keys().filter(|k| !tr.contains_key(*k)).collect();
        missing.extend(tr.keys().filter(|k| !en.contains_key(*k)));
        assert!(missing.is_empty(), "keys not in both catalogs: {missing:?}");
    }

    #[test]
    fn placeholders_match_between_languages() {
        let placeholders = |s: &str| {
            let mut v: Vec<String> = s.split('{').skip(1).filter_map(|x| x.split_once('}').map(|(n, _)| n.to_string())).collect();
            v.sort();
            v
        };
        let (en, tr) = (load(EN), load(TR));
        for (k, e) in &en {
            assert_eq!(placeholders(e), placeholders(&tr[k]), "placeholders differ for {k}");
        }
    }

    #[test]
    fn translates_with_fallback_and_placeholders() {
        let tr = I18n::new("tr");
        assert_eq!(tr.t("status.verified"), "DOĞRULANDI");
        assert_eq!(I18n::new("en").t("status.verified"), "VERIFIED");
        assert_eq!(tr.t("no.such.key"), "no.such.key");
        assert_eq!(I18n::new("en").tf("cli.score", &[("score", "94")]), "Score: 94/100");
    }
}
