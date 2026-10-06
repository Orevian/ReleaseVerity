//! SBOM discovery and structural validation (CycloneDX and SPDX).

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SbomSummary {
    pub format: String,
    pub spec_version: String,
    pub components: usize,
    pub with_version: usize,
    pub with_license: usize,
    /// Structural problems found (missing required fields etc.).
    pub issues: Vec<String>,
}

pub fn parse(text: &str) -> Result<SbomSummary> {
    let t = text.trim_start();
    if t.starts_with('<') {
        return parse_cyclonedx_xml(text);
    }
    let v: Value = serde_json::from_str(text).map_err(|e| anyhow::anyhow!("not valid JSON: {e}"))?;
    if v.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        return Ok(parse_cyclonedx(&v));
    }
    if v.get("spdxVersion").is_some() {
        return Ok(parse_spdx(&v));
    }
    bail!("neither CycloneDX (bomFormat) nor SPDX (spdxVersion) JSON")
}

fn parse_cyclonedx(v: &Value) -> SbomSummary {
    let mut issues = vec![];
    let spec = v.get("specVersion").and_then(Value::as_str).unwrap_or("").to_string();
    if spec.is_empty() {
        issues.push("missing specVersion".into());
    }
    let comps = v.get("components").and_then(Value::as_array).cloned().unwrap_or_default();
    if comps.is_empty() {
        issues.push("no components listed".into());
    }
    let with_version = comps.iter().filter(|c| c.get("version").and_then(Value::as_str).is_some_and(|s| !s.is_empty())).count();
    let with_license = comps.iter().filter(|c| c.get("licenses").and_then(Value::as_array).is_some_and(|l| !l.is_empty())).count();
    for c in comps.iter().filter(|c| c.get("name").is_none()) {
        issues.push(format!("component without name: {}", c.to_string().chars().take(60).collect::<String>()));
    }
    SbomSummary { format: "CycloneDX".into(), spec_version: spec, components: comps.len(), with_version, with_license, issues }
}

fn parse_spdx(v: &Value) -> SbomSummary {
    let mut issues = vec![];
    let spec = v.get("spdxVersion").and_then(Value::as_str).unwrap_or("").to_string();
    for f in ["SPDXID", "name", "dataLicense"] {
        if v.get(f).is_none() {
            issues.push(format!("missing {f}"));
        }
    }
    let pk = v.get("packages").and_then(Value::as_array).cloned().unwrap_or_default();
    if pk.is_empty() {
        issues.push("no packages listed".into());
    }
    let with_version = pk.iter().filter(|p| p.get("versionInfo").and_then(Value::as_str).is_some_and(|s| !s.is_empty())).count();
    let known = |s: &str| !s.is_empty() && s != "NOASSERTION" && s != "NONE";
    let with_license = pk
        .iter()
        .filter(|p| {
            p.get("licenseConcluded").and_then(Value::as_str).is_some_and(known)
                || p.get("licenseDeclared").and_then(Value::as_str).is_some_and(known)
        })
        .count();
    SbomSummary { format: "SPDX".into(), spec_version: spec, components: pk.len(), with_version, with_license, issues }
}

fn parse_cyclonedx_xml(text: &str) -> Result<SbomSummary> {
    if !text.contains("cyclonedx.org/schema/bom") {
        bail!("XML document is not a CycloneDX BOM");
    }
    let spec = text.split("cyclonedx.org/schema/bom/").nth(1).and_then(|s| s.split('"').next()).unwrap_or("").to_string();
    // Count component elements directly under <components>; nested ones are counted too (they are components).
    let n = text.matches("<component ").count() + text.matches("<component>").count();
    Ok(SbomSummary {
        format: "CycloneDX (XML)".into(),
        spec_version: spec,
        components: n,
        with_version: text.matches("<version>").count().min(n),
        with_license: text.matches("<licenses>").count().min(n),
        issues: if n == 0 { vec!["no components listed".into()] } else { vec![] },
    })
}

/// Repo paths that typically are (or hold) an SBOM.
pub fn looks_like_sbom_path(p: &str) -> bool {
    let n = p.rsplit('/').next().unwrap_or(p).to_ascii_lowercase();
    n.contains("sbom") || n.ends_with(".cdx.json") || n.ends_with(".spdx.json") || n == "bom.json" || n == "bom.xml"
}

pub const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
    "packages.lock.json",
    "Gemfile.lock",
    "composer.lock",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cyclonedx_json() {
        let s = parse(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"a","version":"1","licenses":[{"license":{"id":"MIT"}}]},{"name":"b"}]}"#,
        )
        .unwrap();
        assert_eq!((s.components, s.with_version, s.with_license), (2, 1, 1));
        assert!(s.issues.is_empty());
    }

    #[test]
    fn parses_spdx_and_flags_issues() {
        let s = parse(r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"name":"x","versionInfo":"2","licenseConcluded":"NOASSERTION"}]}"#).unwrap();
        assert_eq!(s.components, 1);
        assert_eq!(s.with_license, 0);
        assert!(s.issues.iter().any(|i| i.contains("name")) && s.issues.iter().any(|i| i.contains("dataLicense")));
    }

    #[test]
    fn rejects_non_sbom_and_empty_boms_are_flagged() {
        assert!(parse(r#"{"hello":1}"#).is_err());
        assert!(parse("garbage").is_err());
        let s = parse(r#"{"bomFormat":"CycloneDX","specVersion":"1.4"}"#).unwrap();
        assert!(s.issues.contains(&"no components listed".to_string()));
    }

    #[test]
    fn parses_cyclonedx_xml() {
        let x = r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.4"><components><component type="library"><name>a</name><version>1</version></component></components></bom>"#;
        let s = parse(x).unwrap();
        assert_eq!((s.format.as_str(), s.spec_version.as_str(), s.components), ("CycloneDX (XML)", "1.4", 1));
    }
}
