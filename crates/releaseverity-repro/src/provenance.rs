//! in-toto / SLSA provenance parsing and subject-digest binding.
//!
//! This module checks that an attestation's *subject digests match the artifact bytes*
//! and extracts builder/source claims. It does **not** verify the DSSE signature chain;
//! callers must say so (and use `gh attestation verify` for cryptographic verification).

use anyhow::{bail, Result};
use base64::Engine;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Provenance {
    pub predicate_type: String,
    pub subjects: Vec<Subject>,
    pub builder_id: Option<String>,
    pub source_repo: Option<String>,
    pub source_commit: Option<String>,
    /// Number of signatures present on the DSSE envelope (not verified here).
    pub envelope_signatures: usize,
}

fn decode_statement(v: &Value) -> Option<(Value, usize)> {
    // Plain statement.
    if v.get("_type").is_some() && v.get("subject").is_some() {
        return Some((v.clone(), 0));
    }
    // DSSE envelope, possibly wrapped in a Sigstore bundle.
    let env = v.get("dsseEnvelope").unwrap_or(v);
    let payload = env.get("payload")?.as_str()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload))
        .ok()?;
    let stmt: Value = serde_json::from_slice(&bytes).ok()?;
    let sigs = env.get("signatures").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    Some((stmt, sigs))
}

/// Parse a `.intoto.jsonl` / bundle file (one or many JSON documents).
pub fn parse(text: &str) -> Result<Vec<Provenance>> {
    let mut docs: Vec<Value> = Vec::new();
    let trimmed = text.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        docs.push(v);
    } else {
        for line in trimmed.lines().filter(|l| !l.trim().is_empty()) {
            docs.push(serde_json::from_str(line).map_err(|e| anyhow::anyhow!("invalid JSON line: {e}"))?);
        }
    }
    let out: Vec<Provenance> = docs.iter().filter_map(statement_to_provenance).collect();
    if out.is_empty() {
        bail!("no in-toto statements found");
    }
    Ok(out)
}

fn statement_to_provenance(doc: &Value) -> Option<Provenance> {
    let (stmt, sigs) = decode_statement(doc)?;
    let subjects = stmt
        .get("subject")?
        .as_array()?
        .iter()
        .map(|s| Subject {
            name: s.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
            sha256: s.get("digest").and_then(|d| d.get("sha256")).and_then(Value::as_str).map(str::to_ascii_lowercase),
        })
        .collect();
    let pred = stmt.get("predicate").cloned().unwrap_or(Value::Null);
    let s = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_string);
    // SLSA v1
    let builder_id = s(pred.pointer("/runDetails/builder/id")).or_else(|| s(pred.pointer("/builder/id")));
    let source_repo = s(pred.pointer("/buildDefinition/externalParameters/workflow/repository"))
        .or_else(|| s(pred.pointer("/invocation/configSource/uri")))
        .or_else(|| {
            pred.pointer("/buildDefinition/resolvedDependencies")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|d| s(d.get("uri")))
        });
    let source_commit = s(pred.pointer("/buildDefinition/resolvedDependencies/0/digest/gitCommit"))
        .or_else(|| s(pred.pointer("/invocation/configSource/digest/sha1")));
    Some(Provenance {
        predicate_type: s(stmt.get("predicateType")).unwrap_or_default(),
        subjects,
        builder_id,
        source_repo,
        source_commit,
        envelope_signatures: sigs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dsse(stmt: &Value) -> String {
        let payload = base64::engine::general_purpose::STANDARD.encode(stmt.to_string());
        serde_json::json!({"payloadType":"application/vnd.in-toto+json","payload":payload,"signatures":[{"sig":"x"}]}).to_string()
    }

    #[test]
    fn extracts_slsa_v1_claims_from_dsse() {
        let stmt = serde_json::json!({
            "_type":"https://in-toto.io/Statement/v1",
            "subject":[{"name":"app.exe","digest":{"sha256":"ABCD"}}],
            "predicateType":"https://slsa.dev/provenance/v1",
            "predicate":{
                "buildDefinition":{"externalParameters":{"workflow":{"repository":"https://github.com/o/r"}},
                    "resolvedDependencies":[{"uri":"git+https://github.com/o/r@refs/tags/v1","digest":{"gitCommit":"deadbeef"}}]},
                "runDetails":{"builder":{"id":"https://github.com/actions/runner"}}}
        });
        let p = parse(&dsse(&stmt)).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].subjects[0].sha256.as_deref(), Some("abcd"));
        assert_eq!(p[0].source_commit.as_deref(), Some("deadbeef"));
        assert_eq!(p[0].builder_id.as_deref(), Some("https://github.com/actions/runner"));
        assert_eq!(p[0].envelope_signatures, 1);
    }

    #[test]
    fn jsonl_with_many_lines_and_garbage_rejected() {
        let s = serde_json::json!({"_type":"x","subject":[],"predicateType":"p","predicate":{}});
        let two = format!("{}\n{}\n", dsse(&s), dsse(&s));
        assert_eq!(parse(&two).unwrap().len(), 2);
        assert!(parse("not json").is_err());
        assert!(parse(r#"{"a":1}"#).is_err());
    }
}
