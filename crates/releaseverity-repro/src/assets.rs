//! Classification of release assets and parsing of checksum files.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetRole {
    /// The thing users install or run.
    Artifact,
    ChecksumFile,
    DetachedSignature,
    Sbom,
    Attestation,
    Other,
}

pub fn file_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

pub fn classify(p: &Path) -> AssetRole {
    let n = file_name(p).to_ascii_lowercase();
    let ends = |s: &[&str]| s.iter().any(|x| n.ends_with(x));
    if ends(&[".intoto.jsonl", ".intoto", ".sigstore", ".sigstore.json", ".att"]) || n.contains("attestation") {
        AssetRole::Attestation
    } else if n.contains("sbom") || ends(&[".cdx.json", ".spdx.json", ".cdx.xml", ".spdx", "bom.json", "bom.xml"]) {
        AssetRole::Sbom
    } else if ends(&[".asc", ".sig", ".minisig"]) {
        AssetRole::DetachedSignature
    } else if n.contains("sha256sum")
        || n.contains("sha512sum")
        || n.contains("checksums")
        || ends(&[".sha256", ".sha512", ".sha256sum", ".sha512sum"])
    {
        AssetRole::ChecksumFile
    } else if ends(&[".txt", ".md", ".json", ".pdb"]) {
        AssetRole::Other
    } else {
        AssetRole::Artifact
    }
}

pub fn of_role(assets: &[PathBuf], role: AssetRole) -> Vec<&PathBuf> {
    assets.iter().filter(|p| classify(p) == role).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumEntry {
    pub file: String,
    pub algo: Algo,
    pub hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Sha256,
    Sha512,
}

fn algo_for_len(n: usize) -> Option<Algo> {
    match n {
        64 => Some(Algo::Sha256),
        128 => Some(Algo::Sha512),
        _ => None,
    }
}

/// Parse `sha256sum`-style files (`<hex>  <name>` / `<hex> *<name>`), BSD style
/// (`SHA256 (name) = hex`) and bare single-hash files (`foo.exe.sha256` containing only the hash).
pub fn parse_checksum_file(path: &Path, text: &str) -> Vec<ChecksumEntry> {
    let mut out = Vec::new();
    let is_hex = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        // BSD: SHA256 (file) = hex
        if let Some((lhs, hex)) = line.rsplit_once(" = ") {
            if let (Some(a), Some(b)) = (lhs.find('('), lhs.rfind(')')) {
                if let Some(algo) = algo_for_len(hex.trim().len()).filter(|_| is_hex(hex.trim())) {
                    out.push(ChecksumEntry { file: lhs[a + 1..b].to_string(), algo, hex: hex.trim().to_ascii_lowercase() });
                    continue;
                }
            }
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let (hex, rest) = (parts.next().unwrap_or(""), parts.next().map(str::trim));
        let Some(algo) = algo_for_len(hex.len()).filter(|_| is_hex(hex)) else { continue };
        let file = match rest {
            Some(r) if !r.is_empty() => r.trim_start_matches('*').to_string(),
            // Bare hash: refers to the file this checksum file is named after.
            _ => {
                let n = file_name(path);
                n.rsplit_once('.').map(|(stem, _)| stem.to_string()).unwrap_or(n)
            }
        };
        out.push(ChecksumEntry { file, algo, hex: hex.to_ascii_lowercase() });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_release_assets() {
        let c = |n: &str| classify(Path::new(n));
        assert_eq!(c("app-setup.exe"), AssetRole::Artifact);
        assert_eq!(c("app.tar.gz"), AssetRole::Artifact);
        assert_eq!(c("SHA256SUMS"), AssetRole::ChecksumFile);
        assert_eq!(c("app.exe.sha256"), AssetRole::ChecksumFile);
        assert_eq!(c("app.exe.asc"), AssetRole::DetachedSignature);
        assert_eq!(c("bom.cdx.json"), AssetRole::Sbom);
        assert_eq!(c("multiple.intoto.jsonl"), AssetRole::Attestation);
        assert_eq!(c("notes.txt"), AssetRole::Other);
    }

    #[test]
    fn parses_gnu_bsd_and_bare_checksum_files() {
        let h = "a".repeat(64);
        let gnu = format!("{h}  app.zip\n{h} *b.zip\n# c\n");
        let e = parse_checksum_file(Path::new("SHA256SUMS"), &gnu);
        assert_eq!(e.iter().map(|x| x.file.as_str()).collect::<Vec<_>>(), ["app.zip", "b.zip"]);
        let bsd = format!("SHA256 (x.bin) = {h}\n");
        assert_eq!(parse_checksum_file(Path::new("s"), &bsd)[0].file, "x.bin");
        let bare = parse_checksum_file(Path::new("app.exe.sha256"), &format!("{h}\n"));
        assert_eq!(bare[0].file, "app.exe");
        let sha512 = parse_checksum_file(Path::new("s"), &format!("{} f", "b".repeat(128)));
        assert_eq!(sha512[0].algo, Algo::Sha512);
        assert!(parse_checksum_file(Path::new("s"), "not a checksum line").is_empty());
    }
}
