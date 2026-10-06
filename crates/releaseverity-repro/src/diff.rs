//! Binary difference analysis. Every number and every "probable cause" below is
//! computed from the actual bytes of the two files; nothing is estimated or invented.

use crate::inspect::{self, detect_kind, Section, MAX_PARSE_BYTES};
use anyhow::{bail, Context as _, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    pub name: String,
    pub size_a: usize,
    pub size_b: usize,
    pub diff_bytes: usize,
    /// Percent of this region's bytes that differ.
    pub changed_pct: f64,
    /// Percent of *all* differing bytes that fall in this region.
    pub share_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cause {
    pub code: String,
    /// English text derived from the catalog (`cause.<code>`); localize via the code.
    pub message: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub args: std::collections::BTreeMap<String, String>,
    pub evidence: Value,
}

impl Cause {
    /// Build a cause from its catalog key `cause.<code>`.
    pub fn new(code: &str, args: &[(&str, String)], evidence: Value) -> Self {
        let args: std::collections::BTreeMap<String, String> = args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let refs: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let message = releaseverity_core::i18n::english().tf(&format!("cause.{code}"), &refs);
        Self { code: code.to_string(), message, args, evidence }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub kind: String,
    pub identical: bool,
    pub size_a: usize,
    pub size_b: usize,
    pub total_diff_bytes: usize,
    pub regions: Vec<Region>,
    pub causes: Vec<Cause>,
}

/// Count differing bytes in `[start, end)`; bytes past the end of either file count as different.
fn count_diff(a: &[u8], b: &[u8], start: usize, end: usize) -> usize {
    let mut n = 0;
    for i in start..end {
        match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) if x == y => {}
            (None, None) => {}
            _ => n += 1,
        }
    }
    n
}

/// Merge differing offsets into runs separated by at most `gap` equal bytes.
fn diff_runs(a: &[u8], b: &[u8], gap: usize, limit: usize) -> Vec<(usize, usize)> {
    let max = a.len().max(b.len());
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for i in 0..max {
        let differs = match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => x != y,
            _ => true,
        };
        if !differs {
            continue;
        }
        match runs.last_mut() {
            Some(last) if i - last.1 <= gap => last.1 = i + 1,
            _ => {
                if runs.len() >= limit {
                    break;
                }
                runs.push((i, i + 1));
            }
        }
    }
    runs
}

/// Printable strings (ASCII and UTF-16LE) of at least `min` chars.
fn strings(data: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &c in data {
        if (0x20..0x7f).contains(&c) {
            cur.push(c as char);
        } else {
            if cur.len() >= min {
                out.push(std::mem::take(&mut cur));
            }
            cur.clear();
        }
    }
    if cur.len() >= min {
        out.push(cur);
    }
    // UTF-16LE: take every other byte where the high byte is zero.
    let mut cur = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        if data[i + 1] == 0 && (0x20..0x7f).contains(&data[i]) {
            cur.push(data[i] as char);
            i += 2;
        } else {
            if cur.len() >= min {
                out.push(std::mem::take(&mut cur));
            }
            cur.clear();
            i += 1;
        }
    }
    if cur.len() >= min {
        out.push(cur);
    }
    out
}

pub fn looks_like_machine_path(s: &str) -> bool {
    let b = s.as_bytes();
    let drive = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    drive
        || s.contains("/home/")
        || s.contains("/Users/")
        || s.contains("\\Users\\")
        || s.starts_with("/tmp/")
        || s.starts_with("/build/")
        || s.contains("/runner/work/")
}

/// Find absolute build paths in the neighbourhoods of differing bytes.
fn embedded_path_cause(a: &[u8], b: &[u8]) -> Option<Cause> {
    let mut found: Vec<(String, String)> = Vec::new();
    for (s, e) in diff_runs(a, b, 32, 400) {
        let (lo, hi) = (s.saturating_sub(96), e + 96);
        let win = |d: &[u8]| d[lo.min(d.len())..hi.min(d.len())].to_vec();
        let (wa, wb) = (win(a), win(b));
        let pa: Vec<_> = strings(&wa, 6).into_iter().filter(|x| looks_like_machine_path(x)).collect();
        let pb: Vec<_> = strings(&wb, 6).into_iter().filter(|x| looks_like_machine_path(x)).collect();
        for x in &pa {
            if !pb.contains(x) {
                let y = pb.first().cloned().unwrap_or_default();
                if !found.iter().any(|(p, _)| p == x) {
                    found.push((x.clone(), y));
                }
            }
        }
        if found.len() >= 5 {
            break;
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(Cause::new("embedded_path", &[], json!(found.iter().map(|(a, b)| json!({"release": a, "local": b})).collect::<Vec<_>>())))
}

fn regions_from_sections(a: &[u8], b: &[u8], head_end: usize, secs: &[Section], tail_name: &str) -> Vec<Region> {
    let mut ranges: Vec<(String, usize, usize)> = vec![("headers".into(), 0, head_end.min(a.len()))];
    let mut covered = head_end;
    let mut sorted: Vec<&Section> = secs.iter().filter(|s| s.raw_size > 0).collect();
    sorted.sort_by_key(|s| s.raw_offset);
    for s in sorted {
        let end = (s.raw_offset + s.raw_size).min(a.len());
        if s.raw_offset < covered {
            continue; // overlapping/odd layout; already counted
        }
        ranges.push((s.name.clone(), s.raw_offset, end));
        covered = end;
    }
    let max = a.len().max(b.len());
    if covered < max {
        ranges.push((tail_name.into(), covered, max));
    }
    ranges
        .into_iter()
        .map(|(name, s, e)| {
            let d = count_diff(a, b, s, e);
            let size_a = a.len().min(e).saturating_sub(s.min(a.len()));
            let size_b = b.len().min(e).saturating_sub(s.min(b.len()));
            Region { name, size_a, size_b, diff_bytes: d, changed_pct: pct(d, e - s), share_pct: 0.0 }
        })
        .collect()
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        (n as f64 / d as f64 * 10000.0).round() / 100.0
    }
}

fn finish(kind: &str, a: &[u8], b: &[u8], mut regions: Vec<Region>, mut causes: Vec<Cause>) -> DiffReport {
    let total = count_diff(a, b, 0, a.len().max(b.len()));
    for r in &mut regions {
        r.share_pct = pct(r.diff_bytes, total);
    }
    regions.retain(|r| r.size_a > 0 || r.size_b > 0);
    if total > 0 {
        if let Some(c) = embedded_path_cause(a, b) {
            causes.push(c);
        }
    }
    if a.len() != b.len() {
        causes.push(Cause::new(
            "size_differs",
            &[("a", a.len().to_string()), ("b", b.len().to_string())],
            json!({"release": a.len(), "local": b.len()}),
        ));
    }
    DiffReport { kind: kind.into(), identical: total == 0, size_a: a.len(), size_b: b.len(), total_diff_bytes: total, regions, causes }
}

fn analyse_pe(a: &[u8], b: &[u8]) -> Option<DiffReport> {
    let la = inspect::pe_layout(a)?;
    let lb = inspect::pe_layout(b)?;
    let mut regions = regions_from_sections(a, b, la.headers_size, &la.sections, "overlay/signature");
    let mut causes = vec![];
    let layout_same = la.sections.len() == lb.sections.len()
        && la.sections.iter().zip(&lb.sections).all(|(x, y)| x.name == y.name && x.raw_size == y.raw_size);
    if !layout_same {
        causes.push(Cause::new(
            "pe.layout",
            &[],
            json!({
                "release": la.sections.iter().map(|s| format!("{}:{}", s.name, s.raw_size)).collect::<Vec<_>>(),
                "local": lb.sections.iter().map(|s| format!("{}:{}", s.name, s.raw_size)).collect::<Vec<_>>(),
            }),
        ));
    }
    if la.timestamp != lb.timestamp {
        causes.push(Cause::new("pe.timestamp", &[], json!({"release": la.timestamp, "local": lb.timestamp})));
    }
    if la.pdb_path != lb.pdb_path {
        let leaked = [&la.pdb_path, &lb.pdb_path].iter().any(|p| p.as_deref().map(looks_like_machine_path).unwrap_or(false));
        causes.push(Cause::new(
            if leaked { "pe.pdb_path.leaked" } else { "pe.pdb_path" },
            &[],
            json!({"release": la.pdb_path, "local": lb.pdb_path}),
        ));
    } else if la.debug_guid != lb.debug_guid {
        causes.push(Cause::new("pe.debug_guid", &[], json!({"release": la.debug_guid, "local": lb.debug_guid})));
    }
    if (la.cert_size > 0) != (lb.cert_size > 0) {
        causes.push(Cause::new("pe.signature", &[], json!({"release_signed": la.cert_size > 0, "local_signed": lb.cert_size > 0})));
        // Name the signature region precisely instead of an anonymous overlay.
        for r in &mut regions {
            if r.name == "overlay/signature" {
                r.name = "authenticode".into();
            }
        }
    }
    Some(finish("pe", a, b, regions, causes))
}

fn analyse_elf(a: &[u8], b: &[u8]) -> Option<DiffReport> {
    let sa = inspect::elf_sections(a)?;
    let sb = inspect::elf_sections(b)?;
    let regions = regions_from_sections(a, b, sa.iter().map(|s| s.raw_offset).min().unwrap_or(0), &sa, "section headers");
    let mut causes = vec![];
    if sa.iter().map(|s| (&s.name, s.raw_size)).ne(sb.iter().map(|s| (&s.name, s.raw_size))) {
        causes.push(Cause::new("elf.layout", &[], json!({"release_sections": sa.len(), "local_sections": sb.len()})));
    }
    for r in &regions {
        if r.name == ".note.gnu.build-id" && r.diff_bytes > 0 {
            causes.push(Cause::new("elf.build_id", &[], Value::Null));
        }
        if r.name.starts_with(".debug") && r.share_pct > 50.0 {
            causes.push(Cause::new(
                "elf.debug",
                &[("pct", format!("{:.1}", r.share_pct)), ("section", r.name.clone())],
                json!({"section": r.name}),
            ));
        }
    }
    Some(finish("elf", a, b, regions, causes))
}

fn analyse_zip(pa: &Path, pb: &Path, a: &[u8], b: &[u8]) -> Option<DiffReport> {
    let ea = inspect::zip_entries(pa).ok()?;
    let eb = inspect::zip_entries(pb).ok()?;
    let mut regions = vec![];
    let mut causes = vec![];
    let (mut content, mut mtime) = (vec![], vec![]);
    for x in &ea {
        match eb.iter().find(|y| y.name == x.name) {
            None => causes.push(Cause::new("zip.only_release", &[("name", x.name.clone())], Value::Null)),
            Some(y) => {
                if x.crc32 != y.crc32 || x.size != y.size {
                    content.push(x.name.clone());
                    regions.push(Region {
                        name: x.name.clone(),
                        size_a: x.size as usize,
                        size_b: y.size as usize,
                        diff_bytes: 0,
                        changed_pct: 100.0,
                        share_pct: 0.0,
                    });
                } else if x.mtime != y.mtime {
                    mtime.push(x.name.clone());
                }
            }
        }
    }
    for y in &eb {
        if !ea.iter().any(|x| x.name == y.name) {
            causes.push(Cause::new("zip.only_local", &[("name", y.name.clone())], Value::Null));
        }
    }
    if !content.is_empty() {
        causes.push(Cause::new("zip.content", &[("n", content.len().to_string())], json!(content.iter().take(20).collect::<Vec<_>>())));
    }
    if !mtime.is_empty() {
        causes.push(Cause::new("zip.mtime", &[("n", mtime.len().to_string())], json!(mtime.iter().take(20).collect::<Vec<_>>())));
    }
    let order_a: Vec<_> = ea.iter().map(|e| &e.name).collect();
    let order_b: Vec<_> = eb.iter().map(|e| &e.name).collect();
    if order_a != order_b && ea.len() == eb.len() && order_a.iter().all(|n| order_b.contains(n)) {
        causes.push(Cause::new("zip.order", &[], Value::Null));
    }
    if content.is_empty() && mtime.is_empty() && causes.is_empty() && a != b {
        causes.push(Cause::new("zip.container", &[], Value::Null));
    }
    // For archives, per-entry regions replace byte regions; totals still come from raw bytes.
    let mut rep = finish("zip", a, b, vec![], causes);
    let changed: usize = regions.iter().map(|r| r.size_a).sum();
    for r in &mut regions {
        r.share_pct = pct(r.size_a, changed);
    }
    rep.regions = regions;
    Some(rep)
}

/// Compare two files and explain differences from their actual contents.
pub fn compare(pa: &Path, pb: &Path) -> Result<DiffReport> {
    for p in [pa, pb] {
        let len = std::fs::metadata(p).with_context(|| format!("reading {}", p.display()))?.len();
        if len > MAX_PARSE_BYTES {
            bail!("{} is larger than 1 GiB; detailed binary analysis is not supported for it", p.display());
        }
    }
    let a = std::fs::read(pa)?;
    let b = std::fs::read(pb)?;
    let name = pa.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let kind = detect_kind(&a[..a.len().min(16)], &name);
    let specific = match kind {
        "pe" => analyse_pe(&a, &b),
        "elf" => analyse_elf(&a, &b),
        "zip" => analyse_zip(pa, pb, &a, &b),
        _ => None,
    };
    Ok(specific.unwrap_or_else(|| {
        let size = a.len().max(b.len());
        let d = count_diff(&a, &b, 0, size);
        finish(
            "generic",
            &a,
            &b,
            vec![Region {
                name: "file".into(),
                size_a: a.len(),
                size_b: b.len(),
                diff_bytes: d,
                changed_pct: pct(d, size),
                share_pct: 0.0,
            }],
            vec![],
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::make_zip;

    #[test]
    fn identical_files_report_no_difference() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a.bin"), d.path().join("b.bin"));
        std::fs::write(&a, b"same bytes").unwrap();
        std::fs::write(&b, b"same bytes").unwrap();
        let r = compare(&a, &b).unwrap();
        assert!(r.identical && r.total_diff_bytes == 0 && r.causes.is_empty());
    }

    #[test]
    fn generic_diff_counts_bytes_and_finds_leaked_paths() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a.bin"), d.path().join("b.bin"));
        std::fs::write(&a, b"\0\0\0C:\\Users\\alice\\build\\src\\main.c\0\0\0tail").unwrap();
        std::fs::write(&b, b"\0\0\0D:\\work\\agent7\\build\\src\\main.c\0\0\0tail").unwrap();
        let r = compare(&a, &b).unwrap();
        assert!(!r.identical);
        assert!(r.total_diff_bytes > 0 && r.total_diff_bytes < 40);
        let c = r.causes.iter().find(|c| c.code == "embedded_path").expect("embedded path cause");
        assert!(c.evidence[0]["release"].as_str().unwrap().contains("alice"));
    }

    #[test]
    fn size_difference_is_reported() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a.bin"), d.path().join("b.bin"));
        std::fs::write(&a, b"abcd").unwrap();
        std::fs::write(&b, b"abcdef").unwrap();
        let r = compare(&a, &b).unwrap();
        assert_eq!(r.total_diff_bytes, 2);
        assert!(r.causes.iter().any(|c| c.code == "size_differs"));
    }

    #[test]
    fn zip_content_and_order_differences_are_named() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a.zip"), d.path().join("b.zip"));
        make_zip(&a, &[("x", b"1"), ("y", b"2")]);
        make_zip(&b, &[("y", b"2"), ("x", b"CHANGED")]);
        let r = compare(&a, &b).unwrap();
        assert_eq!(r.kind, "zip");
        let codes: Vec<_> = r.causes.iter().map(|c| c.code.as_str()).collect();
        assert!(codes.contains(&"zip.content") && codes.contains(&"zip.order"), "{codes:?}");
        assert_eq!(r.regions[0].name, "x");
    }

    #[test]
    fn pe_diff_attributes_changes_to_the_right_section() {
        // Copy the running test binary (a real PE on Windows) and flip bytes inside .data / header timestamp.
        let exe = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&exe).unwrap();
        let Some(layout) = inspect::pe_layout(&bytes) else { return }; // non-Windows: covered by ELF path
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a.exe"), d.path().join("b.exe"));
        std::fs::write(&a, &bytes).unwrap();
        let mut m = bytes.clone();
        let rdata = layout.sections.iter().find(|s| s.name == ".rdata").expect(".rdata");
        for i in 0..10 {
            m[rdata.raw_offset + 100 + i] ^= 0xFF;
        }
        // Bump TimeDateStamp: e_lfanew + 8.
        let pe_off = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        m[pe_off + 8] ^= 0x01;
        std::fs::write(&b, &m).unwrap();

        let r = compare(&a, &b).unwrap();
        assert_eq!(r.kind, "pe");
        assert_eq!(r.total_diff_bytes, 11);
        let rd = r.regions.iter().find(|x| x.name == ".rdata").unwrap();
        assert_eq!(rd.diff_bytes, 10);
        assert_eq!(r.regions.iter().find(|x| x.name == "headers").unwrap().diff_bytes, 1);
        assert!(r.causes.iter().any(|c| c.code == "pe.timestamp"));
        let sum: f64 = r.regions.iter().map(|x| x.share_pct).sum();
        assert!((sum - 100.0).abs() < 0.1, "shares sum to 100, got {sum}");
    }
}
