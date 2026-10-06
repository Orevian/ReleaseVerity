//! Artifact inspection: format detection and structural facts read from the real bytes.

use anyhow::{Context as _, Result};
use goblin::{elf::Elf, pe::PE};
use releaseverity_core::hash::hash_file;
use releaseverity_core::model::ArtifactInfo;
use serde_json::{json, Value};
use std::path::Path;

pub const MAX_PARSE_BYTES: u64 = 1 << 30; // 1 GiB

pub fn detect_kind(head: &[u8], name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    if head.starts_with(b"MZ") {
        "pe"
    } else if head.starts_with(b"\x7fELF") {
        "elf"
    } else if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        "zip"
    } else if head.starts_with(&[0x1f, 0x8b]) {
        "gzip"
    } else if head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        if n.ends_with(".msi") {
            "msi"
        } else {
            "ole"
        }
    } else if head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        "macho"
    } else {
        "other"
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub raw_offset: usize,
    pub raw_size: usize,
    pub virtual_size: usize,
}

#[derive(Debug, Clone, Default)]
pub struct PeLayout {
    pub machine: String,
    pub is_dll: bool,
    pub timestamp: u32,
    pub sections: Vec<Section>,
    pub headers_size: usize,
    pub pdb_path: Option<String>,
    pub debug_guid: Option<String>,
    pub cert_offset: usize,
    pub cert_size: usize,
}

fn machine_name(m: u16) -> String {
    match m {
        0x014c => "x86".into(),
        0x8664 => "x64".into(),
        0xaa64 => "arm64".into(),
        0x01c4 => "arm".into(),
        o => format!("0x{o:04x}"),
    }
}

pub fn pe_layout(bytes: &[u8]) -> Option<PeLayout> {
    let pe = PE::parse(bytes).ok()?;
    let sections: Vec<Section> = pe
        .sections
        .iter()
        .map(|s| Section {
            name: s.name().unwrap_or("?").to_string(),
            raw_offset: s.pointer_to_raw_data as usize,
            raw_size: s.size_of_raw_data as usize,
            virtual_size: s.virtual_size as usize,
        })
        .collect();
    let headers_size = sections.iter().map(|s| s.raw_offset).filter(|o| *o > 0).min().unwrap_or(bytes.len());
    let (cert_offset, cert_size) = match pe.header.optional_header {
        Some(o) => o.data_directories.get_certificate_table().map(|d| (d.virtual_address as usize, d.size as usize)).unwrap_or((0, 0)),
        None => (0, 0),
    };
    let (pdb_path, debug_guid) = pe
        .debug_data
        .and_then(|d| d.codeview_pdb70_debug_info)
        .map(|cv| {
            let end = cv.filename.iter().position(|b| *b == 0).unwrap_or(cv.filename.len());
            (Some(String::from_utf8_lossy(&cv.filename[..end]).into_owned()), Some(format!("{}-{}", hex::encode(cv.signature), cv.age)))
        })
        .unwrap_or((None, None));
    Some(PeLayout {
        machine: machine_name(pe.header.coff_header.machine),
        is_dll: pe.is_lib,
        timestamp: pe.header.coff_header.time_date_stamp,
        sections,
        headers_size,
        pdb_path,
        debug_guid,
        cert_offset,
        cert_size,
    })
}

pub fn elf_sections(bytes: &[u8]) -> Option<Vec<Section>> {
    let elf = Elf::parse(bytes).ok()?;
    Some(
        elf.section_headers
            .iter()
            .filter(|s| s.sh_type != goblin::elf::section_header::SHT_NOBITS && s.sh_size > 0)
            .map(|s| Section {
                name: elf.shdr_strtab.get_at(s.sh_name).unwrap_or("?").to_string(),
                raw_offset: s.sh_offset as usize,
                raw_size: s.sh_size as usize,
                virtual_size: s.sh_size as usize,
            })
            .collect(),
    )
}

#[derive(Debug, Clone)]
pub struct Inspection {
    pub info: ArtifactInfo,
    pub details: Value,
}

pub fn inspect(path: &Path) -> Result<Inspection> {
    let h = hash_file(path).with_context(|| format!("reading {}", path.display()))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut head = [0u8; 16];
    {
        use std::io::Read;
        let mut f = std::fs::File::open(path)?;
        let n = f.read(&mut head)?;
        head[n..].fill(0);
    }
    let kind = detect_kind(&head, &name);
    let details = if h.size > MAX_PARSE_BYTES {
        json!({ "note": "file too large for structural parsing" })
    } else {
        match kind {
            "pe" => pe_details(&std::fs::read(path)?),
            "elf" => elf_details(&std::fs::read(path)?),
            "zip" => zip_details(path),
            _ => Value::Null,
        }
    };
    Ok(Inspection {
        info: ArtifactInfo {
            name,
            path: path.to_string_lossy().into_owned(),
            size: h.size,
            sha256: h.sha256,
            sha512: h.sha512,
            kind: kind.to_string(),
        },
        details,
    })
}

fn pe_details(bytes: &[u8]) -> Value {
    let Some(l) = pe_layout(bytes) else { return json!({ "note": "not a parseable PE image" }) };
    let ts = chrono::DateTime::from_timestamp(l.timestamp as i64, 0).map(|d| d.to_rfc3339());
    json!({
        "machine": l.machine,
        "dll": l.is_dll,
        "timestamp": l.timestamp,
        "timestamp_utc": ts,
        "pdb_path": l.pdb_path,
        "debug_guid": l.debug_guid,
        "authenticode_present": l.cert_size > 0,
        "sections": l.sections.iter().map(|s| json!({
            "name": s.name, "raw_size": s.raw_size, "virtual_size": s.virtual_size
        })).collect::<Vec<_>>(),
    })
}

fn elf_details(bytes: &[u8]) -> Value {
    match Elf::parse(bytes) {
        Ok(e) => json!({
            "machine": goblin::elf::header::machine_to_str(e.header.e_machine),
            "bits": if e.is_64 { 64 } else { 32 },
            "type": goblin::elf::header::et_to_str(e.header.e_type),
            "interpreter": e.interpreter,
            "sections": elf_sections(bytes).unwrap_or_default().iter().map(|s| json!({
                "name": s.name, "size": s.raw_size })).collect::<Vec<_>>(),
        }),
        Err(_) => json!({ "note": "not a parseable ELF image" }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    pub name: String,
    pub size: u64,
    pub crc32: u32,
    pub mtime: String,
}

pub fn zip_entries(path: &Path) -> Result<Vec<ZipEntry>> {
    let f = std::fs::File::open(path)?;
    let mut z = zip::ZipArchive::new(f).context("not a valid zip archive")?;
    let mut v = Vec::with_capacity(z.len());
    for i in 0..z.len() {
        let e = z.by_index_raw(i)?;
        let m = e.last_modified();
        let mtime = match m {
            Some(t) => format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", t.year(), t.month(), t.day(), t.hour(), t.minute(), t.second()),
            None => String::new(),
        };
        v.push(ZipEntry { name: e.name().to_string(), size: e.size(), crc32: e.crc32(), mtime });
    }
    Ok(v)
}

fn zip_details(path: &Path) -> Value {
    match zip_entries(path) {
        Ok(es) => json!({
            "entries": es.len(),
            "uncompressed_bytes": es.iter().map(|e| e.size).sum::<u64>(),
            "sample": es.iter().take(20).map(|e| e.name.clone()).collect::<Vec<_>>(),
        }),
        Err(e) => json!({ "note": format!("{e:#}") }),
    }
}

#[cfg(test)]
pub use tests::make_zip;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    pub fn make_zip(path: &Path, files: &[(&str, &[u8])]) {
        let mut z = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        let o = zip::write::SimpleFileOptions::default().last_modified_time(zip::DateTime::default());
        for (n, c) in files {
            z.start_file(*n, o).unwrap();
            z.write_all(c).unwrap();
        }
        z.finish().unwrap();
    }

    #[test]
    fn detects_formats_from_magic_not_extension() {
        assert_eq!(detect_kind(b"MZ\x90\0", "x.dat"), "pe");
        assert_eq!(detect_kind(b"\x7fELF", "x"), "elf");
        assert_eq!(detect_kind(b"PK\x03\x04", "x"), "zip");
        assert_eq!(detect_kind(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], "a.msi"), "msi");
        assert_eq!(detect_kind(b"hello", "x.exe"), "other");
    }

    #[test]
    fn inspects_zip_with_hashes_and_entries() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.zip");
        make_zip(&p, &[("a.txt", b"one"), ("b/c.txt", b"two")]);
        let i = inspect(&p).unwrap();
        assert_eq!(i.info.kind, "zip");
        assert_eq!(i.details["entries"], 2);
        assert_eq!(i.info.sha256.len(), 64);
        assert_eq!(zip_entries(&p).unwrap()[1].name, "b/c.txt");
    }

    #[test]
    fn inspects_this_test_binary_as_pe_or_elf() {
        let exe = std::env::current_exe().unwrap();
        let i = inspect(&exe).unwrap();
        assert!(matches!(i.info.kind.as_str(), "pe" | "elf" | "macho"));
        if i.info.kind == "pe" {
            assert!(i.details["sections"].as_array().unwrap().iter().any(|s| s["name"] == ".text"));
            assert!(i.details["machine"].is_string());
        }
    }
}
