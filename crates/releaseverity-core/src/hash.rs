//! Streaming file hashing.

use sha2::{Digest, Sha256, Sha512};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    pub sha256: String,
    pub sha512: String,
    pub size: u64,
}

/// Compute SHA-256 and SHA-512 in a single pass without loading the file into memory.
pub fn hash_file(path: &Path) -> std::io::Result<Hashes> {
    let mut f = std::fs::File::open(path)?;
    let (mut a, mut b) = (Sha256::new(), Sha512::new());
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        a.update(&buf[..n]);
        b.update(&buf[..n]);
        size += n as u64;
    }
    Ok(Hashes { sha256: hex::encode(a.finalize()), sha512: hex::encode(b.finalize()), size })
}

pub fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_vectors() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"abc").unwrap();
        let h = hash_file(&p).unwrap();
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(h.sha512.starts_with("ddaf35a193617aba"));
        assert_eq!(h.size, 3);
        assert_eq!(sha256_bytes(b"abc"), h.sha256);
    }
}
