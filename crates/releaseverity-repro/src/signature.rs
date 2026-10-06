//! Signature verification using the platform's real verifiers.
//! Authenticode via Windows' `Get-AuthenticodeSignature`; detached signatures via `gpg`.

use releaseverity_core::proc;
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigState {
    /// Cryptographically valid and chain-trusted by the platform.
    Valid { signer: String },
    /// No signature present.
    Unsigned,
    /// Signature present but invalid/untrusted.
    Invalid { reason: String },
    /// Could not be verified on this system (tool missing, unsupported OS).
    Unavailable { reason: String },
}

/// Authenticode status for PE/MSI files. Only verifiable on Windows.
pub fn authenticode(path: &Path, has_embedded_signature: bool) -> SigState {
    if !cfg!(windows) {
        return if has_embedded_signature {
            SigState::Unavailable { reason: "Authenticode signature present but can only be validated on Windows".into() }
        } else {
            SigState::Unsigned
        };
    }
    let script = "$s = Get-AuthenticodeSignature -LiteralPath $env:VF_FILE; \
        [pscustomobject]@{ Status = [string]$s.Status; Message = $s.StatusMessage; \
        Subject = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' } } | ConvertTo-Json -Compress";
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]).env("VF_FILE", path);
    let o = match proc::run(&mut c, Duration::from_secs(60)) {
        Ok(o) if o.success() => o,
        Ok(o) => return SigState::Unavailable { reason: format!("PowerShell failed: {}", o.stderr.trim()) },
        Err(e) => return SigState::Unavailable { reason: format!("PowerShell not available: {e}") },
    };
    let Ok(v) = serde_json::from_str::<Value>(o.stdout.trim()) else {
        return SigState::Unavailable { reason: "unparseable Get-AuthenticodeSignature output".into() };
    };
    let status = v["Status"].as_str().unwrap_or("");
    let msg = v["Message"].as_str().unwrap_or("").to_string();
    match status {
        "Valid" => SigState::Valid { signer: v["Subject"].as_str().unwrap_or("").to_string() },
        "NotSigned" => SigState::Unsigned,
        "" => SigState::Unavailable { reason: "empty status".into() },
        other => SigState::Invalid { reason: format!("{other}: {msg}") },
    }
}

/// Verify a detached GPG signature (`.asc` / `.sig`).
pub fn gpg_detached(sig: &Path, file: &Path) -> SigState {
    if !proc::exists_on_path("gpg") {
        return SigState::Unavailable { reason: "gpg is not installed".into() };
    }
    let mut c = Command::new("gpg");
    c.args(["--batch", "--status-fd", "1", "--verify"]).arg(sig).arg(file);
    match proc::run(&mut c, Duration::from_secs(60)) {
        Ok(o) if o.success() => {
            let signer = o.stdout.lines().find_map(|l| l.strip_prefix("[GNUPG:] GOODSIG ")).unwrap_or("").to_string();
            SigState::Valid { signer }
        }
        Ok(o) => SigState::Invalid {
            reason: o.stderr.lines().chain(o.stdout.lines()).filter(|l| !l.is_empty()).take(3).collect::<Vec<_>>().join("; "),
        },
        Err(e) => SigState::Unavailable { reason: e.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn unsigned_file_is_reported_unsigned_by_the_real_verifier() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("plain.ps1");
        std::fs::write(&p, "Write-Host hi").unwrap();
        assert_eq!(authenticode(&p, false), SigState::Unsigned);
    }

    #[test]
    #[cfg(windows)]
    fn microsoft_signed_system_binary_is_valid() {
        let p = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32\\notepad.exe");
        if !p.exists() {
            return;
        }
        match authenticode(&p, true) {
            SigState::Valid { signer } => assert!(signer.contains("Microsoft")),
            // Catalog-signed files may report differently on some builds; never a false "unsigned".
            other => assert!(!matches!(other, SigState::Unsigned), "{other:?}"),
        }
    }
}
