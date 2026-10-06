//! Secure token storage. On Windows the token lives in Windows Credential Manager
//! (encrypted per user by the OS); it is never written to config.toml or SQLite.
//! Elsewhere (CI, Linux) tokens come from the environment.

use anyhow::{bail, Result};

pub const ENV_VARS: [&str; 2] = ["RELEASEVERITY_GITHUB_TOKEN", "GITHUB_TOKEN"];

/// Token from the environment (CI), if any.
pub fn from_env() -> Option<String> {
    ENV_VARS.iter().find_map(|v| std::env::var(v).ok()).map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn save(name: &str, token: &str) -> Result<()> {
        let mut target = wide(name);
        let mut user = wide("token");
        let blob = token.as_bytes();
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            Comment: std::ptr::null_mut(),
            LastWritten: unsafe { std::mem::zeroed() },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: user.as_mut_ptr(),
        };
        if unsafe { CredWriteW(&cred, 0) } == 0 {
            bail!("Windows Credential Manager refused to store the token: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn load(name: &str) -> Option<String> {
        let target = wide(name);
        let mut p: *mut CREDENTIALW = std::ptr::null_mut();
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut p) } == 0 || p.is_null() {
            return None;
        }
        let token = unsafe {
            let c = &*p;
            let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
            let s = String::from_utf8_lossy(bytes).into_owned();
            CredFree(p as *const _);
            s
        };
        Some(token).filter(|t| !t.is_empty())
    }

    pub fn delete(name: &str) -> Result<bool> {
        let target = wide(name);
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(1168) {
                return Ok(false); // ERROR_NOT_FOUND
            }
            bail!("could not remove the stored token: {e}");
        }
        Ok(true)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn save(_: &str, _: &str) -> Result<()> {
        bail!("secure token storage is only available on Windows; set the RELEASEVERITY_GITHUB_TOKEN environment variable instead")
    }
    pub fn load(_: &str) -> Option<String> {
        None
    }
    pub fn delete(_: &str) -> Result<bool> {
        Ok(false)
    }
}

pub fn save(credential_name: &str, token: &str) -> Result<()> {
    anyhow::ensure!(!token.trim().is_empty(), "the token is empty");
    imp::save(credential_name, token.trim())
}

/// Stored token (Credential Manager), else environment.
pub fn load(credential_name: &str) -> Option<String> {
    imp::load(credential_name).or_else(from_env)
}

pub fn delete(credential_name: &str) -> Result<bool> {
    imp::delete(credential_name)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn token_round_trips_through_credential_manager_and_is_deletable() {
        let name = format!("ReleaseVerity/test-{}", std::process::id());
        assert!(imp::load(&name).is_none());
        save(&name, "  ghp_exampleTOKEN123  ").unwrap();
        assert_eq!(imp::load(&name).as_deref(), Some("ghp_exampleTOKEN123"), "stored trimmed, read back exactly");
        assert!(delete(&name).unwrap());
        assert!(imp::load(&name).is_none());
        assert!(!delete(&name).unwrap(), "deleting a missing credential is not an error");
        assert!(save(&name, "   ").is_err());
    }
}
