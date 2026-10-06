//! ReleaseVerity's own isolated environment: a Windows **AppContainer**.
//!
//! Works on every Windows edition (including Home) without a VM. The OS itself enforces:
//!   * file system: the process can only touch locations whose ACL names its container SID
//!     (we grant the package directory read/execute and one scratch directory write access);
//!   * network: a container without capabilities has no network access, not even loopback;
//!   * registry: HKLM is read-only and HKCU is the container's private hive;
//!   * other processes/windows: no access to the user's other processes (low integrity, UIPI).
//!
//! On top of that every process runs inside a Job Object (memory/process limits, tree kill).
//!
//! Limits (stated honestly): an AppContainer is not a VM. It can run *portable* applications;
//! it cannot run installers (they need to write Program Files / HKLM), and a kernel exploit
//! would escape it. Installers need a VM-backed environment.

use crate::winproc::Spawned;
use std::ffi::c_void;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::Path;
use std::process::Command;
use windows_sys::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{FreeSid, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
    EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const CREATE_SUSPENDED: u32 = 0x4;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const ERROR_ALREADY_EXISTS_HR: i32 = 0x8007_00B7u32 as i32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Owned process handle (closed when the supervised process is done).
struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
unsafe impl Send for OwnedHandle {}

/// An AppContainer profile. Dropping it deletes the profile.
pub struct Container {
    name: String,
    sid: *mut c_void,
    pub sid_string: String,
}

impl Container {
    pub fn create(name: &str) -> Result<Self, String> {
        let wname = wide(name);
        let (disp, desc) = (
            wide("ReleaseVerity ShipCheck sandbox"),
            wide("Disposable isolated environment used by ReleaseVerity to run untrusted software"),
        );
        let mut sid: *mut c_void = std::ptr::null_mut();
        let hr = unsafe { CreateAppContainerProfile(wname.as_ptr(), disp.as_ptr(), desc.as_ptr(), std::ptr::null(), 0, &mut sid) };
        if hr == ERROR_ALREADY_EXISTS_HR {
            let hr2 = unsafe { DeriveAppContainerSidFromAppContainerName(wname.as_ptr(), &mut sid) };
            if hr2 < 0 {
                return Err(format!("could not open the existing AppContainer profile (HRESULT 0x{:08X})", hr2 as u32));
            }
        } else if hr < 0 {
            return Err(format!("CreateAppContainerProfile failed (HRESULT 0x{:08X})", hr as u32));
        }
        let mut p: *mut u16 = std::ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut p) };
        if ok == 0 || p.is_null() {
            unsafe { FreeSid(sid) };
            return Err("could not format the container SID".into());
        }
        let sid_string = unsafe {
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
            windows_sys::Win32::Foundation::LocalFree(p as *mut c_void);
            s
        };
        Ok(Self { name: name.to_string(), sid, sid_string })
    }

    /// Grant the container access to `dir` and everything below it.
    /// `write == false` → read & execute; `write == true` → modify.
    pub fn grant(&self, dir: &Path, write: bool) -> Result<(), String> {
        let perm = if write { "M" } else { "RX" };
        let mut c = Command::new("icacls");
        c.arg(dir).arg("/grant").arg(format!("*{}:(OI)(CI){perm}", self.sid_string)).args(["/T", "/C", "/Q"]);
        let o = releaseverity_proc(&mut c).map_err(|e| format!("icacls failed to start: {e}"))?;
        if o.0 != Some(0) {
            return Err(format!("could not grant the container access to {}: {}", dir.display(), o.1.trim()));
        }
        Ok(())
    }

    /// Start `exe args` suspended inside the container, with stdout/stderr piped back.
    pub fn spawn(&self, exe: &Path, args: &[String], cwd: &Path) -> std::io::Result<Spawned> {
        unsafe {
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: 1,
            };
            let (mut out_r, mut out_w, mut err_r, mut err_w): (HANDLE, HANDLE, HANDLE, HANDLE) =
                (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
            if CreatePipe(&mut out_r, &mut out_w, &sa, 0) == 0 || CreatePipe(&mut err_r, &mut err_w, &sa, 0) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The parent's read ends must not be inherited by the child.
            SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);
            let nul = CreateFileW(
                wide("NUL").as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sa,
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if nul == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }

            // Attribute list: security capabilities (the container) + explicit inherited-handle list.
            let mut size = 0usize;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size);
            let mut buf = vec![0u8; size];
            let list = buf.as_mut_ptr() as *mut c_void;
            if InitializeProcThreadAttributeList(list, 2, 0, &mut size) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let caps =
                SECURITY_CAPABILITIES { AppContainerSid: self.sid, Capabilities: std::ptr::null_mut(), CapabilityCount: 0, Reserved: 0 };
            if UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                &caps as *const _ as *const c_void,
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let handles = [nul, out_w, err_w];
            if UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr() as *const c_void,
                std::mem::size_of_val(&handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }

            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = nul;
            si.StartupInfo.hStdOutput = out_w;
            si.StartupInfo.hStdError = err_w;
            si.lpAttributeList = list;

            let mut cmdline = wide(&command_line(exe, args));
            let wcwd = wide(&cwd.to_string_lossy());
            let wexe = wide(&exe.to_string_lossy());
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let ok = CreateProcessW(
                wexe.as_ptr(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW_IF_CONSOLE,
                std::ptr::null(),
                wcwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            );
            let err = std::io::Error::last_os_error();
            DeleteProcThreadAttributeList(list);
            // Child has its copies now; close ours so reads see EOF when it exits.
            CloseHandle(out_w);
            CloseHandle(err_w);
            CloseHandle(nul);
            if ok == 0 {
                CloseHandle(out_r);
                CloseHandle(err_r);
                return Err(err);
            }
            CloseHandle(pi.hThread);
            Ok(Spawned {
                handle: pi.hProcess,
                out: Box::new(std::fs::File::from_raw_handle(out_r as RawHandle)),
                err: Box::new(std::fs::File::from_raw_handle(err_r as RawHandle)),
                _owner: Box::new(OwnedHandle(pi.hProcess)),
            })
        }
    }
}

// Console apps get no extra window; GUI apps are unaffected by this flag.
const CREATE_NO_WINDOW_IF_CONSOLE: u32 = CREATE_NO_WINDOW;

impl Drop for Container {
    fn drop(&mut self) {
        unsafe {
            FreeSid(self.sid);
            DeleteAppContainerProfile(wide(&self.name).as_ptr());
        }
    }
}

/// Windows command line quoting (CommandLineToArgvW rules).
pub fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '\n', '"']) {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

pub fn command_line(exe: &Path, args: &[String]) -> String {
    let mut s = quote_arg(&exe.to_string_lossy());
    for a in args {
        s.push(' ');
        s.push_str(&quote_arg(a));
    }
    s
}

/// Minimal blocking runner for `icacls` (the agent must not depend on the host crates).
fn releaseverity_proc(c: &mut Command) -> std::io::Result<(Option<i32>, String)> {
    use std::os::windows::process::CommandExt;
    let o = c.creation_flags(CREATE_NO_WINDOW).output()?;
    Ok((o.status.code(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winproc::{run_supervised, Limits, Mode};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::time::Duration;

    const L: Limits = Limits { memory_mb: 512, max_processes: 16 };

    fn system32(name: &str) -> PathBuf {
        PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join(name)
    }

    /// A directory holding a real copy of `tool` as app.exe, made readable by the container.
    fn app_dir(c: &Container, tool: &str) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("app.exe");
        std::fs::copy(system32(tool), &exe).unwrap();
        c.grant(d.path(), false).unwrap();
        (d, exe)
    }

    fn run(c: &Container, exe: &Path, args: &[&str]) -> crate::winproc::Outcome {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let sp = c.spawn(exe, &args, exe.parent().unwrap()).expect("spawn in container");
        run_supervised(sp, Duration::from_secs(30), L, Mode::RunToExit).unwrap()
    }

    #[test]
    fn quoting_follows_windows_rules() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote_arg(r"C:\dir with space\"), r#""C:\dir with space\\""#);
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn container_runs_a_process_and_captures_output() {
        let c = Container::create("ReleaseVerity.Test.Basic").unwrap();
        assert!(c.sid_string.starts_with("S-1-15-2-"), "AppContainer SIDs live under S-1-15-2: {}", c.sid_string);
        let (_d, exe) = app_dir(&c, "cmd.exe");
        let o = run(&c, &exe, &["/C", "echo", "inside-container"]);
        assert_eq!(o.exit_code, Some(0), "{o:?}");
        assert!(o.stdout.contains("inside-container"));
    }

    #[test]
    fn container_cannot_write_outside_its_grants_but_can_write_where_granted() {
        let c = Container::create("ReleaseVerity.Test.Fs").unwrap();
        let (_d, exe) = app_dir(&c, "cmd.exe");
        // A directory the container was NOT granted (the test's own temp dir).
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("pwned.txt");
        let o = run(&c, &exe, &["/C", &format!("echo x> {}", target.display())]);
        assert!(!target.exists(), "write outside the sandbox must be denied: {o:?}");
        assert_ne!(o.exit_code, Some(0));

        // Where it IS granted write access, it works.
        let scratch = tempfile::tempdir().unwrap();
        c.grant(scratch.path(), true).unwrap();
        let ok_target = scratch.path().join("ok.txt");
        let o = run(&c, &exe, &["/C", &format!("echo x> {}", ok_target.display())]);
        assert_eq!(o.exit_code, Some(0), "{o:?}");
        assert!(ok_target.exists());
    }

    #[test]
    fn container_has_no_network_not_even_loopback() {
        // A real listener; the same curl.exe reaches it from the host but not from the container.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h2 = hits.clone();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            while let Ok((mut s, _)) = l.accept() {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                h2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            }
        });
        let url = format!("http://127.0.0.1:{port}/");

        // Control: from the host the connection works (proves the test would detect a leak).
        let host = std::process::Command::new(system32("curl.exe")).args(["-s", "-m", "10", &url]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&host.stdout), "ok", "control request from the host must succeed");
        let before = hits.load(std::sync::atomic::Ordering::SeqCst);

        let c = Container::create("ReleaseVerity.Test.Net").unwrap();
        let (_d, exe) = app_dir(&c, "curl.exe");
        let o = run(&c, &exe, &["-s", "-m", "10", &url]);
        assert_ne!(o.exit_code, Some(0), "container must not reach loopback: {o:?}");
        assert!(!o.stdout.contains("ok"));
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), before, "the server must never see the sandboxed request");
    }

    #[test]
    fn container_cannot_read_user_files_it_was_not_granted() {
        let secret = tempfile::tempdir().unwrap();
        let f = secret.path().join("secret.txt");
        std::fs::write(&f, "top-secret").unwrap();
        let c = Container::create("ReleaseVerity.Test.Read").unwrap();
        let (_d, exe) = app_dir(&c, "cmd.exe");
        let o = run(&c, &exe, &["/C", &format!("type {}", f.display())]);
        assert!(!o.stdout.contains("top-secret"), "{o:?}");
        assert_ne!(o.exit_code, Some(0));
    }
}
