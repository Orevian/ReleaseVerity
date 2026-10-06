//! Child process execution with a hard timeout and captured output.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProcOutput {
    /// `None` if the process was killed (timeout) or terminated by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl ProcOutput {
    pub fn success(&self) -> bool {
        !self.timed_out && self.code == Some(0)
    }
}

/// Run `cmd` to completion, killing it after `timeout`. Fails only if it cannot be spawned.
pub fn run(cmd: &mut Command, timeout: Duration) -> std::io::Result<ProcOutput> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console flash from the GUI
    }
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let (code, timed_out) = loop {
        if let Some(st) = child.try_wait()? {
            break (st.code(), false);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            break (None, true);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
    Ok(ProcOutput { code, stdout, stderr, timed_out })
}

/// Whether a process with this id currently exists.
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
            fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
            fn WaitForSingleObject(h: *mut std::ffi::c_void, ms: u32) -> u32;
        }
        const SYNCHRONIZE: u32 = 0x0010_0000;
        unsafe {
            let h = OpenProcess(SYNCHRONIZE, 0, pid);
            if h.is_null() {
                return false;
            }
            let alive = WaitForSingleObject(h, 0) == 0x102; // WAIT_TIMEOUT: still running
            CloseHandle(h);
            alive
        }
    }
    #[cfg(not(windows))]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
}

/// True if `name` resolves to an executable on PATH.
pub fn exists_on_path(name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else { return false };
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT").unwrap_or(".EXE;.CMD;.BAT".into()).split(';').map(|s| s.to_ascii_lowercase()).collect()
    } else {
        vec![String::new()]
    };
    std::env::split_paths(&paths).any(|dir| exts.iter().any(|e| dir.join(format!("{name}{e}")).is_file()) || dir.join(name).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_and_exit_code() {
        let mut c = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", "echo hello & exit 3"]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", "echo hello; exit 3"]);
            c
        };
        let o = run(&mut c, Duration::from_secs(10)).unwrap();
        assert_eq!(o.code, Some(3));
        assert!(o.stdout.contains("hello"));
        assert!(!o.success());
    }

    #[test]
    fn kills_on_timeout() {
        let mut c = if cfg!(windows) {
            let mut c = Command::new("ping");
            c.args(["-n", "30", "127.0.0.1"]);
            c
        } else {
            let mut c = Command::new("sleep");
            c.arg("30");
            c
        };
        let t = Instant::now();
        let o = run(&mut c, Duration::from_millis(300)).unwrap();
        assert!(o.timed_out && o.code.is_none());
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn pid_alive_knows_itself_and_rejects_unused_ids() {
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(0x7fff_fff0));
    }

    #[test]
    fn spawn_failure_is_an_error() {
        assert!(run(&mut Command::new("definitely-not-a-real-binary-xyz"), Duration::from_secs(1)).is_err());
    }
}
