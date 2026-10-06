//! Process execution inside a Windows Job Object: process-tree tracking, memory and
//! process-count limits, hard timeouts, kill-on-close cleanup, and hang detection.

use std::collections::HashSet;
use std::ffi::c_void;
use std::io::Read;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM};
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, TerminateProcess, WaitForSingleObject};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsHungAppWindow, IsWindowVisible};

#[link(name = "ntdll")]
extern "system" {
    fn NtResumeProcess(process: HANDLE) -> i32;
}

const CREATE_SUSPENDED: u32 = 0x0000_0004;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub memory_mb: u64,
    pub max_processes: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum Mode {
    /// Wait for the whole process tree to finish.
    RunToExit,
    /// GUI app: it must still be running (and responsive) after `alive`.
    GuiAlive { alive: Duration },
}

#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// Exit code of the main process; `None` if it was still running when we stopped it.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub hung: bool,
    /// Visible top-level windows seen belonging to the process tree.
    pub windows_seen: usize,
    pub stdout: String,
    pub stderr: String,
    pub pids_seen: Vec<u32>,
    pub peak_memory_mb: u64,
    pub duration_ms: u64,
}

struct Job(HANDLE);
impl Drop for Job {
    fn drop(&mut self) {
        // KILL_ON_JOB_CLOSE guarantees no process of the tree survives us.
        unsafe { CloseHandle(self.0) };
    }
}

fn create_job(l: Limits) -> std::io::Result<Job> {
    unsafe {
        let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if h.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Job(h);
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = l.max_processes.max(1);
        info.JobMemoryLimit = (l.memory_mb.max(64) * 1024 * 1024) as usize;
        let ok = SetInformationJobObject(
            h,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }
}

fn job_pids(job: &Job) -> Vec<u32> {
    // Layout: u32 NumberOfAssignedProcesses, u32 NumberOfProcessIdsInList, usize[] ids.
    let mut buf = vec![0u64; 2 + 512];
    let ok = unsafe {
        QueryInformationJobObject(
            job.0,
            JobObjectBasicProcessIdList,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * 8) as u32,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return vec![];
    }
    let in_list = (buf[0] >> 32) as usize;
    buf[1..].iter().take(in_list.min(512)).map(|p| *p as u32).collect()
}

fn peak_memory_mb(job: &Job) -> u64 {
    unsafe {
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        let ok = QueryInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            std::ptr::null_mut(),
        );
        if ok == 0 {
            0
        } else {
            (info.PeakJobMemoryUsed as u64) / (1024 * 1024)
        }
    }
}

struct WinScan<'a> {
    pids: &'a HashSet<u32>,
    visible: usize,
    hung: bool,
}

unsafe extern "system" fn enum_cb(hwnd: HWND, lp: LPARAM) -> BOOL {
    let scan = &mut *(lp as *mut WinScan);
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, &mut pid);
    if scan.pids.contains(&pid) {
        if IsWindowVisible(hwnd) != 0 {
            scan.visible += 1;
        }
        if IsHungAppWindow(hwnd) != 0 {
            scan.hung = true;
        }
    }
    1
}

/// (visible windows, any hung) among the given processes.
fn scan_windows(pids: &HashSet<u32>) -> (usize, bool) {
    let mut s = WinScan { pids, visible: 0, hung: false };
    unsafe { EnumWindows(Some(enum_cb), &mut s as *mut _ as LPARAM) };
    (s.visible, s.hung)
}

fn drain(mut r: Box<dyn Read + Send>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = r.read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    })
}

/// A started-but-suspended process plus its output pipes. Created by `run_limited`
/// (plain child) or by `ac::spawn` (AppContainer); both are supervised identically.
pub struct Spawned {
    pub handle: HANDLE,
    pub out: Box<dyn Read + Send>,
    pub err: Box<dyn Read + Send>,
    /// Keeps the process handle valid for the duration of supervision.
    pub _owner: Box<dyn std::any::Any>,
}

const WAIT_OBJECT_0: u32 = 0;

fn exit_code(h: HANDLE) -> Option<i32> {
    unsafe {
        if WaitForSingleObject(h, 0) != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        if GetExitCodeProcess(h, &mut code) == 0 {
            return Some(-1);
        }
        Some(code as i32)
    }
}

pub fn run_limited(mut cmd: Command, timeout: Duration, limits: Limits, mode: Mode) -> std::io::Result<Outcome> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(CREATE_SUSPENDED);
    let mut child = cmd.spawn()?;
    let handle = child.as_raw_handle() as HANDLE;
    let out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    run_supervised(Spawned { handle, out: Box::new(out), err: Box::new(err), _owner: Box::new(child) }, timeout, limits, mode)
}

/// Put a suspended process into a fresh Job Object, resume it, and watch it until it
/// exits, times out, or (GUI mode) has proven it stays alive and responsive.
pub fn run_supervised(sp: Spawned, timeout: Duration, limits: Limits, mode: Mode) -> std::io::Result<Outcome> {
    let job = create_job(limits)?;
    let start = Instant::now();
    let h = sp.handle;
    if unsafe { AssignProcessToJobObject(job.0, h) } == 0 {
        let e = std::io::Error::last_os_error();
        unsafe { TerminateProcess(h, 1) };
        return Err(e);
    }
    unsafe { NtResumeProcess(h) };
    let t_out = drain(sp.out);
    let t_err = drain(sp.err);

    let mut out = Outcome::default();
    let mut seen: HashSet<u32> = HashSet::new();
    let mut hung_polls = 0;
    let mut last_scan = Instant::now() - Duration::from_secs(1);
    let mut main_exit: Option<i32> = None;
    loop {
        if main_exit.is_none() {
            main_exit = exit_code(h);
        }
        let live = job_pids(&job);
        seen.extend(live.iter().copied());
        let elapsed = start.elapsed();

        match mode {
            Mode::RunToExit => {
                if main_exit.is_some() && live.is_empty() {
                    break;
                }
            }
            Mode::GuiAlive { alive } => {
                if main_exit.is_some() {
                    break; // exited before the alive window elapsed
                }
                if last_scan.elapsed() >= Duration::from_millis(400) {
                    last_scan = Instant::now();
                    let (vis, hung) = scan_windows(&live.iter().copied().collect());
                    out.windows_seen = out.windows_seen.max(vis);
                    hung_polls = if hung { hung_polls + 1 } else { 0 };
                    if hung_polls >= 3 {
                        out.hung = true;
                        break;
                    }
                }
                if elapsed >= alive {
                    break;
                }
            }
        }
        if elapsed >= timeout {
            out.timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    out.peak_memory_mb = peak_memory_mb(&job);
    out.exit_code = main_exit;
    unsafe {
        TerminateJobObject(job.0, 1);
        WaitForSingleObject(h, 5000);
    }
    drop(job);
    out.stdout = t_out.join().unwrap_or_default();
    out.stderr = t_err.join().unwrap_or_default();
    out.pids_seen = seen.into_iter().collect();
    out.pids_seen.sort_unstable();
    out.duration_ms = start.elapsed().as_millis() as u64;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: Limits = Limits { memory_mb: 512, max_processes: 16 };

    fn cmd(script: &str) -> Command {
        let mut c = Command::new("cmd");
        c.args(["/C", script]);
        c
    }

    #[test]
    fn captures_exit_code_and_output() {
        let o = run_limited(cmd("echo hello&& exit 7"), Duration::from_secs(20), L, Mode::RunToExit).unwrap();
        assert_eq!(o.exit_code, Some(7));
        assert!(o.stdout.contains("hello") && !o.timed_out);
    }

    #[test]
    fn timeout_kills_the_whole_process_tree() {
        let t = Instant::now();
        let o = run_limited(cmd("ping -n 60 127.0.0.1 >nul"), Duration::from_millis(800), L, Mode::RunToExit).unwrap();
        assert!(o.timed_out && o.exit_code.is_none());
        assert!(o.pids_seen.len() >= 2, "cmd + ping should both be tracked: {:?}", o.pids_seen);
        assert!(t.elapsed() < Duration::from_secs(8));
    }

    #[test]
    fn process_limit_is_enforced() {
        // Limit of 1 process: cmd cannot start a child ping.
        let l = Limits { memory_mb: 512, max_processes: 1 };
        let o = run_limited(cmd("ping -n 2 127.0.0.1 >nul"), Duration::from_secs(20), l, Mode::RunToExit).unwrap();
        assert_ne!(o.exit_code, Some(0), "child creation must be blocked by the job limit: {o:?}");
    }

    #[test]
    fn gui_mode_reports_early_exit() {
        let o = run_limited(cmd("exit 3"), Duration::from_secs(20), L, Mode::GuiAlive { alive: Duration::from_secs(5) }).unwrap();
        assert_eq!(o.exit_code, Some(3));
    }
}
