//! Test fixture: a GUI application that shows a window and then never processes
//! its message queue. Windows reports such a window as "not responding"
//! (IsHungAppWindow) after ~5 seconds — exactly the condition ShipCheck must classify
//! as APPLICATION HUNG.
#![cfg(windows)]

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::Sleep;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, RegisterClassW, ShowWindow, SW_SHOW, WNDCLASSW, WS_OVERLAPPEDWINDOW,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let class = wide("ReleaseVerityHangFixture");
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(DefWindowProcW),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
        };
        RegisterClassW(&wc);
        let title = wide("hang fixture");
        let hwnd: HWND = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            100,
            100,
            320,
            200,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        ShowWindow(hwnd, SW_SHOW);
        // Block forever without pumping messages.
        loop {
            Sleep(1000);
        }
    }
}
