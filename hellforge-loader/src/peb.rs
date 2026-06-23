//! PEB-walking routines for hash-based module and export resolution.
//!
//! Provides two public functions:
//!
//! * `get_module_handle_h(module_hash)` — walk the PEB LDR
//!   `InMemoryOrderModuleList` and return the DLL base address whose full
//!   path name (wide→ASCII cast, uppercased) hashes to `module_hash`.
//!
//! * `get_proc_address_h(module_base, api_hash)` — walk the PE export table
//!   of `module_base` and return the function address whose ASCII name hashes
//!   to `api_hash`.
//!
//! Both functions are direct ports of `GetModuleHandleH` / `GetProcAddressH`
//! from `ApiHashing.c`.

#![allow(dead_code, unused_imports)]

use crate::types::*;

// ---------------------------------------------------------------------------
// Internal: read PEB pointer from GS:[0x60] (x64 only)
// ---------------------------------------------------------------------------

/// Read the Process Environment Block pointer from `GS:[0x60]` (x64).
///
/// # Safety
/// Must be called on a 64-bit Windows thread.  Undefined behaviour on any
/// other platform.
#[inline]
unsafe fn get_peb_ptr() -> *mut Peb {
    let peb: *mut Peb;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );
    peb
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Walk the PEB LDR `InMemoryOrderModuleList` and return the base address of
/// the first module whose full DLL name (wide characters cast to `u8`,
/// uppercased) produces a Jenkins OAT hash equal to `module_hash`.
///
/// This matches `GetModuleHandleH` in `ApiHashing.c` exactly:
/// the C code casts each wide `FullDllName.Buffer[i]` to `CHAR`, runs it
/// through `_toUpper`, then calls `HASHA` (byte-level Jenkins OAT) on the
/// resulting ASCII array.
///
/// Returns a null pointer if no matching module is found.
///
/// # Safety
/// Must be called on a 64-bit Windows thread with a valid PEB.
pub unsafe fn get_module_handle_h(module_hash: u32) -> *mut u8 {
    if module_hash == 0 {
        return core::ptr::null_mut();
    }

    let peb = get_peb_ptr();
    if peb.is_null() {
        return core::ptr::null_mut();
    }

    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return core::ptr::null_mut();
    }

    // `InMemoryOrderModuleList` is a circular doubly-linked list.
    // Each `Flink` / `Blink` points to the `in_memory_order_links` field
    // (offset 16) inside the corresponding `LdrDataTableEntry`.
    //
    // To recover the full `LdrDataTableEntry*` we subtract 16 bytes from the
    // list pointer (i.e. CONTAINING_RECORD macro equivalent).

    // Pointer to the list head inside PebLdrData — used as the sentinel.
    let list_head = &raw const (*ldr).in_memory_order_module_list as *const ListEntry;

    // First element
    let mut cur_link = (*ldr).in_memory_order_module_list.flink;

    // Small scratch buffer for the ASCII-cast, uppercased name.
    // MAX_PATH = 260.  Stack allocation is fine in a no_std loader.
    const MAX_PATH: usize = 260;

    while !cur_link.is_null() && cur_link as *const ListEntry != list_head {
        // CONTAINING_RECORD: in_memory_order_links is at offset 16 in
        // LdrDataTableEntry, so the entry base is (cur_link - 16).
        let entry = (cur_link as usize)
            .wrapping_sub(core::mem::offset_of!(LdrDataTableEntry, in_memory_order_links))
            as *mut LdrDataTableEntry;

        let name_len_bytes = (*entry).full_dll_name.length;

        if name_len_bytes != 0 {
            let name_buf = (*entry).full_dll_name.buffer;

            if !name_buf.is_null() {
                // Number of wide characters (length field is in bytes)
                let char_count = (name_len_bytes / 2) as usize;

                // Guard against pathologically long names
                if char_count <= MAX_PATH {
                    // Build an uppercase ASCII byte array from the wide string,
                    // exactly as the C code does via _toUpper(CHAR).
                    let mut ascii_buf = [0u8; MAX_PATH];
                    let mut i = 0usize;
                    while i < char_count {
                        let wc = *name_buf.add(i);
                        // Cast wide char to u8 (low byte only), then uppercase
                        let mut b = wc as u8;
                        if b >= b'a' && b <= b'z' {
                            b -= 0x20;
                        }
                        ascii_buf[i] = b;
                        i += 1;
                    }

                    let h = crate::hashing::joaat_a_bytes(&ascii_buf[..char_count]);

                    if h == module_hash {
                        // Return the DLL base address
                        let dll_base = (*entry).dll_base;
                        return dll_base;
                    }
                }
            }
        }

        // Advance to next node
        cur_link = (*cur_link).flink;
    }

    core::ptr::null_mut()
}

/// Walk the PE export table of `module_base` and return the address of the
/// first exported function whose ASCII name produces a Jenkins OAT hash equal
/// to `api_hash`.
///
/// This is a direct port of `GetProcAddressH` from `ApiHashing.c`.
///
/// Returns a null pointer if `module_base` is null, `api_hash` is zero,
/// either PE magic is wrong, or no matching export is found.
///
/// # Safety
/// `module_base` must point to the base of a valid, fully-loaded PE image
/// mapped into the current process address space.
pub unsafe fn get_proc_address_h(module_base: *mut u8, api_hash: u32) -> *mut u8 {
    if module_base.is_null() || api_hash == 0 {
        return core::ptr::null_mut();
    }

    let base = module_base;

    // Validate DOS header
    let dos = base as *const ImageDosHeader;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return core::ptr::null_mut();
    }

    // Validate NT headers
    let nt = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != IMAGE_NT_SIGNATURE {
        return core::ptr::null_mut();
    }

    // Locate the export directory
    let export_rva = (*nt)
        .optional_header
        .data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        .virtual_address;

    if export_rva == 0 {
        return core::ptr::null_mut();
    }

    let export_dir = base.add(export_rva as usize) as *const ImageExportDirectory;

    // Export directory parallel arrays
    let name_rvas  = base.add((*export_dir).address_of_names        as usize) as *const u32;
    let func_rvas  = base.add((*export_dir).address_of_functions     as usize) as *const u32;
    let ordinals   = base.add((*export_dir).address_of_name_ordinals as usize) as *const u16;

    // NOTE: The C code iterates `NumberOfFunctions` but indexes `FunctionNameArray`
    // which has `NumberOfNames` entries.  We iterate `NumberOfNames` to stay
    // in bounds — this matches the practical behaviour of the original.
    let count = (*export_dir).number_of_names as usize;

    for i in 0..count {
        let name_ptr = base.add(*name_rvas.add(i) as usize) as *const u8;

        // Hash the null-terminated ASCII function name
        if crate::hashing::joaat_a_ptr(name_ptr) == api_hash {
            // Resolve function address via ordinal indirection
            let ordinal = *ordinals.add(i) as usize;
            let func_ptr = base.add(*func_rvas.add(ordinal) as usize);
            return func_ptr;
        }
    }

    core::ptr::null_mut()
}
