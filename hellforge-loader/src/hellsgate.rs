//! HellsGate PE-walking routines.
//!
//! Provides:
//!   - `get_teb()`                    — read the TEB pointer from GS:0x30
//!   - `get_peb()`                    — read the PEB pointer from GS:0x60
//!   - `get_image_export_directory()` — validate DOS/NT headers, return export dir
//!   - `get_vx_entry()`               — resolve SSN for one `VxEntry` by hash

#![allow(unused_imports, dead_code)]

use crate::types::*;

// ---------------------------------------------------------------------------
// TEB / PEB accessors
// ---------------------------------------------------------------------------

/// Read the Thread Environment Block pointer from `gs:[0x30]` (x64).
#[inline]
pub unsafe fn get_teb() -> *mut Teb {
    let teb: *mut Teb;
    core::arch::asm!(
        "mov {}, gs:[0x30]",
        out(reg) teb,
        options(nostack, preserves_flags),
    );
    teb
}

/// Read the Process Environment Block pointer from `gs:[0x60]` (x64).
#[inline]
pub unsafe fn get_peb() -> *mut Peb {
    let peb: *mut Peb;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );
    peb
}

// ---------------------------------------------------------------------------
// PE export directory
// ---------------------------------------------------------------------------

/// Validate the DOS and NT headers of a loaded PE image and return a pointer
/// to its `IMAGE_EXPORT_DIRECTORY`.
///
/// Returns `None` if either magic value is wrong.
///
/// # Safety
/// `module_base` must point to the base of a valid, fully-loaded PE image
/// in the current process address space.
pub unsafe fn get_image_export_directory(
    module_base: *mut u8,
) -> Option<*mut ImageExportDirectory> {
    let dos = module_base as *const ImageDosHeader;

    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt = module_base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;

    if (*nt).signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let export_rva = (*nt)
        .optional_header
        .data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        .virtual_address;

    let export_dir = module_base.add(export_rva as usize) as *mut ImageExportDirectory;
    Some(export_dir)
}

// ---------------------------------------------------------------------------
// VxEntry resolution
// ---------------------------------------------------------------------------

/// Walk `export_dir` looking for the export whose name hashes to
/// `entry.hash`.  When found, scan the function bytes for the syscall
/// prologue `4C 8B D1 B8 ?? ?? 00 00` and read the SSN from bytes 4–5.
///
/// Returns `true` and fills `entry.ssn` + `entry.address` on success.
/// Returns `false` if the name is not found or if no valid prologue is
/// located within the first 32 bytes of the function.
///
/// # Safety
/// All three pointers must be valid for the lifetime of this call.
pub unsafe fn get_vx_entry(
    module_base: *mut u8,
    export_dir: *mut ImageExportDirectory,
    entry: &mut VxEntry,
) -> bool {
    let base = module_base;

    // Parallel arrays in the export directory
    let name_rvas   = base.add((*export_dir).address_of_names       as usize) as *const u32;
    let func_rvas   = base.add((*export_dir).address_of_functions    as usize) as *const u32;
    let ordinals    = base.add((*export_dir).address_of_name_ordinals as usize) as *const u16;

    let count = (*export_dir).number_of_names as usize;

    for cx in 0..count {
        // Pointer to null-terminated ASCII function name
        let name_ptr = base.add(*name_rvas.add(cx) as usize) as *const u8;

        // Measure name length (walk to null byte)
        let mut name_len = 0usize;
        while *name_ptr.add(name_len) != 0 {
            name_len += 1;
        }
        let name_bytes = core::slice::from_raw_parts(name_ptr, name_len);

        if entry.hash != crate::hashing::joaat_a_bytes(name_bytes) {
            continue;
        }

        // Found the matching export — resolve its function address
        let ordinal = *ordinals.add(cx) as usize;
        let func_ptr = base.add(*func_rvas.add(ordinal) as usize);

        // Scan for the syscall prologue: 4C 8B D1 B8
        // mov r10, rcx  →  4C 8B D1
        // mov eax, imm  →  B8 <lo> <hi> 00 00
        //
        // If the function is hooked the first few bytes may be a trampoline;
        // scan up to 32 bytes to find the real stub.
        let mut cw: usize = 0;
        loop {
            let p = func_ptr.add(cw);
            if *p       == 0x4C
            && *p.add(1) == 0x8B
            && *p.add(2) == 0xD1
            && *p.add(3) == 0xB8
            {
                // SSN is the 16-bit little-endian value at offset +4
                entry.ssn     = *(func_ptr.add(4 + cw) as *const u16);
                entry.address = func_ptr;
                return true;
            }

            if cw >= 32 {
                return false;
            }
            cw += 1;
        }
    }

    false
}
