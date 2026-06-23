//! Jenkins One-At-A-Time (JOAAT) hash functions.
//!
//! These are direct ports of `HashStringJenkinsOneAtATime32BitA` and
//! `HashStringJenkinsOneAtATime32BitW` from `WinApi.c`.
//!
//! `INITIAL_SEED = 8` matches the C macro.

#![allow(dead_code)]

pub const INITIAL_SEED: u32 = 8;

// ---------------------------------------------------------------------------
// ASCII / byte-slice variants
// ---------------------------------------------------------------------------

/// Jenkins One-At-A-Time hash over an ASCII byte slice (no case conversion).
///
/// Equivalent to `HashStringJenkinsOneAtATime32BitA` when the caller supplies
/// the full string as a slice.
#[inline]
pub fn joaat_a_bytes(s: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &b in s {
        hash = hash.wrapping_add(b as u32);
        hash = hash.wrapping_add(hash << INITIAL_SEED);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);
    hash
}

/// Jenkins OAT hash over a null-terminated ASCII (`*const u8`) pointer.
///
/// Equivalent to calling `HashStringJenkinsOneAtATime32BitA` with the
/// pointer directly.
///
/// # Safety
/// `ptr` must point to a valid null-terminated C string for the duration of
/// this call.
pub unsafe fn joaat_a_ptr(ptr: *const u8) -> u32 {
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    joaat_a_bytes(core::slice::from_raw_parts(ptr, len))
}

// ---------------------------------------------------------------------------
// Wide / UTF-16 variants (with uppercase conversion)
// ---------------------------------------------------------------------------

/// Jenkins OAT hash over a wide (`u16`) slice with ASCII-range uppercase
/// conversion.
///
/// Each code-unit is uppercased (`'a'..='z'` → `'A'..='Z'`) before being
/// added to the hash, matching the `_toUpper` call in
/// `GetModuleHandleH` → `HashStringJenkinsOneAtATime32BitW`.
pub fn joaat_w_upper_slice(s: &[u16]) -> u32 {
    let mut hash: u32 = 0;
    for &c in s {
        // ASCII-range uppercase only (mirrors _toUpper(CHAR))
        let cu: u32 = if c >= b'a' as u16 && c <= b'z' as u16 {
            (c - 0x20) as u32
        } else {
            c as u32
        };
        hash = hash.wrapping_add(cu);
        hash = hash.wrapping_add(hash << INITIAL_SEED);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);
    hash
}

/// Jenkins OAT hash over a null-terminated wide string pointer with
/// ASCII-range uppercase conversion.
///
/// Used to hash module names obtained from `FullDllName.Buffer` in the PEB
/// LDR linked list.
///
/// # Safety
/// `ptr` must point to a valid null-terminated wide (`u16`) string for the
/// duration of this call.
pub unsafe fn joaat_w_upper_ptr(ptr: *const u16) -> u32 {
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    joaat_w_upper_slice(core::slice::from_raw_parts(ptr, len))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Sanity: JOAAT of "KERNEL32.DLL" (uppercase ASCII) → 0xFD2AD9BD
    // (matches HASH_KERNEL32 in types.rs)
    //
    // NOTE: These tests cannot execute on a non-Windows host for the
    // PEB-walking code, but the pure-Rust hashing logic can be verified
    // anywhere.
    #[test]
    fn kernel32_ascii_hash() {
        let h = joaat_a_bytes(b"KERNEL32.DLL");
        assert_eq!(h, 0xFD2AD9BD, "KERNEL32.DLL hash mismatch: got {h:#010x}");
    }

    #[test]
    fn kernel32_wide_upper_hash() {
        // Wide encoding of "KERNEL32.DLL" (already uppercase, so no conversion)
        let wide: Vec<u16> = "KERNEL32.DLL".encode_utf16().collect();
        let h = joaat_w_upper_slice(&wide);
        assert_eq!(h, 0xFD2AD9BD, "wide KERNEL32.DLL hash mismatch: got {h:#010x}");
    }

    #[test]
    fn lowercase_wide_uppercased() {
        // "kernel32.dll" wide, uppercased → same hash as "KERNEL32.DLL" ASCII
        let wide: Vec<u16> = "kernel32.dll".encode_utf16().collect();
        let h = joaat_w_upper_slice(&wide);
        assert_eq!(h, 0xFD2AD9BD, "lowercase wide kernel32.dll hash mismatch: got {h:#010x}");
    }
}
