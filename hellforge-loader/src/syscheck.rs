//! System environment checks: installed-software enumeration and thread-ID
//! from TEB. Used for sandbox detection and execution context verification.

#![allow(dead_code)]

use crate::types::*;
use windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

/// Walk HKLM\...\Uninstall and return the count of entries that have a
/// DisplayName value. Real systems typically have 20+; sandboxes < 10.
pub fn enum_installed_software() -> u32 {
    let mut count: u32 = 0;

    let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\0"
        .encode_utf16()
        .collect();

    let mut h_key: HKEY = core::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut h_key)
    };
    if status != 0 {
        return 0;
    }

    let mut dw_index: u32 = 0;
    loop {
        let mut key_name = [0u16; 260];
        let mut key_name_len: u32 = 260;

        let rc = unsafe {
            RegEnumKeyExW(
                h_key,
                dw_index,
                key_name.as_mut_ptr(),
                &mut key_name_len,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }

        let mut h_sub: HKEY = core::ptr::null_mut();
        if unsafe { RegOpenKeyExW(h_key, key_name.as_ptr(), 0, KEY_READ, &mut h_sub) } == 0 {
            let display_name_key: Vec<u16> = "DisplayName\0".encode_utf16().collect();
            let mut buf = [0u16; 260];
            let mut buf_len: u32 = (buf.len() * 2) as u32;

            // Only count entries that actually have a DisplayName
            if unsafe {
                RegQueryValueExW(
                    h_sub,
                    display_name_key.as_ptr(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    buf.as_mut_ptr() as *mut u8,
                    &mut buf_len,
                )
            } == 0
            {
                count += 1;
            }

            unsafe { RegCloseKey(h_sub) };
        }

        dw_index += 1;
    }

    unsafe { RegCloseKey(h_key) };
    count
}

/// Read the current thread ID directly from the TEB (GS:[0x30]) without
/// going through the Win32 import table.
///
/// TEB layout (x64):
///   +0x000  NtTib            (56 bytes)
///   +0x038  EnvironmentPointer
///   +0x040  ClientId.UniqueProcess
///   +0x048  ClientId.UniqueThread   ← we read here
#[cfg(target_arch = "x86_64")]
pub fn get_current_thread_id() -> u32 {
    unsafe {
        let teb: usize;
        core::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, pure, readonly),
        );
        // UniqueThread is a HANDLE (8 bytes); low 32 bits are the TID
        *((teb + 0x48) as *const u32)
    }
}
