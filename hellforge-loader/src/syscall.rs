//! HellsGate syscall stub — inline assembly + macro for direct syscalls.
//!
//! Two assembly routines are defined via `global_asm!`:
//!   - `HellsGate(ssn)` — writes the syscall number into the hidden `.data` word.
//!   - `HellDescent()`  — executes the syscall using the number stored by `HellsGate`.
//!
//! Use the `syscall!` macro to invoke a syscall in one expression.

#![allow(unused_imports, dead_code)]

use core::arch::global_asm;
use crate::types::*;

global_asm!(
    ".intel_syntax noprefix",
    ".section .data",
    "wSystemCall: .long 0",
    ".section .text",
    ".global HellsGate",
    "HellsGate:",
    "    mov DWORD PTR [wSystemCall + rip], 0",
    "    mov DWORD PTR [wSystemCall + rip], ecx",
    "    ret",
    ".global HellDescent",
    "HellDescent:",
    "    mov r10, rcx",
    "    mov eax, DWORD PTR [wSystemCall + rip]",
    "    syscall",
    "    ret",
    ".att_syntax prefix",
);

extern "C" {
    /// Set the syscall number that `HellDescent` will use.
    /// Must be called immediately before `HellDescent` / the `syscall!` macro.
    pub fn HellsGate(ssn: u16);

    /// Execute the system call previously armed by `HellsGate`.
    /// The actual argument registers are set by the caller — the Rust compiler
    /// passes the first four integer arguments in RCX, RDX, R8, R9 per the
    /// Windows x64 ABI, which is exactly what the NT syscall stub expects.
    pub fn HellDescent();
}

/// Invoke a direct syscall through HellsGate + HellDescent.
///
/// # Usage
/// ```rust
/// let status: NTSTATUS = syscall!(
///     vx_table.nt_close,
///     unsafe extern "system" fn(HANDLE) -> NTSTATUS,
///     handle
/// );
/// ```
///
/// The macro:
/// 1. Arms `HellsGate` with the SSN from the `VxEntry`.
/// 2. Transmutes `HellDescent` to the supplied function type.
/// 3. Calls it with the provided arguments.
///
/// # Safety
/// The caller must ensure the argument list and types match the actual
/// NT syscall ABI for the targeted function.
#[macro_export]
macro_rules! syscall {
    ($entry:expr, $fn_type:ty $(, $arg:expr)* $(,)?) => {
        unsafe {
            $crate::syscall::HellsGate(($entry).ssn);
            let f: $fn_type = core::mem::transmute($crate::syscall::HellDescent as *const ());
            f($($arg),*)
        }
    };
}

/// Convenience wrapper around `HellsGate` — arms the syscall number.
///
/// In most cases the `syscall!` macro is preferred; use this only when you
/// need to arm and call separately.
#[inline]
pub unsafe fn hells_gate(ssn: u16) {
    HellsGate(ssn);
}
