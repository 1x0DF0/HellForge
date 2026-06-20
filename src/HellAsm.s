/* GAS (Intel syntax) translation of HellAsm.asm for MinGW x64 cross-compile */
.intel_syntax noprefix

.data
wSystemCall:
    .long 0

.text

.global HellsGate
HellsGate:
    mov DWORD PTR [wSystemCall + rip], 0
    mov DWORD PTR [wSystemCall + rip], ecx
    ret

.global HellDescent
HellDescent:
    mov r10, rcx
    mov eax, DWORD PTR [wSystemCall + rip]
    syscall
    ret
