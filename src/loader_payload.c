#include "loader_config.h"
#include <windows.h>

// Stub payload/key arrays for VS compilation.
// Real builds replace this file with generated output from build.exe / build.
// The byte values here are a null-padded placeholder — they will not execute anything useful.

#ifdef INJECT_EARLY_BIRD
unsigned short SPAWN_PROCESS[] = { 0 }; // stub: real builds write a full path here
#endif

unsigned char Rc4CipherText[PAYLOAD_SIZE] = { 0 };
unsigned char EncRc4Key[KEY_SIZE]          = { 0 };
