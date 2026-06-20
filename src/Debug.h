/*
    file that contains printf & wprinf replacements
*/

#pragma once

#include <Windows.h>

// DEBUG is defined per-build in loader_config.h

#ifdef DEBUG

// wprintf replacement
#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * sizeof(WCHAR) ); \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, ##__VA_ARGS__ );                                  \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  


// printf replacement
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, ##__VA_ARGS__ );                                  \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  



#endif // DEBUG




