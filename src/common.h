#pragma once

#include <windows.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <shlobj.h>

/* CRT-free console output via Win32 -- no stdio dependency */
static __inline void ConWriteW(HANDLE h, LPCWSTR msg) {
    DWORD written;
    WriteConsoleW(h, msg, (DWORD)lstrlenW(msg), &written, NULL);
}
#define CON_OUT (GetStdHandle(STD_OUTPUT_HANDLE))
#define CON_ERR (GetStdHandle(STD_ERROR_HANDLE))

/* Safe handle close -- nulls the handle after closing to prevent double-close */
#define SAFE_CLOSEHANDLE(h) \
    do { if ((h) && (h) != INVALID_HANDLE_VALUE) { CloseHandle(h); (h) = NULL; } } while(0)

/* MinGW-w64 compatibility fallbacks */
#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
