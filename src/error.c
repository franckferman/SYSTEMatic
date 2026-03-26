#include "error.h"

void LogErrorEx(LPCWSTR prefix, DWORD errorCode) {
    LPWSTR msgBuf = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&msgBuf,
        0,
        NULL);

    WCHAR buf[1024];
    StringCchPrintfW(buf, ARRAYSIZE(buf), L"%ls: %ls\n", prefix, msgBuf ? msgBuf : L"(unknown error)");
    ConWriteW(CON_ERR, buf);

    if (msgBuf)
        LocalFree(msgBuf);
}
