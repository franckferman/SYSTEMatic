#include "process.h"
#include "error.h"

static BOOL LaunchWithParentSpoof(DWORD dwSystemPid, LPCWSTR lpApplicationName) {
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwSystemPid);
    if (!hParent) {
        LogErrorEx(L"OpenProcess(PROCESS_CREATE_PROCESS) failed", GetLastError());
        return FALSE;
    }

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!pAttrList) {
        CloseHandle(hParent);
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrSize)) {
        LogErrorEx(L"InitializeProcThreadAttributeList failed", GetLastError());
        HeapFree(GetProcessHeap(), 0, pAttrList);
        CloseHandle(hParent);
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(pAttrList, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(HANDLE), NULL, NULL)) {
        LogErrorEx(L"UpdateProcThreadAttribute failed", GetLastError());
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        CloseHandle(hParent);
        return FALSE;
    }

    STARTUPINFOEXW siex = { 0 };
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siex.lpAttributeList = pAttrList;
    PROCESS_INFORMATION pi = { 0 };

    BOOL result = CreateProcessW(lpApplicationName, NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, (LPSTARTUPINFOW)&siex, &pi);

    DeleteProcThreadAttributeList(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    CloseHandle(hParent);

    if (!result) {
        LogErrorEx(L"Failed to launch process (parent spoof fallback)", GetLastError());
    } else {
        WCHAR buf[MAX_PATH + 64];
        StringCchPrintfW(buf, ARRAYSIZE(buf),
            L"[+] Process launched as NT AUTHORITY\\SYSTEM: %ls\n"
            L"    Method: parent process spoofing (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)\n",
            lpApplicationName);
        ConWriteW(CON_OUT, buf);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return result;
}

BOOL LaunchProcessWithToken(HANDLE hToken, DWORD dwSystemPid, LPCWSTR lpApplicationName, DWORD dwLogonFlags) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL result = CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, NULL,
        CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    if (!result) {
        DWORD err = GetLastError();
        if (err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_ACCESS_DENIED) {
            return LaunchWithParentSpoof(dwSystemPid, lpApplicationName);
        }
        LogErrorEx(L"Failed to launch process with token", err);
        return FALSE;
    }

    WCHAR buf[MAX_PATH + 64];
    StringCchPrintfW(buf, ARRAYSIZE(buf),
        L"[+] Process launched as NT AUTHORITY\\SYSTEM: %ls\n"
        L"    Method: token impersonation (CreateProcessWithTokenW)\n",
        lpApplicationName);
    ConWriteW(CON_OUT, buf);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}
