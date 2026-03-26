#include "token.h"
#include "error.h"

BOOL EnablePrivilege(LPCWSTR lpPrivilegeName) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp = { 1 };
    BOOL result = LookupPrivilegeValueW(NULL, lpPrivilegeName, &tp.Privileges[0].Luid);
    if (result) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        result = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(hToken);
    return result;
}

/* Processes to try first, in priority order, before falling back to full scan. */
static const LPCWSTR PRIORITY_PROCESSES[] = {
    L"services.exe",
    L"winlogon.exe",
    L"lsass.exe",
};

BOOL IsSystemToken(HANDLE hToken) {
    BOOL isSystem = FALSE;
    DWORD neededSize = 0;
    PTOKEN_USER pTokenUser = NULL;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &neededSize) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, neededSize);
        if (pTokenUser != NULL) {
            if (GetTokenInformation(hToken, TokenUser, pTokenUser, neededSize, &neededSize)) {
                SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
                PSID pSystemSid = NULL;
                if (AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_LOCAL_SYSTEM_RID,
                    0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
                    if (EqualSid(pTokenUser->User.Sid, pSystemSid)) {
                        isSystem = TRUE;
                    }
                    FreeSid(pSystemSid);
                }
            }
            HeapFree(GetProcessHeap(), 0, pTokenUser);
        }
    }
    return isSystem;
}

static BOOL TryGetSystemTokenFromPID(DWORD dwPid, HANDLE* phToken) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (!hProcess)
        return FALSE;

    BOOL bResult = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        if (IsSystemToken(hToken)) {
            *phToken = hToken;
            bResult = TRUE;
        }
        else {
            CloseHandle(hToken);
        }
    }
    CloseHandle(hProcess);
    return bResult;
}

static DWORD FindPIDByName(HANDLE hSnapshot, LPCWSTR lpName) {
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32))
        return 0;

    do {
        if (_wcsicmp(pe32.szExeFile, lpName) == 0)
            return pe32.th32ProcessID;
    } while (Process32NextW(hSnapshot, &pe32));

    return 0;
}

BOOL GetSystemToken(HANDLE* phToken, DWORD* pdwPid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogErrorEx(L"CreateToolhelp32Snapshot failed", GetLastError());
        return FALSE;
    }

    /* Pass 1: try known SYSTEM processes in priority order. */
    for (int i = 0; i < ARRAYSIZE(PRIORITY_PROCESSES); i++) {
        DWORD dwPid = FindPIDByName(hSnapshot, PRIORITY_PROCESSES[i]);
        if (dwPid && TryGetSystemTokenFromPID(dwPid, phToken)) {
            *pdwPid = dwPid;
            CloseHandle(hSnapshot);
            return TRUE;
        }
    }

    /* Pass 2: full scan fallback over all remaining processes. */
    BOOL bResult = FALSE;
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (TryGetSystemTokenFromPID(pe32.th32ProcessID, phToken)) {
                *pdwPid = pe32.th32ProcessID;
                bResult = TRUE;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    else {
        LogErrorEx(L"Process32FirstW failed", GetLastError());
    }

    CloseHandle(hSnapshot);
    return bResult;
}

BOOL DuplicateSystemToken(HANDLE hToken, HANDLE* phNewToken) {
    return DuplicateTokenEx(hToken,
        TOKEN_ALL_ACCESS,
        NULL, SecurityImpersonation, TokenPrimary, phNewToken);
}
