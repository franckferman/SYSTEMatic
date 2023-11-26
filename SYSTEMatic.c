#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <Shlobj.h>

#define ERROR_CREATE_SNAPSHOT "CreateToolhelp32Snapshot failed with error %lu\n"
#define ERROR_PROCESS_FIRST "Process32First failed with error %lu\n"
#define ERROR_LAUNCH_PROCESS "Failed to create a process with the impersonated token. Error: %lu\n"
#define ERROR_DUPLICATE_TOKEN "Failed to duplicate the SYSTEM token. Error: %lu\n"
#define ERROR_GET_SYSTEM_TOKEN "Failed to get SYSTEM token.\n"

void LogError(const char* errorMessage, DWORD lastError);
BOOL IsSystemToken(HANDLE hToken);
BOOL GetSystemToken(HANDLE* phToken);
BOOL DuplicateSystemToken(HANDLE hToken, HANDLE* phNewToken);
BOOL LaunchProcessWithToken(HANDLE hToken, LPCWSTR lpApplicationName);

void LogError(const char* errorMessage, DWORD lastError) {
    fprintf(stderr, errorMessage, lastError);
}

BOOL IsSystemToken(HANDLE hToken) {
    BOOL isSystem = FALSE;
    DWORD neededSize;
    PTOKEN_USER pTokenUser = NULL;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &neededSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        pTokenUser = (PTOKEN_USER)malloc(neededSize);
        if (pTokenUser && GetTokenInformation(hToken, TokenUser, pTokenUser, neededSize, &neededSize)) {
            SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
            PSID pSystemSid;
            if (AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
                if (EqualSid(pTokenUser->User.Sid, pSystemSid)) {
                    isSystem = TRUE;
                }
                FreeSid(pSystemSid);
            }
        }
        if (pTokenUser) {
            free(pTokenUser);
        }
    }
    return isSystem;
}

BOOL GetSystemToken(HANDLE* phToken) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogError(ERROR_CREATE_SNAPSHOT, GetLastError());
        return FALSE;
    }

    BOOL bResult = FALSE;
    PROCESSENTRY32 pe32 = { sizeof(pe32) };
    if (Process32First(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                HANDLE hToken;
                if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                    if (IsSystemToken(hToken)) {
                        *phToken = hToken;
                        bResult = TRUE;
                        break;
                    }
                    else {
                        CloseHandle(hToken);
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(hSnapshot, &pe32) && !bResult);
    }
    else {
        LogError(ERROR_PROCESS_FIRST, GetLastError());
    }

    CloseHandle(hSnapshot);
    return bResult;
}

BOOL DuplicateSystemToken(HANDLE hToken, HANDLE* phNewToken) {
    return DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, phNewToken);
}

BOOL LaunchProcessWithToken(HANDLE hToken, LPCWSTR lpApplicationName) {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL result = CreateProcessWithTokenW(hToken, LOGON_NETCREDENTIALS_ONLY, lpApplicationName, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (!result) {
        LogError(ERROR_LAUNCH_PROCESS, GetLastError());
    }
    else {
        printf("Successfully launched a new process with SYSTEM privileges.\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return result;
}

int main(int argc, char* argv[]) {
    BOOL isAdmin = IsUserAnAdmin();
    if (!isAdmin) {
        fprintf(stderr, "This program needs to be run as an administrator.\n");
        return 1;
    }

    HANDLE hToken, hNewToken;

    if (!GetSystemToken(&hToken)) {
        LogError(ERROR_GET_SYSTEM_TOKEN, GetLastError());
        return 1;
    }

    if (!DuplicateSystemToken(hToken, &hNewToken)) {
        LogError(ERROR_DUPLICATE_TOKEN, GetLastError());
        CloseHandle(hToken);
        return 1;
    }

    CloseHandle(hToken);

    if (!LaunchProcessWithToken(hNewToken, L"C:\\Windows\\System32\\cmd.exe")) {
        CloseHandle(hNewToken);
        return 1;
    }

    CloseHandle(hNewToken);
    return 0;
}
