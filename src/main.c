#include "common.h"
#include "error.h"
#include "token.h"
#include "process.h"

static void PrintUsage(LPCWSTR progName) {
    WCHAR buf[2048];
    ConWriteW(CON_ERR, L"Usage: ");
    ConWriteW(CON_ERR, progName);
    ConWriteW(CON_ERR,
        L" [OPTIONS] [COMMAND]\n"
        L"\n"
        L"Escalate from Administrator to NT AUTHORITY\\SYSTEM via token impersonation.\n"
        L"\n"
        L"Options:\n"
        L"  -h, --help            Show this help message and exit\n"
        L"  --logon-profile       Load SYSTEM user profile (LOGON_WITH_PROFILE).\n"
        L"                        Default: LOGON_NETCREDENTIALS_ONLY\n"
        L"\n"
        L"Arguments:\n"
        L"  COMMAND               Process to spawn as SYSTEM (default: cmd.exe)\n"
        L"\n"
        L"Examples:\n");
    StringCchPrintfW(buf, ARRAYSIZE(buf),
        L"  %ls\n"
        L"  %ls powershell.exe\n"
        L"  %ls --logon-profile powershell.exe\n"
        L"  %ls \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"\n",
        progName, progName, progName, progName);
    ConWriteW(CON_ERR, buf);
}

int wmain(int argc, wchar_t* argv[]) {
    BOOL bLogonProfile = FALSE;
    LPCWSTR lpCommand = NULL;

    for (int i = 1; i < argc; i++) {
        if (lstrcmpW(argv[i], L"-h") == 0 || lstrcmpW(argv[i], L"--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        else if (lstrcmpW(argv[i], L"--logon-profile") == 0) {
            bLogonProfile = TRUE;
        }
        else if (argv[i][0] != L'-') {
            lpCommand = argv[i];
        }
        else {
            WCHAR buf[256];
            StringCchPrintfW(buf, ARRAYSIZE(buf), L"Unknown option: %ls\n", argv[i]);
            ConWriteW(CON_ERR, buf);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (!IsUserAnAdmin()) {
        ConWriteW(CON_ERR, L"[-] This program needs to be run as an administrator.\n");
        return 1;
    }

    EnablePrivilege(SE_DEBUG_NAME);

    HANDLE hToken = NULL, hNewToken = NULL;
    DWORD dwSystemPid = 0;

    if (!GetSystemToken(&hToken, &dwSystemPid)) {
        ConWriteW(CON_ERR, L"[-] Failed to obtain a SYSTEM token.\n");
        return 1;
    }

    if (!DuplicateSystemToken(hToken, &hNewToken)) {
        LogErrorEx(L"[-] Failed to duplicate the SYSTEM token", GetLastError());
        CloseHandle(hToken);
        return 1;
    }
    CloseHandle(hToken);

    WCHAR szTargetPath[MAX_PATH];
    if (lpCommand != NULL) {
        lstrcpynW(szTargetPath, lpCommand, MAX_PATH);
    }
    else {
        if (!ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\cmd.exe", szTargetPath, MAX_PATH)) {
            LogErrorEx(L"[-] ExpandEnvironmentStringsW failed", GetLastError());
            CloseHandle(hNewToken);
            return 1;
        }
    }

    DWORD dwLogonFlags = bLogonProfile ? LOGON_WITH_PROFILE : LOGON_NETCREDENTIALS_ONLY;

    if (!LaunchProcessWithToken(hNewToken, dwSystemPid, szTargetPath, dwLogonFlags)) {
        CloseHandle(hNewToken);
        return 1;
    }

    CloseHandle(hNewToken);
    return 0;
}
