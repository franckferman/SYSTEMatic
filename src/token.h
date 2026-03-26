#pragma once

#include "common.h"

BOOL EnablePrivilege(LPCWSTR lpPrivilegeName);

BOOL IsSystemToken(HANDLE hToken);

BOOL GetSystemToken(HANDLE* phToken, DWORD* pdwPid);

BOOL DuplicateSystemToken(HANDLE hToken, HANDLE* phNewToken);
