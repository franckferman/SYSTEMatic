#pragma once

#include "common.h"

BOOL LaunchProcessWithToken(HANDLE hToken, DWORD dwSystemPid, LPCWSTR lpApplicationName, DWORD dwLogonFlags);
