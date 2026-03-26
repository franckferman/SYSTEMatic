<div align="center">

<a href="https://github.com/franckferman/SYSTEMatic">
  <img src="https://raw.githubusercontent.com/franckferman/SYSTEMatic/stable/docs/github/graphical_resources/Logo-without_background-SYSTEMatic.png" alt="SYSTEMatic" width="500">
</a>

# SYSTEMatic

**Windows privilege escalation from Administrator to NT AUTHORITY\SYSTEM via token impersonation.**

[![Language](https://img.shields.io/badge/C-Win32_API-00599C?style=flat-square&logo=c&logoColor=white)](https://learn.microsoft.com/en-us/windows/win32/api/)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D4?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Release](https://github.com/franckferman/SYSTEMatic/actions/workflows/release.yml/badge.svg)](https://github.com/franckferman/SYSTEMatic/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Why Administrator is not enough](#why-administrator-is-not-enough)
- [Compared to PsExec](#compared-to-psexec)
- [How it works](#how-it-works)
  - [Token fundamentals](#token-fundamentals)
  - [Execution flow](#execution-flow)
  - [Priority process scan](#priority-process-scan)
  - [Token duplication](#token-duplication)
  - [Process creation and logon flags](#process-creation-and-logon-flags)
- [Project structure](#project-structure)
- [Build](#build)
- [Usage](#usage)
  - [Options](#options)
  - [Examples](#examples)
- [Windows API reference](#windows-api-reference)
- [Legal disclaimer](#legal-disclaimer)
- [License](#license)

---

## Overview

SYSTEMatic is a C proof-of-concept that demonstrates Windows privilege escalation from a local Administrator session to `NT AUTHORITY\SYSTEM` using token impersonation — without UAC prompts, without external tools, and without writing to disk beyond the binary itself.

The technique is based on a well-understood Windows primitive: any process running as Administrator can open a handle to a SYSTEM process with `PROCESS_QUERY_INFORMATION`, extract its token, duplicate it as a primary token, and use it to spawn a new process. SYSTEMatic implements this cleanly using pure Win32 API.

**When is this useful:**

- System administration: running commands that require SYSTEM context (modifying protected registry keys, accessing `HKLM\SECURITY`, interacting with services that reject non-SYSTEM callers)
- Security research: studying token impersonation as a building block of privilege escalation
- Penetration testing: obtaining a SYSTEM shell on a target where you already have Administrator access

**What it is not:** it is not a UAC bypass, it does not exploit a vulnerability, and it does not work without prior Administrator privileges.

---

## Why Administrator is not enough

A common misconception: local Administrator and `NT AUTHORITY\SYSTEM` are equivalent. They are not.

Administrator is a user account with elevated privileges. SYSTEM is the operating system itself — it is not a user, has no password, and cannot be used to authenticate over the network. The distinction matters because several Windows subsystems enforce SYSTEM-only access regardless of the caller's privilege level:

| Capability | Local Administrator | NT AUTHORITY\SYSTEM |
|-----------|--------------------|--------------------|
| Read `HKLM\SECURITY` (LSA secrets, cached domain hashes) | No | Yes |
| Full access to `HKLM\SAM` without volume shadow copy | No | Yes |
| Open a handle to LSASS with `PROCESS_ALL_ACCESS` | Depends on EDR | More reliable |
| Steal tokens from processes in other user sessions | No | Yes |
| `SeDebugPrivilege` enabled by default | No | Yes |
| Interact with services that reject non-SYSTEM callers | No | Yes |
| Install kernel drivers (with DSE bypass) | No | Yes |
| Full control over the SCM and all registered services | Partial | Total |

In a post-exploitation chain, Administrator access is the entry point. SYSTEM access is what enables the next stage: credential extraction, token theft across sessions, persistence at the kernel level, and lateral movement using machine account credentials.

---

## Compared to PsExec

PsExec is a legitimate administration tool — not a red team primitive. The behavioral difference is significant:

| | SYSTEMatic | PsExec |
|---|-----------|--------|
| **Disk writes** | None beyond the binary itself | Drops `PSEXESVC.exe` in `C:\Windows\` |
| **Service creation** | None | Creates and starts a Windows service (Event ID 7045) |
| **Network dependency** | None — local only | Requires SMB + admin share (`ADMIN$`) |
| **Credentials** | Not transmitted — works on the current session token | Requires explicit credentials or pass-the-hash |
| **Event log noise** | Minimal | 7045 (service installed), 4697, SMB authentication events |
| **EDR visibility** | Low — pure Win32 token operations | High — service drop + SCM interaction is a known detection pattern |
| **Fileless option** | Yes — via donut shellcode loaded in memory | No |
| **Mechanism** | Token impersonation (`DuplicateTokenEx` + `CreateProcessWithTokenW`) | Remote service execution over SMB |

PsExec is designed for system administrators who need to run commands on remote machines. SYSTEMatic is designed for the specific post-exploitation scenario where you already have a local Administrator session and need to escalate to SYSTEM without generating the network traffic, service events, and file artifacts that PsExec produces.

---

## How it works

### Token fundamentals

Every Windows process carries an **access token** — a kernel object that identifies who the process is and what it is allowed to do. The token contains:

- The user SID (the identity — e.g., `S-1-5-18` for SYSTEM)
- Group SIDs and their attributes
- Privileges (`SeDebugPrivilege`, `SeTcbPrivilege`, etc.)
- Integrity level

Two token types exist:

| Type | Purpose |
|------|---------|
| `TokenPrimary` | Assigned to a process at creation. Represents the process identity. |
| `TokenImpersonation` | Used by threads to temporarily act as a different user. |

To spawn a new process with a different identity, a **primary token** is required. Impersonation tokens cannot be passed to `CreateProcessWithTokenW` directly — they must first be duplicated into a primary token.

### Execution flow

```
1. IsUserAnAdmin()
        |
        v
2. EnablePrivilege(SE_DEBUG_NAME)
        |
        v
3. CreateToolhelp32Snapshot()
        |
        v
4. Priority scan: services.exe -> winlogon.exe -> lsass.exe
        |
        | (if none found)
        v
5. Full process enumeration fallback
        |
        v
6. OpenProcess(PROCESS_QUERY_INFORMATION)
   OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY)
        |
        v
7. GetTokenInformation(TokenUser) + EqualSid() vs SECURITY_LOCAL_SYSTEM_RID
        |
        v
8. DuplicateTokenEx() -> TokenPrimary (TOKEN_ALL_ACCESS)
        |
        v
9. ExpandEnvironmentStringsW("%SystemRoot%\System32\cmd.exe") or argv[1]
        |
        v
10. CreateProcessWithTokenW(hToken, dwLogonFlags, ...)
        |
        | (if ERROR_PRIVILEGE_NOT_HELD or ERROR_ACCESS_DENIED)
        v
11. Fallback: parent process spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
```

### Priority process scan

Rather than iterating all processes immediately, SYSTEMatic first tries a short list of processes that are guaranteed to be owned by SYSTEM and stable for the lifetime of the system:

| Process | Why |
|---------|-----|
| `services.exe` | Service Control Manager. Always running. Always SYSTEM. Safe to query. |
| `winlogon.exe` | Windows logon process. Always SYSTEM on a live session. |
| `lsass.exe` | Local Security Authority. Always SYSTEM. Queried last to avoid unnecessary noise. |

`FindPIDByName()` scans the snapshot for the process name using `_wcsicmp` (case-insensitive wide string comparison). `TryGetSystemTokenFromPID()` opens the process, reads its token, and validates the SID. If a priority process yields a valid SYSTEM token, the scan stops immediately.

If none of the three priority processes return a usable token (rare, but possible in hardened or minimal environments), SYSTEMatic falls back to a full enumeration of all running processes.

### Token duplication

Once a valid SYSTEM token handle is obtained:

```c
DuplicateTokenEx(
    hToken,
    TOKEN_ALL_ACCESS,
    NULL,
    SecurityImpersonation,
    TokenPrimary,    // primary token required for CreateProcessWithTokenW
    &hNewToken
);
```

`TOKEN_ALL_ACCESS` is required. `CreateProcessWithTokenW` internally adjusts the token's session and default DACL — it needs `TOKEN_ADJUST_SESSIONID` and `TOKEN_ADJUST_DEFAULT` in addition to the basic assign/duplicate/impersonate/query set. A minimal mask causes `ERROR_ACCESS_DENIED` when the Secondary Logon service validates the token during process setup.

The `SecurityImpersonation` impersonation level is irrelevant for primary tokens — it is only meaningful for impersonation tokens used by threads. It is retained here for API correctness.

Once `DuplicateTokenEx()` succeeds, the original token handle is closed. The duplicated token is a kernel object with its own reference count — it remains valid regardless of the source process's lifecycle. There is no race condition between obtaining the token and using it.

### Process creation and logon flags

`CreateProcessWithTokenW` accepts a `dwLogonFlags` parameter that controls how the new process's logon session and credentials are set up:

| Flag | Local access | Network access | Profile loaded |
|------|-------------|----------------|----------------|
| `LOGON_NETCREDENTIALS_ONLY` (default) | SYSTEM token | Caller's credentials | No |
| `LOGON_WITH_PROFILE` (`--logon-profile`) | SYSTEM token | Machine account (`DOMAIN\PC$`) | Yes |

**`LOGON_NETCREDENTIALS_ONLY`** — the spawned process runs locally as SYSTEM (full local rights, kernel objects, protected files, restricted registry hives) but its network authentication uses the credentials of the process that called `CreateProcessWithTokenW`. Practically: `\\server\share` access authenticates as the Admin who ran SYSTEMatic, not as SYSTEM.

**`LOGON_WITH_PROFILE`** — Windows loads the SYSTEM user profile (`C:\Windows\system32\config\systemprofile`), mounts its registry hive as `HKCU`, and sets the correct environment variables (`%USERNAME%=SYSTEM`, `%USERPROFILE%=C:\Windows\system32\config\systemprofile`). Network authentication uses the machine account. Requires `SE_INCREASE_QUOTA_PRIVILEGE` on the calling token, which is present by default on elevated Administrator sessions.

**Which to use:**

- Default (`LOGON_NETCREDENTIALS_ONLY`): sufficient for the overwhelming majority of local privilege escalation use cases. More portable — does not depend on the SYSTEM profile being intact.
- `--logon-profile`: use when the spawned process reads `HKCU` or `%APPDATA%` and must see SYSTEM's environment rather than the caller's, or when network operations must authenticate as the machine account.

---

## Project structure

```
SYSTEMatic/
├── Makefile
├── README.md
├── LICENSE
├── src/
│   ├── common.h          Shared Windows headers (windows.h, tlhelp32.h, shlobj.h)
│   ├── error.h / .c      LogErrorEx() — FormatMessage-based Win32 error reporting
│   ├── token.h / .c      EnablePrivilege, IsSystemToken, FindPIDByName,
│   │                     TryGetSystemTokenFromPID, GetSystemToken, DuplicateSystemToken
│   ├── process.h / .c    LaunchProcessWithToken
│   └── main.c            wmain, argument parsing, orchestration
└── docs/
    └── github/graphical_resources/
        └── Logo-without_background-SYSTEMatic.png
```

---

## Build

Six build targets are available depending on the environment and the desired output characteristics:

| Target | Toolchain | Platform | Use case |
|--------|-----------|----------|----------|
| `nmake` | MSVC `cl.exe` | Windows | Standard build on the target machine |
| `make linux` | MinGW-w64 `gcc` | Linux | Cross-compilation, CI/CD |
| `make obfuscate` | llvm-mingw `clang` | Linux | Reduced PE footprint, full LTO + ICF |
| `make polymorphic` | llvm-mingw `clang` + `poly_patch.py` | Linux | Unique SHA256 per build |
| `make evasive` | llvm-mingw `clang` + `make_evasive.py` | Linux | No advapi32/shell32 in IAT |
| `make full` | llvm-mingw `clang` + both scripts | Linux | Maximum — evasive + polymorphic |

---

### Windows — MSVC (`cl.exe` + `nmake`)

**Requirements:** MSVC Build Tools — `cl.exe` in PATH. No IDE needed.

Install (free): [visualstudio.microsoft.com/visual-cpp-build-tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

Open an **x64 Native Tools Command Prompt** (installed with Build Tools), or run:

```cmd
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
```

Then:

```cmd
nmake
nmake clean
```

Output: `SYSTEMatic.exe`

**Compiler flags:** `/W3 /sdl /Ox /Oi /Oy /GL /MT /guard:cf`

| Flag | Effect |
|------|--------|
| `/Ox /Oi /Oy` | Full optimization + intrinsics + omit frame pointer |
| `/GL` | Whole-program optimization (link-time) |
| `/MT` | Static CRT linkage — no MSVCRT dependency on the target |
| `/guard:cf` | Control Flow Guard |
| `/sdl` | Security Development Lifecycle checks (extra warnings + runtime mitigations) |
| `/W3` | Warning level 3 |

**Linker flags:** `/LTCG /DYNAMICBASE /NXCOMPAT /OPT:REF /OPT:ICF` — ASLR, DEP, dead code elimination, identical COMDAT folding.

---

### Linux — MinGW-w64 cross-compilation (`make linux`)

Cross-compile a native Windows PE64 from Linux using GCC + MinGW-w64:

```bash
# Install the cross-compiler (Debian / Ubuntu)
sudo apt install gcc-mingw-w64-x86-64
# or:
make install-deps

# Cross-compile
make linux

# Clean
make clean-linux
```

Output: `SYSTEMatic.exe` — standard Windows PE64. Transfer to a Windows target and run from an elevated prompt.

**Compiler flags:** `-O3 -flto -ffunction-sections -fdata-sections -fno-ident -fno-asynchronous-unwind-tables -fno-unwind-tables -fomit-frame-pointer`

| Flag | Effect |
|------|--------|
| `-O3 -flto` | Maximum optimization + link-time optimization |
| `-ffunction-sections -fdata-sections` | Place each symbol in its own section — enables linker dead code removal |
| `-fno-ident` | Suppress `.comment` section (GCC version string) |
| `-fno-asynchronous-unwind-tables -fno-unwind-tables` | Remove `.eh_frame` / `.pdata` unwind metadata |
| `-fomit-frame-pointer` | No frame pointer in prologue/epilogue |

**Linker flags:** `-static --strip-all --gc-sections --no-insert-timestamp`

| Flag | Effect |
|------|--------|
| `-static` | All libraries linked statically — no DLL imports beyond Win32 |
| `--strip-all` | Remove all symbol and debug information from the PE |
| `--gc-sections` | Discard unreferenced sections (works with `-ffunction-sections`) |
| `--no-insert-timestamp` | Zero COFF timestamp — reproducible builds |

---

### Linux — llvm-mingw / clang with full LTO (`make obfuscate`)

Uses clang + LLD from llvm-mingw. The toolchain is **auto-downloaded** on first run — no manual install required:

```bash
# First run: downloads and extracts llvm-mingw to ~/llvm-mingw (~500 MB, once)
make obfuscate

# Custom toolchain path
make obfuscate LLVM_MINGW=/path/to/llvm-mingw

# Clean
make clean-obfuscate
```

**Additional flags over `make linux`:**

| Flag | Effect |
|------|--------|
| `-flto=full` | Full LTO (clang cross-unit inlining and dead code removal) |
| `-fmerge-all-constants` | Deduplicate identical constants across translation units |
| `-fuse-ld=lld` | Use LLD instead of GNU ld |
| `-Wl,--icf=all` | Identical Code Folding — merges functions with identical machine code |

The combination of full LTO + ICF + constant merging + section GC produces a smaller PE with fewer recognizable code patterns than the GCC build.

---

### Linux — polymorphic build (`make polymorphic`)

`make obfuscate` + `scripts/poly_patch.py` post-processing:

```bash
make polymorphic
```

After compilation, `poly_patch.py` patches the PE in-place:

- Randomizes the DOS stub (the 64-byte `MZ` header preamble before the PE signature)
- Randomizes the COFF `TimeDateStamp` field

Result: every invocation of `make polymorphic` produces a binary with a **different SHA256**, while the code behavior is identical. Breaks hash-based static detections that fingerprint a fixed binary.

---

### Linux — evasive build (`make evasive`)

`scripts/make_evasive.py` rewrites the source to replace all `advapi32`, `shell32`, and `kernel32` imports with **runtime dynamic resolution via `GetProcAddress`**:

```bash
make evasive
```

The generated binary has no `advapi32.dll`, `shell32.dll`, or `kernel32.dll` entries in its Import Address Table for the resolved functions. All calls (`OpenProcessToken`, `IsUserAnAdmin`, `CreateProcessWithTokenW`, `CreateToolhelp32Snapshot`, `OpenProcess`, etc.) are resolved at runtime via `LoadLibraryA` + `GetProcAddress` after in-place XOR decryption of the DLL and function name strings.

The XOR key is randomly generated at build time — every invocation of `make evasive` produces different encrypted byte arrays in `.rdata`, defeating static signatures keyed on those strings. This removes a significant static detection surface: IAT inspection, import-based YARA rules, and AV signatures keyed on specific API imports no longer match.

---

### Linux — full build (`make full`)

Combines evasive + polymorphic in a single target:

```bash
make full
```

Execution order: `make_evasive.py` (dynamic API resolution) -> clang LTO compilation -> `poly_patch.py` (DOS stub + timestamp randomization).

This is the maximum output: no standard IAT entries, no symbols, no unwind tables, no compiler fingerprints, different SHA256 on every build.

---

## Usage

SYSTEMatic requires an elevated Administrator session. Run from an elevated `cmd.exe` or PowerShell prompt.

```
SYSTEMatic.exe [OPTIONS] [COMMAND]
```

### Options

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Print usage and exit |
| `--logon-profile` | Load SYSTEM's user profile (`LOGON_WITH_PROFILE`). Default: `LOGON_NETCREDENTIALS_ONLY` |
| `COMMAND` | Process to spawn as SYSTEM. Accepts a name resolvable via `%PATH%` or a full path. Default: `cmd.exe` (resolved via `ExpandEnvironmentStringsW` on `%SystemRoot%\System32\cmd.exe`) |

### Examples

```cmd
REM Default: open a SYSTEM cmd.exe shell
SYSTEMatic.exe

REM Spawn PowerShell as SYSTEM
SYSTEMatic.exe powershell.exe

REM Full path to avoid PATH resolution
SYSTEMatic.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

REM Load the full SYSTEM profile (HKCU, %USERPROFILE%, machine account network auth)
SYSTEMatic.exe --logon-profile powershell.exe

REM Verify the result
whoami
REM -> nt authority\system
```

**Expected output:**

```
[+] Process launched as NT AUTHORITY\SYSTEM: C:\Windows\System32\cmd.exe
```

A new console window opens running as `NT AUTHORITY\SYSTEM`. The parent process exits cleanly.

---

## Windows API reference

| API | Usage |
|-----|-------|
| `IsUserAnAdmin()` | Verify caller has Administrator rights before proceeding |
| `OpenProcessToken(TOKEN_ADJUST_PRIVILEGES \| TOKEN_QUERY)` | Open the current process token for privilege adjustment |
| `LookupPrivilegeValueW()` | Resolve the LUID for `SeDebugPrivilege` by name |
| `AdjustTokenPrivileges()` | Enable `SeDebugPrivilege` on the current process token |
| `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` | Take a snapshot of all running processes |
| `Process32FirstW / Process32NextW` | Iterate the process snapshot (wide string variant for Unicode consistency) |
| `OpenProcess(PROCESS_QUERY_INFORMATION)` | Open a process handle -- query only, no memory access |
| `OpenProcessToken(TOKEN_DUPLICATE \| TOKEN_QUERY)` | Obtain a handle to the process's primary token |
| `GetTokenInformation(TokenUser)` | Retrieve the SID of the token's owner |
| `AllocateAndInitializeSid(SECURITY_LOCAL_SYSTEM_RID)` | Build the well-known SID for `NT AUTHORITY\SYSTEM` (`S-1-5-18`) |
| `EqualSid()` | Compare the token's owner SID against the SYSTEM SID |
| `DuplicateTokenEx(TOKEN_ALL_ACCESS, TokenPrimary)` | Clone the SYSTEM token as a primary token usable by `CreateProcessWithTokenW` |
| `ExpandEnvironmentStringsW()` | Resolve `%SystemRoot%\System32\cmd.exe` at runtime |
| `CreateProcessWithTokenW()` | Spawn a process under the duplicated SYSTEM token (primary path) |
| `OpenProcess(PROCESS_CREATE_PROCESS)` | Open a SYSTEM process handle for parent spoofing (fallback path) |
| `InitializeProcThreadAttributeList()` | Allocate and initialize a process attribute list (parent spoof) |
| `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)` | Set the spoofed parent process in the attribute list |
| `DeleteProcThreadAttributeList()` | Release the attribute list after process creation |
| `CreateProcessW(EXTENDED_STARTUPINFO_PRESENT)` | Spawn the process with spoofed parent, inheriting SYSTEM token (fallback path) |

All handles are closed on every code path (success and error). Memory allocated with `HeapAlloc` is freed with `HeapFree` before returning. `FormatMessage` buffers allocated with `FORMAT_MESSAGE_ALLOCATE_BUFFER` are released with `LocalFree`.

---

## Legal disclaimer

SYSTEMatic is provided for security research, education, and authorized penetration testing only.

Use of this tool against systems for which you do not have explicit written authorization is illegal and may result in criminal and civil penalties. The author accepts no responsibility for misuse.

By using SYSTEMatic, you confirm that you have the legal right to do so on the systems you are targeting.

---

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
