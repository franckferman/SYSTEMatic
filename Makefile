# SYSTEMatic -- Makefile
#
# Windows (nmake + cl.exe):
#   Requirements : MSVC Build Tools -- cl.exe in PATH
#   Install      : https://visualstudio.microsoft.com/visual-cpp-build-tools/
#   Setup env    : run "x64 Native Tools Command Prompt" or vcvarsall.bat x64
#   Build        : nmake
#   Clean        : nmake clean
#
# Linux -- gcc cross-compile (MinGW-w64):
#   Requirements : make install-deps  (or: sudo apt install gcc-mingw-w64-x86-64)
#   Build        : make linux
#   Clean        : make clean-linux
#
# Linux -- clang cross-compile with LTO (llvm-mingw, auto-downloaded):
#   Requirements : wget, tar (auto-downloads llvm-mingw on first run)
#   Build        : make obfuscate
#   Clean        : make clean-obfuscate
#   Custom path  : make obfuscate LLVM_MINGW=/path/to/llvm-mingw

# --- Windows (MSVC / nmake) ---
CC     = cl.exe
CFLAGS = /nologo /W3 /sdl /Ox /Oi /Oy /GL /MT /guard:cf /DUNICODE /D_UNICODE
LIBS   = advapi32.lib shell32.lib
LFLAGS = /LTCG /DYNAMICBASE /NXCOMPAT /OPT:REF /OPT:ICF
OUT    = SYSTEMatic.exe
SRCS   = src\main.c src\token.c src\process.c src\error.c

all: $(OUT)

$(OUT): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) /Fe:$(OUT) /link $(LIBS) $(LFLAGS)

clean:
	-del /Q $(OUT) *.obj 2>nul

# --- Linux cross-compile (MinGW-w64 / gcc) ---
CC_LINUX     = x86_64-w64-mingw32-gcc
CFLAGS_LINUX = -O3 -flto \
               -ffunction-sections -fdata-sections \
               -fno-ident \
               -fno-asynchronous-unwind-tables -fno-unwind-tables \
               -fomit-frame-pointer \
               -DUNICODE -D_UNICODE -municode
LFLAGS_LINUX = -static \
               -Wl,--strip-all \
               -Wl,--gc-sections \
               -Wl,--no-insert-timestamp
LIBS_LINUX   = -ladvapi32 -lshell32
SRCS_LINUX   = src/main.c src/token.c src/process.c src/error.c

linux: $(SRCS_LINUX)
	$(CC_LINUX) $(CFLAGS_LINUX) $(SRCS_LINUX) $(LFLAGS_LINUX) -o SYSTEMatic.exe $(LIBS_LINUX)

install-deps:
	sudo apt install -y gcc-mingw-w64-x86-64

clean-linux:
	rm -f SYSTEMatic.exe *.o

# --- Linux cross-compile with clang/LTO (llvm-mingw, auto-downloaded) ---
LLVM_MINGW_VERSION = 20260311
LLVM_MINGW_ARCHIVE = llvm-mingw-$(LLVM_MINGW_VERSION)-ucrt-ubuntu-22.04-x86_64
LLVM_MINGW_URL     = https://github.com/mstorsjo/llvm-mingw/releases/download/$(LLVM_MINGW_VERSION)/$(LLVM_MINGW_ARCHIVE).tar.xz
LLVM_MINGW        ?= $(HOME)/llvm-mingw
CC_OBF             = $(LLVM_MINGW)/bin/x86_64-w64-mingw32-clang
CFLAGS_OBF         = -O3 -flto=full \
                     -ffunction-sections -fdata-sections \
                     -fno-ident \
                     -fno-asynchronous-unwind-tables -fno-unwind-tables \
                     -fomit-frame-pointer \
                     -fmerge-all-constants \
                     -DUNICODE -D_UNICODE -municode
LFLAGS_OBF         = -static \
                     -fuse-ld=lld \
                     -Wl,--strip-all \
                     -Wl,--gc-sections \
                     -Wl,--no-insert-timestamp \
                     -Wl,--icf=all
LIBS_OBF           = -ladvapi32 -lshell32
SRCS_OBF           = src/main.c src/token.c src/process.c src/error.c

# Auto-download llvm-mingw if not present -- used as a Make prerequisite via the binary path
$(CC_OBF):
	@echo "[*] llvm-mingw not found at $(LLVM_MINGW) -- downloading..."
	@wget -q --show-progress $(LLVM_MINGW_URL) -O /tmp/$(LLVM_MINGW_ARCHIVE).tar.xz
	@tar xf /tmp/$(LLVM_MINGW_ARCHIVE).tar.xz -C $(HOME)
	@mv $(HOME)/$(LLVM_MINGW_ARCHIVE) $(LLVM_MINGW)
	@rm /tmp/$(LLVM_MINGW_ARCHIVE).tar.xz
	@echo "[+] llvm-mingw installed at $(LLVM_MINGW)"

obfuscate: $(CC_OBF) $(SRCS_OBF)
	$(CC_OBF) $(CFLAGS_OBF) $(SRCS_OBF) $(LFLAGS_OBF) -o SYSTEMatic.exe $(LIBS_OBF)

# make polymorphic -- obfuscate + unique binary on every build:
#   - random seed passed to clang (affects register allocation / scheduling)
#   - post-build PE patcher: randomizes DOS stub + COFF timestamp
#     -> different SHA256 on every run, breaks hash-based AV detections
polymorphic: $(CC_OBF) $(SRCS_OBF)
	$(CC_OBF) $(CFLAGS_OBF) $(SRCS_OBF) $(LFLAGS_OBF) -o SYSTEMatic.exe $(LIBS_OBF)
	python3 scripts/poly_patch.py SYSTEMatic.exe

clean-obfuscate:
	rm -f SYSTEMatic.exe *.o

# --- Evasive build: dynamic API resolution (no advapi32/shell32 in IAT, kernel32 partial) ---
# make evasive   -- clang LTO + GetProcAddress for all advapi32/shell32 + selected kernel32 imports
# make full      -- evasive + polymorphic PE patcher (maximum)
CC_EV     = $(CC_OBF)
CFLAGS_EV = $(CFLAGS_OBF)
LFLAGS_EV = $(LFLAGS_OBF)

evasive: $(CC_OBF) $(SRCS_OBF)
	CC_EV="$(CC_EV)" CFLAGS_EV="$(CFLAGS_EV)" LFLAGS_EV="$(LFLAGS_EV)" \
	    python3 scripts/make_evasive.py

full: $(CC_OBF) $(SRCS_OBF)
	CC_EV="$(CC_EV)" CFLAGS_EV="$(CFLAGS_EV)" LFLAGS_EV="$(LFLAGS_EV)" \
	    python3 scripts/make_evasive.py
	python3 scripts/poly_patch.py SYSTEMatic.exe

clean-evasive:
	rm -f SYSTEMatic.exe *.o

.PHONY: all linux obfuscate polymorphic evasive full install-deps clean clean-linux clean-obfuscate clean-evasive
