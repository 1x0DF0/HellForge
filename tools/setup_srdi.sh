#!/usr/bin/env bash
# setup_srdi.sh — build sRDI toolchain for LoaderBuilder DLL input mode
#
# Produces:
#   tools/sRDI_builder          — Linux ELF that converts a DLL to sRDI shellcode
#   tools/reflective_loader.dll — x64 Windows DLL with the reflective loader stub
#
# Requires: Rust toolchain + cross targets
#   rustup target add x86_64-pc-windows-gnu
#   cargo install cross   (optional, for musl builds)
#
# Reference: https://github.com/monoxgas/sRDI

set -e
TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
SRDI_REPO="$TOOLS_DIR/.srdi_src"

if [ ! -d "$SRDI_REPO" ]; then
    git clone https://github.com/monoxgas/sRDI "$SRDI_REPO"
fi

cd "$SRDI_REPO"

# Build the Python-based converter as a self-contained native binary via PyInstaller,
# or build a Rust reimplementation if available.
# Fallback: use the Python tool directly.

if command -v pyinstaller >/dev/null 2>&1; then
    pip install pefile
    pyinstaller --onefile Python/ShellcodeRDI.py -n sRDI_builder \
        --distpath "$TOOLS_DIR"
    echo "[+] sRDI_builder -> $TOOLS_DIR/sRDI_builder"
else
    echo "[!] pyinstaller not found. Install it: pip install pyinstaller"
    echo "    Alternatively, run the Python tool directly:"
    echo "    python3 $SRDI_REPO/Python/ShellcodeRDI.py --help"
    echo ""
    echo "    And update build.c to call python3 instead of tools/sRDI_builder."
fi

# Build reflective loader DLL (x64 Windows, MinGW)
LOADER_SRC="$SRDI_REPO/dll/src/ReflectiveDLLInjection.c"
if [ -f "$LOADER_SRC" ]; then
    x86_64-w64-mingw32-gcc -O2 -shared -o "$TOOLS_DIR/reflective_loader.dll" \
        "$LOADER_SRC" -lkernel32 -lntdll
    echo "[+] reflective_loader.dll -> $TOOLS_DIR/reflective_loader.dll"
else
    echo "[!] Loader source not found at $LOADER_SRC"
    echo "    Check the sRDI repo structure and adjust path."
fi
