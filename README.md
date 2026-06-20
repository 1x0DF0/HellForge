# HellForge

A configurable Windows x64 shellcode loader builder with EDR evasion features for red team and EDR testing.

> **Authorized use only.** This tool is intended for penetration testers and red teamers operating on systems they own or have explicit written permission to test. Misuse is illegal.

---

Based on [MalDevAcademy](https://maldevacademy.com/) work by [@NUL0x4C](https://github.com/NUL0x4C) and [@mrd0x](https://github.com/mrd0x).

---

## Features

All evasion features are individually toggleable at build time.

**Syscall / Hook Evasion**
- **Hell's Gate** — direct syscalls via PEB walk; extracts SSNs from ntdll exports by hash, bypassing userland hooks
- **NTDLL unhook from disk** — maps a clean ntdll.dll copy via `SEC_IMAGE_NO_EXECUTE` and overwrites the hooked in-memory `.text` section
- **ETW patch** — corrupts `NtTraceEvent` SSN and NOP-patches `EtwEventWrite` to blind Windows telemetry

**Payload Protection**
- **RC4 encryption** — payload encrypted at rest; key obfuscated with XOR + offset scheme, brute-forced at runtime via `HINT_BYTE`
- **API hashing** — all WinAPI calls resolved by Jenkins OAT hash; no plaintext import names in the binary
- **IAT camouflage** — hides suspicious import entries

**Anti-Analysis**
- **Mouse-click monitoring** — requires 6 real mouse clicks before execution proceeds
- **Timing checks** — `NtDelayExecution` delta measurement to detect sandbox time fast-forwarding
- **Self-deletion** — renames binary via NTFS alternate data stream trick and deletes itself on launch

**Sleep Obfuscation**
- **Ekko technique** — encrypts loader memory region while sleeping

**Injection Methods**
- **Section mapping** — `NtCreateSection` / `NtMapViewOfSection` / `NtCreateThreadEx` via direct syscalls
- **Early Bird APC** — spawns a suspended process, queues an APC before the main thread starts
- **Self-injection or remote injection** — target a specific process by name, or inject into the current process

---

## Architecture

```
HellForge/
├── src/                  C loader template (Windows x64, MinGW-w64)
├── hellforge-build/      Rust CLI build orchestrator  ← hfbuild binary
│   └── src/
│       ├── main.rs       arg parsing, build flow, RAII temp dirs
│       ├── crypto.rs     RC4, key obfuscation, rand_bytes
│       ├── codegen.rs    generates loader_config.h + loader_payload.c
│       ├── compiler.rs   MinGW-w64 assemble / compile / link pipeline
│       └── config.rs     BuildConfig struct and CLI usage
├── hellforge-gui/        Rust + egui cross-platform GUI  ← hellforge binary
│   └── src/
│       ├── main.rs       entry point
│       ├── app.rs        egui app state and UI
│       ├── runner.rs     spawns hfbuild, streams stdout/stderr to log
│       ├── msf.rs        msfvenom generation dialog
│       └── types.rs      shared types
├── gui.c                 Native Win32 GUI (Windows only, legacy)
├── hellforge.py          Python / tkinter GUI fallback (Mac / Linux, legacy)
└── tools/
    ├── sRDI_builder      sRDI conversion tool
    ├── reflective_loader.dll
    └── setup_srdi.sh     Builds sRDI tooling
```

`hellforge-build` is the core orchestrator. It reads the raw payload, RC4-encrypts it, generates `loader_config.h` and `loader_payload.c` from the selected options, then invokes MinGW-w64 to cross-compile. The output is always a Windows x64 PE regardless of the host OS.

---

## Requirements

| Dependency | Purpose |
|---|---|
| `x86_64-w64-mingw32-gcc` | Cross-compilation to Windows x64 (required) |
| `msfvenom` | Payload generation via GUI Gen button (optional) |
| `tools/sRDI_builder` + `tools/reflective_loader.dll` | DLL-to-shellcode conversion via sRDI (optional) |

**Install MinGW-w64:**
```sh
# macOS
brew install mingw-w64

# Debian / Ubuntu
sudo apt install mingw-w64
```

**Set up sRDI (optional):**
```sh
bash tools/setup_srdi.sh
```

---

## Build Instructions

### Requirements

```sh
# macOS
brew install mingw-w64 rust

# Debian / Ubuntu
sudo apt install mingw-w64 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build both tools (from project root)

```sh
cargo build --release
# Produces:
#   target/release/hfbuild   — CLI build orchestrator
#   target/release/hellforge  — cross-platform GUI
```

### Run individually

```sh
# CLI only
cargo build --release -p hellforge-build

# GUI only
cargo build --release -p hellforge-gui
```

---

## Usage

### CLI

```
./hfbuild --payload <shellcode.bin> [options]
```

| Flag | Description |
|---|---|
| `--payload <file>` | Raw Windows x64 shellcode (.bin) |
| `--dll <file>` | Windows DLL — converted via sRDI before injection |
| `--target <proc>` | Remote process name to inject into (omit for self-injection) |
| `--inject early-bird` | Use Early Bird APC injection instead of section mapping |
| `--spawn <path>` | Executable to spawn as the Early Bird host process |
| `--no-aa` | Disable anti-analysis checks |
| `--etw-patch` | Patch ETW (`NtTraceEvent` + `EtwEventWrite`) |
| `--unhook` | Unhook ntdll by mapping a clean copy from disk |
| `--sleep-obf` | Enable Ekko sleep obfuscation |
| `--sleep-ms <N>` | Sleep duration in milliseconds (default: 10000) |
| `--debug` | Enable debug output in the compiled loader |
| `--out <name>` | Output filename without `.exe` extension |

Output is written to `./output/`.

**Examples:**

```sh
# Self-injection with ETW patch and ntdll unhook
./hfbuild --payload beacon.bin --etw-patch --unhook --out beacon_loader

# Remote injection into explorer.exe with Early Bird APC and sleep obfuscation
./hfbuild --payload beacon.bin --target explorer.exe --inject early-bird \
          --spawn "C:\\Windows\\System32\\notepad.exe" --sleep-obf --out beacon_loader

# DLL payload via sRDI, self-inject, all evasion on
./hfbuild --dll implant.dll --etw-patch --unhook --sleep-obf --out implant_loader
```

### GUI

**Rust / egui (cross-platform — recommended):**
```sh
cargo run --release -p hellforge-gui
# or place hfbuild and hellforge binaries in the same directory and run hellforge
```

**Python / tkinter (Mac / Linux legacy fallback):**
```sh
python3 hellforge.py
```

**Native Win32 GUI (Windows only, legacy):**
Compile `gui.c` with MinGW-w64 or open in your preferred Windows build environment.

---

## Legal Notice

HellForge is provided for **authorized security testing and EDR validation only**. Use it exclusively on systems you own or have explicit written permission to test. The authors accept no liability for misuse. Unauthorized use against systems you do not own is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in other jurisdictions.
