/*
 * HellForge GUI — main window, global state, entry point
 *
 * Build (MinGW):
 *   x86_64-w64-mingw32-gcc -O2 -DUNICODE -D_UNICODE -mwindows \
 *       -o HellForge.exe gui.c gui_build.c gui_gen.c -lcomdlg32 -luser32 -lgdi32
 */
#include "gui.h"

/* ---- Global definitions ---- */
HWND g_hFile;
HWND g_hBtnBrowse;
HWND g_hBtnGen;
HWND g_hRadioSC,    g_hRadioDLL;
HWND g_hRadioMap,   g_hRadioEarly;
HWND g_hInjectLabel, g_hInjectField;
HWND g_hChkAA,      g_hChkDbg;
HWND g_hChkEtw,     g_hChkUnhook,  g_hChkSlp;
HWND g_hSleepMs;
HWND g_hOutput;
HWND g_hBtnBuild;
HWND g_hLog;

HWND g_hDlg      = NULL;
HWND g_hDlgStatus;
HWND g_hDlgCombo;
HWND g_hDlgLhost;
HWND g_hDlgLport;
HWND g_hDlgRun;

HANDLE g_hGenProcess  = NULL;
BOOL   g_bNativeBuild = FALSE;
BOOL   g_bNativeMsf   = FALSE;
WCHAR  g_sGenOutWin[MAX_PATH];

/* ---- Utilities ---- */

void win_to_wsl(const WCHAR *win, char *out, int outlen) {
    if (win[1] == L':') {
        int pos = snprintf(out, outlen, "/mnt/%c", (char)towlower(win[0]));
        for (int i = 2; win[i] && pos < outlen - 1; i++)
            out[pos++] = (win[i] == L'\\') ? '/' : (char)win[i];
        out[pos] = '\0';
    } else {
        WideCharToMultiByte(CP_UTF8, 0, win, -1, out, outlen, NULL, NULL);
    }
}

void AppendLog(const WCHAR *text) {
    int len = (int)wcslen(text);
    WCHAR *buf = malloc(((size_t)len * 2 + 2) * sizeof(WCHAR));
    if (!buf) return;
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (text[i] == L'\n' && (i == 0 || text[i-1] != L'\r'))
            buf[j++] = L'\r';
        buf[j++] = text[i];
    }
    buf[j] = L'\0';
    int end = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL,      (WPARAM)end, (LPARAM)end);
    SendMessageW(g_hLog, EM_REPLACESEL,  FALSE,        (LPARAM)buf);
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
    free(buf);
}

/* ---- Main window helpers ---- */

void UpdateInjectRow(void) {
    BOOL bEarly = (SendMessageW(g_hRadioEarly, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (bEarly) {
        SetWindowTextW(g_hInjectLabel, L"Spawn:");
        WCHAR buf[8]; GetWindowTextW(g_hInjectField, buf, 8);
        if (!buf[0])
            SetWindowTextW(g_hInjectField, L"C:\\Windows\\System32\\RuntimeBroker.exe");
        SendMessageW(g_hInjectField, EM_SETCUEBANNER, 0, (LPARAM)L"");
    } else {
        SetWindowTextW(g_hInjectLabel, L"Target:");
        SetWindowTextW(g_hInjectField, L"");
        SendMessageW(g_hInjectField, EM_SETCUEBANNER, 0,
                     (LPARAM)L"process name for remote inject (blank = self)");
    }
}

void OnBrowse(HWND hwnd) {
    BOOL bDll = (SendMessageW(g_hRadioDLL, BM_GETCHECK, 0, 0) == BST_CHECKED);
    WCHAR path[MAX_PATH] = {0};
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner   = hwnd;
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrFilter = bDll
        ? L"DLL Files\0*.dll\0All Files\0*.*\0\0"
        : L"Shellcode Binary\0*.bin\0All Files\0*.*\0\0";
    if (GetOpenFileNameW(&ofn))
        SetWindowTextW(g_hFile, path);
}

void CreateControls(HWND hwnd) {
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);
    HFONT font      = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

#define LBL(txt, x, y, w) do {                                                 \
    HWND _h = CreateWindowW(L"STATIC", txt, WS_CHILD|WS_VISIBLE|SS_RIGHT,     \
        x, y, w, 20, hwnd, NULL, hInst, NULL);                                 \
    SendMessageW(_h, WM_SETFONT, (WPARAM)font, TRUE); } while(0)

#define HRULE(y) do {                                                           \
    HWND _h = CreateWindowW(L"STATIC", L"", WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,\
        10, y, 570, 2, hwnd, NULL, hInst, NULL); (void)_h; } while(0)

#define EDIT_H(phwnd, x, y, w) do {                                            \
    *(phwnd) = CreateWindowW(L"EDIT", L"",                                     \
        WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,                          \
        x, y, w, 22, hwnd, NULL, hInst, NULL);                                 \
    SendMessageW(*(phwnd), WM_SETFONT, (WPARAM)font, TRUE); } while(0)

#define BTN(phwnd, txt, x, y, w, h, id) do {                                   \
    *(phwnd) = CreateWindowW(L"BUTTON", txt, WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,\
        x, y, w, h, hwnd, (HMENU)(UINT_PTR)(id), hInst, NULL);                \
    SendMessageW(*(phwnd), WM_SETFONT, (WPARAM)font, TRUE); } while(0)

#define RADIO(phwnd, txt, x, y, w, id, grp) do {                               \
    DWORD _s = WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON|((grp)?WS_GROUP:0);     \
    *(phwnd) = CreateWindowW(L"BUTTON", txt, _s,                               \
        x, y, w, 20, hwnd, (HMENU)(UINT_PTR)(id), hInst, NULL);               \
    SendMessageW(*(phwnd), WM_SETFONT, (WPARAM)font, TRUE); } while(0)

#define CHK(phwnd, txt, x, y, w, id) do {                                      \
    *(phwnd) = CreateWindowW(L"BUTTON", txt, WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,\
        x, y, w, 20, hwnd, (HMENU)(UINT_PTR)(id), hInst, NULL);               \
    SendMessageW(*(phwnd), WM_SETFONT, (WPARAM)font, TRUE); } while(0)

    LBL(L"Mode:", 10, 13, 75);
    RADIO(&g_hRadioSC,  L"Shellcode (.bin)", 90,  10, 140, ID_RADIO_SC,  1);
    RADIO(&g_hRadioDLL, L"DLL (sRDI)",      240,  10, 110, ID_RADIO_DLL, 0);
    SendMessageW(g_hRadioSC, BM_SETCHECK, BST_CHECKED, 0);

    LBL(L"File:", 10, 43, 75);
    EDIT_H(&g_hFile, 90, 40, 270);
    BTN(&g_hBtnBrowse, L"Browse...", 365, 40, 90, 22, ID_BROWSE);
    BTN(&g_hBtnGen,    L"Gen (msf)", 460, 40, 110, 22, ID_GEN_PAYLOAD);

    HRULE(74);

    LBL(L"Inject:", 10, 83, 75);
    RADIO(&g_hRadioMap,   L"Mapping",    90, 80, 100, ID_RADIO_MAP,   1);
    RADIO(&g_hRadioEarly, L"Early Bird", 200, 80, 100, ID_RADIO_EARLY, 0);
    SendMessageW(g_hRadioMap, BM_SETCHECK, BST_CHECKED, 0);

    g_hInjectLabel = CreateWindowW(L"STATIC", L"Target:",
        WS_CHILD|WS_VISIBLE|SS_RIGHT, 10, 113, 75, 20, hwnd, NULL, hInst, NULL);
    SendMessageW(g_hInjectLabel, WM_SETFONT, (WPARAM)font, TRUE);
    EDIT_H(&g_hInjectField, 90, 110, 480);
    SendMessageW(g_hInjectField, EM_SETCUEBANNER, 0,
                 (LPARAM)L"process name for remote inject (blank = self)");

    HRULE(144);

    CHK(&g_hChkAA,     L"Anti-Analysis", 10,  153, 130, ID_CHKAA);
    CHK(&g_hChkEtw,    L"ETW Patch",    155,  153, 110, ID_CHKETW);
    CHK(&g_hChkUnhook, L"Unhook NTDLL", 280,  153, 120, ID_CHKUNHOOK);
    SendMessageW(g_hChkAA, BM_SETCHECK, BST_CHECKED, 0);

    CHK(&g_hChkSlp, L"Sleep Obfuscation", 10, 183, 150, ID_CHKSLP);
    EDIT_H(&g_hSleepMs, 168, 181, 80);
    SendMessageW(g_hSleepMs, EM_SETCUEBANNER, 0, (LPARAM)L"10000");
    {
        HWND _ms = CreateWindowW(L"STATIC", L"ms", WS_CHILD|WS_VISIBLE|SS_LEFT,
            254, 186, 30, 18, hwnd, NULL, hInst, NULL);
        SendMessageW(_ms, WM_SETFONT, (WPARAM)font, TRUE);
    }

    HRULE(215);

    LBL(L"Output:", 10, 225, 75);
    EDIT_H(&g_hOutput, 90, 222, 390);
    SendMessageW(g_hOutput, EM_SETCUEBANNER, 0, (LPARAM)L"loader_<timestamp>");

    CHK(&g_hChkDbg, L"Debug Output", 90, 253, 130, ID_CHKDBG);

    g_hBtnBuild = CreateWindowW(L"BUTTON", L"BUILD",
        WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
        90, 285, 300, 30, hwnd, (HMENU)ID_BUILD, hInst, NULL);
    SendMessageW(g_hBtnBuild, WM_SETFONT, (WPARAM)font, TRUE);

    {
        HWND _cl = CreateWindowW(L"BUTTON", L"Clear Log",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            400, 285, 100, 30, hwnd, (HMENU)ID_CLEAR, hInst, NULL);
        SendMessageW(_cl, WM_SETFONT, (WPARAM)font, TRUE);
    }

    g_hLog = CreateWindowW(L"EDIT", L"",
        WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
        10, 328, 570, 200, hwnd, NULL, hInst, NULL);
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)font, TRUE);

#undef LBL
#undef HRULE
#undef EDIT_H
#undef BTN
#undef RADIO
#undef CHK
}

void ResizeLog(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int h = rc.bottom - 328 - 10;
    if (h < 60) h = 60;
    SetWindowPos(g_hLog, NULL, 10, 328, rc.right - 20, h, SWP_NOZORDER);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        CreateControls(hwnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_BROWSE:     OnBrowse(hwnd);              break;
        case ID_GEN_PAYLOAD: ShowGenPayloadDialog(hwnd); break;
        case ID_BUILD:      OnBuild(hwnd);               break;
        case ID_CLEAR:      SetWindowTextW(g_hLog, L""); break;
        case ID_RADIO_SC:
        case ID_RADIO_DLL:  SetWindowTextW(g_hFile, L""); break;
        case ID_RADIO_MAP:
        case ID_RADIO_EARLY: UpdateInjectRow();           break;
        }
        return 0;

    case WM_APPEND_LOG:
        AppendLog((WCHAR*)lp);
        free((void*)lp);
        return 0;

    case WM_BUILD_DONE:
        EnableWindow(g_hBtnBuild, TRUE);
        AppendLog(wp == 0 ? L"[+] Build succeeded.\r\n" : L"[!] Build failed.\r\n");
        return 0;

    case WM_SIZE:
        ResizeLog(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

#pragma warning(suppress: 28251)
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hPrev; (void)lpCmd;

    WNDCLASSW wc = {
        .style         = CS_HREDRAW | CS_VREDRAW,
        .lpfnWndProc   = WndProc,
        .hInstance     = hInst,
        .hCursor       = LoadCursorW(NULL, IDC_ARROW),
        .hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1),
        .lpszClassName = L"HellForgeGUI",
    };
    if (!RegisterClassW(&wc)) return 1;

    {
        WCHAR exe_w[MAX_PATH], bld_w[MAX_PATH];
        GetModuleFileNameW(NULL, exe_w, MAX_PATH);
        WCHAR *s = wcsrchr(exe_w, L'\\'); if (s) *(s+1) = L'\0';
        swprintf(bld_w, MAX_PATH, L"%sbuild.exe", exe_w);
        g_bNativeBuild = (GetFileAttributesW(bld_w) != INVALID_FILE_ATTRIBUTES);
        g_bNativeMsf   = FindNativeMsf();
    }

    RECT rc = { 0, 0, 590, 560 };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);

    HWND hwnd = CreateWindowW(
        L"HellForgeGUI", L"HellForge  [Windows x64 output only]",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
