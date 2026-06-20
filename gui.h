#pragma once

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0600

#include <windows.h>
#ifndef EM_SETCUEBANNER
#define EM_SETCUEBANNER 0x1501
#endif
#include <commdlg.h>
#include <stdio.h>
#include <wchar.h>
#include <ctype.h>
#include <stdlib.h>

/* Control IDs — main window */
#define ID_BROWSE       101
#define ID_BUILD        102
#define ID_CLEAR        103
#define ID_CHKAA        104
#define ID_CHKDBG       105
#define ID_RADIO_SC     107
#define ID_RADIO_DLL    108
#define ID_RADIO_MAP    109
#define ID_RADIO_EARLY  110
#define ID_CHKETW       111
#define ID_CHKUNHOOK    112
#define ID_CHKSLP       113
#define ID_GEN_PAYLOAD  114

/* Control IDs — generator dialog */
#define DLG_COMBO    201
#define DLG_LHOST    202
#define DLG_LPORT    203
#define DLG_RUN      204
#define DLG_CANCEL   205
#define DLG_STATUS   206

/* Private window messages */
#define WM_APPEND_LOG  (WM_APP + 1)   /* lParam = heap WCHAR*, freed by handler */
#define WM_BUILD_DONE  (WM_APP + 2)   /* wParam = exit code                     */
#define WM_GEN_DONE    (WM_APP + 3)   /* wParam = exit code                     */

/* Control handles — main window */
extern HWND g_hFile;
extern HWND g_hBtnBrowse;
extern HWND g_hBtnGen;
extern HWND g_hRadioSC,    g_hRadioDLL;
extern HWND g_hRadioMap,   g_hRadioEarly;
extern HWND g_hInjectLabel, g_hInjectField;
extern HWND g_hChkAA,      g_hChkDbg;
extern HWND g_hChkEtw,     g_hChkUnhook,  g_hChkSlp;
extern HWND g_hSleepMs;
extern HWND g_hOutput;
extern HWND g_hBtnBuild;
extern HWND g_hLog;

/* Control handles — generator dialog */
extern HWND g_hDlg;
extern HWND g_hDlgStatus;
extern HWND g_hDlgCombo;
extern HWND g_hDlgLhost;
extern HWND g_hDlgLport;
extern HWND g_hDlgRun;

/* Shared state */
extern HANDLE g_hGenProcess;
extern BOOL   g_bNativeBuild;
extern BOOL   g_bNativeMsf;
extern WCHAR  g_sGenOutWin[MAX_PATH];

/* Payload list (defined in gui_gen.c) */
extern const WCHAR *g_payloadTypes[];

/* Prototypes */
void             AppendLog(const WCHAR *text);
void             win_to_wsl(const WCHAR *win, char *out, int outlen);
BOOL             FindNativeMsf(void);
BOOL             PayloadNeedsConn(const WCHAR *p);
void             ShowGenPayloadDialog(HWND parent);
void             OnBuild(HWND hwnd);
void             OnBrowse(HWND hwnd);
void             UpdateInjectRow(void);
void             CreateControls(HWND hwnd);
void             ResizeLog(HWND hwnd);
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
LRESULT CALLBACK GenDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
