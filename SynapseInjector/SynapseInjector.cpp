#define UNICODE
#include <windows.h>
#include <commctrl.h>
#include <ShlObj.h>
#include <string>
#include <vector>
#include <algorithm>
#include <set>
#include "Injector.h"

// Link required libraries
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Comctl32.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Control and Message IDs
#define IDC_PROCESS_COMBO 101
#define IDC_REFRESH_BTN 102
#define IDC_DLL_PATH_EDIT 103
#define IDC_BROWSE_BTN 104
#define IDC_INJECT_BTN 105
#define IDC_CONSOLE_EDIT 106
#define IDC_STATUS_BAR 107
#define ID_TIMER_REFRESH 108

// Global Handles and State
HWND g_hProcessCombo, g_hDllPathEdit, g_hInjectBtn, g_hConsole, g_hStatusBar;
HFONT g_hFont = NULL;
static std::vector<std::wstring> g_allProcessNames;

// Forward Declarations
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateLayout(HWND hwnd, int dpi);
void AddLogMessage(const std::wstring& msg);
void PopulateProcessList();
void ApplyProcessFilter();
void OnDpiChanged(HWND hwnd, int newDpi);

// Main Entry Point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    if (!IsUserAnAdmin()) {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.lpVerb = L"runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;
            if (!ShellExecuteEx(&sei)) {
                MessageBox(NULL, L"This application requires administrator privileges.", L"Error", MB_OK | MB_ICONERROR);
            }
        }
        return 0;
    }

    Injector::EnableDebugPrivilege();

    WNDCLASSEX wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"ModernInjectorWindowClass";
    wc.hIcon = LoadIcon(hInstance, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(hInstance, IDI_APPLICATION);
    RegisterClassEx(&wc);

    DWORD dwStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    HWND hwnd = CreateWindowEx(
        0, wc.lpszClassName, L"Synapse Injector", dwStyle,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, hInstance, NULL
    );

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG Msg;
    while (GetMessage(&Msg, NULL, 0, 0) > 0) {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }
    return static_cast<int>(Msg.wParam);
}


// UI Creation and Layout Logic - with corrected scaling
void CreateLayout(HWND hwnd, int dpi) {
    if (g_hFont) DeleteObject(g_hFont);

    NONCLIENTMETRICS ncm = { sizeof(ncm) };
    SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    g_hFont = CreateFontW(MulDiv(-12, dpi, 96), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");

    // --- FIX: Get REAL font metrics instead of approximating ---
    HDC hdc = GetDC(hwnd);
    HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFont);
    TEXTMETRIC tm;
    GetTextMetrics(hdc, &tm);
    SelectObject(hdc, hOldFont);
    ReleaseDC(hwnd, hdc);

    const int fontHeight = tm.tmHeight;
    const int avgCharWidth = tm.tmAveCharWidth;
    // --- End of Fix ---

    // Define layout constants based on the new, accurate metrics
    const int margin = avgCharWidth * 3;
    const int padding = avgCharWidth;
    const int controlHeight = fontHeight + padding; // Ensures controls are tall enough
    const int buttonWidth = avgCharWidth * 16;
    const int labelWidth = avgCharWidth * 18;
    const int ySpacing = fontHeight / 2;
    int currentY = margin;

    const int clientWidth = avgCharWidth * 100;

    EnumChildWindows(hwnd, [](HWND child, LPARAM) { DestroyWindow(child); return TRUE; }, 0);

    // --- Row 1: Process Selection ---
    CreateWindow(L"STATIC", L"Target Process:", WS_VISIBLE | WS_CHILD | SS_RIGHT,
        margin, currentY + padding / 2, labelWidth, controlHeight, hwnd, NULL, NULL, NULL);

    int controlX = margin + labelWidth + padding;
    int controlWidth = clientWidth - controlX - margin - buttonWidth - padding;
    g_hProcessCombo = CreateWindow(WC_COMBOBOX, L"", CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL | WS_VISIBLE | WS_CHILD | WS_TABSTOP,
        controlX, currentY, controlWidth, controlHeight * 10, hwnd, (HMENU)IDC_PROCESS_COMBO, NULL, NULL);

    CreateWindow(WC_BUTTON, L"Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
        controlX + controlWidth + padding, currentY, buttonWidth, controlHeight, hwnd, (HMENU)IDC_REFRESH_BTN, NULL, NULL);

    currentY += controlHeight + ySpacing;

    // --- Row 2: DLL Path ---
    CreateWindow(L"STATIC", L"DLL Path:", WS_VISIBLE | WS_CHILD | SS_RIGHT,
        margin, currentY + padding / 2, labelWidth, controlHeight, hwnd, NULL, NULL, NULL);

    g_hDllPathEdit = CreateWindow(WC_EDIT, L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP,
        controlX, currentY, controlWidth, controlHeight, hwnd, (HMENU)IDC_DLL_PATH_EDIT, NULL, NULL);

    CreateWindow(WC_BUTTON, L"Browse...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
        controlX + controlWidth + padding, currentY, buttonWidth, controlHeight, hwnd, (HMENU)IDC_BROWSE_BTN, NULL, NULL);

    currentY += controlHeight + margin;

    // --- Row 3: Inject Button ---
    g_hInjectBtn = CreateWindow(WC_BUTTON, L"INJECT", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
        margin, currentY, clientWidth - margin * 2, controlHeight + padding, hwnd, (HMENU)IDC_INJECT_BTN, NULL, NULL);

    currentY += controlHeight + padding + ySpacing;

    // --- Row 4: Console Output ---
    int consoleHeight = fontHeight * 10;
    g_hConsole = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, L"", WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        margin, currentY, clientWidth - margin * 2, consoleHeight, hwnd, (HMENU)IDC_CONSOLE_EDIT, NULL, NULL);

    currentY += consoleHeight;

    // --- Finalize Layout ---
    g_hStatusBar = CreateWindow(STATUSCLASSNAME, L"Ready", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS_BAR, NULL, NULL);

    int statusBarHeight = controlHeight + padding;
    int clientHeight = currentY + margin + statusBarHeight;
    RECT windowRect = { 0, 0, clientWidth, clientHeight };
    AdjustWindowRect(&windowRect, GetWindowLong(hwnd, GWL_STYLE), FALSE);

    int windowWidth = windowRect.right - windowRect.left;
    int windowHeight = windowRect.bottom - windowRect.top;

    SetWindowPos(hwnd, NULL, 0, 0, windowWidth, windowHeight, SWP_NOMOVE | SWP_NOZORDER);

    EnumChildWindows(hwnd, [](HWND child, LPARAM font) {
        SendMessage(child, WM_SETFONT, (WPARAM)font, TRUE);
        return TRUE;
        }, (LPARAM)g_hFont);
}


void OnDpiChanged(HWND hwnd, int newDpi) {
    CreateLayout(hwnd, newDpi);
    // After recreating the layout, which sets its own ideal size,
    // we need to center the newly resized window.
    RECT rcWindow;
    GetWindowRect(hwnd, &rcWindow);
    int width = rcWindow.right - rcWindow.left;
    int height = rcWindow.bottom - rcWindow.top;

    // Get monitor info for the current cursor position
    POINT pt;
    GetCursorPos(&pt);
    HMONITOR hMonitor = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
    MONITORINFO mi = { sizeof(mi) };
    GetMonitorInfo(hMonitor, &mi);

    int x = mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - width) / 2;
    int y = mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - height) / 2;

    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}


LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        int dpi = GetDpiForWindow(hwnd);
        CreateLayout(hwnd, dpi);
        OnDpiChanged(hwnd, dpi); // Center the initial window
        PopulateProcessList();
        SetTimer(hwnd, ID_TIMER_REFRESH, 5000, NULL);
        AddLogMessage(L"Synapse Injector initialized. Ready to inject.");
        break;
    }

    case WM_DPICHANGED: {
        OnDpiChanged(hwnd, HIWORD(wParam));
        break;
    }

    case WM_COMMAND: {
        if (HIWORD(wParam) == CBN_EDITCHANGE && LOWORD(wParam) == IDC_PROCESS_COMBO) {
            ApplyProcessFilter();
            return 0;
        }

        switch (LOWORD(wParam)) {
        case IDC_REFRESH_BTN:
            PopulateProcessList();
            break;

        case IDC_BROWSE_BTN: {
            wchar_t filePath[MAX_PATH] = { 0 };
            OPENFILENAME ofn = { 0 };
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = filePath;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
            if (GetOpenFileName(&ofn)) {
                SetWindowText(g_hDllPathEdit, filePath);
            }
            break;
        }

        case IDC_INJECT_BTN: {
            wchar_t processName[MAX_PATH], dllPath[MAX_PATH];
            GetWindowText(g_hProcessCombo, processName, MAX_PATH);
            GetWindowText(g_hDllPathEdit, dllPath, MAX_PATH);

            if (wcslen(processName) == 0 || wcslen(dllPath) == 0) {
                AddLogMessage(L"Error: Please specify a process and a DLL path.");
                break;
            }

            std::wstring dllName = dllPath;
            size_t pos = dllName.find_last_of(L"\\/");
            if (pos != std::wstring::npos) dllName = dllName.substr(pos + 1);

            AddLogMessage(L"Attempting to inject " + dllName + L" into " + processName + L"...");
            SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Injecting...");
            EnableWindow(g_hInjectBtn, FALSE);

            try {
                DWORD pid = Injector::GetProcessIdByName(processName);
                if (pid == 0) throw std::runtime_error("Process not found.");
                Injector::Inject(pid, dllPath);
                AddLogMessage(L"SUCCESS: Injected into " + std::wstring(processName) + L" (PID: " + std::to_wstring(pid) + L")");
                SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Injection successful.");
            }
            catch (const std::runtime_error& e) {
                std::string errorMsg = e.what();
                std::wstring wErrorMsg(errorMsg.begin(), errorMsg.end());
                AddLogMessage(L"ERROR: " + wErrorMsg);
                SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Injection failed.");
            }
            EnableWindow(g_hInjectBtn, TRUE);
            break;
        }
        }
        break;
    }

    case WM_TIMER:
        if (wParam == ID_TIMER_REFRESH) PopulateProcessList();
        break;

    case WM_DESTROY: {
        if (g_hFont) DeleteObject(g_hFont);
        PostQuitMessage(0);
        break;
    }

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}


void AddLogMessage(const std::wstring& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestamp[100];
    wsprintf(timestamp, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);

    std::wstring fullMsg = timestamp + msg + L"\r\n";

    int len = GetWindowTextLength(g_hConsole);
    SendMessage(g_hConsole, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(g_hConsole, EM_REPLACESEL, 0, (LPARAM)fullMsg.c_str());
}

void ApplyProcessFilter() {
    wchar_t searchText[MAX_PATH];
    GetWindowText(g_hProcessCombo, searchText, MAX_PATH);

    std::wstring filter(searchText);
    std::transform(filter.begin(), filter.end(), filter.begin(), ::towlower);

    SendMessage(g_hProcessCombo, CB_RESETCONTENT, 0, 0);

    for (const auto& processName : g_allProcessNames) {
        std::wstring lowerProcessName = processName;
        std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::towlower);

        if (filter.empty() || lowerProcessName.find(filter) == 0) {
            SendMessage(g_hProcessCombo, CB_ADDSTRING, 0, (LPARAM)processName.c_str());
        }
    }

    SetWindowText(g_hProcessCombo, searchText);

    DWORD textLen = (DWORD)wcslen(searchText);
    SendMessage(g_hProcessCombo, CB_SETEDITSEL, 0, MAKELPARAM(textLen, textLen));
}

void PopulateProcessList() {
    std::vector<ProcessInfo> processes = Injector::GetAllProcesses();

    std::set<std::wstring> uniqueNames;
    for (const auto& p : processes) {
        if (p.name.length() > 0) uniqueNames.insert(p.name);
    }

    g_allProcessNames.assign(uniqueNames.begin(), uniqueNames.end());

    ApplyProcessFilter();

    wchar_t statusText[100];
    wsprintf(statusText, L"Found %lu unique processes", static_cast<unsigned long>(g_allProcessNames.size()));
    SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)statusText);
}