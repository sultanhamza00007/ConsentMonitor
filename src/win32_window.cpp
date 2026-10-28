// ConsentMonitor — win32_window.cpp
// Native Win32 GUI window with visible consent controls and status disclosure.

#include <consent_monitor/win32_window.hpp>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

namespace consent_monitor {

// Control IDs
constexpr int IDC_BTN_START  = 101;
constexpr int IDC_BTN_PAUSE  = 102;
constexpr int IDC_BTN_RESUME = 103;
constexpr int IDC_BTN_REVOKE = 104;
constexpr int IDC_EDIT_URL   = 105;
constexpr int IDC_LBL_STATUS = 106;
constexpr int IDC_LBL_LOCAL  = 107;
constexpr int IDC_LBL_EGRESS = 108;

Win32Window::Win32Window(ConsentManager& cm, EventPipeline& pipeline)
    : cm_(cm), pipeline_(pipeline) {}

Win32Window::~Win32Window() = default;

std::string Win32Window::GetEndpointUrl() const {
    return endpoint_url_;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* self = reinterpret_cast<Win32Window*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (msg) {
        case WM_CREATE: {
            // Title and local storage disclosure
            CreateWindowW(L"STATIC",
                L"Local Diagnostic Logging: Diagnostic events stored in %LOCALAPPDATA%\\ConsentMonitor\\Logs.\n"
                L"Owner: Current User. Bounded: 20 MiB ceiling. No keystrokes or user data collected.",
                WS_VISIBLE | WS_CHILD, 20, 20, 560, 45, hwnd, (HMENU)IDC_LBL_LOCAL, NULL, NULL);

            // Network consent and endpoint review
            CreateWindowW(L"STATIC",
                L"HTTPS Egress Endpoint (must review and enter manually; no default configured):",
                WS_VISIBLE | WS_CHILD, 20, 75, 560, 20, hwnd, NULL, NULL, NULL);

            CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
                20, 100, 560, 24, hwnd, (HMENU)IDC_EDIT_URL, NULL, NULL);

            // Action Buttons
            CreateWindowW(L"BUTTON", L"Grant & Start",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                20, 140, 120, 32, hwnd, (HMENU)IDC_BTN_START, NULL, NULL);

            CreateWindowW(L"BUTTON", L"Pause",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                150, 140, 100, 32, hwnd, (HMENU)IDC_BTN_PAUSE, NULL, NULL);

            CreateWindowW(L"BUTTON", L"Resume",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                260, 140, 100, 32, hwnd, (HMENU)IDC_BTN_RESUME, NULL, NULL);

            CreateWindowW(L"BUTTON", L"Revoke Consent",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                370, 140, 140, 32, hwnd, (HMENU)IDC_BTN_REVOKE, NULL, NULL);

            // Status label
            CreateWindowW(L"STATIC", L"Status: No consent granted.",
                WS_VISIBLE | WS_CHILD, 20, 190, 560, 40, hwnd, (HMENU)IDC_LBL_STATUS, NULL, NULL);

            SetTimer(hwnd, 1, 200, NULL); // Periodic status refresh timer
            return 0;
        }

        case WM_COMMAND: {
            if (!self) break;
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case IDC_BTN_START: {
                    // Read endpoint from EDIT box
                    wchar_t buf[512] = {0};
                    int chars_read = GetDlgItemTextW(hwnd, IDC_EDIT_URL, buf, 512);
                    std::string url;
                    if (chars_read > 0) {
                        int utf8_len = WideCharToMultiByte(CP_UTF8, 0, buf, chars_read, NULL, 0, NULL, NULL);
                        if (utf8_len > 0) {
                            url.resize(utf8_len);
                            WideCharToMultiByte(CP_UTF8, 0, buf, chars_read, &url[0], utf8_len, NULL, NULL);
                        }
                    }

                    // User must enter and review HTTPS endpoint
                    if (url.empty() || url.rfind("https://", 0) != 0) {
                        SetDlgItemTextW(hwnd, IDC_LBL_STATUS,
                            L"Error: You must enter and review a valid HTTPS endpoint (https://...) before granting consent.");
                        break;
                    }

                    self->endpoint_url_ = url;
                    self->cm_.GrantConsent();
                    break;
                }
                case IDC_BTN_PAUSE:
                    self->cm_.PauseMonitoring();
                    break;
                case IDC_BTN_RESUME:
                    self->cm_.ResumeMonitoring();
                    break;
                case IDC_BTN_REVOKE:
                    self->cm_.RevokeConsent();
                    self->pipeline_.DiscardAll();
                    break;
            }
            return 0;
        }

        case WM_TIMER: {
            if (self) {
                std::string status = "Status: " + self->cm_.GetStatusMessage();
                int wlen = MultiByteToWideChar(CP_UTF8, 0, status.c_str(), -1, NULL, 0);
                std::wstring wstatus(wlen, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, status.c_str(), -1, &wstatus[0], wlen);
                SetDlgItemTextW(hwnd, IDC_LBL_STATUS, wstatus.c_str());
            }
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int Win32Window::Run() {
    HINSTANCE hInstance = GetModuleHandle(NULL);
    const wchar_t CLASS_NAME[] = L"ConsentMonitorWindowClass";

    WNDCLASSW wc{};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(
        0, CLASS_NAME, L"ConsentMonitor — Consent & Diagnostics Control",
        WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 620, 290,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) return 1;

    SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

} // namespace consent_monitor

#else // Non-Windows (Linux build / testing)

namespace consent_monitor {

Win32Window::Win32Window(ConsentManager& cm, EventPipeline& pipeline)
    : cm_(cm), pipeline_(pipeline) {}
Win32Window::~Win32Window() = default;

std::string Win32Window::GetEndpointUrl() const { return {}; }
int Win32Window::Run() { return 0; }

} // namespace consent_monitor

#endif
