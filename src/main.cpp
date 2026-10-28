// ConsentMonitor — main.cpp
// Application entry point.
// Platform: 64-bit Windows 11 (25H2/26H2).
// User-mode only, visible consent controls, allowlisted diagnostics only.

#include <consent_monitor/common.hpp>
#include <consent_monitor/consent_manager.hpp>
#include <consent_monitor/event_pipeline.hpp>
#include <consent_monitor/event_schema.hpp>
#include <consent_monitor/win32_security.hpp>
#include <consent_monitor/win32_window.hpp>

#include <iostream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int main() {
    using namespace consent_monitor;

    std::cout << kAppName << " v" << kAppVersion << " starting...\n";
    std::cout << "Target baseline: " << kSupportedOS << "\n";

#ifdef _WIN32
    // 1. Single-writer mutex verification
    auto sid_r = Win32Security::GetCurrentUserSid();
    if (!sid_r.ok) {
        std::cerr << "Failed to obtain current user SID: " << sid_r.error << "\n";
        return 1;
    }

    std::string mutex_name = "Global\\ConsentMonitor_Writer_" + sid_r.value;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, mutex_name.c_str(), -1, NULL, 0);
    std::wstring wname(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, mutex_name.c_str(), -1, &wname[0], wlen);

    HANDLE hMutex = CreateMutexW(NULL, TRUE, wname.c_str());
    if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cerr << "Another instance of ConsentMonitor is already running for this user.\n";
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }
#endif

    // 2. Initialize Core Components
    ConsentManager cm;
    EventPipeline pipeline(cm);

    // Record application start diagnostic event
    auto start_evt = create_event(EventType::AppStart, "success", 0);
    if (start_evt.ok) {
        pipeline.Enqueue(start_evt.value);
    }

    // 3. Launch GUI
    Win32Window window(cm, pipeline);
    int exit_code = window.Run();

    // Record application stop diagnostic event
    auto stop_evt = create_event(EventType::AppStop, "clean_exit", 0);
    if (stop_evt.ok) {
        pipeline.Enqueue(stop_evt.value);
    }

#ifdef _WIN32
    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
#endif

    std::cout << kAppName << " exited with code " << exit_code << ".\n";
    return exit_code;
}
