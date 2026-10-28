// ConsentMonitor — win32_window.hpp
// Native Win32 GUI window with visible consent controls and status disclosure.
// Platform: 64-bit Windows 11 (25H2/26H2).

#pragma once

#include <consent_monitor/common.hpp>
#include <consent_monitor/consent_manager.hpp>
#include <consent_monitor/event_pipeline.hpp>

#include <string>

namespace consent_monitor {

class Win32Window {
public:
    Win32Window(ConsentManager& cm, EventPipeline& pipeline);
    ~Win32Window();

    /// Run the Win32 message loop.
    /// The UI thread NEVER executes network I/O or closes WinHTTP handles.
    int Run();

    /// Get user-entered HTTPS endpoint. Empty by default.
    std::string GetEndpointUrl() const;

private:
    ConsentManager& cm_;
    EventPipeline&  pipeline_;
    std::string     endpoint_url_;
};

} // namespace consent_monitor
