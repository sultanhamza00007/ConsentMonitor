// ConsentMonitor — win32_security.hpp
// Windows Security Descriptor (SDDL) generation and verification.
// Platform: 64-bit Windows 11 (25H2/26H2).
// Note: On Linux, SDDL string generation is available for unit testing,
// but NTFS ACL enforcement requires a Windows 11 host.

#pragma once

#include <consent_monitor/common.hpp>
#include <string>

namespace consent_monitor {

// ─── SDDL Security Descriptor Helper ────────────────────────────────────────
class Win32Security {
public:
    /// Construct the canonical SDDL string:
    /// O:<UserSID>D:P(A;OICI;GA;;;<UserSID>)(A;OICI;GA;;;SY)
    /// Owner: Current user
    /// DACL: Protected (SE_DACL_PROTECTED)
    /// ACE 1: Current user - Full Control (GA), Container/Object Inherit (OICI)
    /// ACE 2: SYSTEM - Full Control (GA), Container/Object Inherit (OICI)
    static std::string BuildSddlString(const std::string& user_sid);

    /// Get the current user SID string.
    /// On Windows, queries process token.
    /// On Linux, returns a placeholder mock SID for unit tests.
    static Result<std::string> GetCurrentUserSid();

    /// Verify directory/file ACL on disk via GetNamedSecurityInfoW.
    /// Checks:
    /// 1. Owner matches current user SID
    /// 2. DACL is protected (SE_DACL_PROTECTED)
    /// 3. Exactly 2 ACEs present (User & SYSTEM Full Control)
    /// On Linux, returns failure noting that NTFS ACL verification requires Windows.
    static Result<void> VerifySecurityDescriptor(const std::string& path);
};

} // namespace consent_monitor
