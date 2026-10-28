// ConsentMonitor — test_win32_security.cpp
// Unit tests for Win32Security SDDL generation and portable security descriptor logic.
// Note: Actual NTFS ACL enforcement testing requires a Windows 11 host.

#include "test_framework.hpp"
#include <consent_monitor/win32_security.hpp>

using namespace consent_monitor;

int main() {
    cm_test::Suite suite("Win32 Security & SDDL Generation");

    // 1. Canonical SDDL string generation
    suite.add("Canonical SDDL string generation with user SID", [] {
        const std::string sid = "S-1-5-21-1234567890-1234567890-1234567890-1001";
        std::string sddl = Win32Security::BuildSddlString(sid);

        // Canonical format: O:<UserSID>D:P(A;OICI;GA;;;<UserSID>)(A;OICI;GA;;;SY)
        std::string expected = "O:" + sid + "D:P(A;OICI;GA;;;" + sid + ")(A;OICI;GA;;;SY)";
        ASSERT_EQ(sddl, expected);

        // Verify key security attributes in the SDDL string:
        // 1. Owner tag
        ASSERT_TRUE(sddl.rfind("O:" + sid, 0) == 0);
        // 2. Protected DACL (SE_DACL_PROTECTED)
        ASSERT_TRUE(sddl.find("D:P") != std::string::npos);
        // 3. Current user full control (GA = GENERIC_ALL, OICI = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
        ASSERT_TRUE(sddl.find("(A;OICI;GA;;;" + sid + ")") != std::string::npos);
        // 4. SYSTEM full control
        ASSERT_TRUE(sddl.find("(A;OICI;GA;;;SY)") != std::string::npos);
    });

    // 2. Custom SID formatting
    suite.add("SDDL string formatting with custom user SID", [] {
        const std::string custom_sid = "S-1-5-21-999999-888888-777777-500";
        std::string sddl = Win32Security::BuildSddlString(custom_sid);
        std::string expected = "O:" + custom_sid + "D:P(A;OICI;GA;;;" + custom_sid + ")(A;OICI;GA;;;SY)";
        ASSERT_EQ(sddl, expected);
    });

    // 3. Current user SID query
    suite.add("Current user SID query returns valid SID prefix", [] {
        auto sid_result = Win32Security::GetCurrentUserSid();
        ASSERT_TRUE(sid_result.ok);
        ASSERT_FALSE(sid_result.value.empty());
        ASSERT_TRUE(sid_result.value.rfind("S-", 0) == 0);
    });

    // 4. Security descriptor platform boundary check
    suite.add("VerifySecurityDescriptor fails safely on non-Windows platform", [] {
        auto result = Win32Security::VerifySecurityDescriptor("/tmp/test_dir");
#ifndef _WIN32
        ASSERT_FALSE(result.ok);
        ASSERT_TRUE(result.error.find("Windows 11 host") != std::string::npos);
#else
        ASSERT_FALSE(result.ok);
#endif
    });

    return suite.run();
}
