// ConsentMonitor — win32_security.cpp
// Windows Security Descriptor (SDDL) generation and verification.

#include <consent_monitor/win32_security.hpp>

namespace consent_monitor {

std::string Win32Security::BuildSddlString(const std::string& user_sid) {
    // Canonical SDDL format:
    // O:<UserSID>D:P(A;OICI;GA;;;<UserSID>)(A;OICI;GA;;;SY)
    return "O:" + user_sid + "D:P(A;OICI;GA;;;" + user_sid + ")(A;OICI;GA;;;SY)";
}

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

Result<std::string> Win32Security::GetCurrentUserSid() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return Result<std::string>::failure("OpenProcessToken failed");
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return Result<std::string>::failure("GetTokenInformation size query failed");
    }

    std::vector<BYTE> buffer(dwSize);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), dwSize, &dwSize)) {
        CloseHandle(hToken);
        return Result<std::string>::failure("GetTokenInformation failed");
    }
    CloseHandle(hToken);

    TOKEN_USER* pTokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR pStringSid = NULL;
    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &pStringSid)) {
        return Result<std::string>::failure("ConvertSidToStringSidW failed");
    }

    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, pStringSid, -1, NULL, 0, NULL, NULL);
    std::string sid(utf8_len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, pStringSid, -1, &sid[0], utf8_len, NULL, NULL);
    LocalFree(pStringSid);

    return Result<std::string>::success(sid);
}

Result<void> Win32Security::VerifySecurityDescriptor(const std::string& path) {
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, NULL, 0);
    std::wstring wide_path(wide_len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wide_path[0], wide_len);

    PSECURITY_DESCRIPTOR pSD = NULL;
    PSID pOwner = NULL;
    PACL pDacl = NULL;

    DWORD res = GetNamedSecurityInfoW(
        wide_path.c_str(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &pOwner,
        NULL,
        &pDacl,
        NULL,
        &pSD
    );

    if (res != ERROR_SUCCESS) {
        return Result<void>::failure("GetNamedSecurityInfoW failed with error code: "
                                    + std::to_string(res));
    }

    // 1. Verify Owner matches current process user SID
    auto user_sid_r = GetCurrentUserSid();
    if (!user_sid_r.ok) {
        LocalFree(pSD);
        return Result<void>::failure("Failed to query current user SID for comparison");
    }

    PSID pExpectedUserSid = NULL;
    int wuser_len = MultiByteToWideChar(CP_UTF8, 0, user_sid_r.value.c_str(), -1, NULL, 0);
    std::wstring wuser_sid(wuser_len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, user_sid_r.value.c_str(), -1, &wuser_sid[0], wuser_len);
    if (!ConvertStringSidToSidW(wuser_sid.c_str(), &pExpectedUserSid)) {
        LocalFree(pSD);
        return Result<void>::failure("Failed to parse expected user SID");
    }

    if (!pOwner || !EqualSid(pOwner, pExpectedUserSid)) {
        LocalFree(pExpectedUserSid);
        LocalFree(pSD);
        return Result<void>::failure("Security descriptor owner does not match current user SID");
    }
    LocalFree(pExpectedUserSid);

    // 2. Verify protected DACL
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(pSD, &control, &revision)) {
        LocalFree(pSD);
        return Result<void>::failure("GetSecurityDescriptorControl failed");
    }

    if (!(control & SE_DACL_PROTECTED)) {
        LocalFree(pSD);
        return Result<void>::failure("DACL is not protected (SE_DACL_PROTECTED missing)");
    }

    // 3. Verify DACL has exactly 2 ACEs (User and SYSTEM)
    if (!pDacl) {
        LocalFree(pSD);
        return Result<void>::failure("DACL is null");
    }

    ACL_SIZE_INFORMATION aclInfo{};
    if (!GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
        LocalFree(pSD);
        return Result<void>::failure("GetAclInformation failed");
    }

    if (aclInfo.AceCount != 2) {
        LocalFree(pSD);
        return Result<void>::failure("DACL has " + std::to_string(aclInfo.AceCount)
                                    + " ACEs; expected exactly 2 (User and SYSTEM)");
    }

    // Prepare SYSTEM SID (S-1-5-18) for verification
    PSID pSystemSid = NULL;
    if (!ConvertStringSidToSidW(L"S-1-5-18", &pSystemSid)) {
        LocalFree(pSD);
        return Result<void>::failure("Failed to create SYSTEM SID for verification");
    }

    PSID pCurrentUserSid2 = NULL;
    ConvertStringSidToSidW(wuser_sid.c_str(), &pCurrentUserSid2);

    bool found_user_ace = false;
    bool found_system_ace = false;

    for (DWORD i = 0; i < aclInfo.AceCount; ++i) {
        LPVOID pAce = NULL;
        if (GetAce(pDacl, i, &pAce)) {
            ACE_HEADER* pHeader = reinterpret_cast<ACE_HEADER*>(pAce);
            if (pHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE* pAllowed = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAce);
                PSID pAceSid = reinterpret_cast<PSID>(&pAllowed->SidStart);
                if (pCurrentUserSid2 && EqualSid(pAceSid, pCurrentUserSid2)) {
                    found_user_ace = true;
                } else if (pSystemSid && EqualSid(pAceSid, pSystemSid)) {
                    found_system_ace = true;
                }
            }
        }
    }

    if (pSystemSid) LocalFree(pSystemSid);
    if (pCurrentUserSid2) LocalFree(pCurrentUserSid2);
    LocalFree(pSD);

    if (!found_user_ace || !found_system_ace) {
        return Result<void>::failure("DACL does not contain exact required User and SYSTEM ACEs");
    }

    return Result<void>::success();
}

#else // Non-Windows (Linux build / testing)

Result<std::string> Win32Security::GetCurrentUserSid() {
    // Return standard mock user SID for unit testing SDDL string formatting
    return Result<std::string>::success("S-1-5-21-1234567890-1234567890-1234567890-1001");
}

Result<void> Win32Security::VerifySecurityDescriptor(const std::string& /*path*/) {
    return Result<void>::failure(
        "NTFS ACL verification via GetNamedSecurityInfoW requires a Windows 11 host");
}

#endif

} // namespace consent_monitor
