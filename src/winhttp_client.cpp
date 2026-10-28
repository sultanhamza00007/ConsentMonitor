// ConsentMonitor — winhttp_client.cpp
// Synchronous WinHTTP client with two-stage authorization and response gate.
// Platform: 64-bit Windows 11 (25H2/26H2) with Microsoft Windows SDK.

#include <consent_monitor/winhttp_client.hpp>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace consent_monitor {

WinHttpClient::WinHttpClient(ConsentManager& cm) : consent_mgr_(cm) {}

WinHttpClient::~WinHttpClient() = default;

EgressResult WinHttpClient::Transmit(uint64_t generation,
                                     const std::string& endpoint_url,
                                     const std::string& payload) {
    EgressResult result{};

    // Parse URL into host and path components
    URL_COMPONENTSW urlComp{};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwHostNameLength = static_cast<DWORD>(-1);
    urlComp.dwUrlPathLength  = static_cast<DWORD>(-1);
    urlComp.dwSchemeLength   = static_cast<DWORD>(-1);

    int wide_len = MultiByteToWideChar(CP_UTF8, 0, endpoint_url.c_str(), -1, NULL, 0);
    if (wide_len <= 0) {
        result.outcome = NetworkOutcome::HeaderSendFailed;
        result.error_detail = "Invalid URL encoding";
        return result;
    }
    std::wstring wide_url(wide_len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, endpoint_url.c_str(), -1, &wide_url[0], wide_len);

    if (!WinHttpCrackUrl(wide_url.c_str(), 0, 0, &urlComp)) {
        result.outcome = NetworkOutcome::HeaderSendFailed;
        result.error_detail = "WinHttpCrackUrl failed";
        return result;
    }

    // Require HTTPS scheme explicitly
    if (urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
        result.outcome = NetworkOutcome::TlsConfigFailed;
        result.error_detail = "Insecure scheme: endpoint must use HTTPS";
        return result;
    }

    std::wstring host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    auto cleanup_handles = [&](bool& close_ok) {
        consent_mgr_.RecordPhase(generation, NetworkWorkerPhase::ClosingHandles);
        close_ok = true;
        if (hRequest && !WinHttpCloseHandle(hRequest)) close_ok = false;
        if (hConnect && !WinHttpCloseHandle(hConnect)) close_ok = false;
        if (hSession && !WinHttpCloseHandle(hSession)) close_ok = false;
        hRequest = NULL;
        hConnect = NULL;
        hSession = NULL;
    };

    // 1. Open Session — direct connection without proxy
    hSession = WinHttpOpen(
        L"ConsentMonitor/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) {
        result.outcome = NetworkOutcome::HeaderSendFailed;
        result.error_detail = "WinHttpOpen failed";
        return result;
    }

    // Configure TLS 1.2 as the sole allowed protocol (fail-closed if fails)
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    if (!WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
                          &protocols, sizeof(protocols))) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::TlsConfigFailed;
        result.error_detail = "Failed to configure TLS 1.2 protocol";
        return result;
    }

    // Configure certificate revocation check (fail-closed if fails)
    DWORD certCheck = WINHTTP_ENABLE_SSL_REVOCATION;
    if (!WinHttpSetOption(hSession, WINHTTP_OPTION_ENABLE_FEATURE,
                          &certCheck, sizeof(certCheck))) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::TlsConfigFailed;
        result.error_detail = "Failed to enable SSL certificate revocation check";
        return result;
    }

    // 2. Connect
    INTERNET_PORT port = urlComp.nPort ? urlComp.nPort : INTERNET_DEFAULT_HTTPS_PORT;
    hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::HeaderSendFailed;
        result.error_detail = "WinHttpConnect failed";
        return result;
    }

    // 3. Open Request
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE // HTTPS
    );
    if (!hRequest) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::HeaderSendFailed;
        result.error_detail = "WinHttpOpenRequest failed";
        return result;
    }

    // Disable redirects on the request handle: WINHTTP_OPTION_REDIRECT_POLICY_NEVER (fail-closed if fails)
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY,
                          &redirectPolicy, sizeof(redirectPolicy))) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::HeaderSendFailed;
        result.error_detail = "Failed to enforce redirect policy NEVER on request";
        return result;
    }

    // ── STAGE 1: Header Authorization Point ─────────────────────────────────
    if (!consent_mgr_.TryAuthorizeHeader(generation)) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::RevokedBeforeHeader;
        result.error_detail = "Consent revoked or generation mismatch before headers";
        return result;
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    BOOL send_ok = WinHttpSendRequest(
        hRequest,
        headers.c_str(),
        static_cast<DWORD>(-1),
        WINHTTP_NO_ADDITIONAL_DATA,
        0,
        static_cast<DWORD>(payload.size()),
        0
    );
    consent_mgr_.RecordPhase(generation, NetworkWorkerPhase::HeaderSendInitiated);

    if (!send_ok) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::HeaderSendFailed;
        result.error_detail = "WinHttpSendRequest failed";
        return result;
    }

    // ── STAGE 2: Body Authorization Point ───────────────────────────────────
    if (!consent_mgr_.TryAuthorizeBody(generation)) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::RevokedBeforeBody;
        result.error_detail = "Consent revoked or generation mismatch before body write";
        return result;
    }

    // Buffer remains valid until this synchronous call returns
    DWORD bytesWritten = 0;
    BOOL write_ok = WinHttpWriteData(
        hRequest,
        payload.data(),
        static_cast<DWORD>(payload.size()),
        &bytesWritten
    );
    consent_mgr_.RecordPhase(generation, NetworkWorkerPhase::BodyWriteInitiated);
    result.bytes_written = bytesWritten;

    if (!write_ok || bytesWritten < payload.size()) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::BodyWriteFailed;
        result.error_detail = "WinHttpWriteData failed or short write (no retries)";
        return result;
    }

    // ── STAGE 3: Response Authorization Point ───────────────────────────────
    // If consent is revoked before ReceiveResponse, do NOT await response.
    if (!consent_mgr_.TryAuthorizeResponse(generation)) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::RevokedBeforeResponse;
        result.error_detail = "Consent revoked before response; response not awaited";
        return result;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        bool close_ok = false;
        cleanup_handles(close_ok);
        if (close_ok) consent_mgr_.MarkDrained(generation);
        else consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::ResponseFailed;
        result.error_detail = "WinHttpReceiveResponse failed";
        return result;
    }
    consent_mgr_.RecordPhase(generation, NetworkWorkerPhase::ResponseCompleted);

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusSize,
        WINHTTP_NO_HEADER_INDEX
    );
    result.http_status = statusCode;

    // Normal completion: close handles
    bool close_ok = false;
    cleanup_handles(close_ok);
    if (close_ok) {
        consent_mgr_.MarkDrained(generation);
        result.outcome = NetworkOutcome::Success;
    } else {
        consent_mgr_.MarkDegraded(generation);
        result.outcome = NetworkOutcome::HandleCloseFailed;
        result.error_detail = "Failed to close WinHTTP handles cleanly";
    }

    return result;
}

} // namespace consent_monitor

#else // Non-Windows (Linux build / testing)

namespace consent_monitor {

WinHttpClient::WinHttpClient(ConsentManager& cm) : consent_mgr_(cm) {}
WinHttpClient::~WinHttpClient() = default;

EgressResult WinHttpClient::Transmit(uint64_t generation,
                                     const std::string& /*endpoint_url*/,
                                     const std::string& /*payload*/) {
    (void)generation;
    // On Linux, WinHTTP is unavailable.
    return {NetworkOutcome::HeaderSendFailed, 0, 0, "WinHTTP requires Windows 11 host"};
}

} // namespace consent_monitor

#endif
