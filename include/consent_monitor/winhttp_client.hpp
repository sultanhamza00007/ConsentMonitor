// ConsentMonitor — winhttp_client.hpp
// Synchronous WinHTTP client with two-stage authorization and response gate.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <consent_monitor/common.hpp>
#include <consent_monitor/consent_manager.hpp>

#include <string>
#include <vector>

namespace consent_monitor {

// ─── Network Transmission Result ────────────────────────────────────────────
enum class NetworkOutcome : uint8_t {
    Success,
    RevokedBeforeHeader,
    RevokedBeforeBody,
    RevokedBeforeResponse,
    HeaderSendFailed,
    BodyWriteFailed,
    ResponseFailed,
    TlsConfigFailed,
    HandleCloseFailed
};

struct EgressResult {
    NetworkOutcome outcome;
    uint32_t       http_status = 0;
    size_t         bytes_written = 0;
    std::string    error_detail;
};

// ─── WinHttpClient ──────────────────────────────────────────────────────────
// Operates synchronously on a single dedicated network worker thread.
// The UI thread NEVER calls WinHTTP APIs or closes worker handles.
class WinHttpClient {
public:
    explicit WinHttpClient(ConsentManager& cm);
    ~WinHttpClient();

    // Non-copyable, non-movable
    WinHttpClient(const WinHttpClient&) = delete;
    WinHttpClient& operator=(const WinHttpClient&) = delete;

    /// Transmit a diagnostic batch payload over HTTPS.
    /// The user must explicitly enter and review the endpoint URL.
    /// Direct connection without proxy. No cookies, auth tokens, or credentials.
    /// The buffer remains valid until this synchronous call returns.
    EgressResult Transmit(uint64_t generation,
                          const std::string& endpoint_url,
                          const std::string& payload);

private:
    ConsentManager& consent_mgr_;
};

} // namespace consent_monitor
