// ConsentMonitor — consent_manager.hpp
// Consent state machine with generational tracking and network worker phases.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <consent_monitor/common.hpp>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace consent_monitor {

// ─── Consent State Machine ─────────────────────────────────────────────────

enum class ConsentState : uint8_t {
    Idle,       // No consent ever granted
    Granted,    // Active consent
    Paused,     // Monitoring paused, consent still valid
    Revoked     // Consent withdrawn
};

// ─── Network Worker Phases ─────────────────────────────────────────────────

enum class NetworkWorkerPhase : uint8_t {
    Idle,                    // No worker active
    HeaderAuthorized,        // Permission to call WinHttpSendRequest granted
    HeaderSendInitiated,     // WinHttpSendRequest call started (recorded after return)
    BodyAuthorized,          // Permission to call WinHttpWriteData granted
    BodyWriteInitiated,      // WinHttpWriteData call started (recorded after return)
    ResponseAuthorized,      // Permission to call WinHttpReceiveResponse granted
    ResponseCompleted,       // WinHttpReceiveResponse returned
    ClosingHandles,          // Closing WinHTTP handles
    Drained,                 // All handles closed, worker thread joined/exited
    Degraded_EgressUnknown   // Handle close failed or uncertain
};

// ─── ConsentManager ────────────────────────────────────────────────────────
// Thread-safe manager for consent lifecycle and network worker coordination.
// The internal std::mutex (modelling ConsentStateLock) protects ONLY
// in-memory state; it is NEVER held across network calls, waits, joins,
// file I/O, or handle closures.

class ConsentManager {
public:
    ConsentManager();

    // ── State transitions ───────────────────────────────────────────────
    Result<uint64_t> GrantConsent();
    Result<void>     RevokeConsent();
    Result<void>     PauseMonitoring();
    Result<void>     ResumeMonitoring();

    // ── Network authorisation (called by worker thread, acquires lock) ──
    bool TryAuthorizeHeader(uint64_t gen);
    bool TryAuthorizeBody(uint64_t gen);
    bool TryAuthorizeResponse(uint64_t gen);

    // ── Phase recording ─────────────────────────────────────────────────
    void RecordPhase(uint64_t gen, NetworkWorkerPhase phase);
    void MarkDrained(uint64_t gen);
    void MarkDegraded(uint64_t gen);

    // ── Queries ─────────────────────────────────────────────────────────
    bool                IsCancelRequested() const;
    ConsentState        GetState() const;
    uint64_t            GetGeneration() const;
    NetworkWorkerPhase  GetWorkerPhase(uint64_t gen) const;
    bool                IsWorkerDrained(uint64_t gen) const;
    std::string         GetStatusMessage() const;

private:
    // Common authorisation check (must be called under lock).
    bool CanAuthorize(uint64_t gen) const;

    mutable std::mutex        mutex_;
    uint64_t                  consent_generation_{0};
    ConsentState              consent_state_{ConsentState::Idle};
    std::atomic<bool>         network_cancel_requested_{false};

    // Per-generation tracking.
    struct GenerationInfo {
        NetworkWorkerPhase phase{NetworkWorkerPhase::Idle};
        bool               drained{false};
    };
    std::unordered_map<uint64_t, GenerationInfo> generations_;
};

} // namespace consent_monitor
