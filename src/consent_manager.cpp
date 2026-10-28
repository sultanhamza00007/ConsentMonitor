// ConsentMonitor — consent_manager.cpp
// Thread-safe consent state machine with generational tracking.

#include <consent_monitor/consent_manager.hpp>
#include <sstream>

namespace consent_monitor {

ConsentManager::ConsentManager() = default;

// ─── State Transitions ─────────────────────────────────────────────────────

Result<uint64_t> ConsentManager::GrantConsent() {
    std::lock_guard lock(mutex_);
    switch (consent_state_) {
        case ConsentState::Idle:
        case ConsentState::Revoked: {
            ++consent_generation_;
            consent_state_ = ConsentState::Granted;
            network_cancel_requested_.store(false, std::memory_order_release);
            // Create generation info entry.
            generations_[consent_generation_] = GenerationInfo{};
            return Result<uint64_t>::success(consent_generation_);
        }
        case ConsentState::Granted:
            // Idempotent: already granted, return current generation.
            return Result<uint64_t>::success(consent_generation_);
        case ConsentState::Paused:
            return Result<uint64_t>::failure(
                "Cannot grant while paused; call ResumeMonitoring() first");
    }
    return Result<uint64_t>::failure("Unknown consent state");
}

Result<void> ConsentManager::RevokeConsent() {
    std::lock_guard lock(mutex_);
    switch (consent_state_) {
        case ConsentState::Granted:
        case ConsentState::Paused:
            consent_state_ = ConsentState::Revoked;
            network_cancel_requested_.store(true, std::memory_order_release);
            return Result<void>::success();
        case ConsentState::Idle:
            return Result<void>::failure("Cannot revoke: no consent has been granted");
        case ConsentState::Revoked:
            return Result<void>::failure("Consent is already revoked");
    }
    return Result<void>::failure("Unknown consent state");
}

Result<void> ConsentManager::PauseMonitoring() {
    std::lock_guard lock(mutex_);
    if (consent_state_ != ConsentState::Granted)
        return Result<void>::failure("Can only pause from Granted state");
    consent_state_ = ConsentState::Paused;
    return Result<void>::success();
}

Result<void> ConsentManager::ResumeMonitoring() {
    std::lock_guard lock(mutex_);
    if (consent_state_ != ConsentState::Paused)
        return Result<void>::failure("Can only resume from Paused state");
    consent_state_ = ConsentState::Granted;
    return Result<void>::success();
}

// ─── Common authorization predicate (caller holds lock) ─────────────────────

bool ConsentManager::CanAuthorize(uint64_t gen) const {
    return consent_state_ == ConsentState::Granted
        && gen == consent_generation_
        && !network_cancel_requested_.load(std::memory_order_acquire);
}

// ─── Network Authorization ──────────────────────────────────────────────────

bool ConsentManager::TryAuthorizeHeader(uint64_t gen) {
    std::lock_guard lock(mutex_);
    if (!CanAuthorize(gen)) return false;
    generations_[gen].phase = NetworkWorkerPhase::HeaderAuthorized;
    generations_[gen].drained = false;
    return true;
}

bool ConsentManager::TryAuthorizeBody(uint64_t gen) {
    std::lock_guard lock(mutex_);
    if (!CanAuthorize(gen)) return false;
    generations_[gen].phase = NetworkWorkerPhase::BodyAuthorized;
    return true;
}

bool ConsentManager::TryAuthorizeResponse(uint64_t gen) {
    std::lock_guard lock(mutex_);
    if (!CanAuthorize(gen)) return false;
    generations_[gen].phase = NetworkWorkerPhase::ResponseAuthorized;
    return true;
}

// ─── Phase Recording ────────────────────────────────────────────────────────

void ConsentManager::RecordPhase(uint64_t gen, NetworkWorkerPhase phase) {
    std::lock_guard lock(mutex_);
    auto it = generations_.find(gen);
    if (it != generations_.end()) {
        it->second.phase = phase;
    }
}

void ConsentManager::MarkDrained(uint64_t gen) {
    std::lock_guard lock(mutex_);
    auto it = generations_.find(gen);
    if (it != generations_.end()) {
        it->second.phase  = NetworkWorkerPhase::Drained;
        it->second.drained = true;
    }
}

void ConsentManager::MarkDegraded(uint64_t gen) {
    std::lock_guard lock(mutex_);
    auto it = generations_.find(gen);
    if (it != generations_.end()) {
        it->second.phase  = NetworkWorkerPhase::Degraded_EgressUnknown;
        it->second.drained = false;   // NOT drained on degraded
    }
}

// ─── Queries ────────────────────────────────────────────────────────────────

bool ConsentManager::IsCancelRequested() const {
    return network_cancel_requested_.load(std::memory_order_acquire);
}

ConsentState ConsentManager::GetState() const {
    std::lock_guard lock(mutex_);
    return consent_state_;
}

uint64_t ConsentManager::GetGeneration() const {
    std::lock_guard lock(mutex_);
    return consent_generation_;
}

NetworkWorkerPhase ConsentManager::GetWorkerPhase(uint64_t gen) const {
    std::lock_guard lock(mutex_);
    auto it = generations_.find(gen);
    if (it == generations_.end()) return NetworkWorkerPhase::Idle;
    return it->second.phase;
}

bool ConsentManager::IsWorkerDrained(uint64_t gen) const {
    std::lock_guard lock(mutex_);
    auto it = generations_.find(gen);
    if (it == generations_.end()) {
        // Unknown generation: an unlaunched worker is terminal and drained.
        return true;
    }
    if (it->second.phase == NetworkWorkerPhase::Idle) {
        // Unlaunched worker is terminal and drained.
        return true;
    }
    return it->second.drained;
}

std::string ConsentManager::GetStatusMessage() const {
    std::lock_guard lock(mutex_);
    std::ostringstream os;
    switch (consent_state_) {
        case ConsentState::Idle:
            os << "Idle: No consent granted.";
            break;
        case ConsentState::Granted:
            os << "Granted: Consent active (generation " << consent_generation_ << ").";
            break;
        case ConsentState::Paused:
            os << "Paused: Monitoring paused (generation " << consent_generation_ << ").";
            break;
        case ConsentState::Revoked:
            os << "Revoked: Consent revoked.";
            break;
    }

    // Check current generation worker state.
    auto it = generations_.find(consent_generation_);
    if (it != generations_.end()) {
        auto ph = it->second.phase;
        if (ph == NetworkWorkerPhase::Degraded_EgressUnknown) {
            os << " Egress state unknown.";
        } else if (consent_state_ == ConsentState::Revoked && !it->second.drained
                   && ph != NetworkWorkerPhase::Idle) {
            os << " Consent Revoked: network egress may be in flight;"
                  " awaiting worker termination.";
        } else if (it->second.drained) {
            os << " Egress stopped.";
        }
    }
    return os.str();
}

} // namespace consent_monitor
