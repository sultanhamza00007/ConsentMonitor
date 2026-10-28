// ConsentMonitor — journal_types.hpp
// Types for the rotation journal state machine.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace consent_monitor {

enum class JournalOperation : uint8_t {
    CloseActive,
    MoveToStaging,
    RetireArchive3,
    Shift2To3,
    Shift1To2,
    PromoteStagingTo1,
    CreateActive,
    RotationComplete
};

enum class JournalPhase : uint8_t {
    Prepared,
    Completed,
    Absent
};

struct JournalRecord {
    uint32_t schema_version = 1;
    std::string rotation_id;          // Unique rotation identifier
    uint64_t journal_seq = 0;         // Strictly monotonic
    JournalOperation operation = JournalOperation::CloseActive;
    JournalPhase phase = JournalPhase::Prepared;
    std::string source_path;
    std::string destination_path;
    std::string expected_identity;    // Hash/identity of expected file content
    uint32_t checksum = 0;           // CRC-32/IEEE over canonical JSON with checksum omitted
};

// ── String ↔ enum conversion (inline) ───────────────────────────────────────

inline std::string operation_to_string(JournalOperation op) {
    switch (op) {
        case JournalOperation::CloseActive:         return "CloseActive";
        case JournalOperation::MoveToStaging:       return "MoveToStaging";
        case JournalOperation::RetireArchive3:      return "RetireArchive3";
        case JournalOperation::Shift2To3:           return "Shift2To3";
        case JournalOperation::Shift1To2:           return "Shift1To2";
        case JournalOperation::PromoteStagingTo1:   return "PromoteStagingTo1";
        case JournalOperation::CreateActive:        return "CreateActive";
        case JournalOperation::RotationComplete:    return "RotationComplete";
    }
    return "Unknown";
}

inline std::string phase_to_string(JournalPhase ph) {
    switch (ph) {
        case JournalPhase::Prepared:  return "Prepared";
        case JournalPhase::Completed: return "Completed";
        case JournalPhase::Absent:    return "Absent";
    }
    return "Unknown";
}

inline JournalOperation string_to_operation(const std::string& s) {
    if (s == "CloseActive")       return JournalOperation::CloseActive;
    if (s == "MoveToStaging")     return JournalOperation::MoveToStaging;
    if (s == "RetireArchive3")    return JournalOperation::RetireArchive3;
    if (s == "Shift2To3")         return JournalOperation::Shift2To3;
    if (s == "Shift1To2")         return JournalOperation::Shift1To2;
    if (s == "PromoteStagingTo1") return JournalOperation::PromoteStagingTo1;
    if (s == "CreateActive")      return JournalOperation::CreateActive;
    if (s == "RotationComplete")  return JournalOperation::RotationComplete;
    throw std::invalid_argument("Unknown JournalOperation: " + s);
}

inline JournalPhase string_to_phase(const std::string& s) {
    if (s == "Prepared")  return JournalPhase::Prepared;
    if (s == "Completed") return JournalPhase::Completed;
    if (s == "Absent")    return JournalPhase::Absent;
    throw std::invalid_argument("Unknown JournalPhase: " + s);
}

} // namespace consent_monitor
