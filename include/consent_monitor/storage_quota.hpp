// ConsentMonitor — storage_quota.hpp
// Quota calculations for bounded local log storage.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <consent_monitor/common.hpp>
#include <cstdint>

namespace consent_monitor {

// Describes the byte-level usage of every file in the log directory.
struct DirectoryUsage {
    uint64_t active_size = 0;       // active.log
    uint64_t archive_sizes[3] = {}; // archive.1, .2, .3
    uint64_t staging_size = 0;      // active.log.staging (during rotation)
    uint64_t journal_size = 0;      // rotation_journal.json
    uint64_t temp_journal_size = 0; // rotation_journal.*.tmp (counted during overlap)

    // Sum of every field.
    uint64_t total() const;

    // Everything except journal and temp_journal.
    uint64_t ordinary_total() const;
};

// Pure-function calculator — no state, no I/O.
class QuotaCalculator {
public:
    // Sum all fields of a DirectoryUsage.
    static uint64_t TotalUsage(const DirectoryUsage& usage);

    // Pre-admission check: returns true IFF the event can be written
    // without exceeding kOrdinaryWriteCap.
    static bool AdmitEvent(const DirectoryUsage& usage, uint64_t event_size);

    // Returns true when the total directory usage exceeds kHardCeiling.
    static bool ExceedsHardCeiling(const DirectoryUsage& usage);

    // Returns true when the active file has reached or exceeded its ceiling.
    static bool ActiveFileExceedsCeiling(uint64_t active_size);

    // Returns true when the journal fits within the lifecycle reserve.
    static bool JournalFitsReserve(uint64_t journal_total);
};

} // namespace consent_monitor
