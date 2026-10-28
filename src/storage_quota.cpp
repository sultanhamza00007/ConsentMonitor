// ConsentMonitor — storage_quota.cpp
// Quota calculations for bounded local log storage.

#include <consent_monitor/storage_quota.hpp>

namespace consent_monitor {

// ─── DirectoryUsage ─────────────────────────────────────────────────────────

uint64_t DirectoryUsage::total() const {
    uint64_t sum = active_size + staging_size + journal_size + temp_journal_size;
    for (auto s : archive_sizes) sum += s;
    return sum;
}

uint64_t DirectoryUsage::ordinary_total() const {
    uint64_t sum = active_size + staging_size;
    for (auto s : archive_sizes) sum += s;
    return sum;
}

// ─── QuotaCalculator ────────────────────────────────────────────────────────

uint64_t QuotaCalculator::TotalUsage(const DirectoryUsage& usage) {
    return usage.total();
}

bool QuotaCalculator::AdmitEvent(const DirectoryUsage& usage, uint64_t event_size) {
    // Pre-admission: ordinary_total + event_size <= kOrdinaryWriteCap
    // Overflow-safe check: verify ord <= kOrdinaryWriteCap and event_size <= (kOrdinaryWriteCap - ord)
    uint64_t ord = usage.ordinary_total();
    if (ord > kOrdinaryWriteCap) return false;
    if (event_size > (kOrdinaryWriteCap - ord)) return false;

    // Additionally check hard ceiling headroom
    uint64_t tot = usage.total();
    if (tot > kHardCeiling) return false;
    if (event_size > (kHardCeiling - tot)) return false;

    return true;
}

bool QuotaCalculator::ExceedsHardCeiling(const DirectoryUsage& usage) {
    return usage.total() > kHardCeiling;
}

bool QuotaCalculator::ActiveFileExceedsCeiling(uint64_t active_size) {
    return active_size >= kActiveFileCeiling;
}

bool QuotaCalculator::JournalFitsReserve(uint64_t journal_total) {
    return journal_total <= kLifecycleReserve;
}

} // namespace consent_monitor
