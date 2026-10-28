// ConsentMonitor — test_storage_quota.cpp
// Tests for QuotaCalculator: exact-fit, one-byte-over, and boundary enforcement.

#include "test_framework.hpp"
#include <consent_monitor/storage_quota.hpp>

using namespace consent_monitor;

int main() {
    cm_test::Suite suite("Storage Quota & Boundary Enforcement");

    // 1. Exact-fit admission: 20,904,960 + 1,024 = 20,905,984 == kOrdinaryWriteCap
    suite.add("Exact-fit admission (20,904,960 + 1,024 == 20,905,984)", [] {
        DirectoryUsage usage;
        usage.active_size = 20'904'960;
        uint64_t event_size = 1'024;
        ASSERT_TRUE(QuotaCalculator::AdmitEvent(usage, event_size));
    });

    // 2. One-byte-over rejection: 20,904,961 + 1,024 = 20,905,985 > kOrdinaryWriteCap
    suite.add("One-byte-over rejection (20,904,961 + 1,024 == 20,905,985)", [] {
        DirectoryUsage usage;
        usage.active_size = 20'904'961;
        uint64_t event_size = 1'024;
        ASSERT_FALSE(QuotaCalculator::AdmitEvent(usage, event_size));
    });

    // 3. Empty directory admits events
    suite.add("Empty directory admits events", [] {
        DirectoryUsage usage;
        ASSERT_EQ(usage.total(), 0ULL);
        ASSERT_EQ(usage.ordinary_total(), 0ULL);
        ASSERT_TRUE(QuotaCalculator::AdmitEvent(usage, 512));
        ASSERT_TRUE(QuotaCalculator::AdmitEvent(usage, kOrdinaryWriteCap));
        ASSERT_FALSE(QuotaCalculator::AdmitEvent(usage, kOrdinaryWriteCap + 1));
    });

    // 4. Directory usage sum across active, archives, and staging
    suite.add("Directory usage totals across all files", [] {
        DirectoryUsage usage;
        usage.active_size = 5'000'000;
        usage.archive_sizes[0] = 5'000'000;
        usage.archive_sizes[1] = 5'000'000;
        usage.archive_sizes[2] = 5'000'000;
        usage.staging_size = 500'000;
        usage.journal_size = 1'000;
        usage.temp_journal_size = 1'000;

        ASSERT_EQ(usage.ordinary_total(), 20'500'000ULL);
        ASSERT_EQ(usage.total(), 20'502'000ULL);
        ASSERT_EQ(QuotaCalculator::TotalUsage(usage), 20'502'000ULL);
    });

    // 5. Journal and temp journal overlap counted in hard ceiling
    suite.add("Journal + temp journal overlap in hard ceiling", [] {
        DirectoryUsage usage;
        usage.active_size = 20'905'984; // ordinary write cap reached
        usage.journal_size = 32'768;
        usage.temp_journal_size = 32'768; // 32K + 32K = 65,536 == kLifecycleReserve

        // Total = 20,905,984 + 65,536 = 20,971,520 == kHardCeiling exactly
        ASSERT_EQ(usage.total(), kHardCeiling);
        ASSERT_FALSE(QuotaCalculator::ExceedsHardCeiling(usage));

        // 1 byte over hard ceiling
        usage.temp_journal_size += 1;
        ASSERT_TRUE(QuotaCalculator::ExceedsHardCeiling(usage));
    });

    // 6. Active file ceiling check (5 MiB)
    suite.add("Active file ceiling check (5 MiB)", [] {
        ASSERT_FALSE(QuotaCalculator::ActiveFileExceedsCeiling(kActiveFileCeiling - 1));
        ASSERT_TRUE(QuotaCalculator::ActiveFileExceedsCeiling(kActiveFileCeiling));
        ASSERT_TRUE(QuotaCalculator::ActiveFileExceedsCeiling(kActiveFileCeiling + 1));
    });

    // 7. Lifecycle reserve capacity check
    suite.add("Lifecycle reserve capacity check (65,536 bytes)", [] {
        ASSERT_TRUE(QuotaCalculator::JournalFitsReserve(kLifecycleReserve));
        ASSERT_TRUE(QuotaCalculator::JournalFitsReserve(1'024));
        ASSERT_FALSE(QuotaCalculator::JournalFitsReserve(kLifecycleReserve + 1));
    });

    // 8. Integer overflow protection: UINT64_MAX event size must be rejected
    suite.add("Integer overflow protection on huge event_size", [] {
        DirectoryUsage usage;
        usage.active_size = 100;
        ASSERT_FALSE(QuotaCalculator::AdmitEvent(usage, UINT64_MAX));
        ASSERT_FALSE(QuotaCalculator::AdmitEvent(usage, UINT64_MAX - 50));
        ASSERT_FALSE(QuotaCalculator::AdmitEvent(usage, UINT64_MAX - 100));

        // When ordinary_total already exceeds cap
        DirectoryUsage full_usage;
        full_usage.active_size = kOrdinaryWriteCap + 1;
        ASSERT_FALSE(QuotaCalculator::AdmitEvent(full_usage, 0));
        ASSERT_FALSE(QuotaCalculator::AdmitEvent(full_usage, 1));
        ASSERT_FALSE(QuotaCalculator::AdmitEvent(full_usage, UINT64_MAX));
    });

    return suite.run();
}
