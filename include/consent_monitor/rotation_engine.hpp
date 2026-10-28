// ConsentMonitor — rotation_engine.hpp
// Ordered rotation sequence and crash-safe recovery engine.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <consent_monitor/common.hpp>
#include <consent_monitor/filesystem_interface.hpp>
#include <consent_monitor/journal_engine.hpp>
#include <consent_monitor/journal_types.hpp>
#include <consent_monitor/storage_quota.hpp>

#include <string>

namespace consent_monitor {

// ─── Recovery outcome ───────────────────────────────────────────────────────
enum class RecoveryOutcome : uint8_t {
    Clean,              // Normal layout, no recovery needed
    Recovered,          // Recovery completed successfully
    HaltOperatorRepair  // Ambiguous state — operator must repair
};

struct RecoveryResult {
    RecoveryOutcome outcome;
    std::string     message;
};

// ─── Rotation Engine ────────────────────────────────────────────────────────
class RotationEngine {
public:
    RotationEngine(IFilesystem& fs, JournalEngine& journal,
                   std::string base_dir);

    /// Perform the full ordered rotation sequence.
    /// Returns failure if any step fails (journal preserved for recovery).
    Result<void> PerformRotation(const std::string& rotation_id);

    /// Startup recovery: inspect layout, reconcile journal, resume or halt.
    RecoveryResult PerformRecovery();

    // ── Path helpers ────────────────────────────────────────────────────
    std::string ActivePath() const;
    std::string StagingPath() const;
    std::string ArchivePath(int n) const;  // n = 1, 2, or 3

private:
    // Steps in the rotation sequence.
    Result<void> StepCloseActive(const std::string& rot_id);
    Result<void> StepMoveToStaging(const std::string& rot_id);
    Result<void> StepRetireArchive3(const std::string& rot_id);
    Result<void> StepShift(const std::string& rot_id,
                           int from, int to,
                           JournalOperation op);
    Result<void> StepPromoteStagingTo1(const std::string& rot_id);
    Result<void> StepCreateActive(const std::string& rot_id);
    Result<void> StepRotationComplete(const std::string& rot_id);

    // Recovery helpers.
    RecoveryResult RecoverWithJournal(const JournalRecord& rec);
    RecoveryResult RecoverPrepared(const JournalRecord& rec);
    RecoveryResult RecoverCompleted(const JournalRecord& rec);
    RecoveryResult RecoverAbsent(const JournalRecord& rec);
    bool IsCanonicalLayout() const;

    IFilesystem&   fs_;
    JournalEngine& journal_;
    std::string    base_dir_;
};

} // namespace consent_monitor
