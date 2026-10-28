// ConsentMonitor — rotation_engine.cpp
// Ordered rotation sequence and crash-safe recovery engine.

#include <consent_monitor/rotation_engine.hpp>
#include <string>

namespace consent_monitor {

RotationEngine::RotationEngine(IFilesystem& fs, JournalEngine& journal,
                               std::string base_dir)
    : fs_(fs), journal_(journal), base_dir_(std::move(base_dir)) {}

// ─── Path helpers ───────────────────────────────────────────────────────────

std::string RotationEngine::ActivePath() const {
    return base_dir_ + "/active.log";
}

std::string RotationEngine::StagingPath() const {
    return base_dir_ + "/active.log.staging";
}

std::string RotationEngine::ArchivePath(int n) const {
    return base_dir_ + "/archive." + std::to_string(n);
}

bool RotationEngine::IsCanonicalLayout() const {
    // Canonical: active.log present, no staging, no temp journals.
    if (!fs_.FileExists(ActivePath())) return false;
    if (fs_.FileExists(StagingPath())) return false;
    // Check for temp journal files.
    auto list_r = fs_.ListFiles(base_dir_);
    if (!list_r.ok) return false;
    for (auto const& f : list_r.value) {
        if (f.find("rotation_journal.") != std::string::npos
            && f.find(".tmp") != std::string::npos)
            return false;
    }
    return true;
}

// ─── Full Rotation ──────────────────────────────────────────────────────────

Result<void> RotationEngine::PerformRotation(const std::string& rot_id) {
    // Refresh journal sequence.
    auto seq_r = journal_.GetLastValidSequence();
    if (!seq_r.ok)
        return Result<void>::failure("Cannot read journal sequence: " + seq_r.error);

    auto r = StepCloseActive(rot_id);      if (!r.ok) return r;
    r = StepMoveToStaging(rot_id);         if (!r.ok) return r;
    r = StepRetireArchive3(rot_id);        if (!r.ok) return r;
    r = StepShift(rot_id, 2, 3, JournalOperation::Shift2To3); if (!r.ok) return r;
    r = StepShift(rot_id, 1, 2, JournalOperation::Shift1To2); if (!r.ok) return r;
    r = StepPromoteStagingTo1(rot_id);     if (!r.ok) return r;
    r = StepCreateActive(rot_id);          if (!r.ok) return r;
    r = StepRotationComplete(rot_id);      if (!r.ok) return r;
    return Result<void>::success();
}

// ─── Rotation Steps ─────────────────────────────────────────────────────────

Result<void> RotationEngine::StepCloseActive(const std::string& rot_id) {
    JournalRecord rec;
    rec.rotation_id = rot_id;
    rec.operation   = JournalOperation::CloseActive;
    rec.source_path = ActivePath();

    // Get identity of current active file.
    auto id_r = fs_.GetIdentity(ActivePath());
    if (id_r.ok && id_r.value.exists)
        rec.expected_identity = id_r.value.content_hash;

    // PREPARED
    auto r = journal_.PersistPrepared(rec);
    if (!r.ok) return r;

    // Flush the active file (simulates closing the handle).
    if (fs_.FileExists(ActivePath())) {
        auto flush_r = fs_.FlushFile(ActivePath());
        if (!flush_r.ok)
            return Result<void>::failure("Failed to flush active: " + flush_r.error);
    }

    // COMPLETED
    return journal_.PersistCompleted(rec);
}

Result<void> RotationEngine::StepMoveToStaging(const std::string& rot_id) {
    JournalRecord rec;
    rec.rotation_id      = rot_id;
    rec.operation        = JournalOperation::MoveToStaging;
    rec.source_path      = ActivePath();
    rec.destination_path = StagingPath();

    auto id_r = fs_.GetIdentity(ActivePath());
    if (id_r.ok && id_r.value.exists)
        rec.expected_identity = id_r.value.content_hash;

    auto r = journal_.PersistPrepared(rec);
    if (!r.ok) return r;

    auto move_r = fs_.MoveFile(ActivePath(), StagingPath(), false);
    if (!move_r.ok)
        return Result<void>::failure("Failed to move active to staging: " + move_r.error);

    return journal_.PersistCompleted(rec);
}

Result<void> RotationEngine::StepRetireArchive3(const std::string& rot_id) {
    JournalRecord rec;
    rec.rotation_id = rot_id;
    rec.operation   = JournalOperation::RetireArchive3;
    rec.source_path = ArchivePath(3);

    if (!fs_.FileExists(ArchivePath(3))) {
        // Record ABSENT: .3 doesn't exist.
        return journal_.PersistAbsent(rec);
    }

    auto id_r = fs_.GetIdentity(ArchivePath(3));
    if (id_r.ok && id_r.value.exists)
        rec.expected_identity = id_r.value.content_hash;

    auto r = journal_.PersistPrepared(rec);
    if (!r.ok) return r;

    // Irreversible deletion.
    auto del_r = fs_.DeleteFile(ArchivePath(3));
    if (!del_r.ok)
        return Result<void>::failure("Failed to retire archive.3: " + del_r.error);

    return journal_.PersistCompleted(rec);
}

Result<void> RotationEngine::StepShift(const std::string& rot_id,
                                       int from, int to,
                                       JournalOperation op) {
    JournalRecord rec;
    rec.rotation_id      = rot_id;
    rec.operation        = op;
    rec.source_path      = ArchivePath(from);
    rec.destination_path = ArchivePath(to);

    if (!fs_.FileExists(ArchivePath(from))) {
        // Record ABSENT.
        return journal_.PersistAbsent(rec);
    }

    auto id_r = fs_.GetIdentity(ArchivePath(from));
    if (id_r.ok && id_r.value.exists)
        rec.expected_identity = id_r.value.content_hash;

    auto r = journal_.PersistPrepared(rec);
    if (!r.ok) return r;

    auto move_r = fs_.MoveFile(ArchivePath(from), ArchivePath(to), false);
    if (!move_r.ok)
        return Result<void>::failure("Failed to shift archive."
                                    + std::to_string(from) + " to ."
                                    + std::to_string(to) + ": " + move_r.error);

    return journal_.PersistCompleted(rec);
}

Result<void> RotationEngine::StepPromoteStagingTo1(const std::string& rot_id) {
    JournalRecord rec;
    rec.rotation_id      = rot_id;
    rec.operation        = JournalOperation::PromoteStagingTo1;
    rec.source_path      = StagingPath();
    rec.destination_path = ArchivePath(1);

    auto id_r = fs_.GetIdentity(StagingPath());
    if (id_r.ok && id_r.value.exists)
        rec.expected_identity = id_r.value.content_hash;

    auto r = journal_.PersistPrepared(rec);
    if (!r.ok) return r;

    auto move_r = fs_.MoveFile(StagingPath(), ArchivePath(1), false);
    if (!move_r.ok)
        return Result<void>::failure("Failed to promote staging: " + move_r.error);

    return journal_.PersistCompleted(rec);
}

Result<void> RotationEngine::StepCreateActive(const std::string& rot_id) {
    JournalRecord rec;
    rec.rotation_id      = rot_id;
    rec.operation        = JournalOperation::CreateActive;
    rec.destination_path = ActivePath();

    auto r = journal_.PersistPrepared(rec);
    if (!r.ok) return r;

    // CREATE_NEW semantics — fail if file already exists.
    auto create_r = fs_.WriteFileExclusive(ActivePath(), "");
    if (!create_r.ok)
        return Result<void>::failure("Failed to create active: " + create_r.error);

    return journal_.PersistCompleted(rec);
}

Result<void> RotationEngine::StepRotationComplete(const std::string& rot_id) {
    JournalRecord rec;
    rec.rotation_id = rot_id;
    rec.operation   = JournalOperation::RotationComplete;

    auto r = journal_.PersistCompleted(rec);
    if (!r.ok) return r;

    return journal_.ClearJournal();
}

// ─── Crash Recovery ─────────────────────────────────────────────────────────

RecoveryResult RotationEngine::PerformRecovery() {
    // 1. Check for temp journal files.
    auto list_r = fs_.ListFiles(base_dir_);
    std::vector<std::string> temp_journals;
    if (list_r.ok) {
        for (auto const& f : list_r.value) {
            if (f.find("rotation_journal.") != std::string::npos
                && f.find(".tmp") != std::string::npos) {
                temp_journals.push_back(f);
            }
        }
    }

    bool has_journal = fs_.FileExists(journal_.JournalPath());

    // 2. Multiple temp journals → halt.
    if (temp_journals.size() > 1) {
        return {RecoveryOutcome::HaltOperatorRepair,
                "Multiple temp journal files found. Operator repair required."};
    }

    // 3. No journal, no temps.
    if (!has_journal && temp_journals.empty()) {
        if (fs_.FileExists(ActivePath()) && !fs_.FileExists(StagingPath())) {
            // Normal layout. Archive gaps are preserved as-is.
            return {RecoveryOutcome::Clean, "Normal layout, no recovery needed."};
        }
        if (!fs_.FileExists(ActivePath()) && !fs_.FileExists(StagingPath())) {
            // No active, no staging — could be first run or all deleted.
            return {RecoveryOutcome::Clean, "Empty directory, fresh start."};
        }
        // Staging exists without journal or active — ambiguous.
        if (fs_.FileExists(StagingPath()) && !fs_.FileExists(ActivePath())) {
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Staging file exists without journal or active. "
                    "Operator repair required."};
        }
        // Both active and staging exist without journal.
        return {RecoveryOutcome::HaltOperatorRepair,
                "Active and staging both exist without journal. "
                "Operator repair required."};
    }

    // 4. No active journal but one valid temp.
    if (!has_journal && temp_journals.size() == 1) {
        auto read_r = fs_.ReadFile(temp_journals[0]);
        if (!read_r.ok) {
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot read temp journal: " + read_r.error};
        }
        auto parse_r = journal_.ParseJournal(read_r.value);
        if (!parse_r.ok) {
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Invalid temp journal: " + parse_r.error};
        }
        auto& rec = parse_r.value;
        // Accept only CLOSE_ACTIVE / PREPARED with canonical pre-rotation layout.
        if (rec.operation == JournalOperation::CloseActive
            && rec.phase == JournalPhase::Prepared
            && fs_.FileExists(ActivePath())
            && !fs_.FileExists(StagingPath())) {
            // Promote temp to journal.
            auto move_r = fs_.MoveFile(temp_journals[0],
                                       journal_.JournalPath(), true);
            if (!move_r.ok) {
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Cannot promote temp journal: " + move_r.error};
            }
            return RecoverWithJournal(rec);
        }
        return {RecoveryOutcome::HaltOperatorRepair,
                "Temp journal does not match expected initial state. "
                "Operator repair required."};
    }

    // 5. Active journal present.
    if (has_journal) {
        if (!temp_journals.empty()) {
            // Active journal + temp: check temp is valid next-seq.
            auto read_r = fs_.ReadFile(temp_journals[0]);
            if (!read_r.ok) {
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Cannot read temp journal: " + read_r.error};
            }
            auto parse_r = journal_.ParseJournal(read_r.value);
            if (!parse_r.ok) {
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Invalid temp journal: " + parse_r.error};
            }

            auto seq_r = journal_.GetLastValidSequence();
            if (!seq_r.ok) {
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Cannot read journal sequence: " + seq_r.error};
            }
            uint64_t expected_next = seq_r.value + 1;
            if (parse_r.value.journal_seq != expected_next) {
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Temp journal sequence mismatch. "
                        "Operator repair required."};
            }
            // Promote temp to journal.
            auto move_r = fs_.MoveFile(temp_journals[0],
                                       journal_.JournalPath(), true);
            if (!move_r.ok) {
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Cannot promote temp: " + move_r.error};
            }
            return RecoverWithJournal(parse_r.value);
        }

        // Journal only, no temp.
        auto read_r = journal_.ReadCurrentJournal();
        if (!read_r.ok) {
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot read journal: " + read_r.error};
        }
        return RecoverWithJournal(read_r.value);
    }

    return {RecoveryOutcome::HaltOperatorRepair, "Unexpected state."};
}

RecoveryResult RotationEngine::RecoverWithJournal(const JournalRecord& rec) {
    switch (rec.phase) {
        case JournalPhase::Prepared:  return RecoverPrepared(rec);
        case JournalPhase::Completed: return RecoverCompleted(rec);
        case JournalPhase::Absent:    return RecoverAbsent(rec);
    }
    return {RecoveryOutcome::HaltOperatorRepair, "Unknown journal phase."};
}

RecoveryResult RotationEngine::RecoverPrepared(const JournalRecord& rec) {
    // PREPARED means the operation was about to happen or was interrupted.

    bool source_exists = !rec.source_path.empty()
                         && fs_.FileExists(rec.source_path);
    bool dest_exists   = !rec.destination_path.empty()
                         && fs_.FileExists(rec.destination_path);

    // Special case: RetireArchive3 / PREPARED + absent .3
    if (rec.operation == JournalOperation::RetireArchive3 && !source_exists) {
        // .3 is already gone — satisfies the intended postcondition.
        // Persist COMPLETED and continue.
        JournalRecord completed = rec;
        auto r = journal_.PersistCompleted(completed);
        if (!r.ok)
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot complete .3 retirement: " + r.error};
        return {RecoveryOutcome::Recovered,
                "Archive.3 retirement confirmed (already absent)."};
    }

    // For CreateActive: no source, just check dest.
    if (rec.operation == JournalOperation::CreateActive) {
        if (dest_exists) {
            // Already created.
            JournalRecord completed = rec;
            auto r = journal_.PersistCompleted(completed);
            if (!r.ok)
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Cannot complete active creation: " + r.error};
            return {RecoveryOutcome::Recovered,
                    "Active file creation confirmed (already exists)."};
        }
        // Create it.
        auto create_r = fs_.WriteFileExclusive(rec.destination_path, "");
        if (!create_r.ok)
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot create active: " + create_r.error};
        JournalRecord completed = rec;
        auto r = journal_.PersistCompleted(completed);
        if (!r.ok)
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot complete active creation: " + r.error};
        return {RecoveryOutcome::Recovered, "Active file created during recovery."};
    }

    if (source_exists && !dest_exists) {
        // Source present, dest absent → verify expected source identity if recorded
        if (!rec.expected_identity.empty() && rec.operation != JournalOperation::CloseActive) {
            auto src_id = fs_.GetIdentity(rec.source_path);
            if (!src_id.ok || src_id.value.content_hash != rec.expected_identity) {
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Source identity mismatch during PREPARED recovery. Operator repair required."};
            }
        }

        if (rec.operation == JournalOperation::CloseActive) {
            // "Close" = flush. Just mark completed.
            auto flush_r = fs_.FlushFile(rec.source_path);
            (void)flush_r; // Best-effort flush.
            JournalRecord completed = rec;
            auto r = journal_.PersistCompleted(completed);
            if (!r.ok)
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Cannot complete close: " + r.error};
            return {RecoveryOutcome::Recovered, "Close-active completed."};
        }
        // Move operations.
        auto move_r = fs_.MoveFile(rec.source_path, rec.destination_path, false);
        if (!move_r.ok)
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot perform move: " + move_r.error};
        JournalRecord completed = rec;
        auto r = journal_.PersistCompleted(completed);
        if (!r.ok)
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot record completion: " + r.error};
        return {RecoveryOutcome::Recovered,
                "Operation performed during recovery."};
    }

    if (!source_exists && dest_exists) {
        // Source absent, dest present → verify destination has expected identity
        if (!rec.expected_identity.empty()) {
            auto dst_id = fs_.GetIdentity(rec.destination_path);
            if (!dst_id.ok || dst_id.value.content_hash != rec.expected_identity) {
                return {RecoveryOutcome::HaltOperatorRepair,
                        "Destination identity mismatch during PREPARED recovery. Operator repair required."};
            }
        }

        JournalRecord completed = rec;
        auto r = journal_.PersistCompleted(completed);
        if (!r.ok)
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot record completion: " + r.error};
        return {RecoveryOutcome::Recovered,
                "Operation already completed (source absent, dest present)."};
    }

    if (source_exists && dest_exists) {
        return {RecoveryOutcome::HaltOperatorRepair,
                "Both source and destination exist for PREPARED operation. "
                "Operator repair required."};
    }

    // Neither exists — for CloseActive this is ambiguous.
    if (rec.operation == JournalOperation::CloseActive && !source_exists) {
        return {RecoveryOutcome::HaltOperatorRepair,
                "Active file missing during PREPARED CloseActive. "
                "Operator repair required."};
    }

    return {RecoveryOutcome::HaltOperatorRepair,
            "Neither source nor destination exist. "
            "Operator repair required."};
}

RecoveryResult RotationEngine::RecoverCompleted(const JournalRecord& rec) {
    // COMPLETED: verify postconditions.
    if (rec.operation == JournalOperation::RotationComplete) {
        // All done — clear journal.
        auto r = journal_.ClearJournal();
        if (!r.ok)
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Cannot clear journal: " + r.error};
        return {RecoveryOutcome::Recovered,
                "Rotation was already complete. Journal cleared."};
    }

    if (rec.operation == JournalOperation::CloseActive) {
        // Active should still exist (just flushed/closed).
        return {RecoveryOutcome::Recovered, "Close-active already completed."};
    }

    if (rec.operation == JournalOperation::RetireArchive3) {
        // .3 should be absent.
        if (fs_.FileExists(ArchivePath(3))) {
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Archive.3 still exists after COMPLETED retirement."};
        }
        return {RecoveryOutcome::Recovered,
                "Archive.3 retirement already completed."};
    }

    if (rec.operation == JournalOperation::CreateActive) {
        if (!fs_.FileExists(rec.destination_path)) {
            return {RecoveryOutcome::HaltOperatorRepair,
                    "Active file missing after COMPLETED creation."};
        }
        return {RecoveryOutcome::Recovered,
                "Active file creation already completed."};
    }

    // Move operations: source should be absent, dest should exist.
    if (!rec.source_path.empty() && fs_.FileExists(rec.source_path)) {
        return {RecoveryOutcome::HaltOperatorRepair,
                "Source still exists after COMPLETED move. "
                "Operator repair required."};
    }
    if (!rec.destination_path.empty()
        && !fs_.FileExists(rec.destination_path)) {
        return {RecoveryOutcome::HaltOperatorRepair,
                "Destination missing after COMPLETED move. "
                "Operator repair required."};
    }

    return {RecoveryOutcome::Recovered,
            "Completed operation postconditions verified."};
}

RecoveryResult RotationEngine::RecoverAbsent(const JournalRecord& rec) {
    // ABSENT: verify source remains absent.
    if (!rec.source_path.empty() && fs_.FileExists(rec.source_path)) {
        return {RecoveryOutcome::HaltOperatorRepair,
                "Source exists for ABSENT record. Operator repair required."};
    }
    return {RecoveryOutcome::Recovered,
            "Absent record verified (source remains absent)."};
}

} // namespace consent_monitor
