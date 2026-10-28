// ConsentMonitor — test_rotation_engine.cpp
// Tests for RotationEngine: ordered rotation sequence, archive shifting,
// and comprehensive crash recovery state machine.

#include "test_framework.hpp"
#include <consent_monitor/filesystem_interface.hpp>
#include <consent_monitor/journal_engine.hpp>
#include <consent_monitor/rotation_engine.hpp>

using namespace consent_monitor;

int main() {
    cm_test::Suite suite("Rotation Engine & Crash Recovery State Machine");

    // 1. Full clean rotation from fresh state
    suite.add("Full clean rotation from active file", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        // Set up active file
        fs.WriteFile("/logs/active.log", "Event payload 1\n");

        auto r = engine.PerformRotation("rot-001");
        ASSERT_TRUE(r.ok);

        // active.log must be freshly created (empty)
        ASSERT_TRUE(fs.FileExists("/logs/active.log"));
        auto active_content = fs.ReadFile("/logs/active.log");
        ASSERT_TRUE(active_content.ok);
        ASSERT_EQ(active_content.value, std::string(""));

        // archive.1 must contain the previous active content
        ASSERT_TRUE(fs.FileExists("/logs/archive.1"));
        auto a1_content = fs.ReadFile("/logs/archive.1");
        ASSERT_TRUE(a1_content.ok);
        ASSERT_EQ(a1_content.value, std::string("Event payload 1\n"));

        // Staging and journal must be gone
        ASSERT_FALSE(fs.FileExists("/logs/active.log.staging"));
        ASSERT_FALSE(fs.FileExists(journal.JournalPath()));
    });

    // 2. Archive shifting: 1->2, 2->3, 3 retired
    suite.add("Archive shifting and retirement of .3", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        fs.WriteFile("/logs/active.log", "active\n");
        fs.WriteFile("/logs/archive.1",  "arch1\n");
        fs.WriteFile("/logs/archive.2",  "arch2\n");
        fs.WriteFile("/logs/archive.3",  "arch3_retire\n");

        auto r = engine.PerformRotation("rot-002");
        ASSERT_TRUE(r.ok);

        ASSERT_EQ(fs.ReadFile("/logs/archive.1").value, std::string("active\n"));
        ASSERT_EQ(fs.ReadFile("/logs/archive.2").value, std::string("arch1\n"));
        ASSERT_EQ(fs.ReadFile("/logs/archive.3").value, std::string("arch2\n"));
    });

    // 3. Recovery: Clean layout with no journal
    suite.add("Recovery: Clean layout with no journal", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        fs.WriteFile("/logs/active.log", "data\n");
        auto rec = engine.PerformRecovery();
        ASSERT_EQ(rec.outcome, RecoveryOutcome::Clean);
    });

    // 4. Recovery: Archive gaps preserved without renumbering
    suite.add("Recovery: Archive gaps preserved without renumbering", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        fs.WriteFile("/logs/active.log", "data\n");
        fs.WriteFile("/logs/archive.2",  "gap_arch2\n"); // archive.1 absent

        auto rec = engine.PerformRecovery();
        ASSERT_EQ(rec.outcome, RecoveryOutcome::Clean);
        ASSERT_FALSE(fs.FileExists("/logs/archive.1"));
        ASSERT_TRUE(fs.FileExists("/logs/archive.2"));
    });

    // 5. Recovery: Multiple temp journals halt without cleanup
    suite.add("Recovery: Multiple temp journals halt without cleanup", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        fs.WriteFile("/logs/rotation_journal.rot1.1.tmp", "temp1");
        fs.WriteFile("/logs/rotation_journal.rot1.2.tmp", "temp2");

        auto rec = engine.PerformRecovery();
        ASSERT_EQ(rec.outcome, RecoveryOutcome::HaltOperatorRepair);
        // Files must be preserved for operator inspection
        ASSERT_TRUE(fs.FileExists("/logs/rotation_journal.rot1.1.tmp"));
        ASSERT_TRUE(fs.FileExists("/logs/rotation_journal.rot1.2.tmp"));
    });

    // 6. Recovery: Unique valid CLOSE_ACTIVE / PREPARED temp promoted
    suite.add("Recovery: Unique valid CLOSE_ACTIVE / PREPARED temp promoted", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        fs.WriteFile("/logs/active.log", "active_data\n");

        JournalRecord rec;
        rec.rotation_id = "rot-rec";
        rec.journal_seq = 1;
        rec.operation = JournalOperation::CloseActive;
        rec.phase = JournalPhase::Prepared;
        rec.source_path = "/logs/active.log";

        std::string json = journal.SerializeRecord(rec);
        fs.WriteFile("/logs/rotation_journal.rot-rec.1.tmp", json);

        auto outcome = engine.PerformRecovery();
        ASSERT_EQ(outcome.outcome, RecoveryOutcome::Recovered);
        // Temp promoted to journal
        ASSERT_TRUE(fs.FileExists(journal.JournalPath()));
    });

    // 7. Recovery: RetireArchive3 / PREPARED when .3 is already absent
    suite.add("Recovery: RetireArchive3 / PREPARED when .3 already absent", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-retire";
        rec.journal_seq = 1;
        rec.operation = JournalOperation::RetireArchive3;
        rec.phase = JournalPhase::Prepared;
        rec.source_path = "/logs/archive.3";

        std::string json = journal.SerializeRecord(rec);
        fs.WriteFile(journal.JournalPath(), json);

        // archive.3 is absent
        auto outcome = engine.PerformRecovery();
        ASSERT_EQ(outcome.outcome, RecoveryOutcome::Recovered);
        ASSERT_TRUE(outcome.message.find("Archive.3 retirement confirmed") != std::string::npos);
    });

    // 8. Recovery: MoveToStaging PREPARED with source present -> performs move
    suite.add("Recovery: MoveToStaging PREPARED with source present", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        fs.WriteFile("/logs/active.log", "data_to_stage\n");

        JournalRecord rec;
        rec.rotation_id = "rot-move";
        rec.journal_seq = 1;
        rec.operation = JournalOperation::MoveToStaging;
        rec.phase = JournalPhase::Prepared;
        rec.source_path = "/logs/active.log";
        rec.destination_path = "/logs/active.log.staging";

        std::string json = journal.SerializeRecord(rec);
        fs.WriteFile(journal.JournalPath(), json);

        auto outcome = engine.PerformRecovery();
        ASSERT_EQ(outcome.outcome, RecoveryOutcome::Recovered);
        ASSERT_FALSE(fs.FileExists("/logs/active.log"));
        ASSERT_TRUE(fs.FileExists("/logs/active.log.staging"));
    });

    // 9. Recovery: MoveToStaging PREPARED when already moved -> completed
    suite.add("Recovery: MoveToStaging PREPARED when already moved", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        // source absent, destination present
        fs.WriteFile("/logs/active.log.staging", "already_staged\n");

        JournalRecord rec;
        rec.rotation_id = "rot-staged";
        rec.journal_seq = 1;
        rec.operation = JournalOperation::MoveToStaging;
        rec.phase = JournalPhase::Prepared;
        rec.source_path = "/logs/active.log";
        rec.destination_path = "/logs/active.log.staging";

        std::string json = journal.SerializeRecord(rec);
        fs.WriteFile(journal.JournalPath(), json);

        auto outcome = engine.PerformRecovery();
        ASSERT_EQ(outcome.outcome, RecoveryOutcome::Recovered);
        ASSERT_TRUE(fs.FileExists("/logs/active.log.staging"));
    });

    // 10. Recovery: Ambiguous state (both source and dest exist) halts
    suite.add("Recovery: Ambiguous state (both source and dest exist) halts", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        fs.WriteFile("/logs/active.log", "active\n");
        fs.WriteFile("/logs/active.log.staging", "staging\n");

        JournalRecord rec;
        rec.rotation_id = "rot-ambig";
        rec.journal_seq = 1;
        rec.operation = JournalOperation::MoveToStaging;
        rec.phase = JournalPhase::Prepared;
        rec.source_path = "/logs/active.log";
        rec.destination_path = "/logs/active.log.staging";

        std::string json = journal.SerializeRecord(rec);
        fs.WriteFile(journal.JournalPath(), json);

        auto outcome = engine.PerformRecovery();
        ASSERT_EQ(outcome.outcome, RecoveryOutcome::HaltOperatorRepair);
    });

    // 11. Recovery: RotationComplete clears journal
    suite.add("Recovery: RotationComplete clears journal", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-done";
        rec.journal_seq = 10;
        rec.operation = JournalOperation::RotationComplete;
        rec.phase = JournalPhase::Completed;

        std::string json = journal.SerializeRecord(rec);
        fs.WriteFile(journal.JournalPath(), json);

        auto outcome = engine.PerformRecovery();
        ASSERT_EQ(outcome.outcome, RecoveryOutcome::Recovered);
        ASSERT_FALSE(fs.FileExists(journal.JournalPath()));
    });

    // 12. Recovery: Destination identity mismatch halts
    suite.add("Recovery: Destination identity mismatch halts", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        // Destination exists but with unexpected identity
        fs.WriteFile("/logs/active.log.staging", "unexpected_corrupt_content");

        JournalRecord rec;
        rec.rotation_id = "rot-id-mismatch";
        rec.journal_seq = 1;
        rec.operation = JournalOperation::MoveToStaging;
        rec.phase = JournalPhase::Prepared;
        rec.source_path = "/logs/active.log";
        rec.destination_path = "/logs/active.log.staging";
        rec.expected_identity = "expected_hash_999";

        std::string json = journal.SerializeRecord(rec);
        fs.WriteFile(journal.JournalPath(), json);

        auto outcome = engine.PerformRecovery();
        ASSERT_EQ(outcome.outcome, RecoveryOutcome::HaltOperatorRepair);
        ASSERT_TRUE(outcome.message.find("Destination identity mismatch") != std::string::npos);
    });

    // 13. Recovery: Source identity mismatch halts
    suite.add("Recovery: Source identity mismatch halts", [] {
        InMemoryFilesystem fs;
        JournalEngine journal(fs, "/logs");
        RotationEngine engine(fs, journal, "/logs");

        // Source exists but with unexpected identity
        fs.WriteFile("/logs/active.log", "tampered_source");

        JournalRecord rec;
        rec.rotation_id = "rot-src-mismatch";
        rec.journal_seq = 1;
        rec.operation = JournalOperation::MoveToStaging;
        rec.phase = JournalPhase::Prepared;
        rec.source_path = "/logs/active.log";
        rec.destination_path = "/logs/active.log.staging";
        rec.expected_identity = "expected_hash_original";

        std::string json = journal.SerializeRecord(rec);
        fs.WriteFile(journal.JournalPath(), json);

        auto outcome = engine.PerformRecovery();
        ASSERT_EQ(outcome.outcome, RecoveryOutcome::HaltOperatorRepair);
        ASSERT_TRUE(outcome.message.find("Source identity mismatch") != std::string::npos);
    });

    return suite.run();
}
