// ConsentMonitor — test_journal_engine.cpp
// Tests for JournalEngine using InMemoryFilesystem and error injection.

#include "test_framework.hpp"
#include <consent_monitor/filesystem_interface.hpp>
#include <consent_monitor/journal_engine.hpp>

using namespace consent_monitor;

int main() {
    cm_test::Suite suite("Journal Engine & Sequence Tracking");

    // 1. Sequence starts at 1 when no journal exists
    suite.add("Sequence starts at 1 when no journal exists", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");
        auto r = engine.GetLastValidSequence();
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(r.value, 0ULL);
        ASSERT_EQ(engine.NextSequence(), 1ULL);
    });

    // 2. PersistPrepared creates journal with seq 1
    suite.add("PersistPrepared creates journal with seq 1", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::CloseActive;
        rec.source_path = "/logs/active.log";

        auto r = engine.PersistPrepared(rec);
        ASSERT_TRUE(r.ok);
        ASSERT_TRUE(fs.FileExists("/logs/rotation_journal.json"));

        auto cur = engine.ReadCurrentJournal();
        ASSERT_TRUE(cur.ok);
        ASSERT_EQ(cur.value.journal_seq, 1ULL);
        ASSERT_EQ(cur.value.operation, JournalOperation::CloseActive);
        ASSERT_EQ(cur.value.phase, JournalPhase::Prepared);
    });

    // 3. Sequence increments by exactly 1 per persisted snapshot
    suite.add("Sequence increments strictly by 1 per snapshot", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::CloseActive;

        engine.PersistPrepared(rec); // seq 1
        ASSERT_EQ(engine.NextSequence(), 2ULL);

        engine.PersistCompleted(rec); // seq 2
        ASSERT_EQ(engine.NextSequence(), 3ULL);

        rec.operation = JournalOperation::MoveToStaging;
        engine.PersistPrepared(rec); // seq 3
        ASSERT_EQ(engine.NextSequence(), 4ULL);

        auto cur = engine.ReadCurrentJournal();
        ASSERT_TRUE(cur.ok);
        ASSERT_EQ(cur.value.journal_seq, 3ULL);
    });

    // 4. PersistAbsent records absent phase
    suite.add("PersistAbsent records absent phase", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::RetireArchive3;
        rec.source_path = "/logs/archive.3";

        auto r = engine.PersistAbsent(rec);
        ASSERT_TRUE(r.ok);

        auto cur = engine.ReadCurrentJournal();
        ASSERT_TRUE(cur.ok);
        ASSERT_EQ(cur.value.phase, JournalPhase::Absent);
    });

    // 5. ClearJournal deletes the journal file
    suite.add("ClearJournal deletes journal file", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::RotationComplete;
        engine.PersistCompleted(rec);

        ASSERT_TRUE(fs.FileExists(engine.JournalPath()));
        auto r = engine.ClearJournal();
        ASSERT_TRUE(r.ok);
        ASSERT_FALSE(fs.FileExists(engine.JournalPath()));
    });

    // 6. Checksum validation passes for valid, fails for tampered
    suite.add("Checksum detects tampered content", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::CloseActive;
        engine.PersistPrepared(rec);

        auto content = fs.ReadFile(engine.JournalPath());
        ASSERT_TRUE(content.ok);

        // Valid parse
        auto parsed = engine.ParseJournal(content.value);
        ASSERT_TRUE(parsed.ok);

        // Tamper with content (change "CloseActive" to "MoveToStaging")
        std::string tampered = content.value;
        auto pos = tampered.find("CloseActive");
        ASSERT_TRUE(pos != std::string::npos);
        tampered.replace(pos, 11, "MoveToStaging");

        auto bad_parse = engine.ParseJournal(tampered);
        ASSERT_FALSE(bad_parse.ok);
        ASSERT_TRUE(bad_parse.error.find("Checksum mismatch") != std::string::npos);
    });

    // 7. Parse rejects unsupported schema version
    suite.add("Parse rejects unsupported schema version", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        JournalRecord rec;
        rec.schema_version = 2; // unsupported
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::CloseActive;

        std::string serialized = engine.SerializeRecord(rec);
        auto parsed = engine.ParseJournal(serialized);
        ASSERT_FALSE(parsed.ok);
        ASSERT_TRUE(parsed.error.find("Unsupported schema version") != std::string::npos);
    });

    // 8. Error injection: write failure halts safely
    suite.add("Error injection: write failure halts safely", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        std::string temp_path = engine.TempPath("rot-001", 1);
        fs.InjectError(temp_path, "write", "Simulated disk full");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::CloseActive;

        auto r = engine.PersistPrepared(rec);
        ASSERT_FALSE(r.ok);
        ASSERT_FALSE(fs.FileExists(engine.JournalPath()));
    });

    // 9. Error injection: move failure preserves temp file
    suite.add("Error injection: move failure preserves temp file", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        std::string temp_path = engine.TempPath("rot-001", 1);
        fs.InjectError(temp_path, "move", "Simulated I/O lock");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::CloseActive;

        auto r = engine.PersistPrepared(rec);
        ASSERT_FALSE(r.ok);
        // Temp file is preserved for recovery investigation
        ASSERT_TRUE(fs.FileExists(temp_path));
        ASSERT_FALSE(fs.FileExists(engine.JournalPath()));
    });

    // 10. Parse rejects trailing garbage after valid JSON
    suite.add("Parse rejects trailing garbage", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::CloseActive;
        std::string valid_json = engine.SerializeRecord(rec);

        std::string with_garbage = valid_json + "\nEXTRA_TRAILING_DATA";
        auto parsed = engine.ParseJournal(with_garbage);
        ASSERT_FALSE(parsed.ok);
    });

    // 11. Parse rejects unexpected extra keys injected into JSON
    suite.add("Parse rejects injected extra keys", [] {
        InMemoryFilesystem fs;
        JournalEngine engine(fs, "/logs");

        JournalRecord rec;
        rec.rotation_id = "rot-001";
        rec.operation = JournalOperation::CloseActive;
        std::string valid_json = engine.SerializeRecord(rec);

        // Inject an extra key before the closing brace
        std::string with_extra = valid_json;
        auto pos = with_extra.rfind('}');
        ASSERT_TRUE(pos != std::string::npos);
        with_extra.insert(pos, ",\"injected_key\":\"malicious_value\"");

        auto parsed = engine.ParseJournal(with_extra);
        ASSERT_FALSE(parsed.ok);
    });

    return suite.run();
}
