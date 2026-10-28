// ConsentMonitor — journal_engine.hpp
// Persistence engine for the rotation journal state machine.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <consent_monitor/canonical_json.hpp>
#include <consent_monitor/common.hpp>
#include <consent_monitor/crc32.hpp>
#include <consent_monitor/filesystem_interface.hpp>
#include <consent_monitor/journal_types.hpp>

#include <cstdint>
#include <string>

namespace consent_monitor {

class JournalEngine {
public:
    /// Construct with a filesystem implementation and a base directory path.
    JournalEngine(IFilesystem& fs, std::string base_dir);

    /// Return the last valid persisted sequence number (0 if no journal).
    Result<uint64_t> GetLastValidSequence();

    /// Next sequence = last_valid + 1.
    uint64_t NextSequence();

    /// Persist a PREPARED snapshot: write temp, flush, replace journal.
    Result<void> PersistPrepared(JournalRecord rec);

    /// Persist a COMPLETED snapshot.
    Result<void> PersistCompleted(JournalRecord rec);

    /// Persist an ABSENT snapshot.
    Result<void> PersistAbsent(JournalRecord rec);

    /// Delete the journal file after rotation completes.
    Result<void> ClearJournal();

    /// Read and parse the current journal file.
    Result<JournalRecord> ReadCurrentJournal();

    /// Parse raw JSON content into a JournalRecord, validate checksum.
    Result<JournalRecord> ParseJournal(const std::string& content);

    /// Serialize a JournalRecord to canonical JSON with computed checksum.
    std::string SerializeRecord(const JournalRecord& rec);

    /// Verify the CRC-32 checksum of a record against its JSON content.
    bool ValidateChecksum(const JournalRecord& rec,
                          const std::string& json_content);

    /// Path to the main journal file.
    std::string JournalPath() const;

    /// Path to a temp journal file for a given rotation_id and sequence.
    std::string TempPath(const std::string& rotation_id, uint64_t seq) const;

private:
    /// Core persist logic shared by Prepared/Completed/Absent.
    Result<void> PersistSnapshot(JournalRecord rec);

    IFilesystem& fs_;
    std::string  base_dir_;
    uint64_t     last_valid_seq_{0};
};

} // namespace consent_monitor
