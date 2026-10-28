// ConsentMonitor — journal_engine.cpp
// Persistence engine for the rotation journal state machine.

#include <consent_monitor/journal_engine.hpp>

#include <charconv>
#include <sstream>
#include <stdexcept>

namespace consent_monitor {

// ─── Simple JSON value extractor (no full parser needed) ────────────────────
// Extracts a string value for a given key from a flat JSON object string.
static std::string extract_string(const std::string& json,
                                  const std::string& key) {
    std::string needle = "\"" + key + "\":\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    std::string result;
    for (size_t i = pos; i < json.size(); ++i) {
        if (json[i] == '\\' && i + 1 < json.size()) {
            result += json[++i];
        } else if (json[i] == '"') {
            break;
        } else {
            result += json[i];
        }
    }
    return result;
}

// Extracts a uint64 value for a given key from a flat JSON object string.
static uint64_t extract_uint64(const std::string& json,
                               const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    // Skip any whitespace (canonical JSON shouldn't have any, but be safe).
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    uint64_t val = 0;
    auto [ptr, ec] = std::from_chars(json.data() + pos,
                                     json.data() + json.size(), val);
    if (ec != std::errc{}) return 0;
    return val;
}

// ─── Construction ───────────────────────────────────────────────────────────

JournalEngine::JournalEngine(IFilesystem& fs, std::string base_dir)
    : fs_(fs), base_dir_(std::move(base_dir)) {}

// ─── Paths ──────────────────────────────────────────────────────────────────

std::string JournalEngine::JournalPath() const {
    return base_dir_ + "/rotation_journal.json";
}

std::string JournalEngine::TempPath(const std::string& rotation_id,
                                    uint64_t seq) const {
    return base_dir_ + "/rotation_journal." + rotation_id + "."
           + std::to_string(seq) + ".tmp";
}

// ─── Sequence Management ────────────────────────────────────────────────────

Result<uint64_t> JournalEngine::GetLastValidSequence() {
    if (!fs_.FileExists(JournalPath())) {
        last_valid_seq_ = 0;
        return Result<uint64_t>::success(0);
    }
    auto read_r = ReadCurrentJournal();
    if (!read_r.ok) {
        return Result<uint64_t>::failure(
            "Cannot determine last sequence: " + read_r.error);
    }
    last_valid_seq_ = read_r.value.journal_seq;
    return Result<uint64_t>::success(last_valid_seq_);
}

uint64_t JournalEngine::NextSequence() {
    return last_valid_seq_ + 1;
}

// ─── Serialization ──────────────────────────────────────────────────────────

std::string JournalEngine::SerializeRecord(const JournalRecord& rec) {
    CanonicalJsonObject obj;
    obj.set("checksum",           static_cast<uint64_t>(0)); // placeholder
    obj.set("destination_path",   rec.destination_path);
    obj.set("expected_identity",  rec.expected_identity);
    obj.set("journal_seq",        rec.journal_seq);
    obj.set("operation",          operation_to_string(rec.operation));
    obj.set("phase",              phase_to_string(rec.phase));
    obj.set("rotation_id",        rec.rotation_id);
    obj.set("schema_version",     static_cast<uint64_t>(rec.schema_version));
    obj.set("source_path",        rec.source_path);

    // Compute checksum over canonical JSON with checksum field omitted.
    std::string without_checksum = obj.serialize_without("checksum");
    uint32_t csum = crc32(without_checksum);

    // Now set the real checksum and serialize again.
    obj.set("checksum", static_cast<uint64_t>(csum));
    return obj.serialize();
}

// ─── Parsing ────────────────────────────────────────────────────────────────

Result<JournalRecord> JournalEngine::ParseJournal(const std::string& content) {
    // Minimal parse of our known canonical JSON format.
    JournalRecord rec;

    try {
        rec.schema_version   = static_cast<uint32_t>(
                                   extract_uint64(content, "schema_version"));
        rec.rotation_id      = extract_string(content, "rotation_id");
        rec.journal_seq      = extract_uint64(content, "journal_seq");
        rec.source_path      = extract_string(content, "source_path");
        rec.destination_path = extract_string(content, "destination_path");
        rec.expected_identity= extract_string(content, "expected_identity");
        rec.checksum         = static_cast<uint32_t>(
                                   extract_uint64(content, "checksum"));

        std::string op_str  = extract_string(content, "operation");
        std::string ph_str  = extract_string(content, "phase");

        if (op_str.empty() || ph_str.empty())
            return Result<JournalRecord>::failure("Missing operation or phase");

        rec.operation = string_to_operation(op_str);
        rec.phase     = string_to_phase(ph_str);
    } catch (const std::exception& e) {
        return Result<JournalRecord>::failure(
            std::string("Parse error: ") + e.what());
    }

    if (rec.schema_version != 1)
        return Result<JournalRecord>::failure(
            "Unsupported schema version: "
            + std::to_string(rec.schema_version));

    // Validate checksum.
    if (!ValidateChecksum(rec, content))
        return Result<JournalRecord>::failure("Checksum mismatch");

    // Enforce strict canonical JSON formatting: rejects trailing garbage, unexpected keys, and syntax corruption
    std::string canonical_expected = SerializeRecord(rec);
    if (content != canonical_expected) {
        return Result<JournalRecord>::failure(
            "Journal content is corrupt, non-canonical, or contains unexpected keys");
    }

    return Result<JournalRecord>::success(rec);
}

bool JournalEngine::ValidateChecksum(const JournalRecord& rec,
                                     const std::string& json_content) {
    (void)json_content;
    // Re-serialize without checksum to compute expected CRC-32.
    CanonicalJsonObject obj;
    obj.set("destination_path",   rec.destination_path);
    obj.set("expected_identity",  rec.expected_identity);
    obj.set("journal_seq",        rec.journal_seq);
    obj.set("operation",          operation_to_string(rec.operation));
    obj.set("phase",              phase_to_string(rec.phase));
    obj.set("rotation_id",        rec.rotation_id);
    obj.set("schema_version",     static_cast<uint64_t>(rec.schema_version));
    obj.set("source_path",        rec.source_path);

    std::string without_checksum = obj.serialize();
    uint32_t expected = crc32(without_checksum);
    return rec.checksum == expected;
}

// ─── Read current journal ───────────────────────────────────────────────────

Result<JournalRecord> JournalEngine::ReadCurrentJournal() {
    auto read_r = fs_.ReadFile(JournalPath());
    if (!read_r.ok)
        return Result<JournalRecord>::failure("Cannot read journal: " + read_r.error);
    return ParseJournal(read_r.value);
}

// ─── Persist Snapshots ──────────────────────────────────────────────────────

Result<void> JournalEngine::PersistSnapshot(JournalRecord rec) {
    uint64_t seq = NextSequence();
    rec.journal_seq = seq;

    std::string json = SerializeRecord(rec);
    std::string temp = TempPath(rec.rotation_id, seq);

    // 1. Write to temp file.
    auto write_r = fs_.WriteFile(temp, json);
    if (!write_r.ok)
        return Result<void>::failure("Failed to write temp journal: " + write_r.error);

    // 2. Flush temp file.
    auto flush_r = fs_.FlushFile(temp);
    if (!flush_r.ok)
        return Result<void>::failure("Failed to flush temp journal: " + flush_r.error);

    // 3. Replace main journal with temp.
    auto move_r = fs_.MoveFile(temp, JournalPath(), /*replace_existing=*/true);
    if (!move_r.ok) {
        // Temp file is preserved on failure — halt safely.
        return Result<void>::failure(
            "Failed to replace journal (temp preserved at "
            + temp + "): " + move_r.error);
    }

    // 4. Successfully persisted — update last_valid_seq.
    last_valid_seq_ = seq;
    return Result<void>::success();
}

Result<void> JournalEngine::PersistPrepared(JournalRecord rec) {
    rec.phase = JournalPhase::Prepared;
    return PersistSnapshot(std::move(rec));
}

Result<void> JournalEngine::PersistCompleted(JournalRecord rec) {
    rec.phase = JournalPhase::Completed;
    return PersistSnapshot(std::move(rec));
}

Result<void> JournalEngine::PersistAbsent(JournalRecord rec) {
    rec.phase = JournalPhase::Absent;
    return PersistSnapshot(std::move(rec));
}

Result<void> JournalEngine::ClearJournal() {
    if (!fs_.FileExists(JournalPath()))
        return Result<void>::success();
    return fs_.DeleteFile(JournalPath());
}

} // namespace consent_monitor
