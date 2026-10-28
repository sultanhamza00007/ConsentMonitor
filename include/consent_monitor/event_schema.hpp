// ConsentMonitor — event_schema.hpp
// Strictly allowlisted diagnostic event schema.
// CRITICAL: No keystrokes, window titles, clipboard, credentials, usernames,
// device IDs, arbitrary paths, or user content are permitted in this schema.
#pragma once

#include "consent_monitor/common.hpp"

#include <cstdint>
#include <string>

namespace consent_monitor {

/// Exhaustive enumeration of permitted diagnostic event types.
enum class EventType : uint8_t {
    AppStart,
    AppStop,
    ConsentGranted,
    ConsentPaused,
    ConsentStopped,
    ConsentRevoked,
    NetworkAttemptSuccess,
    NetworkAttemptFailure,
    StorageError,
    StorageRotation,
    OperationDuration
};

/// Fixed, bounded diagnostic event record.
/// Contains ONLY the fields listed here — no extension points.
struct EventRecord {
    std::string utc_time;          ///< ISO 8601 UTC timestamp
    EventType   event_type;        ///< Allowlisted event category
    std::string app_version;       ///< From common.hpp kAppVersion
    std::string os_build;          ///< e.g. "26100.1234"
    std::string result_category;   ///< Bounded error/result category
    uint32_t    duration_ms = 0;   ///< Bounded operation duration (ms)
};

/// Convert an EventType to its canonical string name.
std::string event_type_to_string(EventType t);

/// Serialize an EventRecord to JSON with ONLY the allowed fields.
/// No additional fields are ever emitted.
std::string serialize_event(const EventRecord& rec);

/// Factory: create an EventRecord with current UTC time, app version,
/// and placeholder OS build. Validates inputs.
Result<EventRecord> create_event(EventType type,
                                 std::string result_cat,
                                 uint32_t duration_ms);

/// Validate that all fields of an EventRecord are within allowed bounds.
bool validate_event(const EventRecord& rec);

} // namespace consent_monitor
