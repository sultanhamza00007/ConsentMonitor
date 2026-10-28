// ConsentMonitor — event_schema.cpp
// Diagnostic event schema implementation.
#include "consent_monitor/event_schema.hpp"
#include "consent_monitor/canonical_json.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace consent_monitor {
namespace {

/// Generate an ISO 8601 UTC timestamp string for the current time.
std::string utc_now_iso8601() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &time_t_now);
#else
    gmtime_r(&time_t_now, &tm_buf);
#endif
    // Extract milliseconds
    auto since_epoch = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
        since_epoch).count() % 1000;

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << millis
        << 'Z';
    return oss.str();
}

/// Check if the given uint8_t value is a valid EventType enumerator.
bool is_valid_event_type(EventType t) {
    switch (t) {
        case EventType::AppStart:
        case EventType::AppStop:
        case EventType::ConsentGranted:
        case EventType::ConsentPaused:
        case EventType::ConsentStopped:
        case EventType::ConsentRevoked:
        case EventType::NetworkAttemptSuccess:
        case EventType::NetworkAttemptFailure:
        case EventType::StorageError:
        case EventType::StorageRotation:
        case EventType::OperationDuration:
            return true;
    }
    return false;
}

} // anonymous namespace

std::string event_type_to_string(EventType t) {
    switch (t) {
        case EventType::AppStart:              return "AppStart";
        case EventType::AppStop:               return "AppStop";
        case EventType::ConsentGranted:        return "ConsentGranted";
        case EventType::ConsentPaused:         return "ConsentPaused";
        case EventType::ConsentStopped:        return "ConsentStopped";
        case EventType::ConsentRevoked:        return "ConsentRevoked";
        case EventType::NetworkAttemptSuccess: return "NetworkAttemptSuccess";
        case EventType::NetworkAttemptFailure: return "NetworkAttemptFailure";
        case EventType::StorageError:          return "StorageError";
        case EventType::StorageRotation:       return "StorageRotation";
        case EventType::OperationDuration:     return "OperationDuration";
    }
    return "Unknown";
}

std::string serialize_event(const EventRecord& rec) {
    CanonicalJsonObject obj;
    obj.set("app_version",     rec.app_version);
    obj.set("duration_ms",     uint64_t(rec.duration_ms));
    obj.set("event_type",      event_type_to_string(rec.event_type));
    obj.set("os_build",        rec.os_build);
    obj.set("result_category", rec.result_category);
    obj.set("utc_time",        rec.utc_time);
    return obj.serialize();
}

Result<EventRecord> create_event(EventType type,
                                 std::string result_cat,
                                 uint32_t duration_ms) {
    if (!is_valid_event_type(type)) {
        return Result<EventRecord>::failure("unknown event type");
    }
    if (result_cat.empty()) {
        return Result<EventRecord>::failure("result_category must not be empty");
    }

    EventRecord rec;
    rec.utc_time        = utc_now_iso8601();
    rec.event_type      = type;
    rec.app_version     = std::string(kAppVersion);
    rec.os_build        = "0.0.0";  // placeholder until real OS query
    rec.result_category = std::move(result_cat);
    rec.duration_ms     = duration_ms;

    return Result<EventRecord>::success(std::move(rec));
}

bool validate_event(const EventRecord& rec) {
    // Must have a valid event type
    if (!is_valid_event_type(rec.event_type))
        return false;

    // Must have a non-empty timestamp
    if (rec.utc_time.empty())
        return false;

    // Must have a non-empty app version
    if (rec.app_version.empty())
        return false;

    // Must have a non-empty OS build
    if (rec.os_build.empty())
        return false;

    // Must have a non-empty result category
    if (rec.result_category.empty())
        return false;

    // Duration sanity: allow 0 through a reasonable upper bound (1 hour).
    if (rec.duration_ms > 3'600'000u)
        return false;

    return true;
}

} // namespace consent_monitor
