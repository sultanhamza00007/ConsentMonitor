// ConsentMonitor — test_event_schema.cpp
// Tests for the diagnostic event schema module.
#include "consent_monitor/event_schema.hpp"
#include "test_framework.hpp"

#include <cstdint>
#include <string>

int main() {
    using namespace consent_monitor;

    cm_test::Suite suite("Event Schema");

    // ── event_type_to_string ────────────────────────────────────────────────

    suite.add("event_type_to_string: all known types", [] {
        ASSERT_EQ(event_type_to_string(EventType::AppStart),              std::string("AppStart"));
        ASSERT_EQ(event_type_to_string(EventType::AppStop),               std::string("AppStop"));
        ASSERT_EQ(event_type_to_string(EventType::ConsentGranted),        std::string("ConsentGranted"));
        ASSERT_EQ(event_type_to_string(EventType::ConsentPaused),         std::string("ConsentPaused"));
        ASSERT_EQ(event_type_to_string(EventType::ConsentStopped),        std::string("ConsentStopped"));
        ASSERT_EQ(event_type_to_string(EventType::ConsentRevoked),        std::string("ConsentRevoked"));
        ASSERT_EQ(event_type_to_string(EventType::NetworkAttemptSuccess), std::string("NetworkAttemptSuccess"));
        ASSERT_EQ(event_type_to_string(EventType::NetworkAttemptFailure), std::string("NetworkAttemptFailure"));
        ASSERT_EQ(event_type_to_string(EventType::StorageError),          std::string("StorageError"));
        ASSERT_EQ(event_type_to_string(EventType::StorageRotation),       std::string("StorageRotation"));
        ASSERT_EQ(event_type_to_string(EventType::OperationDuration),     std::string("OperationDuration"));
    });

    suite.add("event_type_to_string: invalid enum value", [] {
        auto result = event_type_to_string(static_cast<EventType>(255));
        ASSERT_EQ(result, std::string("Unknown"));
    });

    // ── create_event ────────────────────────────────────────────────────────

    suite.add("create_event: success for each type", [] {
        EventType types[] = {
            EventType::AppStart,
            EventType::AppStop,
            EventType::ConsentGranted,
            EventType::ConsentPaused,
            EventType::ConsentStopped,
            EventType::ConsentRevoked,
            EventType::NetworkAttemptSuccess,
            EventType::NetworkAttemptFailure,
            EventType::StorageError,
            EventType::StorageRotation,
            EventType::OperationDuration,
        };
        for (auto t : types) {
            auto r = create_event(t, "success", 0);
            ASSERT_TRUE(r.ok);
            ASSERT_EQ(r.value.event_type, t);
            ASSERT_EQ(r.value.app_version, std::string(kAppVersion));
            ASSERT_FALSE(r.value.utc_time.empty());
            ASSERT_FALSE(r.value.os_build.empty());
        }
    });

    suite.add("create_event: rejects empty result_category", [] {
        auto r = create_event(EventType::AppStart, "", 0);
        ASSERT_FALSE(r.ok);
        ASSERT_FALSE(r.error.empty());
    });

    suite.add("create_event: rejects unknown enum value", [] {
        auto r = create_event(static_cast<EventType>(200), "success", 0);
        ASSERT_FALSE(r.ok);
        ASSERT_FALSE(r.error.empty());
    });

    suite.add("create_event: preserves duration_ms", [] {
        auto r = create_event(EventType::OperationDuration, "success", 1500);
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(r.value.duration_ms, uint32_t(1500));
    });

    // ── validate_event ──────────────────────────────────────────────────────

    suite.add("validate_event: valid record passes", [] {
        auto r = create_event(EventType::AppStart, "success", 100);
        ASSERT_TRUE(r.ok);
        ASSERT_TRUE(validate_event(r.value));
    });

    suite.add("validate_event: empty utc_time fails", [] {
        EventRecord rec;
        rec.utc_time = "";
        rec.event_type = EventType::AppStart;
        rec.app_version = std::string(kAppVersion);
        rec.os_build = "26100.1234";
        rec.result_category = "success";
        rec.duration_ms = 0;
        ASSERT_FALSE(validate_event(rec));
    });

    suite.add("validate_event: empty result_category fails", [] {
        EventRecord rec;
        rec.utc_time = "2026-01-01T00:00:00.000Z";
        rec.event_type = EventType::AppStart;
        rec.app_version = std::string(kAppVersion);
        rec.os_build = "26100.1234";
        rec.result_category = "";
        rec.duration_ms = 0;
        ASSERT_FALSE(validate_event(rec));
    });

    suite.add("validate_event: excessive duration fails", [] {
        EventRecord rec;
        rec.utc_time = "2026-01-01T00:00:00.000Z";
        rec.event_type = EventType::AppStart;
        rec.app_version = std::string(kAppVersion);
        rec.os_build = "26100.1234";
        rec.result_category = "success";
        rec.duration_ms = 4'000'000;  // > 1 hour
        ASSERT_FALSE(validate_event(rec));
    });

    // ── serialize_event ─────────────────────────────────────────────────────

    suite.add("serialize_event: contains only allowed fields", [] {
        auto r = create_event(EventType::AppStart, "success", 0);
        ASSERT_TRUE(r.ok);
        auto json = serialize_event(r.value);

        // Must contain all allowed field keys
        ASSERT_TRUE(json.find("\"utc_time\"") != std::string::npos);
        ASSERT_TRUE(json.find("\"event_type\"") != std::string::npos);
        ASSERT_TRUE(json.find("\"app_version\"") != std::string::npos);
        ASSERT_TRUE(json.find("\"os_build\"") != std::string::npos);
        ASSERT_TRUE(json.find("\"result_category\"") != std::string::npos);
        ASSERT_TRUE(json.find("\"duration_ms\"") != std::string::npos);

        // Must NOT contain prohibited fields
        ASSERT_TRUE(json.find("keystroke") == std::string::npos);
        ASSERT_TRUE(json.find("window_title") == std::string::npos);
        ASSERT_TRUE(json.find("clipboard") == std::string::npos);
        ASSERT_TRUE(json.find("credential") == std::string::npos);
        ASSERT_TRUE(json.find("username") == std::string::npos);
        ASSERT_TRUE(json.find("device_id") == std::string::npos);
        ASSERT_TRUE(json.find("path") == std::string::npos);
        ASSERT_TRUE(json.find("user_content") == std::string::npos);
    });

    suite.add("serialize_event: output is valid canonical JSON (sorted keys, no whitespace)", [] {
        EventRecord rec;
        rec.utc_time = "2026-01-15T12:00:00.000Z";
        rec.event_type = EventType::ConsentGranted;
        rec.app_version = "1.0.0";
        rec.os_build = "26100.1234";
        rec.result_category = "success";
        rec.duration_ms = 0;

        auto json = serialize_event(rec);

        // Expected: keys in alphabetical order, no whitespace
        std::string expected =
            R"({"app_version":"1.0.0","duration_ms":0,"event_type":"ConsentGranted","os_build":"26100.1234","result_category":"success","utc_time":"2026-01-15T12:00:00.000Z"})";
        ASSERT_EQ(json, expected);
    });

    suite.add("serialize_event: each event type serializes", [] {
        EventType types[] = {
            EventType::AppStart,
            EventType::AppStop,
            EventType::ConsentGranted,
            EventType::ConsentPaused,
            EventType::ConsentStopped,
            EventType::ConsentRevoked,
            EventType::NetworkAttemptSuccess,
            EventType::NetworkAttemptFailure,
            EventType::StorageError,
            EventType::StorageRotation,
            EventType::OperationDuration,
        };
        for (auto t : types) {
            auto r = create_event(t, "success", 42);
            ASSERT_TRUE(r.ok);
            auto json = serialize_event(r.value);
            // Must contain the event type string
            auto type_str = event_type_to_string(t);
            ASSERT_TRUE(json.find(type_str) != std::string::npos);
        }
    });

    suite.add("serialize_event: exactly 6 top-level keys", [] {
        auto r = create_event(EventType::StorageError, "disk_full", 0);
        ASSERT_TRUE(r.ok);
        auto json = serialize_event(r.value);

        // Count colons that are key-value separators.
        // In canonical JSON, the pattern `":` indicates a key.
        // We can count occurrences of `":` (quote then colon).
        size_t count = 0;
        for (size_t pos = 0; (pos = json.find("\":", pos)) != std::string::npos; pos += 2) {
            ++count;
        }
        ASSERT_EQ(count, size_t(6));
    });

    return suite.run();
}
