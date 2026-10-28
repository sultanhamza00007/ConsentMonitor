// ConsentMonitor — canonical_json.hpp
// Minimal RFC 8785 (JCS) canonical JSON serializer for journal records.
// Only supports the subset needed by the consent-monitor schema:
// string, int64_t, and uint64_t values with ASCII keys.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <variant>

namespace consent_monitor {

class CanonicalJsonObject {
public:
    /// Set a string-valued member.
    void set(std::string key, std::string value);

    /// Set a signed integer-valued member.
    void set(std::string key, int64_t value);

    /// Set an unsigned integer-valued member.
    void set(std::string key, uint64_t value);

    /// Produce RFC 8785 canonical JSON serialization.
    [[nodiscard]] std::string serialize() const;

    /// Produce canonical JSON with the named key omitted
    /// (used to compute checksum over payload minus checksum field).
    [[nodiscard]] std::string serialize_without(std::string_view omit_key) const;

private:
    using Value = std::variant<std::string, int64_t, uint64_t>;

    // std::map keeps keys in lexicographic (byte) order, which for ASCII
    // keys matches the RFC 8785 requirement (lexicographic on UTF-16 code
    // units).
    std::map<std::string, Value> members_;

    /// Escape a JSON string per RFC 8259 §7 and RFC 8785 requirements.
    static std::string escape_string(std::string_view s);

    /// Serialize a single value.
    static std::string serialize_value(const Value& v);
};

} // namespace consent_monitor
