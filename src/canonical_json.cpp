// ConsentMonitor — canonical_json.cpp
// RFC 8785 (JCS) canonical JSON serializer implementation.
#include "consent_monitor/canonical_json.hpp"

#include <sstream>

namespace consent_monitor {

void CanonicalJsonObject::set(std::string key, std::string value) {
    members_.insert_or_assign(std::move(key), Value{std::move(value)});
}

void CanonicalJsonObject::set(std::string key, int64_t value) {
    members_.insert_or_assign(std::move(key), Value{value});
}

void CanonicalJsonObject::set(std::string key, uint64_t value) {
    members_.insert_or_assign(std::move(key), Value{value});
}

std::string CanonicalJsonObject::escape_string(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (unsigned char ch : s) {
        switch (ch) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (ch < 0x20) {
                    // Control characters → \u00XX
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", ch);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    out.push_back('"');
    return out;
}

std::string CanonicalJsonObject::serialize_value(const Value& v) {
    struct Visitor {
        std::string operator()(const std::string& s) const {
            return escape_string(s);
        }
        std::string operator()(int64_t n) const {
            return std::to_string(n);
        }
        std::string operator()(uint64_t n) const {
            return std::to_string(n);
        }
    };
    return std::visit(Visitor{}, v);
}

std::string CanonicalJsonObject::serialize() const {
    std::string out;
    out.push_back('{');
    bool first = true;
    for (const auto& [key, val] : members_) {
        if (!first) out.push_back(',');
        first = false;
        out += escape_string(key);
        out.push_back(':');
        out += serialize_value(val);
    }
    out.push_back('}');
    return out;
}

std::string CanonicalJsonObject::serialize_without(std::string_view omit_key) const {
    std::string out;
    out.push_back('{');
    bool first = true;
    for (const auto& [key, val] : members_) {
        if (key == omit_key) continue;
        if (!first) out.push_back(',');
        first = false;
        out += escape_string(key);
        out.push_back(':');
        out += serialize_value(val);
    }
    out.push_back('}');
    return out;
}

} // namespace consent_monitor
