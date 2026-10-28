// ConsentMonitor — test_canonical_json.cpp
// Tests for RFC 8785 canonical JSON serializer.
#include "consent_monitor/canonical_json.hpp"
#include "test_framework.hpp"

#include <string>

int main() {
    using namespace consent_monitor;

    cm_test::Suite suite("Canonical JSON (RFC 8785 subset)");

    suite.add("empty object", [] {
        CanonicalJsonObject obj;
        ASSERT_EQ(obj.serialize(), std::string("{}"));
    });

    suite.add("key ordering (lexicographic)", [] {
        CanonicalJsonObject obj;
        obj.set("zebra", std::string("z"));
        obj.set("alpha", std::string("a"));
        obj.set("middle", std::string("m"));
        auto json = obj.serialize();
        // Keys must appear in order: alpha, middle, zebra
        ASSERT_EQ(json, std::string(R"({"alpha":"a","middle":"m","zebra":"z"})"));
    });

    suite.add("string value escaping: backslash", [] {
        CanonicalJsonObject obj;
        obj.set("path", std::string("C:\\Users\\test"));
        auto json = obj.serialize();
        ASSERT_EQ(json, std::string(R"({"path":"C:\\Users\\test"})"));
    });

    suite.add("string value escaping: double quote", [] {
        CanonicalJsonObject obj;
        obj.set("msg", std::string("say \"hello\""));
        auto json = obj.serialize();
        ASSERT_EQ(json, std::string(R"({"msg":"say \"hello\""})"));
    });

    suite.add("string value escaping: control chars", [] {
        CanonicalJsonObject obj;
        obj.set("ctl", std::string("\b\f\n\r\t"));
        auto json = obj.serialize();
        ASSERT_EQ(json, std::string(R"({"ctl":"\b\f\n\r\t"})"));
    });

    suite.add("string value escaping: NUL and other low control chars", [] {
        CanonicalJsonObject obj;
        // \x00 would truncate string_view, use explicit std::string ctor
        std::string val;
        val.push_back('\x00');
        val.push_back('\x01');
        val.push_back('\x1f');
        obj.set("low", std::move(val));
        auto json = obj.serialize();
        ASSERT_EQ(json, std::string(R"({"low":"\u0000\u0001\u001f"})"));
    });

    suite.add("integer formatting: positive int64_t", [] {
        CanonicalJsonObject obj;
        obj.set("num", int64_t(42));
        auto json = obj.serialize();
        ASSERT_EQ(json, std::string(R"({"num":42})"));
    });

    suite.add("integer formatting: negative int64_t", [] {
        CanonicalJsonObject obj;
        obj.set("neg", int64_t(-100));
        auto json = obj.serialize();
        ASSERT_EQ(json, std::string(R"({"neg":-100})"));
    });

    suite.add("integer formatting: zero int64_t", [] {
        CanonicalJsonObject obj;
        obj.set("z", int64_t(0));
        auto json = obj.serialize();
        ASSERT_EQ(json, std::string(R"({"z":0})"));
    });

    suite.add("integer formatting: uint64_t", [] {
        CanonicalJsonObject obj;
        obj.set("big", uint64_t(18446744073709551615ULL));
        auto json = obj.serialize();
        ASSERT_EQ(json, std::string(R"({"big":18446744073709551615})"));
    });

    suite.add("no whitespace between tokens", [] {
        CanonicalJsonObject obj;
        obj.set("a", int64_t(1));
        obj.set("b", std::string("two"));
        auto json = obj.serialize();
        // Verify no spaces, tabs, newlines
        for (auto ch : json) {
            ASSERT_NE(ch, ' ');
            ASSERT_NE(ch, '\n');
            ASSERT_NE(ch, '\t');
        }
    });

    suite.add("serialize_without omits specified key", [] {
        CanonicalJsonObject obj;
        obj.set("checksum", uint64_t(12345));
        obj.set("data", std::string("payload"));
        obj.set("type", std::string("event"));

        auto without = obj.serialize_without("checksum");
        ASSERT_EQ(without, std::string(R"({"data":"payload","type":"event"})"));

        // Full serialize should include it
        auto full = obj.serialize();
        ASSERT_EQ(full, std::string(R"({"checksum":12345,"data":"payload","type":"event"})"));
    });

    suite.add("serialize_without with non-existent key", [] {
        CanonicalJsonObject obj;
        obj.set("a", int64_t(1));
        auto without = obj.serialize_without("nonexistent");
        auto full = obj.serialize();
        ASSERT_EQ(without, full);
    });

    suite.add("overwrite existing key", [] {
        CanonicalJsonObject obj;
        obj.set("key", std::string("old"));
        obj.set("key", std::string("new"));
        ASSERT_EQ(obj.serialize(), std::string(R"({"key":"new"})"));
    });

    return suite.run();
}
