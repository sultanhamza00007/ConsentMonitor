// ConsentMonitor — test_crc32.cpp
// Tests for CRC-32/IEEE implementation.
#include "consent_monitor/crc32.hpp"
#include "test_framework.hpp"

#include <cstdint>
#include <string>
#include <vector>

int main() {
    using namespace consent_monitor;

    cm_test::Suite suite("CRC-32/IEEE");

    suite.add("empty input", [] {
        ASSERT_EQ(crc32(std::string_view("")), uint32_t(0x00000000));
    });

    suite.add("known vector: \"123456789\" -> 0xCBF43926", [] {
        std::string_view input = "123456789";
        ASSERT_EQ(crc32(input), uint32_t(0xCBF43926));
    });

    suite.add("single byte 0x00", [] {
        uint8_t byte = 0x00;
        ASSERT_EQ(crc32(&byte, 1), uint32_t(0xD202EF8D));
    });

    suite.add("single byte 0xFF", [] {
        uint8_t byte = 0xFF;
        ASSERT_EQ(crc32(&byte, 1), uint32_t(0xFF000000));
    });

    suite.add("known vector: \"Hello, World!\"", [] {
        // Well-known CRC-32 for "Hello, World!" is 0xEC4AC3D0
        ASSERT_EQ(crc32(std::string_view("Hello, World!")), uint32_t(0xEC4AC3D0));
    });

    suite.add("buffer overload matches string_view overload", [] {
        std::string data = "test data for crc32";
        auto sv_result = crc32(std::string_view(data));
        auto buf_result = crc32(reinterpret_cast<const uint8_t*>(data.data()),
                                data.size());
        ASSERT_EQ(sv_result, buf_result);
    });

    suite.add("large buffer (4 KiB of 0xAA)", [] {
        std::vector<uint8_t> buf(4096, 0xAA);
        uint32_t result = crc32(buf.data(), buf.size());
        // Just verify it produces a non-zero, deterministic result.
        ASSERT_NE(result, uint32_t(0));

        // Same input → same output (determinism).
        ASSERT_EQ(crc32(buf.data(), buf.size()), result);
    });

    suite.add("different inputs produce different CRCs", [] {
        auto a = crc32(std::string_view("abc"));
        auto b = crc32(std::string_view("abd"));
        ASSERT_NE(a, b);
    });

    return suite.run();
}
