// ConsentMonitor — crc32.cpp
// CRC-32/IEEE implementation with precomputed 256-entry lookup table.
#include "consent_monitor/crc32.hpp"

#include <array>

namespace consent_monitor {
namespace {

/// Build the CRC-32 table at compile time (polynomial 0xEDB88320, reflected).
consteval std::array<uint32_t, 256> make_crc_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1u)
                crc = (crc >> 1) ^ 0xEDB88320u;
            else
                crc >>= 1;
        }
        table[i] = crc;
    }
    return table;
}

constexpr auto kCrcTable = make_crc_table();

} // anonymous namespace

uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        uint8_t index = static_cast<uint8_t>(crc ^ data[i]);
        crc = (crc >> 8) ^ kCrcTable[index];
    }
    return crc ^ 0xFFFFFFFFu;
}

uint32_t crc32(std::string_view sv) {
    return crc32(reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
}

} // namespace consent_monitor
