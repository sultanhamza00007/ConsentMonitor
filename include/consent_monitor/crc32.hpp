// ConsentMonitor — crc32.hpp
// CRC-32/IEEE checksum for journal integrity verification.
// Polynomial 0xEDB88320 (reflected / LSB-first).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace consent_monitor {

/// Compute CRC-32/IEEE over a raw byte buffer.
uint32_t crc32(const uint8_t* data, size_t len);

/// Convenience overload for string_view.
uint32_t crc32(std::string_view sv);

} // namespace consent_monitor
