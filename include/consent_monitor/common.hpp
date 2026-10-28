// ConsentMonitor — common.hpp
// Foundation types shared across all modules.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <cstdint>
#include <chrono>
#include <string>
#include <string_view>
#include <utility>

namespace consent_monitor {

// ─── Application Identity ───────────────────────────────────────────────────
inline constexpr std::string_view kAppName    = "ConsentMonitor";
inline constexpr std::string_view kAppVersion = "1.0.0";

// ─── Platform Baseline ─────────────────────────────────────────────────────
// Supported: 64-bit Windows 11, versions 25H2 and 26H2 on active servicing.
// Primary test platform: 26H2.  Compatibility: 25H2.
// Windows 10 and out-of-servicing releases are excluded.
inline constexpr std::string_view kSupportedOS = "Windows 11 25H2/26H2 (64-bit)";

// ─── Storage Quota Constants (bytes) ────────────────────────────────────────
inline constexpr uint64_t kActiveFileCeiling   =  5'242'880;   // 5 MiB
inline constexpr uint64_t kMaxArchiveCount     =  3;
inline constexpr uint64_t kHardCeiling         = 20'971'520;   // 20 MiB exactly
inline constexpr uint64_t kOrdinaryWriteCap    = 20'905'984;   // 19.9375 MiB
inline constexpr uint64_t kLifecycleReserve    =     65'536;   // 64 KiB

// ─── Timestamp Alias ────────────────────────────────────────────────────────
using Timestamp = std::chrono::system_clock::time_point;

// ─── Generic Result Type ────────────────────────────────────────────────────
template <typename T>
struct Result {
    bool        ok;
    T           value;
    std::string error;

    static Result success(T v)                { return {true,  std::move(v), {}}; }
    static Result failure(std::string msg)    { return {false, T{},  std::move(msg)}; }
};

template <>
struct Result<void> {
    bool        ok;
    std::string error;

    static Result success()                   { return {true,  {}}; }
    static Result failure(std::string msg)    { return {false, std::move(msg)}; }
};

} // namespace consent_monitor
