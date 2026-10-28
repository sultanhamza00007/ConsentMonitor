// ConsentMonitor — test_framework.hpp
// Minimal, zero-dependency C++20 test harness.
#pragma once

#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace cm_test {

struct TestCase {
    std::string name;
    std::function<void()> body;
};

class Suite {
    std::string suite_name_;
    std::vector<TestCase> cases_;
public:
    explicit Suite(std::string name) : suite_name_(std::move(name)) {}

    Suite& add(std::string name, std::function<void()> fn) {
        cases_.push_back({std::move(name), std::move(fn)});
        return *this;
    }

    int run() const {
        int passed = 0, failed = 0;
        std::cout << "═══ " << suite_name_ << " ═══\n";
        for (auto const& tc : cases_) {
            try {
                tc.body();
                ++passed;
                std::cout << "  ✓ " << tc.name << "\n";
            } catch (std::exception const& e) {
                ++failed;
                std::cerr << "  ✗ " << tc.name << "\n    " << e.what() << "\n";
            }
        }
        std::cout << "  " << passed << " passed, " << failed << " failed\n\n";
        return failed;
    }
};

// ─── Enum-safe streaming helper ─────────────────────────────────────────────
// Enums without operator<< are printed as their underlying integer.
template <typename T>
auto streamable(T const& v) {
    if constexpr (std::is_enum_v<T>)
        return static_cast<std::underlying_type_t<T>>(v);
    else
        return v;
}

// ─── Assertion Helpers ──────────────────────────────────────────────────────

inline void assert_true(bool expr, const char* expr_str,
                        const char* file, int line) {
    if (!expr) {
        std::ostringstream os;
        os << file << ':' << line << ": ASSERT_TRUE(" << expr_str << ") failed";
        throw std::runtime_error(os.str());
    }
}

inline void assert_false(bool expr, const char* expr_str,
                         const char* file, int line) {
    if (expr) {
        std::ostringstream os;
        os << file << ':' << line << ": ASSERT_FALSE(" << expr_str << ") failed";
        throw std::runtime_error(os.str());
    }
}

template <typename A, typename B>
void assert_eq(A const& a, B const& b,
               const char* a_str, const char* b_str,
               const char* file, int line) {
    if (!(a == b)) {
        std::ostringstream os;
        os << file << ':' << line << ": ASSERT_EQ(" << a_str << ", " << b_str
           << ") failed: " << streamable(a) << " != " << streamable(b);
        throw std::runtime_error(os.str());
    }
}

template <typename A, typename B>
void assert_ne(A const& a, B const& b,
               const char* a_str, const char* b_str,
               const char* file, int line) {
    if (a == b) {
        std::ostringstream os;
        os << file << ':' << line << ": ASSERT_NE(" << a_str << ", " << b_str
           << ") failed: both equal " << streamable(a);
        throw std::runtime_error(os.str());
    }
}

template <typename A, typename B>
void assert_lt(A const& a, B const& b,
               const char* a_str, const char* b_str,
               const char* file, int line) {
    if (!(a < b)) {
        std::ostringstream os;
        os << file << ':' << line << ": ASSERT_LT(" << a_str << ", " << b_str
           << ") failed: " << streamable(a) << " >= " << streamable(b);
        throw std::runtime_error(os.str());
    }
}

template <typename A, typename B>
void assert_le(A const& a, B const& b,
               const char* a_str, const char* b_str,
               const char* file, int line) {
    if (!(a <= b)) {
        std::ostringstream os;
        os << file << ':' << line << ": ASSERT_LE(" << a_str << ", " << b_str
           << ") failed: " << streamable(a) << " > " << streamable(b);
        throw std::runtime_error(os.str());
    }
}

template <typename A, typename B>
void assert_gt(A const& a, B const& b,
               const char* a_str, const char* b_str,
               const char* file, int line) {
    if (!(a > b)) {
        std::ostringstream os;
        os << file << ':' << line << ": ASSERT_GT(" << a_str << ", " << b_str
           << ") failed: " << streamable(a) << " <= " << streamable(b);
        throw std::runtime_error(os.str());
    }
}

} // namespace cm_test

// ─── Convenience macros ─────────────────────────────────────────────────────
#define ASSERT_TRUE(e)     ::cm_test::assert_true(!!(e), #e, __FILE__, __LINE__)
#define ASSERT_FALSE(e)    ::cm_test::assert_false(!!(e), #e, __FILE__, __LINE__)
#define ASSERT_EQ(a, b)    ::cm_test::assert_eq((a), (b), #a, #b, __FILE__, __LINE__)
#define ASSERT_NE(a, b)    ::cm_test::assert_ne((a), (b), #a, #b, __FILE__, __LINE__)
#define ASSERT_LT(a, b)    ::cm_test::assert_lt((a), (b), #a, #b, __FILE__, __LINE__)
#define ASSERT_LE(a, b)    ::cm_test::assert_le((a), (b), #a, #b, __FILE__, __LINE__)
#define ASSERT_GT(a, b)    ::cm_test::assert_gt((a), (b), #a, #b, __FILE__, __LINE__)

#define ASSERT_THROWS(expr, ExType) \
    do { \
        bool caught_ = false; \
        try { expr; } catch (ExType const&) { caught_ = true; } \
        if (!caught_) { \
            std::ostringstream os_; \
            os_ << __FILE__ << ':' << __LINE__ \
                << ": ASSERT_THROWS(" #expr ", " #ExType ") — no exception"; \
            throw std::runtime_error(os_.str()); \
        } \
    } while (false)
