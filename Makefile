# ConsentMonitor — Linux Portable Test Build
# Builds and runs ONLY the platform-portable C++20 logic and its tests.
# Windows-specific modules (WinHTTP, NTFS ACL, Win32 GUI) are excluded.

CXX       := g++
CXXFLAGS  := -std=c++20 -Wall -Wextra -Wpedantic -Werror -I include -g -O2
LDFLAGS   := -pthread

PROJ_ROOT := $(shell pwd)

# ── Portable source objects (no Windows APIs) ────────────────────────────────
PORTABLE_SRCS := \
    src/crc32.cpp               \
    src/canonical_json.cpp      \
    src/event_schema.cpp        \
    src/consent_manager.cpp     \
    src/storage_quota.cpp       \
    src/journal_engine.cpp      \
    src/rotation_engine.cpp     \
    src/event_pipeline.cpp      \
    src/win32_security.cpp

PORTABLE_OBJS := $(PORTABLE_SRCS:.cpp=.o)

# ── Test binaries ────────────────────────────────────────────────────────────
TEST_SRCS := $(wildcard tests/test_*.cpp)
TEST_BINS := $(patsubst tests/%.cpp,tests/%,$(TEST_SRCS))

# ── Targets ──────────────────────────────────────────────────────────────────
.PHONY: all lib test clean

all: lib

lib: $(PORTABLE_OBJS)
	@echo "Portable objects built."

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

tests/test_%: tests/test_%.cpp $(PORTABLE_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

test: $(TEST_BINS)
	@echo ""
	@echo "════════════════════════════════════════════"
	@echo " Running portable tests on Linux"
	@echo " NOTE: WinHTTP, NTFS ACL, Win32 GUI, and"
	@echo "       packet-capture tests require a"
	@echo "       Windows 11 (25H2/26H2) host and"
	@echo "       are NOT executed in this build."
	@echo "════════════════════════════════════════════"
	@echo ""
	@failures=0; \
	for t in $(TEST_BINS); do \
	    echo "── $$t ──"; \
	    ./$$t || failures=$$((failures + 1)); \
	    echo ""; \
	done; \
	if [ $$failures -ne 0 ]; then \
	    echo "$$failures test binary/binaries FAILED."; \
	    exit 1; \
	else \
	    echo "All portable tests PASSED."; \
	fi

clean:
	rm -f $(PORTABLE_OBJS) $(TEST_BINS)
