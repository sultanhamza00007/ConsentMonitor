cmake_minimum_required(VERSION 3.25)
project(ConsentMonitor VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Platform baseline enforcement
# Target: 64-bit Windows 11 (25H2/26H2) with Microsoft Windows SDK
if(WIN32)
    add_compile_definitions(
        _WIN32_WINNT=0x0A00     # Windows 10/11 API baseline
        NTDDI_VERSION=0x0A00000C # Modern SDK feature level
        UNICODE
        _UNICODE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )

    if(MSVC)
        add_compile_options(
            /W4
            /WX
            /permissive-
            /utf-8
            /guard:cf
            /Qspectre
            /EHsc
        )
        add_link_options(
            /DYNAMICBASE
            /NXCOMPAT
            /HIGHENTROPYVA
            /GUARD:CF
        )
    endif()
endif()

include_directories(include)

# ─── Portable Core Library ───────────────────────────────────────────────────
set(PORTABLE_SOURCES
    src/crc32.cpp
    src/canonical_json.cpp
    src/event_schema.cpp
    src/consent_manager.cpp
    src/storage_quota.cpp
    src/journal_engine.cpp
    src/rotation_engine.cpp
    src/event_pipeline.cpp
    src/win32_security.cpp
)

add_library(ConsentMonitorCore STATIC ${PORTABLE_SOURCES})

# ─── Windows Application Executable ──────────────────────────────────────────
set(APP_SOURCES
    src/main.cpp
    src/winhttp_client.cpp
    src/win32_window.cpp
)

add_executable(ConsentMonitor ${APP_SOURCES})
target_link_libraries(ConsentMonitor PRIVATE ConsentMonitorCore)

if(WIN32)
    target_link_libraries(ConsentMonitor PRIVATE
        winhttp
        comctl32
        advapi32
    )
    # Windows subsystem for GUI (suppresses console if desired)
    # set_target_properties(ConsentMonitor PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

# ─── Test Executables ────────────────────────────────────────────────────────
enable_testing()

macro(cm_add_test test_name src_file)
    add_executable(${test_name} ${src_file})
    target_link_libraries(${test_name} PRIVATE ConsentMonitorCore)
    target_include_directories(${test_name} PRIVATE tests)
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

cm_add_test(test_crc32 tests/test_crc32.cpp)
cm_add_test(test_canonical_json tests/test_canonical_json.cpp)
cm_add_test(test_event_schema tests/test_event_schema.cpp)
cm_add_test(test_consent_manager tests/test_consent_manager.cpp)
cm_add_test(test_storage_quota tests/test_storage_quota.cpp)
cm_add_test(test_journal_engine tests/test_journal_engine.cpp)
cm_add_test(test_rotation_engine tests/test_rotation_engine.cpp)
cm_add_test(test_event_pipeline tests/test_event_pipeline.cpp)
cm_add_test(test_win32_security tests/test_win32_security.cpp)
