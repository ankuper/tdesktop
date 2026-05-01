# Story 2-1 tests — wired in by `-DTELEPROTO3_TESTS=ON` from the top level.
#
# Two QtTest binaries:
#   - test-vector-passthrough         — Epic 1 conformance vectors through bridge
#   - test-tls-fingerprint-beta-qt    — AR-C3 JA3/JA4 fingerprint-lock
#
# Both link against libteleproto3 (statically imported in Telegram/CMakeLists.txt
# under the `teleproto3` IMPORTED target) and the bridge TU.
# Both register themselves with CTest so the CI workflow can run `ctest`.

find_package(Qt6 REQUIRED COMPONENTS Test Core Network WebSockets)

# Path to unit.json injected at compile time so the test does not depend on
# QDir::currentPath() at runtime.
set(_t3_unit_vectors "${LIBTELEPROTO3_ROOT}/conformance/vectors/unit.json")

set(_t3_bridge_sources
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles/mtproto/teleproto3_bridge.cpp
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles/mtproto/teleproto3_bridge.h
)

# No-op stubs for Logs:: — tdesktop core (logs.cpp) is not linked in tests.
set(_t3_stub_sources
    test-stubs/logs_stubs.cpp
)

# ── test-vector-passthrough ────────────────────────────────────────────────
add_executable(test-vector-passthrough
    test-vector-passthrough.cpp
    ${_t3_bridge_sources}
    ${_t3_stub_sources}
)
set_target_properties(test-vector-passthrough PROPERTIES AUTOMOC ON)
target_include_directories(test-vector-passthrough PRIVATE
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles
)
target_link_libraries(test-vector-passthrough PRIVATE
    teleproto3
    Qt6::Test
    Qt6::Core
    Qt6::Network
    Qt6::WebSockets
)
target_compile_definitions(test-vector-passthrough PRIVATE
    SRCDIR="${CMAKE_SOURCE_DIR}"
    UNIT_VECTORS_PATH="${_t3_unit_vectors}"
)
add_test(NAME test-vector-passthrough COMMAND test-vector-passthrough)

# ── test-tls-fingerprint-beta-qt ───────────────────────────────────────────
add_executable(test-tls-fingerprint-beta-qt
    test-tls-fingerprint-beta-qt.cpp
)
set_target_properties(test-tls-fingerprint-beta-qt PROPERTIES AUTOMOC ON)
target_link_libraries(test-tls-fingerprint-beta-qt PRIVATE
    Qt6::Test
    Qt6::Core
)
target_compile_definitions(test-tls-fingerprint-beta-qt PRIVATE
    SRCDIR="${CMAKE_SOURCE_DIR}"
)
add_test(NAME test-tls-fingerprint-beta-qt COMMAND test-tls-fingerprint-beta-qt)
