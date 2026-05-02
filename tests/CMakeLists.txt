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

# ── test-proxy-clipboard (Story 2-2) ──────────────────────────────────────
# Unit fixtures for the Type3 link-parsing + saved-config-UI story.
# Tests ProxyData::type3KeyOctets(), sameType3Key(), and status() for
# Mtproto3; exercises t3_secret_parse for real (no lib mocking).
add_executable(test-proxy-clipboard
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles/boxes/tests/test_proxy_clipboard.cpp
    ${_t3_bridge_sources}
    ${_t3_stub_sources}
)
set_target_properties(test-proxy-clipboard PROPERTIES AUTOMOC ON)
target_include_directories(test-proxy-clipboard PRIVATE
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles
)
target_link_libraries(test-proxy-clipboard PRIVATE
    teleproto3
    Qt6::Test
    Qt6::Core
    OpenSSL::Crypto
)
target_compile_definitions(test-proxy-clipboard PRIVATE
    SRCDIR="${CMAKE_SOURCE_DIR}"
    UNIT_VECTORS_PATH="${_t3_unit_vectors}"
)
add_test(NAME test-proxy-clipboard COMMAND test-proxy-clipboard)

# ── test-teleproto3-latency (Story 2-3) ───────────────────────────────────────
# NFR7 + NFR2 framing latency budget (loopback mock). Writes aggregate results
# to baselines/2-3-dc-connection.yml (aggregate-only, Epic 2 §9).
add_executable(test-teleproto3-latency
    test-teleproto3-latency.cpp
    ${_t3_bridge_sources}
    ${_t3_stub_sources}
)
set_target_properties(test-teleproto3-latency PROPERTIES AUTOMOC ON)
target_include_directories(test-teleproto3-latency PRIVATE
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles
)
target_link_libraries(test-teleproto3-latency PRIVATE
    teleproto3
    Qt6::Test
    Qt6::Core
    Qt6::Network
    Qt6::WebSockets
)
target_compile_definitions(test-teleproto3-latency PRIVATE
    SRCDIR="${CMAKE_SOURCE_DIR}/tests"
    UNIT_VECTORS_PATH="${_t3_unit_vectors}"
)
add_test(NAME test-teleproto3-latency COMMAND test-teleproto3-latency)

# ── test-teleproto3-soak (Story 2-3) ──────────────────────────────────────────
# 24-hour NFR24 delivery success rate (TELEPROTO3_SOAK=1 gate).
# Scheduled weekly via .github/workflows/teleproto3-soak.yml.
add_executable(test-teleproto3-soak
    test-teleproto3-soak.cpp
    ${_t3_bridge_sources}
    ${_t3_stub_sources}
)
set_target_properties(test-teleproto3-soak PROPERTIES AUTOMOC ON)
target_include_directories(test-teleproto3-soak PRIVATE
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles
)
target_link_libraries(test-teleproto3-soak PRIVATE
    teleproto3
    Qt6::Test
    Qt6::Core
    Qt6::Network
    Qt6::WebSockets
)
target_compile_definitions(test-teleproto3-soak PRIVATE
    SRCDIR="${CMAKE_SOURCE_DIR}/tests"
    UNIT_VECTORS_PATH="${_t3_unit_vectors}"
)
add_test(NAME test-teleproto3-soak COMMAND test-teleproto3-soak)

# ── test-ws-key-entropy (Story 2-4) ───────────────────────────────────────────
# AC #2: Entropy validation for generateSecWebSocketKey() (≥7.9 bits/byte, zero collisions).
add_executable(test-ws-key-entropy
    test-ws-key-entropy.cpp
    ${_t3_bridge_sources}
    ${_t3_stub_sources}
)
set_target_properties(test-ws-key-entropy PROPERTIES AUTOMOC ON)
target_include_directories(test-ws-key-entropy PRIVATE
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles
)
target_link_libraries(test-ws-key-entropy PRIVATE
    teleproto3
    Qt6::Test
    Qt6::Core
)
target_compile_definitions(test-ws-key-entropy PRIVATE
    SRCDIR="${CMAKE_SOURCE_DIR}/tests"
)
add_test(NAME test-ws-key-entropy COMMAND test-ws-key-entropy)

# ── test-secret-storage (Story 2-4) ───────────────────────────────────────────
# AC #5: OS-native secure storage round-trip (store/load/wipe), no plaintext on disk.
add_executable(test-secret-storage
    test-secret-storage.cpp
    ${_t3_bridge_sources}
    ${_t3_stub_sources}
)
set_target_properties(test-secret-storage PROPERTIES AUTOMOC ON)
target_include_directories(test-secret-storage PRIVATE
    ${CMAKE_SOURCE_DIR}/Telegram/SourceFiles
)
target_link_libraries(test-secret-storage PRIVATE
    teleproto3
    Qt6::Test
    Qt6::Core
)
target_compile_definitions(test-secret-storage PRIVATE
    SRCDIR="${CMAKE_SOURCE_DIR}/tests"
)
add_test(NAME test-secret-storage COMMAND test-secret-storage)
