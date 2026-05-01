# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

cmake_minimum_required(VERSION 3.25...3.31)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(cmake/validate_special_target.cmake)
include(cmake/version.cmake)
desktop_app_parse_version(Telegram/build/version)

if (NOT DEFINED CMAKE_CONFIGURATION_TYPES)
    set(configuration_types_init 1)
endif()

project(Telegram
    LANGUAGES C CXX
    VERSION ${desktop_app_version_cmake}
    DESCRIPTION "Official Telegram Desktop messenger"
    HOMEPAGE_URL "https://desktop.telegram.org"
)

# ── Story 2-1 tests-only mode ────────────────────────────────────────────────
# Pass -DTELEPROTO3_TESTS_ONLY=ON to configure ONLY the Story 2-1 QtTest
# binaries without pulling in the full tdesktop dependency graph.
# Required for CI jobs (ar-s12-nm-audit.yml) that install only Qt6 + ninja.
option(TELEPROTO3_TESTS_ONLY "Configure only Story 2-1 test targets (skips full Telegram build)" OFF)
if(TELEPROTO3_TESTS_ONLY)
    set(LIBTELEPROTO3_ROOT
        "${CMAKE_SOURCE_DIR}/../../teleproto3"
        CACHE PATH "Root of the libteleproto3 source tree"
    )
    set(LIBTELEPROTO3_LIB_PATH "${LIBTELEPROTO3_ROOT}/lib/build/libteleproto3.a")
    set(LIBTELEPROTO3_INCLUDE_DIR "${LIBTELEPROTO3_ROOT}/lib/include")
    if(NOT EXISTS "${LIBTELEPROTO3_INCLUDE_DIR}/t3.h")
        message(FATAL_ERROR
            "libteleproto3 not found at ${LIBTELEPROTO3_ROOT}.\n"
            "Set -DLIBTELEPROTO3_ROOT=... or check your workspace layout.")
    endif()
    add_library(teleproto3 STATIC IMPORTED GLOBAL)
    set_target_properties(teleproto3 PROPERTIES
        IMPORTED_LOCATION                "${LIBTELEPROTO3_LIB_PATH}"
        IMPORTED_LOCATION_DEBUG          "${LIBTELEPROTO3_LIB_PATH}"
        IMPORTED_LOCATION_RELEASE        "${LIBTELEPROTO3_LIB_PATH}"
        IMPORTED_LOCATION_RELWITHDEBINFO "${LIBTELEPROTO3_LIB_PATH}"
        IMPORTED_LOCATION_MINSIZEREL     "${LIBTELEPROTO3_LIB_PATH}"
        INTERFACE_INCLUDE_DIRECTORIES    "${LIBTELEPROTO3_INCLUDE_DIR}"
    )
    enable_testing()
    add_subdirectory(tests)
    return()
endif()
# ── End tests-only mode ──────────────────────────────────────────────────────

if (APPLE)
    enable_language(OBJC OBJCXX)
endif()

if (configuration_types_init
    AND CMAKE_CONFIGURATION_TYPES
    AND NOT MinSizeRel IN_LIST CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES};MinSizeRel" CACHE STRING "" FORCE)
endif()

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT Telegram)

get_filename_component(third_party_loc "Telegram/ThirdParty" REALPATH)
get_filename_component(submodules_loc "Telegram" REALPATH)
get_filename_component(cmake_helpers_loc "cmake" REALPATH)

if (NOT DESKTOP_APP_USE_PACKAGED AND WIN32)
    set(Python3_EXECUTABLE ${CMAKE_CURRENT_SOURCE_DIR}/../ThirdParty/python/Scripts/python)
endif()

include(cmake/variables.cmake)
include(cmake/nice_target_sources.cmake)
include(cmake/target_compile_options_if_exists.cmake)
include(cmake/target_link_frameworks.cmake)
include(cmake/target_link_options_if_exists.cmake)
include(cmake/init_target.cmake)
include(cmake/generate_target.cmake)
include(cmake/nuget.cmake)
include(cmake/validate_d3d_compiler.cmake)
include(cmake/target_prepare_qrc.cmake)

include(cmake/options.cmake)
include(cmake/external/qt/package.cmake)

set(desktop_app_skip_libs
    glibmm
    variant
)

add_subdirectory(cmake)
add_subdirectory(Telegram)

# Tests — Story 2-1 conformance harness + AR-C3 fingerprint-lock test.
# Off by default; enable with -DTELEPROTO3_TESTS=ON (full build) or
# -DTELEPROTO3_TESTS_ONLY=ON (tests-only configure, no Telegram).
option(TELEPROTO3_TESTS "Build libteleproto3 conformance + fingerprint tests" OFF)
if(TELEPROTO3_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
