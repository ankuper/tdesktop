/*
 * No-op stubs for Logs:: symbols referenced by teleproto3_bridge.cpp.
 *
 * tdesktop's logs.cpp is not linked into the Story 2-1 test binaries
 * (they do not pull in tdesktop core). These stubs satisfy the linker
 * while keeping bridge behaviour identical to production (log calls are
 * compiled in but silenced at runtime by DebugEnabled() returning false).
 */
#include <QString>

namespace Logs {

bool DebugEnabled() {
    return false;
}

void writeMain(const QString &) {
    // intentional no-op in test builds
}

}  // namespace Logs
