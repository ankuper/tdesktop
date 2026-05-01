/*
 * teleproto3_bridge.h — Qt/OpenSSL host-stack bridge for libteleproto3.
 *
 * Wires the eight t3_callbacks_t extension-points to Qt-native
 * QSslSocket (lower layer), QWebSocket (frame layer), QRandomGenerator,
 * std::chrono::steady_clock (process-wide monotonic origin), and
 * tdesktop's Logs::writeMain() sink.
 *
 * This header is consumed by teleproto3_bridge.cpp (integration TU) and
 * any downstream story that reads the bridge surface (2.3, 2.5).
 * The ABI version-pin static_assert lives in the .cpp, NOT here — per
 * Epic 2 style-guide §3 (single-TU rule).
 */

#ifndef TELEPROTO3_BRIDGE_H
#define TELEPROTO3_BRIDGE_H

#include <t3.h>

class QSslSocket;
class QWebSocket;

namespace Tdesktop::Teleproto3 {

struct BridgeContext;  // opaque; defined in teleproto3_bridge.cpp

// Creates a BridgeContext owning references to tls and ws.
// Uses a process-wide steady_clock epoch for monotonic_ns (shared across reconnects).
// Caller retains ownership of tls and ws — both must outlive the context.
BridgeContext *createContext(QSslSocket *tls, QWebSocket *ws);

// Populates a t3_callbacks_t with the eight Qt-bridged function-pointers
// and stores ctx as the round-trip opaque pointer.
t3_callbacks_t makeCallbacks(BridgeContext *ctx);

// Destroys a context previously created with createContext.
void destroyContext(BridgeContext *ctx);

}  // namespace Tdesktop::Teleproto3

#endif  // TELEPROTO3_BRIDGE_H
