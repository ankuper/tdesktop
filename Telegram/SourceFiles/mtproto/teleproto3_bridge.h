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

#include <QByteArray>
#include "mtproto/secure_store.h"

class QSslSocket;
class QWebSocket;

namespace Tdesktop::Teleproto3 {

// RAII owner for opaque t3_secret_t* — calls t3_secret_free on destruction.
class SecretGuard {
public:
	explicit SecretGuard(t3_secret_t *s = nullptr) noexcept : _s(s) {}
	~SecretGuard() noexcept { if (_s) t3_secret_free(_s); }
	SecretGuard(const SecretGuard &) = delete;
	SecretGuard &operator=(const SecretGuard &) = delete;
	SecretGuard(SecretGuard &&other) noexcept : _s(other._s) { other._s = nullptr; }
	SecretGuard &operator=(SecretGuard &&other) noexcept {
		if (this != &other) {
			if (_s) t3_secret_free(_s);
			_s = other._s;
			other._s = nullptr;
		}
		return *this;
	}
	[[nodiscard]] t3_secret_t *get() const noexcept { return _s; }

private:
	t3_secret_t *_s;
};

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

// FR23: CSPRNG-backed mask generator for QWebSocket.
// Drives BOTH the Sec-WebSocket-Key generation (via QWebSocketPrivate::generateKey,
// which calls maskGenerator->nextMask() x4) AND the per-frame masking. Replaces
// Qt's QDefaultMaskGenerator which uses QRandomGenerator::global() (Qt's own
// source comments call this "insecure").
// Anti-pattern §12.12: qrand() / rand() / timestamp-derived keys are forbidden.
// EXTEND from story 2.4 — write-authority owned by story 2.1.
//
// Forward decl only; concrete class lives in teleproto3_bridge.cpp.
class CsprngMaskGenerator;

// Factory: returns a new mask generator owned by `parent`. Install via
// QWebSocket::setMaskGenerator(...) BEFORE calling QWebSocket::open(...).
QObject *makeCsprngMaskGenerator(QObject *parent);

}  // namespace Tdesktop::Teleproto3

#endif  // TELEPROTO3_BRIDGE_H
