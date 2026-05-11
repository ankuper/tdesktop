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
#include <QtNetwork/QAbstractSocket>
#include "mtproto/secure_store.h"

class QSslSocket;

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
BridgeContext *createContext(QSslSocket *tls, class MiniWebSocket *ws);

// Populates a t3_callbacks_t with the eight Qt-bridged function-pointers
// and stores ctx as the round-trip opaque pointer.
t3_callbacks_t makeCallbacks(BridgeContext *ctx);

// Destroys a context previously created with createContext.
void destroyContext(BridgeContext *ctx);

// A minimal WebSocket client wrapper to replace QWebSocket.
class MiniWebSocket : public QObject {
	Q_OBJECT
public:
	MiniWebSocket(QSslSocket *tls, const QString &host, const QString &path, QObject *parent = nullptr);

	void open();
	qint64 sendBinaryMessage(const QByteArray &msg);
	QAbstractSocket::SocketState state() const;

Q_SIGNALS:
	void connected();
	void disconnected();
	void errorOccurred(int code);
	void binaryMessageReceived(const QByteArray &msg);

private Q_SLOTS:
	void onReadyRead();

private:
	QSslSocket *_tls;
	QString _host;
	QString _path;
	QByteArray _buffer;
	bool _upgraded = false;
};

// rpl payload for the connection → indicator retry-state push channel (story 2.6).
// Both connection_teleproto3.h (producer) and proxy_indicator_c1.h (consumer) use this type
// from this shared header to avoid a layering violation.
struct RetryStatePayload {
	int tier = 0;       // 0..3, mirrors t3_retry_state_t enumerant order
	uint64_t at_ns = 0; // monotonic_ns timestamp of the FSM transition
};

#if TDESKTOP_TYPE3_CALLS
// Story 9-1: localhost SOCKS5/CONNECT shim lifecycle wrappers.
// Thin C++ wrappers over the C t3_shim_* API from t3_shim_socks5.h.
// ShimHandle is an opaque type; callers hold ShimHandle * only.
struct ShimHandle;

// Open a new shim listener.  Returns nullptr on failure (logs internally).
[[nodiscard]] ShimHandle *ShimOpen(
    const std::string &serverHost,
    uint16_t           serverPort,
    const std::string &wsPath,
    const std::string &secretHex,
    uint16_t           localPortHint = 0);

// Close and free the shim.  Safe to call with nullptr.
void ShimClose(ShimHandle *handle);

// Return the localhost port the shim is bound to.  Returns 0 if handle is nullptr.
[[nodiscard]] uint16_t ShimLocalPort(const ShimHandle *handle);
#endif // TDESKTOP_TYPE3_CALLS

}  // namespace Tdesktop::Teleproto3

#endif  // TELEPROTO3_BRIDGE_H
