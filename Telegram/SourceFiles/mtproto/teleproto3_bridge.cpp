/*
 * teleproto3_bridge.cpp — Qt/OpenSSL host-stack bridge implementation.
 *
 * Single integration TU for libteleproto3 in tdesktop.
 * The static_assert ABI version-pin lives here (Epic 2 style-guide §3;
 * single-TU rule — stories 2.3/2.4/2.5/2.6 do NOT duplicate it).
 *
 * log_sink contract: the lib MUST NOT pass secrets (keys, nonces, plaintext
 * payload) through fmt/args. Log messages are forwarded to tdesktop's main
 * log file without scrubbing. Any future lib change that logs secret material
 * must add a defensive scrubber here before forwarding.
 */

#include "mtproto/teleproto3_bridge.h"

// ABI version-pin: updated to lib-v0.1.2 by Story 9-1 (Epic 9 calls integration).
// lib-v0.1.2 is additive (T3_SHIM_SOCKS5 optional API + t3_features.h); no existing
// symbol changed. ABI bump §A checklist run 2026-05-10; two consumer pins updated.
static_assert(T3_ABI_VERSION_MAJOR == 0 &&
              T3_ABI_VERSION_MINOR == 1 &&
              T3_ABI_VERSION_PATCH == 2,
              "Bridge expects lib-v0.1.2; rebuild lib or update macros");

#include <QtNetwork/QAbstractSocket>
#include <QCoreApplication>
#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
#include <QRandomGenerator>
#include <QtNetwork/QSslSocket>

#include <array>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <limits>

#include "logs.h"

namespace Tdesktop::Teleproto3 {

// -----------------------------------------------------------------------
// BridgeContext — owns the Qt-side state passed through t3_callbacks_t.ctx
// -----------------------------------------------------------------------

struct BridgeContext {
    QSslSocket    *tls;
    MiniWebSocket *ws;
    t3_session_t  *session = nullptr;
    QMutex         recvMutex;
    QQueue<QByteArray> recvQueue;
    int            recvQueueBytes = 0;
    // guard: QObject whose lifetime bounds the binaryMessageReceived
    // connection. Destroyed via deleteLater() to drain pending events safely.
    QObject       *guard = nullptr;

    BridgeContext(QSslSocket *tlsSocket, MiniWebSocket *wsSocket)
        : tls(tlsSocket), ws(wsSocket)
    {
        Q_ASSERT(tls);
        Q_ASSERT(ws);
        guard = new QObject();
        // Pin the guard to the WebSocket's thread so the lambda always runs
        // on the same thread as binaryMessageReceived emission, eliminating
        // the cross-thread race on recvQueue.
        guard->moveToThread(ws->thread());
        QObject::connect(ws, &MiniWebSocket::binaryMessageReceived, guard,
            [this](const QByteArray &msg) {
                QMutexLocker locker(&recvMutex);
                // Drop frames that would exceed the queue budget to prevent
                // unbounded memory growth if the lib stalls on frame_recv.
                constexpr int kMaxFrames = 1024;
                constexpr int kMaxBytes  = 16 * 1024 * 1024;  // 16 MiB
                if (recvQueue.size() >= kMaxFrames ||
                    recvQueueBytes + msg.size() > kMaxBytes) {
                    return;  // budget exceeded — drop frame silently
                }
                recvQueueBytes += msg.size();
                recvQueue.enqueue(msg);
            },
            Qt::QueuedConnection);
    }

    ~BridgeContext() {
        if (guard) {
            // Disconnect first: prevents any new binaryMessageReceived events
            // from being queued to guard after this point.
            QObject::disconnect(ws, &MiniWebSocket::binaryMessageReceived,
                                guard, nullptr);
            // Purge already-queued events targeting guard so they cannot fire
            // after BridgeContext memory is freed (lambda captures `this`).
            QCoreApplication::removePostedEvents(guard);
            guard->deleteLater();
            guard = nullptr;
        }
    }

    BridgeContext(const BridgeContext &) = delete;
    BridgeContext &operator=(const BridgeContext &) = delete;
    BridgeContext(BridgeContext &&) = delete;
    BridgeContext &operator=(BridgeContext &&) = delete;
};

// -----------------------------------------------------------------------
// Eight static extern "C" callback shims
// -----------------------------------------------------------------------

// Implements t3_callbacks_t::lower_send (see teleproto3/lib/include/t3.h)
static int64_t lower_send_impl(void *ctx, const uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    auto *bc = static_cast<BridgeContext *>(ctx);
    if (bc->tls->state() != QAbstractSocket::ConnectedState) {
        return -1;
    }
    if (len > static_cast<size_t>(std::numeric_limits<qint64>::max())) {
        return -1;
    }
    qint64 n = bc->tls->write(reinterpret_cast<const char *>(buf),
                               static_cast<qint64>(len));
    return static_cast<int64_t>(n);
}

// Implements t3_callbacks_t::lower_recv (see teleproto3/lib/include/t3.h)
static int64_t lower_recv_impl(void *ctx, uint8_t *buf, size_t len) {
    // Non-blocking: returns 0 if no bytes are ready.
    // Driven by QSslSocket::readyRead in the host run-loop.
    if (len == 0) return 0;
    auto *bc = static_cast<BridgeContext *>(ctx);
    if (!bc->tls->bytesAvailable()) {
        return 0;
    }
    if (len > static_cast<size_t>(std::numeric_limits<qint64>::max())) {
        return -1;
    }
    qint64 n = bc->tls->read(reinterpret_cast<char *>(buf),
                              static_cast<qint64>(len));
    if (n < 0) return -1;
    return static_cast<int64_t>(n);
}

// Implements t3_callbacks_t::frame_send (see teleproto3/lib/include/t3.h)
static int64_t frame_send_impl(void *ctx, const uint8_t *buf, size_t len, int is_binary) {
    // Type3 uses binary frames exclusively (spec/wire-format.md §2 — Opcode).
    // Reject text frames at the bridge boundary.
    if (is_binary != 1) {
        return -1;
    }
    if (len == 0) return 0;
    auto *bc = static_cast<BridgeContext *>(ctx);
    if (bc->ws->state() != QAbstractSocket::ConnectedState) {
        return -1;
    }
    if (len > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return -1;
    }
    // Copy the buffer: MiniWebSocket may queue the QByteArray across threads
    // for asynchronous transmission; aliasing the caller's buffer via
    // QByteArray::fromRawData would be a UAF once frame_send_impl returns.
    QByteArray msg(reinterpret_cast<const char *>(buf), static_cast<int>(len));
    qint64 n = bc->ws->sendBinaryMessage(msg);
    // sendBinaryMessage returns bytes queued on the socket (not just this
    // frame), so use len as the success indicator rather than n directly.
    if (n < 0) return -1;
    return static_cast<int64_t>(len);
}

// Implements t3_callbacks_t::frame_recv (see teleproto3/lib/include/t3.h)
static int64_t frame_recv_impl(void *ctx, uint8_t *buf, size_t cap, int *out_is_binary) {
    // Drains the queue populated by MiniWebSocket::binaryMessageReceived.
    // Returns 0 if queue is empty (non-blocking), -1 on cap-too-small.
    auto *bc = static_cast<BridgeContext *>(ctx);
    QMutexLocker locker(&bc->recvMutex);
    if (out_is_binary) {
        *out_is_binary = 0;
    }
    if (bc->recvQueue.isEmpty()) {
        return 0;
    }
    const QByteArray &front = bc->recvQueue.head();
    if (static_cast<size_t>(front.size()) > cap) {
        // Buffer too small for the next frame. Keep the frame in the queue
        // so the lib can retry with a larger buffer; do NOT silently truncate.
        return -1;
    }
    const size_t copy = static_cast<size_t>(front.size());
    std::memcpy(buf, front.constData(), copy);
    if (out_is_binary) {
        *out_is_binary = 1;
    }
    bc->recvQueueBytes -= front.size();
    bc->recvQueue.dequeue();
    return static_cast<int64_t>(copy);
}

// Implements t3_callbacks_t::rng (see teleproto3/lib/include/t3.h)
static int rng_impl(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    if (len == 0) {
        return 0;
    }
    if (!buf) {
        return -1;
    }
    // Use QRandomGenerator::system() — NIST-approved CSPRNG on all platforms.
    // Anti-pattern §12.12: qrand()/rand()/timestamp-seed are explicitly forbidden.
    auto *gen = QRandomGenerator::system();
    if (!gen) {
        return -1;
    }
    size_t i = 0;
    while (i + sizeof(quint32) <= len) {
        quint32 val = gen->generate();
        std::memcpy(buf + i, &val, sizeof(quint32));
        i += sizeof(quint32);
    }
    if (i < len) {
        quint32 val = gen->generate();
        std::memcpy(buf + i, &val, len - i);
    }
    return 0;
}

// Implements t3_callbacks_t::monotonic_ns (see teleproto3/lib/include/t3.h)
static uint64_t monotonic_ns_impl(void *ctx) {
    (void)ctx;
    // Meyer's singleton: initialised on first call, safe against dynamic-init
    // ordering issues that would affect a namespace-scope variable.
    // Process-wide epoch shared across every BridgeContext so reconnects
    // (new context, same process) never observe a backwards step.
    static const std::chrono::steady_clock::time_point kEpoch =
        std::chrono::steady_clock::now();
    const auto now = std::chrono::steady_clock::now();
    const auto delta = now - kEpoch;
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(delta).count();
    if (ns < 0) return 0;  // clock went backwards — defensive, not an assert
    return static_cast<uint64_t>(ns);
}

// Implements t3_callbacks_t::log_sink (see teleproto3/lib/include/t3.h)
static void log_sink_impl(void *ctx, int level, const char *fmt, ...) {
    (void)ctx;
    if (!fmt) {
        return;
    }
    // level 0 → always emit; level > 0 → only if debug logging is enabled.
    if (level > 0 && !Logs::DebugEnabled()) {
        return;
    }
    char msg[1024];
    std::va_list ap;
    va_start(ap, fmt);
    const int written = std::vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (written < 0) {
        return;
    }
    // vsnprintf fills the buffer completely on truncation; overwrite the tail
    // with a marker so log readers know the message was cut short.
    if (written >= static_cast<int>(sizeof(msg))) {
        constexpr char kTrunc[] = "...[T]";
        constexpr size_t kTruncLen = sizeof(kTrunc) - 1;
        static_assert(sizeof(msg) > kTruncLen, "msg buffer too small for truncation marker");
        std::memcpy(msg + sizeof(msg) - kTruncLen - 1, kTrunc, kTruncLen);
        // null terminator already at msg[sizeof(msg)-1] from vsnprintf
    }
    Logs::writeMain(QLatin1String("[T3] ") + QString::fromUtf8(msg));
}

// -----------------------------------------------------------------------
// Public functions
// -----------------------------------------------------------------------

BridgeContext *createContext(QSslSocket *tls, MiniWebSocket *ws) {
    Q_ASSERT(tls);
    Q_ASSERT(ws);
    return new BridgeContext(tls, ws);
}

t3_callbacks_t makeCallbacks(BridgeContext *ctx) {
    // Positional aggregate init — field order matches t3_callbacks_t declaration
    // exactly (struct_size sentinel first; ctx round-trip pointer last).
    // Update both sides if t3_callbacks_t fields are reordered in a future ABI rev.
    t3_callbacks_t cb = {
        sizeof(t3_callbacks_t),  // struct_size  (forward-compat sentinel)
        lower_send_impl,         // lower_send
        lower_recv_impl,         // lower_recv
        frame_send_impl,         // frame_send
        frame_recv_impl,         // frame_recv
        rng_impl,                // rng
        monotonic_ns_impl,       // monotonic_ns
        log_sink_impl,           // log_sink
        ctx,                     // ctx  (round-trip opaque pointer)
    };
    return cb;
}

void destroyContext(BridgeContext *ctx) {
    delete ctx;
}

// -----------------------------------------------------------------------
// MiniWebSocket Implementation
// -----------------------------------------------------------------------
MiniWebSocket::MiniWebSocket(QSslSocket *tls, const QString &host, const QString &path, QObject *parent)
	: QObject(parent), _tls(tls), _host(host), _path(path) {
	QObject::connect(_tls, &QSslSocket::readyRead, this, &MiniWebSocket::onReadyRead);
	QObject::connect(_tls, &QSslSocket::disconnected, this, &MiniWebSocket::disconnected);
}

void MiniWebSocket::open() {
	if (_tls->state() != QAbstractSocket::ConnectedState) return;
	
	QByteArray keyRaw;
	keyRaw.resize(16);
	auto *gen = QRandomGenerator::system();
	for (int i = 0; i < 4; ++i) {
		quint32 val = gen->generate();
		std::memcpy(keyRaw.data() + i * 4, &val, 4);
	}
	QString key = QString::fromLatin1(keyRaw.toBase64());

	QString req = QString("GET %1 HTTP/1.1\r\n"
						  "Host: %2\r\n"
						  "Upgrade: websocket\r\n"
						  "Connection: Upgrade\r\n"
						  "Sec-WebSocket-Key: %3\r\n"
						  "Sec-WebSocket-Version: 13\r\n\r\n")
				  .arg(_path, _host, key);
	_tls->write(req.toUtf8());
}

qint64 MiniWebSocket::sendBinaryMessage(const QByteArray &msg) {
	if (!_upgraded) return -1;
	
	QByteArray frame;
	frame.append(static_cast<char>(0x82)); // FIN + Binary
	
	int len = msg.size();
	if (len < 126) {
		frame.append(static_cast<char>(0x80 | len));
	} else if (len <= 65535) {
		frame.append(static_cast<char>(0x80 | 126));
		frame.append(static_cast<char>((len >> 8) & 0xFF));
		frame.append(static_cast<char>(len & 0xFF));
	} else {
		frame.append(static_cast<char>(0x80 | 127));
		for (int i = 7; i >= 0; --i) {
			frame.append(static_cast<char>((static_cast<quint64>(len) >> (i * 8)) & 0xFF));
		}
	}
	
	quint32 mask = QRandomGenerator::system()->generate();
	while (mask == 0) mask = QRandomGenerator::system()->generate();
	frame.append(reinterpret_cast<const char*>(&mask), 4);
	
	QByteArray maskedMsg = msg;
	const char *maskPtr = reinterpret_cast<const char*>(&mask);
	for (int i = 0; i < len; ++i) {
		maskedMsg[i] = maskedMsg[i] ^ maskPtr[i % 4];
	}
	frame.append(maskedMsg);
	
	return _tls->write(frame);
}

QAbstractSocket::SocketState MiniWebSocket::state() const {
	return _upgraded ? QAbstractSocket::ConnectedState : _tls->state();
}

void MiniWebSocket::onReadyRead() {
	_buffer.append(_tls->readAll());
	
	if (!_upgraded) {
		int headerEnd = _buffer.indexOf("\r\n\r\n");
		if (headerEnd == -1) return;
		
		QByteArray header = _buffer.left(headerEnd);
		_buffer.remove(0, headerEnd + 4);
		
		if (header.startsWith("HTTP/1.1 101")) {
			_upgraded = true;
			Q_EMIT connected();
		} else {
			Q_EMIT errorOccurred(1);
			_tls->disconnectFromHost();
			return;
		}
	}
	
	while (_buffer.size() >= 2) {
		const char *data = _buffer.constData();
		uint8_t b0 = data[0];
		uint8_t b1 = data[1];
		
		bool fin = (b0 & 0x80) != 0;
		int opcode = b0 & 0x0F;
		bool masked = (b1 & 0x80) != 0;
		quint64 payloadLen = b1 & 0x7F;
		
		int headerLen = 2;
		if (payloadLen == 126) {
			if (_buffer.size() < 4) return;
			payloadLen = (static_cast<uint8_t>(data[2]) << 8) | static_cast<uint8_t>(data[3]);
			headerLen += 2;
		} else if (payloadLen == 127) {
			if (_buffer.size() < 10) return;
			payloadLen = 0;
			for (int i = 0; i < 8; ++i) {
				payloadLen = (payloadLen << 8) | static_cast<uint8_t>(data[2 + i]);
			}
			headerLen += 8;
		}
		
		int maskLen = masked ? 4 : 0;
		if (static_cast<quint64>(_buffer.size()) < headerLen + maskLen + payloadLen) return;
		
		const char *maskKey = data + headerLen;
		const char *payloadData = data + headerLen + maskLen;
		QByteArray payload(payloadData, payloadLen);
		
		if (masked) {
			for (quint64 i = 0; i < payloadLen; ++i) {
				payload[i] = payload[i] ^ maskKey[i % 4];
			}
		}
		
		_buffer.remove(0, headerLen + maskLen + payloadLen);
		
		if (opcode == 0x02 || opcode == 0x01) { // binary or text
			Q_EMIT binaryMessageReceived(payload);
		} else if (opcode == 0x08) { // close
			_tls->disconnectFromHost();
		}
	}
}

#if TDESKTOP_TYPE3_CALLS
// ── Story 9-1: SOCKS5/CONNECT shim wrappers ────────────────────────────────
#include "t3_shim_socks5.h"
#include "logs.h"

struct ShimHandle { t3_shim_t *inner = nullptr; };

ShimHandle *ShimOpen(
    const std::string &serverHost,
    uint16_t           serverPort,
    const std::string &wsPath,
    const std::string &secretHex,
    uint16_t           localPortHint)
{
    // P13: refuse embedded NUL bytes in any std::string passed to a C-string
    // consumer — t3_shim_open uses strlen() / strcpy-style ingestion and would
    // silently truncate at the first '\0', producing a mismatched server_host
    // or secret that the user never authored. Treat as parse failure.
    auto hasNul = [](const std::string &s) {
        return s.find('\0') != std::string::npos;
    };
    if (hasNul(serverHost) || hasNul(wsPath) || hasNul(secretHex)) {
        LOG(("[T3-shim] ShimOpen rejected: embedded NUL in serverHost/wsPath/secretHex"));
        return nullptr;
    }

    t3_shim_t *raw = nullptr;
    t3_result_t rc = t3_shim_open(
        serverHost.c_str(),
        serverPort,
        wsPath.c_str(),
        secretHex.c_str(),
        localPortHint,
        &raw);
    if (rc != T3_OK) {
        LOG(("[T3-shim] t3_shim_open failed: rc=%d", (int)rc));
        return nullptr;
    }
    auto *h = new ShimHandle{raw};
    LOG(("[T3-dogfood] SOCKS5 shim opened on port %u → %s:%u%s",
         (unsigned)t3_shim_local_port(raw),
         serverHost.c_str(), (unsigned)serverPort, wsPath.c_str()));
    return h;
}

void ShimClose(ShimHandle *h) {
    if (!h) return;
    t3_shim_close(h->inner);
    delete h;
}

uint16_t ShimLocalPort(const ShimHandle *h) {
    return h ? t3_shim_local_port(h->inner) : 0;
}
#endif // TDESKTOP_TYPE3_CALLS

}  // namespace Tdesktop::Teleproto3
