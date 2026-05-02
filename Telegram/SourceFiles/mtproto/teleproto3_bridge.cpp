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

#include "teleproto3_bridge.h"

// ABI version-pin: this story targets lib-v0.1.0 (Epic 2 style-guide §3).
// Rebuild lib or bump these macros if the ABI major/minor/patch changes.
static_assert(T3_ABI_VERSION_MAJOR == 0 &&
              T3_ABI_VERSION_MINOR == 1 &&
              T3_ABI_VERSION_PATCH == 0,
              "Epic 2 expects lib-v0.1.0; rebuild lib or update macros");

#include <QAbstractSocket>
#include <QCoreApplication>
#include <QMaskGenerator>
#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
#include <QRandomGenerator>
#include <QSslSocket>
#include <QWebSocket>

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
    QWebSocket    *ws;
    t3_session_t  *session = nullptr;
    QMutex         recvMutex;
    QQueue<QByteArray> recvQueue;
    int            recvQueueBytes = 0;
    // guard: QObject whose lifetime bounds the binaryMessageReceived
    // connection. Destroyed via deleteLater() to drain pending events safely.
    QObject       *guard = nullptr;

    BridgeContext(QSslSocket *tlsSocket, QWebSocket *wsSocket)
        : tls(tlsSocket), ws(wsSocket)
    {
        Q_ASSERT(tls);
        Q_ASSERT(ws);
        guard = new QObject();
        // Pin the guard to the WebSocket's thread so the lambda always runs
        // on the same thread as binaryMessageReceived emission, eliminating
        // the cross-thread race on recvQueue.
        guard->moveToThread(ws->thread());
        QObject::connect(ws, &QWebSocket::binaryMessageReceived, guard,
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
            QObject::disconnect(ws, &QWebSocket::binaryMessageReceived,
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
    // Copy the buffer: QWebSocket may queue the QByteArray across threads
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
    // Drains the queue populated by QWebSocket::binaryMessageReceived.
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

BridgeContext *createContext(QSslSocket *tls, QWebSocket *ws) {
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

// FR23: CSPRNG mask generator. Drives Sec-WebSocket-Key (via Qt's
// QWebSocketPrivate::generateKey -> maskGenerator->nextMask() x4) AND
// per-frame masking. Replaces QDefaultMaskGenerator (which uses
// QRandomGenerator::global() per Qt source).
// EXTEND from story 2.4 — write-authority owned by story 2.1.
class CsprngMaskGenerator final : public QMaskGenerator {
public:
    explicit CsprngMaskGenerator(QObject *parent = nullptr)
        : QMaskGenerator(parent) {}

    bool seed() noexcept override {
        // QRandomGenerator::system() is OS-CSPRNG-backed; no seeding needed.
        return true;
    }

    quint32 nextMask() noexcept override {
        // Anti-pattern §12.12: never qrand()/rand()/timestamp-seed.
        // QRandomGenerator::system() reads from /dev/urandom on Linux,
        // BCryptGenRandom on Windows, SecRandomCopyBytes on macOS.
        quint32 value = QRandomGenerator::system()->generate();
        // RFC 6455: a mask of zero has special meaning; reroll.
        while (Q_UNLIKELY(value == 0)) {
            value = QRandomGenerator::system()->generate();
        }
        return value;
    }
};

QObject *makeCsprngMaskGenerator(QObject *parent) {
    return new CsprngMaskGenerator(parent);
}

}  // namespace Tdesktop::Teleproto3
