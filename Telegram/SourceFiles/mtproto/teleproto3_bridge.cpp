/*
 * teleproto3_bridge.cpp — Qt/OpenSSL host-stack bridge implementation.
 *
 * Single integration TU for libteleproto3 in tdesktop.
 * The static_assert ABI version-pin lives here (Epic 2 style-guide §3;
 * single-TU rule — stories 2.3/2.4/2.5/2.6 do NOT duplicate it).
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
#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
#include <QRandomGenerator>
#include <QSslSocket>
#include <QWebSocket>

#include <cassert>
#include <chrono>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <limits>

#include "logs.h"

namespace Tdesktop::Teleproto3 {

namespace {

// Process-wide monotonic origin used by monotonic_ns_impl.
// Starting from a single epoch shared across every BridgeContext keeps the
// lib's clock-skew detector (T3_ERR_CLOCK_BACKWARDS) sane across reconnects.
const std::chrono::steady_clock::time_point kProcessEpoch =
    std::chrono::steady_clock::now();

}  // namespace

// -----------------------------------------------------------------------
// BridgeContext — owns the Qt-side state passed through t3_callbacks_t.ctx
// -----------------------------------------------------------------------

struct BridgeContext {
    QSslSocket    *tls;
    QWebSocket    *ws;
    t3_session_t  *session = nullptr;
    QMutex         recvMutex;
    QQueue<QByteArray> recvQueue;
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
    if (n < 0) return -1;
    return static_cast<int64_t>(n);
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
    // Process-wide monotonic origin shared across every BridgeContext, so
    // reconnects (new context, same process) never observe a backwards step.
    const auto now = std::chrono::steady_clock::now();
    const auto delta = now - kProcessEpoch;
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(delta).count();
    Q_ASSERT(ns >= 0);
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
    // C++20 designated initialisers: field order matches t3_callbacks_t exactly.
    // struct_size sentinel is REQUIRED by t3_session_bind_callbacks for forward-compat.
    t3_callbacks_t cb = {
        .struct_size  = sizeof(t3_callbacks_t),
        .lower_send   = lower_send_impl,
        .lower_recv   = lower_recv_impl,
        .frame_send   = frame_send_impl,
        .frame_recv   = frame_recv_impl,
        .rng          = rng_impl,
        .monotonic_ns = monotonic_ns_impl,
        .log_sink     = log_sink_impl,
        .ctx          = ctx,
    };
    return cb;
}

void destroyContext(BridgeContext *ctx) {
    delete ctx;
}

}  // namespace Tdesktop::Teleproto3
