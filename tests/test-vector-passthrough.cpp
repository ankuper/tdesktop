/*
 * test-vector-passthrough.cpp — Epic 1 conformance vector pass-through harness.
 *
 * Replays teleproto3/conformance/vectors/unit.json through the Qt-bridged
 * t3_secret_parse / t3_header_parse paths.  Every vector must pass byte-exact.
 * Zero drift; non-zero exit fails CI (AC #4).
 *
 * The harness instantiates Tdesktop::Teleproto3::BridgeContext (via
 * createContext) and calls t3_session_bind_callbacks so the AR-S12 nm-audit
 * runs over the linked binary including the bridge TU (t3_secret_parse /
 * t3_header_parse are stateless and do not use callbacks at runtime).
 *
 * Framework: Qt Test (QTEST_MAIN).  Hard-pinned — tdesktop depends on Qt for
 * the entire connection layer, so Qt::Test is a zero-cost dependency.
 */

// SRCDIR fallback MUST be defined before first use of the macro.
#ifndef SRCDIR
#  define SRCDIR "."
#endif

// UNIT_VECTORS_PATH is the canonical absolute path to unit.json, injected by
// CMake target_compile_definitions. Fallback to SRCDIR-relative search below.
#ifndef UNIT_VECTORS_PATH
#  define UNIT_VECTORS_PATH ""
#endif

#include <QtTest/QtTest>
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QSslSocket>
#include <QString>
#include <QWebSocket>

#include <t3.h>
#include "mtproto/teleproto3_bridge.h"

// ── Error-code description — Epic 1 style-guide §9 ─────────────────────────
// Unknown enumerants treated as T3_ERR_INTERNAL (stability guarantee: new
// enumerants may be added in any lib-v0.1.x patch).
static const char *describe(t3_result_t r) {
    switch (r) {
        case T3_OK:                          return "ok";
        case T3_ERR_INVALID_ARG:             return "INVALID_ARG";
        case T3_ERR_MALFORMED:               return "MALFORMED";
        case T3_ERR_UNSUPPORTED_VERSION:     return "UNSUPPORTED_VERSION";
        case T3_ERR_RNG:                     return "RNG";
        case T3_ERR_HOST_EMPTY:              return "HOST_EMPTY";
        case T3_ERR_HOST_INVALID:            return "HOST_INVALID";
        case T3_ERR_KEY_INVALID:             return "KEY_INVALID";
        case T3_ERR_BUF_TOO_SMALL:           return "BUF_TOO_SMALL";
        case T3_ERR_HOST_NON_ASCII:          return "HOST_NON_ASCII";
        case T3_ERR_CLOCK_BACKWARDS:         return "CLOCK_BACKWARDS";
        case T3_ERR_PATH_MISSING_LEADING_SLASH: return "PATH_MISSING_LEADING_SLASH";
        case T3_ERR_PATH_TRAILING_SLASH:     return "PATH_TRAILING_SLASH";
        case T3_ERR_PATH_PERCENT_ENCODED:    return "PATH_PERCENT_ENCODED";
        case T3_ERR_PATH_EMPTY_SEGMENT:      return "PATH_EMPTY_SEGMENT";
        case T3_ERR_PATH_NON_ASCII:          return "PATH_NON_ASCII";
        case T3_ERR_INTERNAL:                return "INTERNAL";
        default:                             return "INTERNAL"; /* unknown → INTERNAL per §9 */
    }
}

// Map a vector's expect.error class name to the set of t3_result_t enumerants
// that satisfy that class. v0.1.0 vectors use coarse class names ("MALFORMED")
// while the lib may return a more specific sub-code; this mapping enforces
// that the sub-code belongs to the documented family.
// Error families for t3_secret_parse — includes secret-specific enumerants
// (host/key/path errors) that cannot arise from t3_header_parse.
static QSet<t3_result_t> secretFormatErrorFamily(const QString &cls) {
    if (cls == QLatin1String("MALFORMED")) {
        return {T3_ERR_MALFORMED,
                T3_ERR_HOST_EMPTY, T3_ERR_HOST_INVALID, T3_ERR_HOST_NON_ASCII,
                T3_ERR_KEY_INVALID,
                T3_ERR_PATH_MISSING_LEADING_SLASH, T3_ERR_PATH_TRAILING_SLASH,
                T3_ERR_PATH_PERCENT_ENCODED,       T3_ERR_PATH_EMPTY_SEGMENT,
                T3_ERR_PATH_NON_ASCII};
    }
    if (cls == QLatin1String("UNSUPPORTED_VERSION")) {
        return {T3_ERR_UNSUPPORTED_VERSION};
    }
    if (cls == QLatin1String("INVALID_ARG")) {
        return {T3_ERR_INVALID_ARG};
    }
    if (cls == QLatin1String("RNG")) {
        return {T3_ERR_RNG};
    }
    if (cls == QLatin1String("INTERNAL")) {
        return {T3_ERR_INTERNAL};
    }
    return {};  // unknown class → empty set, caller fails the assertion
}

// Error families for t3_header_parse — restricted to errors that can
// actually arise from a 4-byte header parse (no host/key/path errors).
static QSet<t3_result_t> sessionHeaderErrorFamily(const QString &cls) {
    if (cls == QLatin1String("MALFORMED")) {
        return {T3_ERR_MALFORMED};
    }
    if (cls == QLatin1String("UNSUPPORTED_VERSION")) {
        return {T3_ERR_UNSUPPORTED_VERSION};
    }
    if (cls == QLatin1String("INVALID_ARG")) {
        return {T3_ERR_INVALID_ARG};
    }
    if (cls == QLatin1String("INTERNAL")) {
        return {T3_ERR_INTERNAL};
    }
    return {};
}

// Safe wrapper around t3_strerror to handle NULL returns for unknown enumerants.
static QString strerrorSafe(t3_result_t r) {
    const char *s = t3_strerror(r);
    return s ? QString::fromLatin1(s) : QStringLiteral("(null)");
}

// ── Locate conformance vectors file ─────────────────────────────────────────
// Preference order: CMake-injected absolute path → SRCDIR-relative → CWD-relative.
static QString findVectorsFile() {
    // 1. CMake-injected absolute path.
    if (QString injected = QString::fromLatin1(UNIT_VECTORS_PATH);
        !injected.isEmpty() && QFile::exists(injected)) {
        return injected;
    }
    // 2. Fallback search.
    const QStringList candidates = {
        QString(SRCDIR) + "/../../teleproto3/conformance/vectors/unit.json",
        QString(SRCDIR) + "/../teleproto3/conformance/vectors/unit.json",
        QDir::currentPath() + "/../../teleproto3/conformance/vectors/unit.json",
        QDir::currentPath() + "/../teleproto3/conformance/vectors/unit.json",
        QDir::currentPath() + "/teleproto3/conformance/vectors/unit.json",
    };
    for (const auto &c : candidates) {
        if (QFile::exists(c)) return c;
    }
    return {};
}

// RAII deleter for t3_secret_t.
namespace {
struct T3SecretDeleter {
    void operator()(t3_secret_t *s) const noexcept { if (s) t3_secret_free(s); }
};
struct T3SessionDeleter {
    void operator()(t3_session_t *s) const noexcept { if (s) t3_session_free(s); }
};
}  // namespace

// ── Test class ────────────────────────────────────────────────────────────────

class VectorPassthroughTest : public QObject {
    Q_OBJECT

private:
    QJsonObject vectors;

    void loadVectors() {
        QString path = findVectorsFile();
        QVERIFY2(!path.isEmpty(),
                 "teleproto3/conformance/vectors/unit.json not found; "
                 "set -DUNIT_VECTORS_PATH=... or run from tdesktop source root");
        QFile f(path);
        QVERIFY2(f.open(QIODevice::ReadOnly), "Cannot open unit.json");
        QJsonParseError err;
        auto doc = QJsonDocument::fromJson(f.readAll(), &err);
        QVERIFY2(err.error == QJsonParseError::NoError,
                 qPrintable("JSON parse error: " + err.errorString()));
        vectors = doc.object();
    }

private slots:
    void initTestCase() {
        loadVectors();
    }

    void secretFormatVectors() {
        // Instantiate bridge so AR-S12 nm-audit scans the bridge TU.
        QSslSocket tlsSocket;
        QWebSocket wsSocket;
        Tdesktop::Teleproto3::BridgeContext *ctx =
            Tdesktop::Teleproto3::createContext(&tlsSocket, &wsSocket);
        QVERIFY2(ctx != nullptr, "createContext returned null");

        t3_callbacks_t cb = Tdesktop::Teleproto3::makeCallbacks(ctx);
        QCOMPARE(static_cast<Tdesktop::Teleproto3::BridgeContext *>(cb.ctx), ctx);

        const QJsonArray sf = vectors.value("secret-format").toArray();
        QVERIFY2(!sf.isEmpty(), "secret-format vector array is empty");

        // Build a session from the first ok vector to validate the bind path.
        std::unique_ptr<t3_session_t, T3SessionDeleter> sess;
        for (const auto &v : sf) {
            auto obj = v.toObject();
            if (!obj.value("expect").toObject().value("ok").toBool()) continue;
            QByteArray raw = QByteArray::fromHex(
                obj.value("args").toArray().first().toString().toLatin1());
            std::unique_ptr<t3_secret_t, T3SecretDeleter> s;
            t3_secret_t *raw_s = nullptr;
            t3_result_t r = t3_secret_parse(
                reinterpret_cast<const uint8_t *>(raw.constData()),
                static_cast<size_t>(raw.size()), &raw_s);
            s.reset(raw_s);
            if (r != T3_OK || !s) continue;
            t3_session_t *raw_sess = nullptr;
            t3_result_t sr = t3_session_new(s.get(), &raw_sess);
            QVERIFY2(sr == T3_OK,
                     qPrintable(QString("t3_session_new failed: %1 (%2)")
                                .arg(describe(sr)).arg(strerrorSafe(sr))));
            QVERIFY2(raw_sess != nullptr, "t3_session_new returned null sess");
            sess.reset(raw_sess);
            break;
        }
        QVERIFY2(sess != nullptr,
                 "no ok vector produced a valid session for bind test");

        t3_result_t br = t3_session_bind_callbacks(sess.get(), &cb);
        QVERIFY2(br == T3_OK,
                 qPrintable(QString("t3_session_bind_callbacks failed: %1 (%2)")
                            .arg(describe(br)).arg(strerrorSafe(br))));

        // Replay every secret-format vector.
        for (const auto &v : sf) {
            auto obj = v.toObject();
            QString id = obj.value("id").toString();
            const auto exp = obj.value("expect").toObject();
            const bool expectOk = exp.value("ok").toBool();
            const QString expectError = exp.value("error").toString();

            QByteArray raw = QByteArray::fromHex(
                obj.value("args").toArray().first().toString().toLatin1());

            std::unique_ptr<t3_secret_t, T3SecretDeleter> s;
            t3_secret_t *raw_s = nullptr;
            t3_result_t result = t3_secret_parse(
                reinterpret_cast<const uint8_t *>(raw.constData()),
                static_cast<size_t>(raw.size()), &raw_s);
            s.reset(raw_s);  // RAII frees regardless of result

            if (expectOk) {
                QVERIFY2(result == T3_OK,
                         qPrintable(QString("Vector %1: expected T3_OK, got %2 (%3)")
                                    .arg(id, describe(result), strerrorSafe(result))));
            } else {
                QVERIFY2(result != T3_OK,
                         qPrintable(QString("Vector %1: expected error %2, got T3_OK")
                                    .arg(id, expectError)));
                if (!expectError.isEmpty()) {
                    QSet<t3_result_t> family = secretFormatErrorFamily(expectError);
                    QVERIFY2(!family.isEmpty(),
                             qPrintable(QString("Vector %1: unknown error class %2")
                                        .arg(id, expectError)));
                    QVERIFY2(family.contains(result),
                             qPrintable(QString("Vector %1: expected family %2, got %3 (%4)")
                                        .arg(id, expectError, describe(result),
                                             strerrorSafe(result))));
                }
            }
        }

        Tdesktop::Teleproto3::destroyContext(ctx);
    }

    void sessionHeaderVectors() {
        const QJsonArray sh = vectors.value("session-header").toArray();
        QVERIFY2(!sh.isEmpty(), "session-header vector array is empty");

        for (const auto &v : sh) {
            auto obj = v.toObject();
            QString id = obj.value("id").toString();
            const auto exp = obj.value("expect").toObject();
            const bool expectOk = exp.value("ok").toBool();
            const QString expectError = exp.value("error").toString();

            QByteArray raw = QByteArray::fromHex(
                obj.value("args").toArray().first().toString().toLatin1());
            QVERIFY2(raw.size() == 4,
                     qPrintable(QString("Vector %1: args[0] must be 4 bytes").arg(id)));

            t3_header_t out{};
            t3_result_t result = t3_header_parse(
                reinterpret_cast<const uint8_t *>(raw.constData()), &out);

            if (expectOk) {
                QVERIFY2(result == T3_OK,
                         qPrintable(QString("Vector %1: expected T3_OK, got %2 (%3)")
                                    .arg(id, describe(result), strerrorSafe(result))));

                auto expected = exp.value("result").toObject();
                int expCT = expected.value("command_type").toInt();
                int expVer = expected.value("version").toInt();
                int expFlags = expected.value("flags").toInt();

                QCOMPARE_EQ(static_cast<int>(out.command_type), expCT);
                QCOMPARE_EQ(static_cast<int>(out.version), expVer);
                QCOMPARE_EQ(static_cast<int>(out.flags), expFlags);
            } else {
                QVERIFY2(result != T3_OK,
                         qPrintable(QString("Vector %1: expected error, got T3_OK")
                                    .arg(id)));
                if (!expectError.isEmpty()) {
                    QSet<t3_result_t> family = sessionHeaderErrorFamily(expectError);
                    QVERIFY2(!family.isEmpty(),
                             qPrintable(QString("Vector %1: unknown error class %2")
                                        .arg(id, expectError)));
                    QVERIFY2(family.contains(result),
                             qPrintable(QString("Vector %1: expected family %2, got %3 (%4)")
                                        .arg(id, expectError, describe(result),
                                             strerrorSafe(result))));
                }
            }
        }
    }
};

QTEST_MAIN(VectorPassthroughTest)
#include "test-vector-passthrough.moc"
