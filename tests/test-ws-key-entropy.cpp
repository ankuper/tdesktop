/*
 * test-ws-key-entropy.cpp — Story 2-4 AC #2: WS-Key entropy validation.
 *
 * Tests the CSPRNG mask generator (Tdesktop::Teleproto3::makeCsprngMaskGenerator)
 * which feeds Qt's QWebSocketPrivate::generateKey() — i.e. the actual source of
 * Sec-WebSocket-Key bytes on the wire (FR23).
 *
 * Quick mode: 1000 keys generated locally via the same nextMask() path Qt uses.
 * Full 24h soak mode: gated by T3_WS_KEY_SOAK=1 (deferred D2 — needs live proxy).
 * Results appended to tdesktop/baselines/2-4-ws-key-entropy.yml (one block per CI run).
 */

#include <QtTest>
#include <QMaskGenerator>
#include <QFile>
#include <QSysInfo>
#include <QDateTime>
#include <cmath>
#include <set>

#include "mtproto/teleproto3_bridge.h"

class WsKeyEntropyTest : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void testEntropyAndCollisions();

private:
    static constexpr int kNumKeys = 1000;
    bool isSoakMode = false;
    QString baselineOutputPath;

    static double computeShannonEntropy(const QByteArray &data);
    void appendBaselineEntry(double entropy, int collisions,
                             const QString &startIso, const QString &endIso);
};

void WsKeyEntropyTest::initTestCase() {
    isSoakMode = (std::getenv("T3_WS_KEY_SOAK") != nullptr);
    baselineOutputPath = QString::fromUtf8(SRCDIR) + "/../baselines/2-4-ws-key-entropy.yml";
}

double WsKeyEntropyTest::computeShannonEntropy(const QByteArray &data) {
    // Shannon entropy H = -Σ p_i log2(p_i) at byte granularity.
    if (data.isEmpty()) return 0.0;

    std::array<int, 256> freq{};
    for (unsigned char byte : data) {
        freq[byte]++;
    }

    double entropy = 0.0;
    const double n = static_cast<double>(data.size());
    for (int count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) / n;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

void WsKeyEntropyTest::appendBaselineEntry(
        double entropy, int collisions,
        const QString &startIso, const QString &endIso) {
    // P10 fix: append a per-platform entry to the baseline YAML.
    // File grows monotonically; existing entries are preserved.
    QFile f(baselineOutputPath);
    if (!f.open(QIODevice::Append | QIODevice::Text)) {
        qWarning() << "Could not open baseline for append:" << baselineOutputPath;
        return;
    }
    QTextStream out(&f);
    out << "  - platform: " << QSysInfo::productType() << "\n"
        << "    n_handshakes: " << kNumKeys << "\n"
        << "    entropy_bits_per_byte: "
        << QString::number(entropy, 'f', 4) << "\n"
        << "    collision_count: " << collisions << "\n"
        << "    wallclock_start_iso8601: \"" << startIso << "\"\n"
        << "    wallclock_end_iso8601: \"" << endIso << "\"\n"
        << "    mode: " << (isSoakMode ? "soak" : "quick") << "\n";
}

void WsKeyEntropyTest::testEntropyAndCollisions() {
    if (isSoakMode) {
        // D2 (deferred): full 24h soak against live proxy at 94.156.131.252;
        // requires scheduled CI runner. Tracked in deferred-work.md.
        QSKIP("24h soak mode (T3_WS_KEY_SOAK=1) requires live proxy + scheduled CI; deferred D2");
    }

    const QString startIso = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);

    // Quick mode: drive the same QMaskGenerator Qt uses internally for
    // QWebSocketPrivate::generateKey() (4 × nextMask() = 16 bytes).
    QObject ownerCtx;
    auto *gen = qobject_cast<QMaskGenerator*>(
        Tdesktop::Teleproto3::makeCsprngMaskGenerator(&ownerCtx));
    QVERIFY(gen != nullptr);

    QByteArray concatenatedKeys;
    concatenatedKeys.reserve(kNumKeys * 16);
    std::set<QByteArray> keySet;

    for (int i = 0; i < kNumKeys; ++i) {
        // Mirror Qt's QWebSocketPrivate::generateKey logic (qwebsocket_p.cpp).
        QByteArray key;
        key.reserve(16);
        for (int j = 0; j < 4; ++j) {
            const quint32 mask = gen->nextMask();
            // Aliasing-safe: copy via memcpy, no reinterpret_cast over disparate types.
            std::array<char, sizeof(quint32)> buf;
            std::memcpy(buf.data(), &mask, sizeof(quint32));
            key.append(buf.data(), buf.size());
        }
        QCOMPARE(key.size(), 16);

        concatenatedKeys.append(key);
        keySet.insert(key);
    }

    const double entropy = computeShannonEntropy(concatenatedKeys);
    const int collisions = kNumKeys - static_cast<int>(keySet.size());
    const double minEntropyBitsPerByte = 7.9;

    const QString endIso = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);

    qInfo() << "WS-Key entropy test:";
    qInfo() << "  Platform:" << QSysInfo::productType();
    qInfo() << "  N keys:" << kNumKeys;
    qInfo() << "  Entropy:" << entropy << "bits/byte";
    qInfo() << "  Collisions:" << collisions;

    appendBaselineEntry(entropy, collisions, startIso, endIso);

    QVERIFY2(entropy >= minEntropyBitsPerByte,
        QString("Entropy %1 bits/byte < min %2 bits/byte")
            .arg(entropy, 0, 'f', 3)
            .arg(minEntropyBitsPerByte)
            .toLocal8Bit());
    QCOMPARE(collisions, 0);
}

QTEST_MAIN(WsKeyEntropyTest)
#include "test-ws-key-entropy.moc"
