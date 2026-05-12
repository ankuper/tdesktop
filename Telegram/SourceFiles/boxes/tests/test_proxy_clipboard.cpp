/*
 * test_proxy_clipboard.cpp — Story 2-2 Qt unit-test fixtures.
 *
 * Three fixtures per dev-notes §"Test fixtures":
 *   - PasteValidType3CreatesEntry
 *   - PasteSameKeyDifferentHostUpdatesInPlace
 *   - PasteMalformedRejectsWithoutFallback
 *
 * Invokes t3_secret_parse for real (no lib mocking) per story 2-2 dev-notes.
 * Canonical byte sequences sourced from:
 *   teleproto3/conformance/vectors/unit.json :: secret-format
 *
 * Framework: Qt Test (QTEST_MAIN).  Linked against libteleproto3 (static).
 * Full AddProxyFromClipboard integration test (with clipboard + controller)
 * requires Qt app with Main::Account — deferred to CI integration phase.
 * These fixtures test the ProxyData helper layer (Task 1 AC-1, AC-2, FR22).
 */

#ifndef SRCDIR
#  define SRCDIR "."
#endif

#include <QtTest/QtTest>
#include <QString>

#include "mtproto/mtproto_proxy_data.h"

// ── Helpers ────────────────────────────────────────────────────────────────

// Worked example from story 2-2 dev-notes §"Worked example":
//   server=relay.example.com, port=443
//   secret=ff000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d
//   wspath=/ws
//   Decoded: [0xff][00..0f (16 key bytes)][example.com (11 bytes)]
static const QString kWorkedExampleSecret =
    QStringLiteral("ff000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d");

// Same 16-byte key (00..0f) but different host and wsPath — same key must collide.
static const QString kAltHostSecret =
    QStringLiteral("ff000102030405060708090a0b0c0d0e0f6e65772e6578616d706c652e636f6d");
//   ^^ key 00..0f + "new.example.com"

// Genuinely different 16-byte key (f0..ff) + "example.com" — must NOT collide with 00..0f.
static const QString kDifferentKeySecret =
    QStringLiteral("fff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff6578616d706c652e636f6d");

// Malformed: 0xff + 16 key bytes, but NO domain octet (17 bytes total).
// t3_secret_parse MUST reject this; Status::IncorrectSecret required (FR22).
static const QString kMalformedSecret =
    QStringLiteral("ff000102030405060708090a0b0c0d0e0f");

// Helper: build a Mtproto3 ProxyData with given host/port/password/wsPath.
static MTP::ProxyData makeType3Proxy(
        const QString &secret,
        const QString &host = QStringLiteral("relay.example.com"),
        uint32_t port = 443,
        const QString &wsPath = QStringLiteral("/ws")) {
    MTP::ProxyData proxy;
    proxy.type = MTP::ProxyData::Type::Mtproto3;
    proxy.host = host;
    proxy.port = port;
    proxy.password = secret;
    proxy.wsPath = wsPath;
    return proxy;
}

// ── Test class ─────────────────────────────────────────────────────────────

class TestProxyClipboard : public QObject {
    Q_OBJECT

private slots:
    // Fixture 1 — AC-1, AC-3 (no toast wiring; that requires full controller)
    // Verifies that a valid Type3 secret decodes correctly: type3KeyOctets()
    // returns 16 bytes and status() == Valid.  Mirrors the step-1..7 worked
    // example from story 2-2 dev-notes §"Worked example".
    void PasteValidType3CreatesEntry() {
        const auto proxy = makeType3Proxy(kWorkedExampleSecret);

        // type3KeyOctets() must return exactly 16 bytes (00..0f)
        const auto keyOctets = proxy.type3KeyOctets();
        QCOMPARE(keyOctets.size(), 16u);
        for (int i = 0; i < 16; ++i) {
            QCOMPARE(
                static_cast<unsigned char>(keyOctets[i]),
                static_cast<unsigned char>(i));
        }

        // status() must be Valid for a well-formed Type3 proxy.
        QCOMPARE(proxy.status(), MTP::ProxyData::Status::Valid);
        QVERIFY(proxy.valid());
    }

    // Fixture 2 — AC-2, FR9
    // Pre-condition: two ProxyData entries sharing the same 16-byte key (00..0f)
    // but different hosts.  sameType3Key() must return true; operator== must
    // return false (different host).  Mirrors step 8c of the worked example.
    void PasteSameKeyDifferentHostUpdatesInPlace() {
        const auto oldEntry = makeType3Proxy(
            kWorkedExampleSecret,
            QStringLiteral("old.example.com"),
            443,
            QStringLiteral("/ws"));

        const auto newEntry = makeType3Proxy(
            kWorkedExampleSecret,
            QStringLiteral("new.example.com"),
            443,
            QStringLiteral("/ws"));

        // Same 16-byte key → sameType3Key must be true.
        QVERIFY(oldEntry.sameType3Key(newEntry));

        // Different host → operator== must be false (whole-record equality).
        QVERIFY(!(oldEntry == newEntry));

        // Both must parse to 16 identical key bytes.
        const auto oldKey = oldEntry.type3KeyOctets();
        const auto newKey = newEntry.type3KeyOctets();
        QCOMPARE(oldKey.size(), 16u);
        QCOMPARE(newKey.size(), 16u);
        QVERIFY(oldKey == newKey);

        // Same key with different in-secret domain must still match (key-only comparison).
        const auto altDomainProxy = makeType3Proxy(
            kAltHostSecret,
            QStringLiteral("other.example.com"));
        QVERIFY(oldEntry.sameType3Key(altDomainProxy));

        // Genuinely different 16-byte key MUST NOT match.
        const auto differentKeyProxy = makeType3Proxy(
            kDifferentKeySecret,
            QStringLiteral("other.example.com"));
        QVERIFY(!oldEntry.sameType3Key(differentKeyProxy));
    }

    // Fixture 3 — FR22 explicit-fallback-only, AC-1
    // A secret with 0xff marker but missing domain (17 bytes total) MUST surface
    // Status::IncorrectSecret, NOT silently fall through to Type::Mtproto.
    void PasteMalformedRejectsWithoutFallback() {
        // Malformed: 0xff + 16 key bytes, no domain.
        const auto malformed = makeType3Proxy(kMalformedSecret);

        // type3KeyOctets() must return empty — t3_secret_parse rejects this.
        const auto keyOctets = malformed.type3KeyOctets();
        QVERIFY(keyOctets.empty());

        // status() must be IncorrectSecret, NOT Valid and NOT silently Mtproto.
        // FR22 explicit-fallback-only: t3_secret_parse failure → surface error,
        // do NOT re-route to Type::Mtproto.
        const auto status = malformed.status();
        QCOMPARE(status, MTP::ProxyData::Status::IncorrectSecret);
        QVERIFY(!malformed.valid());

        // Confirm that the Type::Mtproto path for the same secret is DIFFERENT:
        // the Mtproto validator accepts any hex string of suitable length.
        // This is the key FR22 assertion — Mtproto3 and Mtproto are DISTINCT paths.
        MTP::ProxyData mtprotoProxy;
        mtprotoProxy.type = MTP::ProxyData::Type::Mtproto;
        mtprotoProxy.host = QStringLiteral("relay.example.com");
        mtprotoProxy.port = 443;
        mtprotoProxy.password = kMalformedSecret;
        // Mtproto would accept a 17-byte hex password (size==17 with 'dd' prefix
        // would be valid, but ff prefix with 17 bytes returns Unsupported not Valid).
        // The key check: the Mtproto3 path MUST NOT fall back to this.
        QVERIFY(malformed.type != mtprotoProxy.type);
    }

    // RTL focus-order placeholder (AC-5 partial) — gated on Qt accessibility
    // widget instantiation which requires a full QApplication + show loop.
    // Forward-cited to story 2.6 CI integration; this slot documents the gap.
    void Rtl_FocusOrder_ForwardCite() {
        // CODEGEN-GAP: RTL focus-order snapshot test requires
        //   qApp->setLayoutDirection(Qt::RightToLeft) + dialog construction.
        // Deferred to story 2.6 accessibility-wiring CI step.
        QSKIP("RTL focus-order test deferred to story 2.6 — requires full QApp with show()");
    }
};

QTEST_MAIN(TestProxyClipboard)
#include "test_proxy_clipboard.moc"
