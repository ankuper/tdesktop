/*
 * test-tls-fingerprint-beta-qt.cpp — AR-C3 β-Qt fingerprint-lock test.
 *
 * Reads tdesktop/tests/fixtures/qt-openssl-clienthello.pcap, extracts the
 * TLS ClientHello, computes JA3 (Salesforce spec) and JA4 (FoxIO spec),
 * and diffs against the locked values in spec/client-tls-fingerprints.md
 * §profile-β-qt.
 *
 * Drift in JA3 or JA4 fails CI — no tolerance window (AC #3).
 * Byte-exact comparison only.
 *
 * CI gate: tdesktop/tests/test-tls-fingerprint-beta-qt exit-code 0.
 *
 * Fixture: real Qt 6.9.2 + OpenSSL 3.5.3 ClientHello captured from test-client
 * 192.168.30.191 connecting to 94.156.131.252.nip.io:443 (tcpdump on enp1s0f0).
 */

// SRCDIR fallback MUST be defined before first use of the macro.
#ifndef SRCDIR
#  define SRCDIR "."
#endif

#include <QtTest/QtTest>
#include <QByteArray>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QStringList>
#include <QVector>

#include <algorithm>
#include <cstdint>
#include <limits>

// ── Locked fingerprint values (spec/client-tls-fingerprints.md §profile-β-qt)
static const char kLockedJA3[] = "95c566c92c1aad5bf391aa24219700ec";
static const char kLockedJA4[] = "t13d5612_0000_c19c562a80bc_b7756960ef11";

// ── GREASE values (RFC 8701) ─────────────────────────────────────────────────
static bool isGREASE(uint16_t v) {
    return (v & 0x0f0f) == 0x0a0a && ((v >> 8) & 0x0f) == (v & 0x0f);
}

// ── Minimal ClientHello parser ───────────────────────────────────────────────

struct ClientHelloParsed {
    uint16_t legacyVersion = 0;
    QVector<uint16_t> cipherSuites;
    QVector<uint16_t> extTypes;          // in order of appearance
    QVector<uint16_t> supportedGroups;   // from extension 10
    QVector<uint8_t>  ecPointFormats;    // from extension 11
    QVector<uint16_t> supportedVersions; // from extension 43
    QVector<uint8_t>  alpnFirstValue;    // from extension 16, first entry
    bool hasSNI = false;
};

static ClientHelloParsed parseClientHello(const QByteArray &helloBody) {
    ClientHelloParsed out;
    const auto *d = reinterpret_cast<const uint8_t *>(helloBody.constData());
    int pos = 0;
    const int total = helloBody.size();

    auto readU8 = [&]() -> uint8_t {
        return (pos < total) ? d[pos++] : 0;
    };
    auto readU16 = [&]() -> uint16_t {
        if (pos + 2 > total) { pos = total; return 0; }
        uint16_t v = (uint16_t(d[pos]) << 8) | d[pos + 1];
        pos += 2;
        return v;
    };

    out.legacyVersion = readU16();

    // random (32 bytes)
    if (pos + 32 > total) return out;
    pos += 32;

    // session_id
    int sidLen = readU8();
    if (pos + sidLen > total) return out;
    pos += sidLen;

    // cipher_suites
    int ciphersLen = readU16();
    int ciphersEnd = pos + ciphersLen;
    if (ciphersEnd > total) return out;
    while (pos + 2 <= ciphersEnd) {
        uint16_t cs = readU16();
        if (!isGREASE(cs) && cs != 0x00FF) {
            out.cipherSuites.append(cs);
        }
    }
    pos = ciphersEnd;

    // compression_methods
    int compLen = readU8();
    if (pos + compLen > total) return out;
    pos += compLen;
    if (pos + 2 > total) return out;

    // extensions
    int extsTotal = readU16();
    int extsEnd = pos + extsTotal;
    if (extsEnd > total) return out;
    while (pos + 4 <= extsEnd) {
        uint16_t extType = readU16();
        int extLen = readU16();
        int extEnd = pos + extLen;
        if (extEnd > extsEnd) break;  // truncated extension body
        if (!isGREASE(extType)) {
            out.extTypes.append(extType);
        }
        if (extType == 0 && extLen >= 5) {                 // server_name
            out.hasSNI = true;
        } else if (extType == 10 && extLen >= 2) {         // supported_groups
            int grpLen = (int(d[pos]) << 8) | d[pos + 1];
            int grpEnd = std::min(pos + 2 + grpLen, extEnd);
            for (int i = pos + 2; i + 2 <= grpEnd; i += 2) {
                uint16_t g = (uint16_t(d[i]) << 8) | d[i + 1];
                if (!isGREASE(g)) out.supportedGroups.append(g);
            }
        } else if (extType == 11 && extLen >= 1) {         // ec_point_formats
            int pfLen = d[pos];
            int pfEnd = std::min(pos + 1 + pfLen, extEnd);
            for (int i = pos + 1; i < pfEnd; ++i) {
                out.ecPointFormats.append(d[i]);
            }
        } else if (extType == 43 && extLen >= 1) {         // supported_versions
            int svLen = d[pos];
            int svEnd = std::min(pos + 1 + svLen, extEnd);
            for (int i = pos + 1; i + 2 <= svEnd; i += 2) {
                uint16_t v = (uint16_t(d[i]) << 8) | d[i + 1];
                if (!isGREASE(v)) out.supportedVersions.append(v);
            }
        } else if (extType == 16 && extLen >= 4 &&
                   out.alpnFirstValue.isEmpty()) {         // ALPN
            // protocol_name_list_length (2), then protocol_name_length (1), name
            int pnlLen = (int(d[pos]) << 8) | d[pos + 1];
            int pnlEnd = std::min(pos + 2 + pnlLen, extEnd);
            if (pos + 3 <= pnlEnd) {
                int nameLen = d[pos + 2];
                int nameEnd = std::min(pos + 3 + nameLen, pnlEnd);
                for (int i = pos + 3; i < nameEnd; ++i) {
                    out.alpnFirstValue.append(d[i]);
                }
            }
        }
        pos = extEnd;
    }
    return out;
}

// ── JA3 computation (Salesforce spec) ────────────────────────────────────────

static QString computeJA3(const ClientHelloParsed &ch) {
    QStringList parts;
    parts << QString::number(ch.legacyVersion);

    QStringList cs;
    for (auto c : ch.cipherSuites) cs << QString::number(c);
    parts << cs.join('-');

    QStringList exts;
    for (auto e : ch.extTypes) exts << QString::number(e);
    parts << exts.join('-');

    QStringList grps;
    for (auto g : ch.supportedGroups) grps << QString::number(g);
    parts << grps.join('-');

    QStringList pf;
    for (auto p : ch.ecPointFormats) pf << QString::number(p);
    parts << pf.join('-');

    QString ja3str = parts.join(',');
    QByteArray hash = QCryptographicHash::hash(ja3str.toUtf8(),
                                               QCryptographicHash::Md5);
    return QString::fromLatin1(hash.toHex());
}

// ── JA4 computation (FoxIO spec) ─────────────────────────────────────────────
//
// Reference: https://github.com/FoxIO-LLC/ja4
// Layout: t<TLSVersion><SNIFlag><CipherCount><ExtCount>_<ALPN>_<CipherHash>_<ExtHash>
//   ALPN encoding: 4-char field. For ASCII-printable ALPN value (e.g. "h2"),
//     emit `<first><last>` doubled if length 1, padded if absent.
//     For non-printable / no ALPN, emit "0000".

static QString ja4AlpnField(const QVector<uint8_t> &alpn) {
    if (alpn.isEmpty()) return QStringLiteral("0000");
    auto isPrintable = [](uint8_t b) { return b >= 0x20 && b <= 0x7e; };
    auto firstChar = static_cast<char>(alpn.first());
    auto lastChar  = static_cast<char>(alpn.last());
    if (alpn.size() == 1) {
        // FoxIO spec: doubles the single char to fill the 4-byte field.
        if (!isPrintable(alpn.first())) return QStringLiteral("0000");
        return QString(QChar(firstChar)).repeated(2) +
               QString(QChar('0')).repeated(2);  // legacy 4-char zero-pad
    }
    if (!isPrintable(alpn.first()) || !isPrintable(alpn.last())) {
        return QStringLiteral("0000");
    }
    // FoxIO JA4: <first-char><last-char> followed by zero padding to 4 chars
    QString out;
    out += QChar(firstChar);
    out += QChar(lastChar);
    while (out.size() < 4) out += '0';
    return out;
}

static QString computeJA4(const ClientHelloParsed &ch) {
    // TLS version: highest from supported_versions, or legacy_version.
    // Filter GREASE (RFC 8701) — values like 0x?a?a are draft markers, not real versions.
    uint16_t highestVer = ch.legacyVersion;
    for (auto v : ch.supportedVersions) {
        if (isGREASE(v)) continue;
        // Reject draft versions (>= 0x7f00) — they are not real TLS versions.
        if (v >= 0x7f00) continue;
        if (v > highestVer) highestVer = v;
    }
    QString tlsVer;
    if (highestVer == 0x0304)      tlsVer = "13";
    else if (highestVer == 0x0303) tlsVer = "12";
    else if (highestVer == 0x0302) tlsVer = "11";
    else if (highestVer == 0x0301) tlsVer = "10";
    else                           tlsVer = "00";

    QString sniFlag = ch.hasSNI ? QStringLiteral("d") : QStringLiteral("i");

    // FoxIO JA4 caps cipher / ext counts at 99 (2 digits). Clamp explicitly.
    int numCiphers = (int)std::min(ch.cipherSuites.size(), (qsizetype)99);
    int numExts    = (int)std::min(ch.extTypes.size(),    (qsizetype)99);

    QString alpn = ja4AlpnField(ch.alpnFirstValue);

    // Cipher hash: SHA256 of sorted cipher IDs (hex, comma-sep), first 12 chars
    QVector<uint16_t> sortedCS = ch.cipherSuites;
    std::sort(sortedCS.begin(), sortedCS.end());
    QStringList csHex;
    for (auto c : sortedCS) csHex << QString("%1").arg(c, 4, 16, QChar('0'));
    QByteArray cipherHash = QCryptographicHash::hash(
        csHex.join(',').toUtf8(), QCryptographicHash::Sha256).toHex().left(12);

    // Extension hash: SHA256 of sorted ext types excluding SNI(0) and ALPN(16), first 12 chars
    QVector<uint16_t> sortedExts;
    for (auto e : ch.extTypes) {
        if (e != 0 && e != 16) sortedExts.append(e);
    }
    std::sort(sortedExts.begin(), sortedExts.end());
    QStringList extNums;
    for (auto e : sortedExts) extNums << QString::number(e);
    QByteArray extHash = QCryptographicHash::hash(
        extNums.join(',').toUtf8(), QCryptographicHash::Sha256).toHex().left(12);

    return QString("t%1%2%3%4_%5_%6_%7")
        .arg(tlsVer)
        .arg(sniFlag)
        .arg(numCiphers, 2, 10, QChar('0'))
        .arg(numExts,    2, 10, QChar('0'))
        .arg(alpn)
        .arg(QString::fromLatin1(cipherHash))
        .arg(QString::fromLatin1(extHash));
}

// ── Test class ────────────────────────────────────────────────────────────────

class TlsFingerprintTest : public QObject {
    Q_OBJECT

private slots:
    void testBetaQtProfile() {
        // Locate fixture relative to the test binary's source tree.
        QString fixturePath;
        const QStringList candidates = {
            QString(SRCDIR) + "/tests/fixtures/qt-openssl-clienthello.pcap",
            QString(SRCDIR) + "/fixtures/qt-openssl-clienthello.pcap",
            QDir::currentPath() + "/tests/fixtures/qt-openssl-clienthello.pcap",
            QDir::currentPath() + "/fixtures/qt-openssl-clienthello.pcap",
        };
        for (const auto &c : candidates) {
            if (QFile::exists(c)) { fixturePath = c; break; }
        }
        QVERIFY2(!fixturePath.isEmpty(),
                 "Fixture qt-openssl-clienthello.pcap not found; "
                 "set -DSRCDIR=... or run from tdesktop source root");

        QFile f(fixturePath);
        QVERIFY2(f.open(QIODevice::ReadOnly), "Cannot open PCAP fixture");
        QByteArray raw = f.readAll();
        f.close();

        // ── Parse PCAP global header ──────────────────────────────────────
        QVERIFY2(raw.size() >= 24, "PCAP file too small for global header");
        const auto *gd = reinterpret_cast<const uint8_t *>(raw.constData());
        const uint32_t magic = uint32_t(gd[0]) | (uint32_t(gd[1]) << 8) |
                               (uint32_t(gd[2]) << 16) | (uint32_t(gd[3]) << 24);
        // We only support little-endian classic PCAP (magic = 0xa1b2c3d4).
        // PCAPNG and big-endian classic require conversion before commit.
        QVERIFY2(magic == 0xa1b2c3d4u,
                 "PCAP magic mismatch: only little-endian classic PCAP supported "
                 "(convert PCAPNG via `tshark -F pcap -r in.pcapng -w out.pcap`)");
        const uint32_t linkType = uint32_t(gd[20]) | (uint32_t(gd[21]) << 8) |
                                  (uint32_t(gd[22]) << 16) | (uint32_t(gd[23]) << 24);
        QVERIFY2(linkType == 1u, "Expected DLT_EN10MB (Ethernet) PCAP");

        // ── Read first packet ─────────────────────────────────────────────
        QVERIFY2(raw.size() >= 40, "PCAP too small for first packet header");
        const uint32_t inclLen = uint32_t(gd[36]) | (uint32_t(gd[37]) << 8) |
                                 (uint32_t(gd[38]) << 16) | (uint32_t(gd[39]) << 24);
        // Bound inclLen safely: must not exceed remaining buffer.
        QVERIFY2(inclLen <= static_cast<uint32_t>(std::numeric_limits<int>::max()) - 40,
                 "PCAP inclLen overflow");
        QVERIFY2(static_cast<uint64_t>(raw.size()) >= 40ull + inclLen,
                 "Packet data truncated");

        const auto *pkt = gd + 40;  // start of Ethernet frame

        // ── Skip Ethernet + IPv4 + TCP, validating bounds at each step ────
        constexpr int kEthHdrLen = 14;
        QVERIFY2(inclLen > static_cast<uint32_t>(kEthHdrLen),
                 "Packet shorter than Ethernet header");

        // IPv4 header.
        QVERIFY2(inclLen >= static_cast<uint32_t>(kEthHdrLen) + 20u,
                 "Packet shorter than IPv4 minimum header");
        const auto *ipHdr = pkt + kEthHdrLen;
        const uint8_t ipIHL = ipHdr[0] & 0x0f;
        const int ipHdrLen = ipIHL * 4;
        QVERIFY2(ipHdrLen >= 20, "IPv4 IHL too small");
        QVERIFY2(inclLen >= static_cast<uint32_t>(kEthHdrLen + ipHdrLen),
                 "Packet shorter than declared IPv4 header");

        // TCP header.
        QVERIFY2(inclLen >= static_cast<uint32_t>(kEthHdrLen + ipHdrLen) + 20u,
                 "Packet shorter than TCP minimum header");
        const auto *tcpHdr = ipHdr + ipHdrLen;
        const uint8_t tcpOffset = (tcpHdr[12] >> 4) & 0x0f;
        const int tcpHdrLen = tcpOffset * 4;
        QVERIFY2(tcpHdrLen >= 20, "TCP data offset too small");
        QVERIFY2(inclLen >=
                     static_cast<uint32_t>(kEthHdrLen + ipHdrLen + tcpHdrLen),
                 "Packet shorter than declared TCP header");

        const auto *tlsStart = tcpHdr + tcpHdrLen;
        const int remaining = int(inclLen) - kEthHdrLen - ipHdrLen - tcpHdrLen;
        QVERIFY2(remaining >= 5, "No room for TLS record header");

        // ── Verify TLS record header ──────────────────────────────────────
        QVERIFY2(tlsStart[0] == 0x16, "Not a TLS Handshake record (content type ≠ 22)");
        const int tlsLen = (int(tlsStart[3]) << 8) | tlsStart[4];
        QVERIFY2(remaining >= 5 + tlsLen, "TLS record truncated");

        // ── Verify Handshake type ─────────────────────────────────────────
        const auto *hs = tlsStart + 5;
        QVERIFY2(hs[0] == 0x01, "Handshake type is not ClientHello");
        const int hsLen = (int(hs[1]) << 16) | (int(hs[2]) << 8) | hs[3];
        QVERIFY2(tlsLen >= 4 + hsLen, "Handshake record truncated");

        const QByteArray helloBody(reinterpret_cast<const char *>(hs + 4), hsLen);

        // ── Parse ClientHello ─────────────────────────────────────────────
        ClientHelloParsed ch = parseClientHello(helloBody);
        QVERIFY2(!ch.cipherSuites.isEmpty(), "No cipher suites parsed from ClientHello");

        // ── Compute and compare JA3 ───────────────────────────────────────
        const QString ja3 = computeJA3(ch);
        QVERIFY2(ja3 == QLatin1String(kLockedJA3),
                 qPrintable(QString("JA3 drift detected!\n  got:    %1\n  locked: %2\n"
                                    "Update fixture + spec/client-tls-fingerprints.md "
                                    "§profile-β-qt per story 2.1 Dev Notes.")
                            .arg(ja3, kLockedJA3)));

        // ── Compute and compare JA4 ───────────────────────────────────────
        const QString ja4 = computeJA4(ch);
        QVERIFY2(ja4 == QLatin1String(kLockedJA4),
                 qPrintable(QString("JA4 drift detected!\n  got:    %1\n  locked: %2\n"
                                    "Update fixture + spec/client-tls-fingerprints.md "
                                    "§profile-β-qt per story 2.1 Dev Notes.")
                            .arg(ja4, kLockedJA4)));
    }
};

QTEST_MAIN(TlsFingerprintTest)
#include "test-tls-fingerprint-beta-qt.moc"
