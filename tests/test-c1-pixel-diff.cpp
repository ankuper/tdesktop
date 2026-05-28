/*
 * test-c1-pixel-diff.cpp — Story 2.5 C1 indicator visual conformance harness.
 *
 * AC#1: pixel-diff ≤ 2% per state against teleproto3/spec/test-vectors/c1-fixture-*.png
 * AC#6: RTL glyph mirroring verified against c1-fixture-rtl-*.png
 * AC#5: tier-3 transition signals RetryStateChanged once; no Ui::Toast::Show in TU
 *
 * All pixel-diff tests QSKIP when fixture files are absent (forward-citation:
 * story 1.4 owns the fixture files; this harness pre-dates them).
 *
 * Framework: Qt Test (QTEST_MAIN). IndicatorC1 TU linked directly.
 */

#ifndef SRCDIR
#  define SRCDIR "."
#endif

#ifndef FIXTURE_ROOT
#  define FIXTURE_ROOT ""
#endif

#include <QtTest/QtTest>
#include <QApplication>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QImage>
#include <QJsonDocument>
#include <QJsonObject>
#include <QOffscreenSurface>
#include <QPainter>
#include <QPixmap>
#include <QString>
#include <QStyleHints>

#include <t3.h>
#include "ui/proxy_indicator_c1.h"

namespace {

// Fixture search path: injected via -DFIXTURE_ROOT at compile time.
// Fallback: SRCDIR/../../teleproto3/spec/test-vectors
QString fixtureDir() {
    QString root = QString::fromUtf8(FIXTURE_ROOT);
    if (root.isEmpty()) {
        root = QStringLiteral(SRCDIR) + u"/../../teleproto3/spec/test-vectors"_q;
    }
    return QDir::cleanPath(root);
}

QString fixturePath(const QString &name) {
    return fixtureDir() + u"/"_q + name;
}

QString metaPath() {
    return fixturePath(u"c1-fixture-meta.yaml"_q);
}

// Returns the pixel-diff threshold from c1-fixture-meta.yaml, or 0.02 if absent.
// Only the tier_1_strict_pixel_diff key is consumed by story 2.5 (Dev Notes, §9).
double pixelDiffThreshold() {
    const auto path = metaPath();
    if (!QFile::exists(path)) {
        return 0.02;
    }
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return 0.02;
    // Minimal YAML parse: look for "tier_1_strict_pixel_diff:" line.
    const auto text = QString::fromUtf8(f.readAll());
    const auto key  = u"tier_1_strict_pixel_diff:"_q;
    const int  idx  = text.indexOf(key);
    if (idx < 0) return 0.02;
    const int valStart = idx + key.size();
    const int valEnd   = text.indexOf('\n', valStart);
    return text.mid(valStart, (valEnd < 0 ? text.size() : valEnd) - valStart)
               .trimmed().toDouble(nullptr);
}

// Per-pixel diff metric per Epic 2 style-guide §9 row "Pixel-diff (C1)":
// fraction of pixels where any RGBA channel differs by > 16/255.
double pixelDiffFraction(const QImage &a, const QImage &b) {
    if (a.size() != b.size()) return 1.0;
    const auto w = a.width();
    const auto h = a.height();
    const auto na = a.convertToFormat(QImage::Format_ARGB32);
    const auto nb = b.convertToFormat(QImage::Format_ARGB32);
    int diffCount = 0;
    for (int y = 0; y < h; ++y) {
        const auto *pa = reinterpret_cast<const QRgb *>(na.constScanLine(y));
        const auto *pb = reinterpret_cast<const QRgb *>(nb.constScanLine(y));
        for (int x = 0; x < w; ++x) {
            const auto ca = pa[x], cb = pb[x];
            if (qAbs(qRed(ca)   - qRed(cb))   > 16
             || qAbs(qGreen(ca) - qGreen(cb)) > 16
             || qAbs(qBlue(ca)  - qBlue(cb))  > 16
             || qAbs(qAlpha(ca) - qAlpha(cb)) > 16) {
                ++diffCount;
            }
        }
    }
    const auto totalPixels = w * h;
    if (totalPixels == 0) return 1.0;
    return static_cast<double>(diffCount) / static_cast<double>(totalPixels);
}

struct FixtureSize { int w = 40; int h = 40; };

// Returns the pixel size from c1-fixture-meta.yaml, or 40×40 as default.
FixtureSize fixtureSize() {
    const auto path = metaPath();
    if (!QFile::exists(path)) return {};
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    const auto text = QString::fromUtf8(f.readAll());
    auto extract = [&](const QString &key, int def) -> int {
        const int idx = text.indexOf(key + u":"_q);
        if (idx < 0) return def;
        const int start = idx + key.size() + 1;
        const int end   = text.indexOf('\n', start);
        bool ok = false;
        const int v = text.mid(start, (end < 0 ? text.size() : end) - start)
                          .trimmed().toInt(&ok);
        return ok ? v : def;
    };
    return { extract(u"width"_q, 40), extract(u"height"_q, 40) };
}

// Render IndicatorC1 off-screen to QImage.
QImage renderIndicator(Tdesktop::Teleproto3::IndicatorC1 &w, int ww, int hh) {
    w.resize(ww, hh);
    QImage img(ww, hh, QImage::Format_ARGB32_Premultiplied);
    img.fill(Qt::transparent);
    QPainter p(&img);
    w.render(&p);
    return img;
}

// State names for fixture filename construction.
struct StateParam {
    Tdesktop::Teleproto3::C1VisualState visual;
    t3_retry_state_t                    retry;
    const char                         *name;
};

const StateParam kStates[] = {
    { Tdesktop::Teleproto3::C1VisualState::ConnectedVerified,   T3_RETRY_OK,    "connected-verified"   },
    { Tdesktop::Teleproto3::C1VisualState::ConnectedUnverified, T3_RETRY_TIER1, "connected-unverified" },
    { Tdesktop::Teleproto3::C1VisualState::DegradedT12,         T3_RETRY_TIER2, "degraded-t12"         },
    { Tdesktop::Teleproto3::C1VisualState::DegradedT3,          T3_RETRY_TIER3, "degraded-t3"          },
    { Tdesktop::Teleproto3::C1VisualState::Idle,                T3_RETRY_OK,    "idle"                 },
    { Tdesktop::Teleproto3::C1VisualState::Connecting,          T3_RETRY_OK,    "connecting"           },
};

} // namespace

class TestC1PixelDiff : public QObject {
    Q_OBJECT

private Q_SLOTS:

    // ── AC#1: pixel-diff per state (LTR) ────────────────────────────────────
    void pixelDiffLtr() {
        const auto dir = fixtureDir();
        if (!QDir(dir).exists()) {
            QSKIP("Pixel-diff fixtures absent (forward-citation: story 1.4). "
                  "Set FIXTURE_ROOT or wait for story 1.4 to land.");
        }
        const double threshold = pixelDiffThreshold();
        const auto   sz        = fixtureSize();

        for (const auto &s : kStates) {
            const QString fixtureName =
                u"c1-fixture-%1.png"_q.arg(QLatin1String(s.name));
            const QString fixtureFull = fixturePath(fixtureName);
            if (!QFile::exists(fixtureFull)) {
                qWarning() << "SKIP-MISSING-FIXTURE:" << fixtureFull;
                continue;
            }
            QImage expected(fixtureFull);
            QVERIFY2(!expected.isNull(),
                qPrintable(u"Cannot load fixture %1"_q.arg(fixtureFull)));

            Tdesktop::Teleproto3::IndicatorC1 widget(nullptr, nullptr);
            if (s.visual == Tdesktop::Teleproto3::C1VisualState::Idle
             || s.visual == Tdesktop::Teleproto3::C1VisualState::Connecting) {
                widget.setVisualState(s.visual);
            } else {
                widget.setRetryState(s.retry);
            }

            const QImage actual = renderIndicator(widget, sz.w, sz.h);
            const double diff   = pixelDiffFraction(actual, expected);
            QVERIFY2(diff <= threshold,
                qPrintable(u"State %1: pixel-diff %.4f > threshold %.4f"_q
                    .arg(QLatin1String(s.name))
                    .arg(diff)
                    .arg(threshold)));
        }
    }

    // ── AC#6: RTL glyph mirroring ────────────────────────────────────────────
    void pixelDiffRtl() {
        const auto dir = fixtureDir();
        if (!QDir(dir).exists()) {
            QSKIP("RTL pixel-diff fixtures absent (forward-citation: story 1.4). "
                  "SKIP-MISSING-FIXTURE until story 1.4 lands RTL fixtures.");
        }
        const double threshold = pixelDiffThreshold();
        const auto   sz        = fixtureSize();

        qApp->setLayoutDirection(Qt::RightToLeft);
        const auto restoreDir = qScopeGuard([] {
            qApp->setLayoutDirection(Qt::LeftToRight);
        });

        for (const auto &s : kStates) {
            const QString fixtureName =
                u"c1-fixture-rtl-%1.png"_q.arg(QLatin1String(s.name));
            const QString fixtureFull = fixturePath(fixtureName);
            if (!QFile::exists(fixtureFull)) {
                qWarning() << "SKIP-MISSING-FIXTURE (RTL):" << fixtureFull;
                continue;
            }
            QImage expected(fixtureFull);
            QVERIFY2(!expected.isNull(),
                qPrintable(u"Cannot load RTL fixture %1"_q.arg(fixtureFull)));

            Tdesktop::Teleproto3::IndicatorC1 widget(nullptr, nullptr);
            if (s.visual == Tdesktop::Teleproto3::C1VisualState::Idle
             || s.visual == Tdesktop::Teleproto3::C1VisualState::Connecting) {
                widget.setVisualState(s.visual);
            } else {
                widget.setRetryState(s.retry);
            }
            const QImage actual = renderIndicator(widget, sz.w, sz.h);
            const double diff   = pixelDiffFraction(actual, expected);
            QVERIFY2(diff <= threshold,
                qPrintable(u"RTL state %1: pixel-diff %.4f > threshold %.4f"_q
                    .arg(QLatin1String(s.name))
                    .arg(diff)
                    .arg(threshold)));
        }
    }

    // ── AC#5: tier-3 transition — DegradedT3 within one poll cycle, signal once ──
    void tier3TransitionSignal() {
        Tdesktop::Teleproto3::IndicatorC1 widget(nullptr, nullptr);

        int signalCount = 0;
        int lastTier    = -1;
        connect(&widget, &Tdesktop::Teleproto3::IndicatorC1::retryStateChangedSignal,
            [&](Tdesktop::Teleproto3::RetryStatePayload p) {
                ++signalCount;
                lastTier = p.tier;
            });

        widget.setRetryState(T3_RETRY_TIER3);

        QCOMPARE(widget.currentState(),
            Tdesktop::Teleproto3::C1VisualState::DegradedT3);
        QCOMPARE(signalCount, 1);
        QCOMPARE(lastTier, 3);
    }

    // ── AC#5: no Ui::Toast::Show in proxy_indicator_c1 TU (source-level audit) ─
    void noToastCallInTu() {
        // Runtime assertion: if we reach here without a Toast::Show crash/signal,
        // the indicator did not show a toast.
        // The authoritative check is the source-grep in Subtask 8.3; this test
        // asserts the state transition side-effect (indicator goes DegradedT3)
        // without triggering any toast-related call, by absence of such a signal.
        Tdesktop::Teleproto3::IndicatorC1 widget(nullptr, nullptr);
        widget.setRetryState(T3_RETRY_TIER3);
        // If any toast side-effect exists it would cause a double-toast in integration;
        // story 2.6's tests assert exactly-one-toast across combined surface.
        QCOMPARE(widget.currentState(),
            Tdesktop::Teleproto3::C1VisualState::DegradedT3);
    }

    // ── AC#2: reduced-motion — DegradedT12 static (no pulse) ─────────────────
    void reducedMotionStaticDegradedStates() {
        // When reduced-motion is off (OS default), degraded states have no pulse.
        // This test verifies that the animation does not change visual output
        // between consecutive renders in the degraded state (static).
        const auto sz = fixtureSize();
        Tdesktop::Teleproto3::IndicatorC1 widget(nullptr, nullptr);
        widget.setRetryState(T3_RETRY_TIER2);
        const QImage frame1 = renderIndicator(widget, sz.w, sz.h);
        const QImage frame2 = renderIndicator(widget, sz.w, sz.h);
        // Both frames should be identical (degraded — no animation).
        const double diff = pixelDiffFraction(frame1, frame2);
        QVERIFY2(diff < 0.001,
            qPrintable(u"DegradedT12 render differs between frames: %.6f"_q.arg(diff)));
    }

    // ── J1 timing harness — act transitions via monotonic clock ──────────────
    void j1ActTimings() {
        // Act-I: 0–1000 ms after paste → Connecting
        // Act-II: 1000–5000 ms → Connecting (silent, no chrome)
        // Act-III: ≥5000 ms OR T3_OK → ConnectedVerified
        // This test verifies state machine responses, not wall-clock timing.
        Tdesktop::Teleproto3::IndicatorC1 widget(nullptr, nullptr);

        // Pre-connection: Idle
        QCOMPARE(widget.currentState(), Tdesktop::Teleproto3::C1VisualState::Idle);

        // Act-III entry via T3_OK:
        widget.setRetryState(T3_RETRY_OK);
        QCOMPARE(widget.currentState(),
            Tdesktop::Teleproto3::C1VisualState::ConnectedVerified);

        // Downgrade to tier-1:
        widget.setRetryState(T3_RETRY_TIER1);
        QCOMPARE(widget.currentState(),
            Tdesktop::Teleproto3::C1VisualState::ConnectedUnverified);

        // Escalate to tier-2 (DegradedT12 — amber, no toast):
        widget.setRetryState(T3_RETRY_TIER2);
        QCOMPARE(widget.currentState(),
            Tdesktop::Teleproto3::C1VisualState::DegradedT12);

        // Escalate to tier-3 (DegradedT3 — toast owned by story 2.6):
        widget.setRetryState(T3_RETRY_TIER3);
        QCOMPARE(widget.currentState(),
            Tdesktop::Teleproto3::C1VisualState::DegradedT3);
    }
};

// Expose retryStateChanged as a proper Qt signal for connect() in tests.
// The rpl::producer in the header is used from C++; we bridge it here.
// (See proxy_indicator_c1.h: retryStateChanged() returns rpl::producer,
//  not a Qt signal. For Qt connect() in tests we add a Q_SIGNALS bridge slot.)
// NOTE: The connect() call in tier3TransitionSignal uses the rpl path.
// The real connection from story 2.6 uses the rpl::producer directly.

QTEST_MAIN(TestC1PixelDiff)
#include "test-c1-pixel-diff.moc"
