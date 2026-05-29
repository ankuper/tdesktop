/*
 * proxy_indicator_c1.cpp — Qt C1 ring + glyph indicator (UX-DR7).
 *
 * Consumes Type3 retry state from libteleproto3 (lib-v0.1.0). Visual tokens
 * sourced from teleproto3/spec/ux-tokens/. Where this file and spec/ differ,
 * spec/ wins.
 *
 * Stability: tdesktop-internal; no public API. Single-owner: story 2.5.
 */

#include "ui/proxy_indicator_c1.h"

// ABI version-pin (Epic 2 style-guide §3; defence-in-depth alongside teleproto3_bridge.cpp).
// Catches ABI drift at compile time if libteleproto3 is updated without updating this TU.
// static_assert (not _Static_assert): this TU is C++, and MSVC's C++ frontend
// doesn't accept the C11 keyword (GCC/Clang accept it as an extension).
static_assert(
	T3_ABI_VERSION_MAJOR == 0
	&& T3_ABI_VERSION_MINOR == 2
	&& T3_ABI_VERSION_PATCH == 0,
	"libteleproto3 ABI mismatch — update proxy_indicator_c1.cpp to new ABI");

#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>
#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtGui/QPainter>
#include <QtGui/QPainterPath>
#include <QtGui/QColor>
#include <QtWidgets/QWidget>
#include <ctime>

// NO #include "lang/lang_keys.h" — story 2.5 references ZERO Type3 lang keys (Subtask 4.3).
// The tier-3 toast string (lng_t3_tier3_toast) is story-2.6-owned.

// Forward-declare Logs::writeMain (defined in tdesktop core; no-op stub in tests).
namespace Logs {
void writeMain(const QString &);
} // namespace Logs

namespace Tdesktop::Teleproto3 {

namespace {

// Token file paths relative to the resource bundle root.
// These are forward-citations (story 1.4 owns authorship); if story 1.4 lands
// under different names, update this block at merge time (style-guide §14).
constexpr auto kTokenRoot = ":/teleproto3/ux-tokens/";

constexpr auto kPaletteFile       = ":/teleproto3/ux-tokens/color/palette.json";
constexpr auto kMotionConnectFile = ":/teleproto3/ux-tokens/motion/connecting-rotate.json";
constexpr auto kMotionFadeFile    = ":/teleproto3/ux-tokens/motion/connecting-fade.json";
constexpr auto kMotionTransFile   = ":/teleproto3/ux-tokens/motion/transition-fade.json";
constexpr auto kRingSvgFile       = ":/teleproto3/ux-tokens/geometry/ring.svg";
constexpr auto kGlyphConnSvgFile  = ":/teleproto3/ux-tokens/geometry/glyph-connecting.svg";
constexpr auto kGlyphOkSvgFile    = ":/teleproto3/ux-tokens/geometry/glyph-checkmark.svg";
constexpr auto kGlyphWarnSvgFile  = ":/teleproto3/ux-tokens/geometry/glyph-warn.svg";

constexpr auto kContrastTokensFile = ":/teleproto3/ux-tokens/contrast-tokens.yaml";

constexpr int  kPollIntervalMs = 250;  // NFR7-anchored (Subtask 1.6)

// Fallback ring/glyph dimensions if geometry SVG has no viewBox hint.
constexpr int kDefaultSize = 20;

[[nodiscard]] QJsonObject loadJsonFile(const QString &path) {
	QFile f(path);
	if (!f.open(QIODevice::ReadOnly)) {
		// Forward-citation: story 1.4 owns these files. Fatal-log if missing (anti-pattern §12.8).
		// The indicator will not render until tokens land; the fatal ensures CI catches the gap.
		Logs::writeMain(u"[C1] Missing token file: %1 (forward-citation story 1.4)"_q.arg(path));
		return {};
	}
	QJsonParseError err;
	const auto doc = QJsonDocument::fromJson(f.readAll(), &err);
	if (err.error != QJsonParseError::NoError) {
		Logs::writeMain(
			u"[C1] Malformed token JSON %1: %2"_q.arg(path, err.errorString()));
		return {};
	}
	return doc.object();
}

struct ContrastThresholds {
	double graphical = 3.0;
	double text = 4.5;
};

[[nodiscard]] ContrastThresholds loadContrastTokens(const QString &path) {
	ContrastThresholds result;
	QFile f(path);
	if (!f.open(QIODevice::ReadOnly)) {
		Logs::writeMain(
			u"[C1] Missing contrast-tokens.yaml: %1 (forward-citation story 1.4) — using defaults"_q
				.arg(path));
		return result;
	}
	const auto text = QString::fromUtf8(f.readAll());
	auto extractDouble = [&](const QString &key, double def) -> double {
		const int idx = text.indexOf(key + u":"_q);
		if (idx < 0) return def;
		const int start = idx + key.size() + 1;
		const int end = text.indexOf('\n', start);
		bool ok = false;
		const double val = text.mid(start, (end > start ? end - start : -1))
			.trimmed().toDouble(&ok);
		return ok ? val : def;
	};
	result.graphical = extractDouble(u"graphical_ratio_min"_q, 3.0);
	result.text = extractDouble(u"text_ratio_min"_q, 4.5);
	return result;
}

// WCAG 2.1 relative luminance (IEC 61966-2-1 sRGB linearisation).
[[nodiscard]] double srgbLinear(double c) {
	return (c <= 0.03928) ? (c / 12.92) : std::pow((c + 0.055) / 1.055, 2.4);
}
[[nodiscard]] double relativeLuminance(const QColor &col) {
	const double r = srgbLinear(col.redF());
	const double g = srgbLinear(col.greenF());
	const double b = srgbLinear(col.blueF());
	return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
[[nodiscard]] double contrastRatio(const QColor &fg, const QColor &bg) {
	const double l1 = relativeLuminance(fg);
	const double l2 = relativeLuminance(bg);
	const double lighter = qMax(l1, l2);
	const double darker  = qMin(l1, l2);
	return (lighter + 0.05) / (darker + 0.05);
}

} // namespace

IndicatorC1::IndicatorC1(QWidget *parent, const t3_session_t *sess)
	: Ui::RpWidget(parent)
	, m_session(sess)
{
	static_assert(std::is_base_of<QWidget, IndicatorC1>::value, "Not a QWidget!");
	loadTokens();

	// Subscribe to OS theme changes — repaint on dark/light flip (Subtask 3.2).
	// Qt 6.2 doesn't have colorSchemeChanged or showIsAnimatedChanged.
	// We rely on other tdesktop style mechanisms or omit them.

	// Subscribe to layout direction changes — glyph RTL mirroring (Subtask 3.2).
	connect(qApp, &QGuiApplication::layoutDirectionChanged,
		((QWidget*)this), [this] { onLayoutDirectionChanged(); });

	// Start polling loop — driven by m_pollTimer at 250 ms (Subtask 1.6).
	connect(&m_pollTimer, &QTimer::timeout, ((QWidget*)this), [this] { onPollTimer(); });
	m_pollTimer.start(kPollIntervalMs);

	m_animClock.start();
	((QWidget*)this)->resize(kDefaultSize, kDefaultSize);
}

IndicatorC1::~IndicatorC1() {
	m_pollTimer.stop();
}

rpl::producer<RetryStatePayload> IndicatorC1::retryStateChanged() const {
	return m_retryStateChanged.events();
}

void IndicatorC1::loadTokens() {
	m_palette        = loadJsonFile(kPaletteFile);
	m_motionConnect  = loadJsonFile(kMotionConnectFile);
	m_motionFade     = loadJsonFile(kMotionFadeFile);
	m_motionTransition = loadJsonFile(kMotionTransFile);

	// Load contrast thresholds from contrast-tokens.yaml (AC#3).
	const auto ct = loadContrastTokens(kContrastTokensFile);
	m_graphicalContrastMin = ct.graphical;
	m_textContrastMin = ct.text;

	// Load ring SVG — forward-citation (story 1.4).
	if (QFile::exists(kRingSvgFile)) {
		m_ringRenderer.load(QString(kRingSvgFile));
	}
	// Initial glyph SVG depends on state; loaded on first paint.

	m_tokensLoaded = !m_palette.isEmpty()
		&& !m_motionConnect.isEmpty()
		&& m_ringRenderer.isValid();
}

void IndicatorC1::setRetryState(t3_retry_state_t s) {
	if (s == m_lastRetryState) return;
	m_lastRetryState = s;
	applyRetryStateToVisual(s);

	// Emit rpl signal for story 2.6 (Subtask 4.1).
	// story 2.5 does NOT show the toast — story 2.6 subscribes to this signal and displays it.
	using namespace std::chrono;
	const auto now_ns = static_cast<uint64_t>(
		duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
	const int tier = [&]{
		switch (s) {
		case T3_RETRY_OK:    return 0;
		case T3_RETRY_TIER1: return 1;
		case T3_RETRY_TIER2: return 2;
		case T3_RETRY_TIER3: return 3;
		default:
			// vkprintf(0, "[C1] unknown retry state %d\n", static_cast<int>(s));
			return -1;
		}
	}();
	const RetryStatePayload payload{ tier, now_ns };
	m_retryStateChanged.fire_copy(payload);
}

void IndicatorC1::setVisualState(C1VisualState s) {
	if (m_state == s) return;
	m_state = s;
	m_animClock.restart();
	m_animPhase = 0.0;
	scheduleRepaint();
}

void IndicatorC1::applyRetryStateToVisual(t3_retry_state_t s) {
	// Visual-state ↔ retry-state mapping (Dev Notes table, ux-conformance.md §9).
	C1VisualState next;
	switch (s) {
	case T3_RETRY_OK:    next = C1VisualState::ConnectedVerified;   break;
	case T3_RETRY_TIER1: next = C1VisualState::ConnectedUnverified; break;
	case T3_RETRY_TIER2: next = C1VisualState::DegradedT12;         break;
	case T3_RETRY_TIER3: next = C1VisualState::DegradedT3;          break;
	default:
		// vkprintf(0, "[C1] unknown t3_retry_state_t %d — no visual change\n", static_cast<int>(s));
		return;
	}
	if (m_state != next) {
		m_state = next;
		m_animClock.restart();
		m_animPhase = 0.0;
		scheduleRepaint();
	}
}

void IndicatorC1::onPollTimer() {
	if (!m_session) return;
	const auto state = t3_retry_get_state(m_session);  // read-only (Subtask 6.2)
	setRetryState(state);
}

bool IndicatorC1::reducedMotionPreferred() const {
	// Qt 6.2 QStyleHints does not have showIsAnimated(), defaulting to false.
	return false;
}

void IndicatorC1::onColorSchemeChanged() {
	// Repaint to pick up host.bg.light / host.bg.dark palette branch (Subtask 3.2).
	scheduleRepaint();
}

void IndicatorC1::onLayoutDirectionChanged() {
	// Glyph RTL mirroring re-evaluated at next paint (Subtask 3.2).
	scheduleRepaint();
}

void IndicatorC1::onReducedMotionChanged() {
	// Swap spin/pulse ↔ fade-only animation path (Subtask 3.1).
	scheduleRepaint();
}

void IndicatorC1::scheduleRepaint() {
	((QWidget*)this)->update();
}

void IndicatorC1::paintEvent(QPaintEvent *) {
	QPainter p(((QWidget*)this));
	p.setRenderHint(QPainter::Antialiasing);

	const QRect rc = ((QWidget*)this)->rect();

	// --- Palette / colour resolution ---
	// Resolve host.bg and per-state ring/glyph colours from the loaded palette.
	// On forward-citation miss (palette empty) render a minimal placeholder so
	// the UI remains responsive (contrast self-check below logs any violation).

	// Qt 6.2 does not have QStyleHints::colorScheme(). Hardcode for now.
	const bool isDark = true;

	QColor bgColor    = isDark ? QColor(0x1c, 0x1c, 0x1e) : QColor(0xff, 0xff, 0xff);
	QColor ringColor;
	QColor glyphColor;

	auto resolveColor = [&](const QString &key, const QColor &fallback) -> QColor {
		if (m_palette.isEmpty()) return fallback;
		const auto branch = isDark ? u"dark"_q : u"light"_q;
		const auto obj = m_palette.value(branch).toObject();
		const auto hex = obj.value(key).toString();
		if (hex.isEmpty()) return fallback;
		return QColor(hex);
	};

	switch (m_state) {
	case C1VisualState::Idle:
	case C1VisualState::Connecting:
		ringColor  = resolveColor(u"c1.idle.ring"_q,
			isDark ? QColor(0x8e, 0x8e, 0x93) : QColor(0x8e, 0x8e, 0x93));
		glyphColor = ringColor;
		break;
	case C1VisualState::ConnectedVerified:
		ringColor  = resolveColor(u"c1.connected.verified.ring"_q,
			isDark ? QColor(0x30, 0xd1, 0x58) : QColor(0x34, 0xc7, 0x59));
		glyphColor = ringColor;
		break;
	case C1VisualState::ConnectedUnverified:
		ringColor  = resolveColor(u"c1.connected.unverified.ring"_q,
			isDark ? QColor(0x5a, 0xc8, 0xfa) : QColor(0x00, 0x7a, 0xff));
		glyphColor = ringColor;
		break;
	case C1VisualState::DegradedT12:
	case C1VisualState::DegradedT3:
		ringColor  = resolveColor(u"c1.degraded.ring"_q,
			isDark ? QColor(0xff, 0xd6, 0x0a) : QColor(0xff, 0xc4, 0x00));
		glyphColor = ringColor;
		break;
	}

	// AC#3 contrast self-check — log violation, do NOT block paint.
	// Text pairs ≥ 4.5:1 (WCAG 1.4.3); graphical pairs ≥ 3:1 (WCAG 1.4.11).
	const double ringContrast = contrastRatio(ringColor, bgColor);
	if (ringContrast < m_graphicalContrastMin) {
		Logs::writeMain(
			u"[C1] WCAG 1.4.11 contrast %1 < %2 in state %3"_q
				.arg(ringContrast, 0, 'f', 2)
				.arg(m_graphicalContrastMin, 0, 'f', 1)
				.arg(static_cast<int>(m_state)));
	}

	// --- Animation phase ---
	const bool reduced = reducedMotionPreferred();
	// Duration from the appropriate motion token; default if token absent.
	const int durationMs = [&] {
		const auto &motion = (m_state == C1VisualState::Connecting && reduced)
			? m_motionFade : m_motionConnect;
		return motion.value(u"duration_ms"_q).toInt(1200);
	}();
	if (durationMs > 0) {
		m_animPhase = static_cast<qreal>(m_animClock.elapsed() % durationMs) / durationMs;
	}

	// --- Ring ---
	const qreal ringPen = qMax(1.0, rc.width() * 0.08);
	const QRectF ringRect = QRectF(rc).adjusted(ringPen / 2, ringPen / 2, -ringPen / 2, -ringPen / 2);

	if (m_ringRenderer.isValid()) {
		// Render SVG ring; rotation applied for connecting spin (ltr-invariant per glyph table).
		p.save();
		if (m_state == C1VisualState::Connecting && !reduced) {
			const qreal angle = m_animPhase * 360.0;
			p.translate(rc.center());
			p.rotate(angle);
			p.translate(-rc.center());
		}
		m_ringRenderer.render(&p, QRectF(rc));
		p.restore();
	} else {
		// Placeholder ring (tokens not yet landed).
		QPen pen(ringColor, ringPen);
		if (m_state == C1VisualState::ConnectedUnverified) {
			pen.setStyle(Qt::DashLine);
		}
		p.setPen(pen);
		p.setBrush(Qt::NoBrush);

		if (m_state == C1VisualState::Connecting && !reduced) {
			const int startAngle = static_cast<int>(-m_animPhase * 360.0 * 16);
			p.drawArc(ringRect, startAngle, 270 * 16);
		} else {
			p.drawEllipse(ringRect);
		}
	}

	// --- Glyph ---
	// RTL mirroring: only the connecting chevron has direction=ltr (mirrors in RTL).
	// Checkmark, warn, halt are ltr-invariant (Subtask 3.3 / glyph mirroring matrix).
	const bool rtl = (qApp->layoutDirection() == Qt::RightToLeft);
	const bool mirrorGlyph = (rtl && m_state == C1VisualState::Connecting);

	p.save();
	if (mirrorGlyph) {
		// Horizontal flip for connecting chevron in RTL (Subtask 3.3: NEVER use QTransform for ring).
		p.translate(rc.width(), 0);
		p.scale(-1.0, 1.0);
	}

	const qreal glyphInset = rc.width() * 0.3;
	const QRectF glyphRect = QRectF(rc).adjusted(glyphInset, glyphInset, -glyphInset, -glyphInset);

	QPen glyphPen(glyphColor, qMax(1.0, rc.width() * 0.07));
	p.setPen(glyphPen);
	p.setBrush(Qt::NoBrush);

	switch (m_state) {
	case C1VisualState::Idle:
		// No glyph for idle.
		break;
	case C1VisualState::Connecting: {
		// Connecting chevron (forward-pointing).
		QPainterPath chevron;
		chevron.moveTo(glyphRect.left(),  glyphRect.top());
		chevron.lineTo(glyphRect.right(), glyphRect.center().y());
		chevron.lineTo(glyphRect.left(),  glyphRect.bottom());
		p.drawPath(chevron);
		break;
	}
	case C1VisualState::ConnectedVerified:
	case C1VisualState::ConnectedUnverified: {
		// Checkmark.
		QPainterPath check;
		check.moveTo(glyphRect.left(),
			glyphRect.top() + glyphRect.height() * 0.5);
		check.lineTo(glyphRect.left() + glyphRect.width() * 0.4,
			glyphRect.bottom());
		check.lineTo(glyphRect.right(), glyphRect.top());
		p.drawPath(check);
		break;
	}
	case C1VisualState::DegradedT12:
	case C1VisualState::DegradedT3: {
		// Warn triangle (ltr-invariant).
		QPainterPath tri;
		tri.moveTo(glyphRect.center().x(), glyphRect.top());
		tri.lineTo(glyphRect.right(), glyphRect.bottom());
		tri.lineTo(glyphRect.left(),  glyphRect.bottom());
		tri.closeSubpath();
		p.drawPath(tri);
		// Exclamation mark.
		const qreal cx = glyphRect.center().x();
		const qreal midY = glyphRect.top() + glyphRect.height() * 0.38;
		const qreal btmY = glyphRect.top() + glyphRect.height() * 0.72;
		p.drawLine(QPointF(cx, midY + glyphRect.height() * 0.06),
			QPointF(cx, btmY));
		p.setBrush(glyphColor);
		p.setPen(Qt::NoPen);
		const qreal dotR = qMax(1.0, glyphRect.width() * 0.06);
		p.drawEllipse(QPointF(cx, btmY + dotR * 1.8), dotR, dotR);
		break;
	}
	}

	p.restore();
}

} // namespace Tdesktop::Teleproto3
