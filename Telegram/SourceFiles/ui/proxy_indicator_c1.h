/*
 * proxy_indicator_c1.h — Qt C1 ring + glyph indicator (UX-DR7).
 *
 * Consumes Type3 retry state from libteleproto3 (lib-v0.1.0). Visual tokens
 * sourced from teleproto3/spec/ux-tokens/. Where this file and spec/ differ,
 * spec/ wins.
 *
 * Stability: tdesktop-internal; no public API. Single-owner: story 2.5.
 */
#pragma once

#include "ui/rp_widget.h"
#include "mtproto/teleproto3_bridge.h"  // RetryStatePayload (canonical owner: story 2.6)

#include <QtCore/QTimer>
#include <QtCore/QElapsedTimer>
#include <QtGui/QGuiApplication>
#include <QtGui/QStyleHints>
#include <QtSvg/QSvgRenderer>
#include <QtCore/QJsonObject>

extern "C" {
#include <t3.h>
}

namespace Tdesktop::Teleproto3 {

// Visual state mirrors the C1 state set from ux-conformance.md §9.
// NOT an Error state — alarm semantics are intentionally absent (UX spec §Visual §Color §Accessibility).
enum class C1VisualState {
	Idle,
	Connecting,
	ConnectedVerified,
	ConnectedUnverified,
	DegradedT12,
	DegradedT3,
};

// RetryStatePayload is now defined in teleproto3_bridge.h (shared between connection + indicator).

class IndicatorC1 final : public Ui::RpWidget {
public:
	// sess is borrowed (not owned); must outlive IndicatorC1.
	explicit IndicatorC1(QWidget *parent, const t3_session_t *sess);
	~IndicatorC1() override;

	void setRetryState(t3_retry_state_t s);
	// For pre-session states (Idle, Connecting) driven by the connection lifecycle,
	// not by t3_retry_state_t. Called by connection_box when ItemState is Checking/Connecting.
	void setVisualState(C1VisualState s);
	[[nodiscard]] C1VisualState currentState() const noexcept { return m_state; }

	// rpl signal — emitted when retry state changes; story 2.6 subscribes via rpl.
	[[nodiscard]] rpl::producer<RetryStatePayload> retryStateChanged() const;


protected:
	void paintEvent(QPaintEvent *e) override;

private:
	void loadTokens();
	void onColorSchemeChanged();
	void onLayoutDirectionChanged();
	void onReducedMotionChanged();
	void onPollTimer();
	[[nodiscard]] bool reducedMotionPreferred() const;

	void applyRetryStateToVisual(t3_retry_state_t s);
	void scheduleRepaint();

	const t3_session_t     *m_session;    // borrowed; not owned
	C1VisualState           m_state = C1VisualState::Idle;
	t3_retry_state_t        m_lastRetryState = T3_RETRY_OK;

	QTimer                  m_pollTimer;  // 250 ms cadence (NFR7-anchored — Subtask 1.6)

	// Loaded from teleproto3/spec/ux-tokens/ at construction.
	// Fatal-log via Logs::Main() if any file is missing (anti-pattern §12.8 forbids fallbacks).
	bool                    m_tokensLoaded = false;
	QJsonObject             m_palette;    // color/palette.json
	QJsonObject             m_motionConnect;   // motion/connecting-rotate.json (or fade variant)
	QJsonObject             m_motionFade;      // motion/connecting-fade.json (reduced-motion)
	QJsonObject             m_motionTransition; // motion/transition-fade.json
	QSvgRenderer            m_ringRenderer;
	QSvgRenderer            m_glyphRenderer;

	// WCAG contrast thresholds sourced from contrast-tokens.yaml (AC#3).
	double                  m_graphicalContrastMin = 3.0;
	double                  m_textContrastMin = 4.5;

	// Animation state.
	qreal                   m_animPhase = 0.0;  // [0, 1) — updated each repaint
	QElapsedTimer           m_animClock;

	rpl::event_stream<RetryStatePayload> m_retryStateChanged;
	rpl::lifetime                        m_lifetime;
};

} // namespace Tdesktop::Teleproto3
