/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/connection_teleproto3_ui.h"

#include "mtproto/connection_teleproto3.h"
#include "lang/lang_keys.h"
#include "ui/toast/toast.h"
#include "window/window_session_controller.h"
#include "boxes/connection_box.h"

#include <QPointer>

// Story 2.6 Task 2 — tier-3 toast wiring.
//
// Subscribes to ConnectionTeleproto3::tier3Reached() (emitted on the connection thread,
// delivered to main-thread via Qt::QueuedConnection) and shows a single non-modal toast
// per AC#3: body = ui.tier3-toast, action = ui.tier3-action-switch → proxy list dialog.
//
// Design constraints (story 2.6 Dev Notes §tier-3-toast-ux):
//   - NO modal dialog, NO blocking wait.
//   - Single instance: _tier3ToastVisible on the connection guards re-emission.
//   - Dismiss (auto or manual) MUST NOT clear tier-3 FSM state.
//   - Accept action (proxy-list selection) triggers explicit endpoint switch (FR22).
//   - "Try again" (same endpoint) calls connection->userRetry() which resets FSM to tier-1.

namespace Tdesktop::Teleproto3 {

void wireT3Toast(
		MTP::details::ConnectionTeleproto3 *connection,
		Window::SessionController *controller) {
	if (!connection || !controller) return;

	const auto ctrlWeak = base::make_weak(controller);

	// Qt::QueuedConnection ensures the lambda runs on the main thread even though
	// tier3Reached() is emitted from the connection's worker thread.
	QObject::connect(
		connection,
		&MTP::details::ConnectionTeleproto3::tier3Reached,
		qApp,
		[ctrlWeak]() {
			if (const auto ctrl = ctrlWeak.get()) {
				TextWithEntities text;
				text.text = t3lang::lng_t3_tier3_toast() + "\n\n" + t3lang::lng_t3_tier3_action_switch();
				
				ctrl->showToast(Ui::Toast::Config{
					.title = QString(),
					.text  = text,
					.filter = [ctrlWeak](const auto &, auto) {
						if (const auto c = ctrlWeak.get()) {
							ProxiesBoxController::Show(c);
						}
						return true;
					},
				});
			}
		},
		Qt::QueuedConnection);

	// When the user taps "Try again" via the proxy list affordance, the box calls
	// connection->userRetry() (Q_INVOKABLE, marshalled to connection thread).
	// No explicit wiring needed here; the proxy list box accesses the MTP instance
	// via Core::App().mtp() and can call t3_retry_user_retry through the connection's
	// userRetry() slot.
}

} // namespace Tdesktop::Teleproto3
