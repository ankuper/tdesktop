/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

// Story 2.6 Task 2 — UI wiring for ConnectionTeleproto3 tier-3 toast.
//
// Separates the UI concern (Ui::Toast::Show) from the transport layer
// (connection_teleproto3.cpp). Call wireT3Toast() once per ConnectionTeleproto3
// instance, from any code that has access to a Window::SessionController.

namespace Window {
class SessionController;
} // namespace Window

namespace MTP::details {
class ConnectionTeleproto3;
} // namespace MTP::details

namespace Tdesktop::Teleproto3 {

// Connects the tier3Reached() signal from `connection` to a main-thread handler
// that shows Ui::Toast::Show() with the tier-3 toast body and action button.
// `controller` provides the window context for the proxy list dialog action.
// MUST be called on the main thread.
void wireT3Toast(
	MTP::details::ConnectionTeleproto3 *connection,
	Window::SessionController *controller);

} // namespace Tdesktop::Teleproto3
