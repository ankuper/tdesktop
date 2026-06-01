/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

// NO #ifdef Q_OS_LINUX guard here: moc does not have Q_OS_LINUX defined when it
// scans this header, so a guard would make it skip the Q_OBJECT class and emit
// an empty moc (→ undefined vtable / pathChanged at link time). Instead the
// header is gated to Linux-only in CMakeLists (AUTOMOC processes it only there).

#include <QObject>

namespace Tdesktop::Teleproto3 {

class LinuxNetworkObserver : public QObject {
	Q_OBJECT

public:
	explicit LinuxNetworkObserver(QObject *parent = nullptr);

Q_SIGNALS:
	void pathChanged();

private Q_SLOTS:
	void onNmStateChanged(uint state);
};

} // namespace Tdesktop::Teleproto3
