/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#ifdef Q_OS_LINUX

#include <QObject>

namespace Tdesktop::Teleproto3 {

// Q_OBJECT must NOT be in an anonymous namespace: MOC generates signal
// bodies and vtable entries that would have internal linkage, causing
// "undefined reference to vtable / pathChanged()" at link time.
// The class is private (only used by createNetworkObserver) but must
// be in a named scope so AUTOMOC generates correctly-linked symbols.
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

#endif // Q_OS_LINUX
