/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/

// Linux network-change observer — NetworkManager DBus StateChanged signal.
//
// Subscribes to org.freedesktop.NetworkManager.StateChanged on the system bus.
// On distros where NetworkManager is absent (systemd-networkd-only), the DBus
// connection will fail; we fall back to a 30-second polling timer that emits
// pathChanged() on every tick so any genuine path change is caught within 30 s.
//
// Anti-pattern: NEVER use QNetworkConfigurationManager — deprecated Qt 5.15 / removed Qt 6 (AR-G1).

#ifdef Q_OS_LINUX

#include "mtproto/connection_teleproto3.h"

#include <QDBusConnection>
#include <QDBusInterface>
#include <QObject>
#include <QTimer>

namespace Tdesktop::Teleproto3 {

namespace {

class LinuxNetworkObserver : public QObject {
	Q_OBJECT

public:
	explicit LinuxNetworkObserver(QObject *parent = nullptr)
	: QObject(parent) {
		auto bus = QDBusConnection::systemBus();
		const auto connected = bus.connect(
			u"org.freedesktop.NetworkManager"_q,
			u"/org/freedesktop/NetworkManager"_q,
			u"org.freedesktop.NetworkManager"_q,
			u"StateChanged"_q,
			this,
			SLOT(onNmStateChanged(uint)));
		if (!connected) {
			// NetworkManager unavailable — fall back to 30-second suspect-resume polling.
			auto *timer = new QTimer(this);
			timer->setInterval(30'000);
			QObject::connect(timer, &QTimer::timeout, this, [this] { Q_EMIT pathChanged(); });
			timer->start();
		}
	}

Q_SIGNALS:
	void pathChanged();

private Q_SLOTS:
	void onNmStateChanged(uint /*state*/) {
		Q_EMIT pathChanged();
	}
};

} // namespace

QObject *createNetworkObserver(QObject *parent) {
	return new LinuxNetworkObserver(parent);
}

} // namespace Tdesktop::Teleproto3

#include "network_change_observer_linux.moc"

#endif // Q_OS_LINUX
