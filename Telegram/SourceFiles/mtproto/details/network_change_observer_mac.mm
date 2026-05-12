/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/

// macOS network-change observer — Apple Network.framework nw_path_monitor_t.
// Weak-linked: if Network.framework is unavailable at runtime, returns nullptr.

#ifdef Q_OS_MAC

#include "mtproto/connection_teleproto3.h"

#include <QObject>
#include <QPointer>
#include <QTimer>

#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <Network/Network.h>

namespace Tdesktop::Teleproto3 {

namespace {

class MacNetworkObserver : public QObject {
public:
	explicit MacNetworkObserver(QObject *parent = nullptr)
	: QObject(parent) {
		// Runtime check: is Network.framework loaded?
		if (!dlsym(RTLD_DEFAULT, "nw_path_monitor_create")) return;

		_monitor = nw_path_monitor_create();
		if (!_monitor) return;

		_queue = dispatch_queue_create(
			"io.teleproto3.network_observer",
			DISPATCH_QUEUE_SERIAL);

		QPointer<MacNetworkObserver> self(this);
		nw_path_monitor_set_update_handler(_monitor, ^(nw_path_t /*path*/) {
			if (auto *obj = self.data()) {
				QTimer::singleShot(0, obj, [self] {
					if (auto *obj2 = self.data()) {
						// nw_path_monitor always fires once on start
						// with the current path state. Skip that initial
						// callback — it's not an actual network change.
						if (!obj2->_initialFired) {
							obj2->_initialFired = true;
							return;
						}
						if (auto *conn = qobject_cast<MTP::details::ConnectionTeleproto3*>(obj2->parent())) {
							conn->onNetworkChanged();
						}
					}
				});
			}
		});
		nw_path_monitor_set_queue(_monitor, _queue);
		nw_path_monitor_start(_monitor);
	}

	~MacNetworkObserver() override {
		if (_monitor) {
			auto q = _queue;
			_queue = nullptr;
			nw_path_monitor_set_cancel_handler(_monitor, ^{
				if (q) dispatch_release(q);
			});
			nw_path_monitor_cancel(_monitor);
			nw_release(_monitor);
		} else if (_queue) {
			dispatch_release(_queue);
		}
	}

private:
	nw_path_monitor_t _monitor = nullptr;
	dispatch_queue_t _queue = nullptr;
	bool _initialFired = false;
};

} // namespace

QObject *createNetworkObserver(QObject *parent) {
	// Graceful fallback: if Network.framework is not available, return nullptr.
	if (!dlsym(RTLD_DEFAULT, "nw_path_monitor_create")) return nullptr;
	return new MacNetworkObserver(parent);
}

} // namespace Tdesktop::Teleproto3

#endif // Q_OS_MAC
