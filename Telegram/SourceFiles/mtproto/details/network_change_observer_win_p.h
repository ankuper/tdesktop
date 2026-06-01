/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

// NO #ifdef Q_OS_WIN guard here: moc does not have Q_OS_WIN defined when it
// scans this header, so a guard would make it skip the Q_OBJECT class and emit
// an empty moc (→ unresolved metaObject/qt_metacall at link). The header is
// gated to Windows-only in CMakeLists (AUTOMOC processes it only there).
//
// COM interfaces are forward-declared instead of pulling in <netlistmgr.h> etc.
// so moc parses only Qt — heavy Windows SDK headers can trip moc's preprocessor.

#include <QObject>

struct INetworkListManager;
struct IConnectionPoint;
struct INetworkListManagerEvents;

namespace Tdesktop::Teleproto3 {

class Win32NetworkObserver : public QObject {
	Q_OBJECT

public:
	explicit Win32NetworkObserver(QObject *parent = nullptr);
	~Win32NetworkObserver() override;

Q_SIGNALS:
	void pathChanged();

private:
	bool _comInitialised = false;
	INetworkListManager *_nlm = nullptr;
	IConnectionPoint *_cp = nullptr;
	INetworkListManagerEvents *_sink = nullptr;
	unsigned long _cookie = 0; // DWORD without dragging in <windows.h>.
};

} // namespace Tdesktop::Teleproto3
