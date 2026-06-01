/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#ifdef Q_OS_WIN

#include <QObject>
#include <objbase.h>
#include <netlistmgr.h>
#include <ocidl.h>

namespace Tdesktop::Teleproto3 {

// Win32NetworkObserver must be declared in a header (not inside an anonymous
// namespace in a .cpp) so that AUTOMOC generates moc_*_win_p.cpp with external
// linkage — placing Q_OBJECT in an anonymous namespace causes MSVC C7631 /
// LNK2001 (staticMetaObject internal-linkage conflict).
//
// _sink is typed as INetworkListManagerEvents* so NlmEventSink (defined in the
// .cpp's anonymous namespace) does not need to be forward-declared here.
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
	DWORD _cookie = 0;
};

} // namespace Tdesktop::Teleproto3

#endif // Q_OS_WIN
