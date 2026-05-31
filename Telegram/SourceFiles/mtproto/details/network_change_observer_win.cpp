/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/

// Windows network-change observer — Win32 Network List Manager COM API.
//
// Subscribes to INetworkListManagerEvents::ConnectivityChanged via
// IConnectionPointContainer. Emits pathChanged() on the Qt event loop
// by posting a QMetaObject::invokeMethod call from the COM callback thread.
//
// Anti-pattern: NEVER use QNetworkConfigurationManager — deprecated Qt 5.15 / removed Qt 6 (AR-G1).

#ifdef Q_OS_WIN

#include "mtproto/details/network_change_observer_win_p.h"

#include <QPointer>
#include <atomic>

namespace Tdesktop::Teleproto3 {

namespace {
// COM sink: receives INetworkListManagerEvents notifications on a COM thread.
// Marshals pathChanged() emission back to the Qt thread via QMetaObject::invokeMethod.
// NlmEventSink has no Q_OBJECT so anonymous namespace is safe here.
class NlmEventSink final
	: public INetworkListManagerEvents {
public:
	explicit NlmEventSink(QObject *target) : _target(target), _refCount(1) {}

	// IUnknown
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override {
		if (riid == IID_IUnknown || riid == IID_INetworkListManagerEvents) {
			*ppv = static_cast<INetworkListManagerEvents*>(this);
			AddRef();
			return S_OK;
		}
		*ppv = nullptr;
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef() override { return ++_refCount; }
	ULONG STDMETHODCALLTYPE Release() override {
		const auto n = --_refCount;
		if (n == 0) delete this;
		return n;
	}

	// INetworkListManagerEvents
	HRESULT STDMETHODCALLTYPE ConnectivityChanged(NLM_CONNECTIVITY /*connectivity*/) override {
		// COM callback runs on a COM apartment thread — marshal to Qt main thread.
		if (auto *t = _target.data()) {
			QMetaObject::invokeMethod(t, "pathChanged", Qt::QueuedConnection);
		}
		return S_OK;
	}

private:
	QPointer<QObject> _target;
	std::atomic<ULONG> _refCount;
};

} // namespace

Win32NetworkObserver::Win32NetworkObserver(QObject *parent)
: QObject(parent) {
	if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) {
		return;
	}
	_comInitialised = true;

	INetworkListManager *nlm = nullptr;
	if (FAILED(CoCreateInstance(
			CLSID_NetworkListManager, nullptr,
			CLSCTX_ALL, IID_INetworkListManager,
			reinterpret_cast<void**>(&nlm)))) {
		return;
	}
	_nlm = nlm;

	IConnectionPointContainer *cpc = nullptr;
	if (FAILED(nlm->QueryInterface(IID_IConnectionPointContainer, reinterpret_cast<void**>(&cpc)))) {
		return;
	}

	IConnectionPoint *cp = nullptr;
	if (FAILED(cpc->FindConnectionPoint(IID_INetworkListManagerEvents, &cp))) {
		cpc->Release();
		return;
	}
	cpc->Release();

	_sink = new NlmEventSink(this);
	if (FAILED(cp->Advise(_sink, &_cookie))) {
		_sink->Release();
		_sink = nullptr;
		cp->Release();
		return;
	}
	_cp = cp;
}

Win32NetworkObserver::~Win32NetworkObserver() {
	if (_cp && _cookie != 0) {
		_cp->Unadvise(_cookie);
	}
	if (_cp) { _cp->Release(); }
	if (_sink) { _sink->Release(); }
	if (_nlm) { _nlm->Release(); }
	if (_comInitialised) { CoUninitialize(); }
}

QObject *createNetworkObserver(QObject *parent) {
	return new Win32NetworkObserver(parent);
}

} // namespace Tdesktop::Teleproto3

#endif // Q_OS_WIN
