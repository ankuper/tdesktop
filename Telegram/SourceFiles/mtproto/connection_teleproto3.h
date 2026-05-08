/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/connection_abstract.h"
#include "mtproto/mtproto_auth_key.h"
#include "mtproto/teleproto3_bridge.h"
#include "base/openssl_help.h"
#include "base/random.h"

#include <t3.h>

#include <QtNetwork/QAbstractSocket>
#include <deque>

class QSslSocket;

namespace Tdesktop::Teleproto3 {

// Platform-specific factory. Each platform file (details/network_change_observer_{win,mac,linux}.{cpp,mm})
// implements this once. Returns a QObject whose "pathChanged()" signal fires when the OS network
// path changes. Caller owns the returned pointer.
QObject *createNetworkObserver(QObject *parent = nullptr);

} // namespace Tdesktop::Teleproto3

namespace MTP {
namespace details {

// ConnectionTeleproto3 — WebSocket+TLS transport implementing the Type3 protocol.
//
// Lifecycle mirrors TcpConnection:
//   Waiting → Connecting (connectToServer) → Negotiating (WS up, header sent)
//           → Ready (version OK, drain queue) → Finished (disconnectFromServer / error)
//
// Auth state lives in mtproto_auth_key; transport swap does not touch it.
class ConnectionTeleproto3 : public AbstractConnection {
	Q_OBJECT

public:
	ConnectionTeleproto3(
		not_null<Instance*> instance,
		QThread *thread,
		const ProxyData &proxy,
		std::deque<mtpBuffer> inheritedQueue = {},
		int initialBackoffMs = 0);
	~ConnectionTeleproto3() override;

	// Moves _pendingQueue into a new instance for the new proxy; frees this session.
	ConnectionPointer clone(const ProxyData &proxy) override;

	crl::time pingTime() const override;
	crl::time fullConnectTimeout() const override;
	void sendData(mtpBuffer &&buffer) override;
	void disconnectFromServer() override;
	void connectToServer(
		const QString &ip,
		int port,
		const bytes::vector &protocolSecret,
		int16 protocolDcId,
		bool protocolForFiles) override;
	void timedOut() override;
	bool isConnected() const override;
	int32 debugState() const override;
	QString transport() const override;
	QString tag() const override;

	// Story 2.6 §rpl-signal-contract — push channel for retry-tier transitions.
	// Worker-thread only. UI consumers MUST use the retryStateChanged() Qt signal
	// (delivered via Qt::QueuedConnection) instead of subscribing to rpl directly.
	[[nodiscard]] rpl::producer<Tdesktop::Teleproto3::RetryStatePayload>
		retryStateChanges() const;

	// Called by the proxy-list "Try again" action (Task 2); resets FSM to tier-1.
	// Safe to invoke via QMetaObject::invokeMethod from the main thread (marshalled to connection thread).
	Q_INVOKABLE void userRetry();

Q_SIGNALS:
	// Emitted on every retry-tier transition. UI consumers connect with Qt::QueuedConnection
	// to receive callbacks on the main thread (rpl stream is worker-thread only).
	void retryStateChanged(Tdesktop::Teleproto3::RetryStatePayload payload);

	// Emitted (once per tier-3 entry) to prompt the main thread to show the non-modal toast.
	// Subscribers MUST use Qt::QueuedConnection so the handler runs on the main thread.
	void tier3Reached();

public Q_SLOTS:
	// Connected to the platform NetworkObserver::pathChanged() signal.
	// Re-initiates the Type3 session after an OS network-path change (AC3).
	void onNetworkChanged();

private Q_SLOTS:
	void onWsConnected();
	void onWsDisconnected();
	void onWsError(int err);
	void onWsBinaryMessage(const QByteArray &data);

private:
	enum class Status { Waiting, Connecting, Negotiating, Ready, Finished };

	void doConnect();
	void teardownSession();
	void drainPendingQueue();
	void sendImmediate(const mtpBuffer &buffer);
	uint64_t nowMonotonicNs() const;
	// Fires rpl stream + tier3Reached() signal on first T3_RETRY_TIER3 entry.
	void emitRetryState(t3_retry_state_t state);
	// Returns composite reconnect delay: silent-close inner layer + NFR25 outer layer (ms).
	int computeReconnectDelayMs();
	// Emits a single level-0 [T3-disco] log line with four diagnostic fields.
	// Call BEFORE teardownSession() so _t3session is still live for tier sampling.
	void emitDiscoMarker(
		const QString &state,
		const QString &wsClose,
		const QString &transportErr,
		const QString &tier);

	const not_null<Instance*> _instance;

	Tdesktop::Teleproto3::MiniWebSocket *_ws = nullptr;
	QSslSocket *_tls = nullptr;

	t3_session_t *_t3session = nullptr;
	Tdesktop::Teleproto3::BridgeContext *_bridgeCtx = nullptr;
	t3_callbacks_t _callbacks = {};

	// Pending queue: messages buffered while Connecting/Negotiating or on proxy switch.
	// Bound by Story 2.3 Task 6; align with AR-S3 once frozen.
	static constexpr int kQueueMaxMessages = 1024;
	static constexpr int kQueueMaxBytes    = 8 * 1024 * 1024; // 8 MiB

	std::deque<mtpBuffer> _pendingQueue;
	int _pendingQueueBytes = 0;

	// NFR25 backoff — 1 s initial, 60 s cap, exponential doubling.
	crl::time _backoffNextAttemptMs = 0;
	int _backoffStepMs = 1000;

	int _negotiatedVersion = 0;

	// Saved for reconnect on network-change (AC3).
	QString _connectAddress;
	int _connectPort = 0;
	bytes::vector _connectProtocolSecret;
	int16 _connectProtocolDcId = 0;
	bool _connectProtocolForFiles = false;

	Status _status = Status::Waiting;
	crl::time _pingTimeMs = 0;

	// MTProto DD obfuscated handshake state.
	uchar _obfSendKey[32] = {};
	uchar _obfRecvKey[32] = {};
	CTRState _obfSendState = {};
	CTRState _obfRecvState = {};
	MTPint128 _checkNonce = {};
	bool _connectionStarted = false;

	// Network-change observer (platform-specific; owns the QObject via Qt parent chain).
	QObject *_networkObserver = nullptr;

	// Story 2.6: retry-state push channel + tier-3 toast guard.
	rpl::event_stream<Tdesktop::Teleproto3::RetryStatePayload> _retryStateStream;
	bool _tier3ToastVisible = false;  // single-instance toast guard (Dev Notes §tier-3-toast-ux)
	rpl::lifetime _lifetime;
};

} // namespace details
} // namespace MTP
