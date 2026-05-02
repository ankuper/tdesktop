/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/connection_teleproto3.h"

#include "base/bytes.h"
#include "logs.h"

#include <QAbstractSocket>
#include <QMaskGenerator>
#include <QSslSocket>
#include <QWebSocket>
#include <QTimer>

#include <chrono>
#include <cstring>
#include <limits>

// ABI version-pin is in teleproto3_bridge.cpp (Epic 2 style-guide §3 single-TU rule).
// This file includes the bridge header; the static_assert is thus reachable at compile time.

// Anti-pattern §12.9: Every transport transition in this file is driven by an explicit
// user action (clone) or an explicit OS network-change event (onNetworkChanged).
// There is NO code path that auto-selects a different proxy on Type3 failure.

namespace {

constexpr auto kFullConnectTimeoutMs = crl::time(20'000); // 20 s
constexpr auto kTransportName = "Type3/WS";

// Decode proxy.password (hex or base64url) to raw bytes for t3_secret_parse.
QByteArray decodeProxyPassword(const QString &password) {
	const auto latin = password.toLatin1();
	// Hex: even length, all hex digits.
	if (latin.size() > 0 && latin.size() % 2 == 0) {
		const auto allHex = std::all_of(latin.begin(), latin.end(), [](char c) {
			return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
		});
		if (allHex) {
			return QByteArray::fromHex(latin);
		}
	}
	// Base64url (RFC 4648 §5, padding optional).
	return QByteArray::fromBase64(
		latin,
		QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

} // namespace

// createNetworkObserver is declared in connection_teleproto3.h and implemented in
// exactly one of: details/network_change_observer_{linux,mac,win}.{cpp,mm}.
// CMake compiles all three files; platform #ifdef guards ensure only one provides
// a definition. The full Telegram build always links the correct implementation.

namespace MTP {
namespace details {

ConnectionTeleproto3::ConnectionTeleproto3(
	not_null<Instance*> instance,
	QThread *thread,
	const ProxyData &proxy,
	std::deque<mtpBuffer> inheritedQueue)
: AbstractConnection(thread, proxy)
, _instance(instance)
, _pendingQueue(std::move(inheritedQueue)) {
	for (const auto &buf : _pendingQueue) {
		_pendingQueueBytes += int(buf.size()) * int(sizeof(mtpPrime));
	}
	// Platform-specific network observer (AC3).
	_networkObserver = Tdesktop::Teleproto3::createNetworkObserver(this);
	if (_networkObserver) {
		QObject::connect(
			_networkObserver, SIGNAL(pathChanged()),
			this, SLOT(onNetworkChanged()));
	}
}

ConnectionTeleproto3::~ConnectionTeleproto3() {
	teardownSession();
}

ConnectionPointer ConnectionTeleproto3::clone(const ProxyData &proxy) {
	// Auth state owned by mtproto_auth_key; transport swap does not touch it.
	if (_t3session) {
		t3_retry_state_t state;
		t3_retry_record_close(_t3session, nowMonotonicNs(), &state);
	}
	teardownSession();
	auto inherited = std::move(_pendingQueue);
	_pendingQueueBytes = 0;
	return ConnectionPointer::New<ConnectionTeleproto3>(
		_instance,
		thread(),
		proxy,
		std::move(inherited));
}

crl::time ConnectionTeleproto3::pingTime() const {
	return _pingTimeMs;
}

crl::time ConnectionTeleproto3::fullConnectTimeout() const {
	return kFullConnectTimeoutMs;
}

bool ConnectionTeleproto3::isConnected() const {
	return _status == Status::Ready;
}

int32 ConnectionTeleproto3::debugState() const {
	return static_cast<int32>(_status);
}

QString ConnectionTeleproto3::transport() const {
	return QString::fromLatin1(kTransportName);
}

QString ConnectionTeleproto3::tag() const {
	return QString::fromLatin1(kTransportName);
}

void ConnectionTeleproto3::timedOut() {
	if (_status == Status::Connecting || _status == Status::Negotiating) {
		logError(u"connect timeout"_q);
		teardownSession();
		emit error(kErrorCodeOther);
	}
}

void ConnectionTeleproto3::connectToServer(
		const QString &ip,
		int port,
		const bytes::vector &protocolSecret,
		int16 protocolDcId,
		bool protocolForFiles) {
	_connectAddress = ip;
	_connectPort = port;
	_connectProtocolSecret = protocolSecret;
	_connectProtocolDcId = protocolDcId;
	_connectProtocolForFiles = protocolForFiles;
	doConnect();
}

void ConnectionTeleproto3::doConnect() {
	teardownSession();
	_status = Status::Connecting;

	// Decode proxy password to raw bytes for t3_secret_parse.
	const auto rawPwd = decodeProxyPassword(_proxy.password);
	if (rawPwd.size() < 18 || static_cast<uint8_t>(rawPwd[0]) != 0xff) {
		logError(u"Type3 secret decode failed"_q);
		_status = Status::Finished;
		emit error(kErrorCodeOther);
		return;
	}
	// Parse the full secret (key + domain) from the proxy password.
	t3_secret_t *secret = nullptr;
	const auto rc = t3_secret_parse(
		reinterpret_cast<const uint8_t*>(rawPwd.constData()),
		static_cast<size_t>(rawPwd.size()),
		&secret);
	Tdesktop::Teleproto3::SecretGuard secretGuard(secret);
	if (rc != T3_OK) {
		// Error code MUST use t3_strerror — do NOT leak lib-internal text (style-guide §4 ban-list).
		logError(u"t3_secret_parse: "_q + QString::fromUtf8(t3_strerror(rc)));
		_status = Status::Finished;
		emit error(kErrorCodeOther);
		return;
	}

	// Compose the wss:// URL.
	const auto wsPath = _proxy.wsPath.isEmpty()
		? QString()
		: (_proxy.wsPath.startsWith('/') ? _proxy.wsPath : '/' + _proxy.wsPath);
	const auto url = QUrl(
		u"wss://"_q + _connectAddress + ':' + QString::number(_connectPort) + wsPath);

	_ws = new QWebSocket(QString(), QWebSocketProtocol::VersionLatest, this);
	QObject::connect(_ws, &QWebSocket::connected, this, &ConnectionTeleproto3::onWsConnected);
	QObject::connect(_ws, &QWebSocket::disconnected, this, &ConnectionTeleproto3::onWsDisconnected);
	QObject::connect(
		_ws,
		QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
		this,
		&ConnectionTeleproto3::onWsError);
	QObject::connect(
		_ws, &QWebSocket::binaryMessageReceived,
		this, &ConnectionTeleproto3::onWsBinaryMessage);

	// EXTEND from story 2.4 — write-authority owned by story 2.3.
	// FR23: install CSPRNG mask generator BEFORE open(). Qt's QWebSocketPrivate::generateKey
	// calls maskGenerator->nextMask() x4 to build Sec-WebSocket-Key (RFC 6455 §4.1),
	// and per-frame masks come from the same generator. Replacing the default mask
	// generator (which uses QRandomGenerator::global() per Qt source) routes both
	// through QRandomGenerator::system() — anti-pattern §12.12.
	auto *maskGen = qobject_cast<QMaskGenerator*>(
		Tdesktop::Teleproto3::makeCsprngMaskGenerator(_ws));
	_ws->setMaskGenerator(maskGen);
	_ws->open(url);

	// Pre-create the session (before WS connects) so we have the secret available.
	// The actual bind_callbacks happens in onWsConnected once the socket is live.
	t3_session_t *sess = nullptr;
	const auto sessRc = t3_session_new(secret, &sess);
	if (sessRc != T3_OK) {
		logError(u"t3_session_new: "_q + QString::fromUtf8(t3_strerror(sessRc)));
		_ws->close();
		_ws->deleteLater();
		_ws = nullptr;
		_status = Status::Finished;
		emit error(kErrorCodeOther);
		return;
	}
	_t3session = sess;
}

void ConnectionTeleproto3::onWsConnected() {
	if (_status != Status::Connecting) return;

	// Retrieve the underlying TLS socket from the QWebSocket.
	_tls = qobject_cast<QSslSocket*>(_ws->socket());
	if (!_tls) {
		logError(u"QWebSocket socket is not QSslSocket"_q);
		teardownSession();
		emit error(kErrorCodeOther);
		return;
	}

	// Create the bridge context + callbacks now that both socket objects are live.
	_bridgeCtx = Tdesktop::Teleproto3::createContext(_tls, _ws);
	_callbacks = Tdesktop::Teleproto3::makeCallbacks(_bridgeCtx);

	const auto bindRc = t3_session_bind_callbacks(_t3session, &_callbacks);
	if (bindRc != T3_OK) {
		logError(u"t3_session_bind_callbacks: "_q + QString::fromUtf8(t3_strerror(bindRc)));
		teardownSession();
		emit error(kErrorCodeOther);
		return;
	}

	// Send the 4-byte session header (spec/wire-format.md §3; AR-S1).
	t3_header_t hdr;
	hdr.command_type = 0x01; // MTPROTO_PASSTHROUGH at v0.1.0
	hdr.version      = 0x01;
	hdr.flags        = 0;    // MUST be 0 at v0.1.0

	uint8_t buf4[4];
	const auto serRc = t3_header_serialise(&hdr, buf4);
	if (serRc != T3_OK) {
		logError(u"t3_header_serialise: "_q + QString::fromUtf8(t3_strerror(serRc)));
		teardownSession();
		emit error(kErrorCodeOther);
		return;
	}
	_ws->sendBinaryMessage(QByteArray(reinterpret_cast<const char*>(buf4), 4));

	_status = Status::Negotiating;
	CONNECTION_LOG_INFO(u"session header sent, awaiting peer version"_q);
}

void ConnectionTeleproto3::onWsBinaryMessage(const QByteArray &data) {
	if (_status == Status::Negotiating) {
		// First frame from server: the 4-byte session header response.
		if (data.size() < 4) {
			logError(u"peer header too short: "_q + QString::number(data.size()));
			teardownSession();
			emit error(kErrorCodeOther);
			return;
		}
		t3_header_t peerHdr;
		const auto parseRc = t3_header_parse(
			reinterpret_cast<const uint8_t*>(data.constData()),
			&peerHdr);
		if (parseRc != T3_OK) {
			logError(u"t3_header_parse: "_q + QString::fromUtf8(t3_strerror(parseRc)));
			teardownSession();
			emit error(kErrorCodeOther);
			return;
		}

		t3_version_action_t action;
		const auto negRc = t3_session_negotiate_version(
			_t3session,
			peerHdr.version,
			&action);
		if (negRc != T3_OK) {
			logError(u"t3_session_negotiate_version: "_q + QString::fromUtf8(t3_strerror(negRc)));
			teardownSession();
			emit error(kErrorCodeOther);
			return;
		}

		switch (action) {
		case T3_VERSION_OK:
			_negotiatedVersion = peerHdr.version;
			_status = Status::Ready;
			CONNECTION_LOG_INFO(u"Type3 version negotiated: "_q + QString::number(_negotiatedVersion));
			emit connected();
			drainPendingQueue();
			break;

		case T3_VERSION_SILENT_CLOSE: {
			// Anti-probe: record close for tier tracking; do NOT leak reason (style-guide §4).
			t3_retry_state_t state;
			t3_retry_record_close(_t3session, nowMonotonicNs(), &state);
			logError(u"peer requested silent close (tier="_q + QString::number(state) + ')');
			teardownSession();
			emit error(kErrorCodeOther);
			break;
		}

		case T3_VERSION_RETRY_DOWNGRADE:
			// In-band version downgrade within Type3 (FR43, spec §4.1 trailing-octet tolerance).
			// v0.1.0 has no lower version to retry; treat as permanent failure.
			// Anti-pattern §12.9: this is NOT auto-fallback to Type1/Type2 — it is a within-Type3
			// in-band downgrade attempt. Since no lower version exists at v0.1.0, we surface error().
			logError(u"peer requested version downgrade (unsupported at v0.1.0)"_q);
			teardownSession();
			emit error(kErrorCodeOther);
			break;
		}
		return;
	}

	if (_status != Status::Ready) return;

	// Normal data frame — wrap in mtpBuffer and deliver to upper MTP layer.
	const auto len = data.size();
	if (len == 0) return;
	if (len % static_cast<int>(sizeof(mtpPrime)) != 0) {
		logError(u"received non-aligned WS frame: "_q + QString::number(len));
		return;
	}
	auto buf = mtpBuffer(len / sizeof(mtpPrime));
	std::memcpy(buf.data(), data.constData(), len);
	_receivedQueue.push_back(std::move(buf));
	emit receivedSome();
	emit receivedData();
}

void ConnectionTeleproto3::onWsDisconnected() {
	if (_status == Status::Finished) return;
	logError(u"WS disconnected"_q);
	const auto wasReady = (_status == Status::Ready);
	teardownSession();
	emit disconnected();
	if (!wasReady) {
		emit error(kErrorCodeOther);
	}
}

void ConnectionTeleproto3::onWsError(QAbstractSocket::SocketError err) {
	logError(u"WS socket error: "_q + QString::number(static_cast<int>(err)));
	teardownSession();
	emit error(kErrorCodeOther);
}

void ConnectionTeleproto3::sendData(mtpBuffer &&buffer) {
	Expects(!buffer.empty());

	if (_status != Status::Ready) {
		const auto bytes = int(buffer.size()) * int(sizeof(mtpPrime));
		if (_pendingQueue.size() >= static_cast<size_t>(kQueueMaxMessages)
			|| _pendingQueueBytes + bytes > kQueueMaxBytes) {
			// Queue full: drop oldest entry, then append (AC2 queue bound, Task 6).
			_pendingQueueBytes -= int(_pendingQueue.front().size()) * int(sizeof(mtpPrime));
			_pendingQueue.pop_front();
			emit error(kErrorCodeOther); // signal upstream to decide retransmit policy
		}
		_pendingQueueBytes += bytes;
		_pendingQueue.push_back(std::move(buffer));
		return;
	}
	sendImmediate(buffer);
}

void ConnectionTeleproto3::sendImmediate(const mtpBuffer &buffer) {
	const auto data = reinterpret_cast<const char*>(buffer.data());
	const auto len = int(buffer.size()) * int(sizeof(mtpPrime));
	_ws->sendBinaryMessage(QByteArray(data, len));
}

void ConnectionTeleproto3::drainPendingQueue() {
	while (!_pendingQueue.empty()) {
		sendImmediate(_pendingQueue.front());
		_pendingQueueBytes -= int(_pendingQueue.front().size()) * int(sizeof(mtpPrime));
		_pendingQueue.pop_front();
	}
}

void ConnectionTeleproto3::disconnectFromServer() {
	if (_t3session) {
		t3_retry_state_t state;
		t3_retry_record_close(_t3session, nowMonotonicNs(), &state);
	}
	teardownSession();
}

void ConnectionTeleproto3::onNetworkChanged() {
	// OS reported a network-path change (Wi-Fi ↔ LTE / wired ↔ wireless).
	// Transparently reconnect WITHOUT surfacing a re-login prompt (AC3).
	// MTP::Instance is signalled with the same transient-disconnect signal Type1/Type2 use.
	// Anti-pattern §12.9: this IS an explicit OS network-change event — not an auto-fallback.
	CONNECTION_LOG_INFO(u"network path changed — transparently reconnecting"_q);

	if (_t3session) {
		t3_retry_state_t state;
		t3_retry_record_close(_t3session, nowMonotonicNs(), &state);
	}
	const auto hadConnect = !_connectAddress.isEmpty();
	teardownSession();
	emit disconnected(); // same signal Type1/Type2 use for transient disconnect (AC3)

	if (hadConnect) {
		// Reconnect on the same proxy/DC (AC3: no re-login, no proxyDeath signal).
		QTimer::singleShot(0, this, [this] {
			if (_status == Status::Waiting) {
				doConnect();
			}
		});
	}
}

void ConnectionTeleproto3::teardownSession() {
	_status = Status::Waiting;
	_negotiatedVersion = 0;
	_tls = nullptr; // non-owning

	if (_t3session) {
		t3_session_free(_t3session);
		_t3session = nullptr;
	}
	if (_bridgeCtx) {
		Tdesktop::Teleproto3::destroyContext(_bridgeCtx);
		_bridgeCtx = nullptr;
		_callbacks = {};
	}
	if (_ws) {
		_ws->disconnect(); // Qt disconnect all signals
		_ws->close();
		_ws->deleteLater();
		_ws = nullptr;
	}
}

uint64_t ConnectionTeleproto3::nowMonotonicNs() const {
	if (_callbacks.monotonic_ns) {
		return _callbacks.monotonic_ns(_callbacks.ctx);
	}
	// Fallback when callbacks not yet initialised.
	using namespace std::chrono;
	static const auto kEpoch = steady_clock::now();
	const auto delta = duration_cast<nanoseconds>(steady_clock::now() - kEpoch).count();
	return (delta < 0) ? 0 : static_cast<uint64_t>(delta);
}

} // namespace details
} // namespace MTP
