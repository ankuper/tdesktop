/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/connection_teleproto3.h"

#include "base/bytes.h"
#include "base/openssl_help.h"
#include "base/random.h"
#include "logs.h"

#include <QtNetwork/QAbstractSocket>
#include <QtNetwork/QSslSocket>
#include <QPointer>
#include <QRandomGenerator>
#include <QThread>
#include <QTimer>
#include <chrono>
#include <cstring>
#include <limits>

// Story 2-9 (macOS dev-build): DevBuildOnly runtime self-check moved to .mm file.
// Foundation.h cannot be included from .cpp; NSBundle access requires Objective-C++.

// ABI version-pin is in teleproto3_bridge.cpp (Epic 2 style-guide §3 single-TU rule).
// This file includes the bridge header; the static_assert is thus reachable at compile time.

// Anti-pattern §12.9: Every transport transition in this file is driven by an explicit
// user action (clone) or an explicit OS network-change event (onNetworkChanged).
// There is NO code path that auto-selects a different proxy on Type3 failure.

namespace {

constexpr auto kFullConnectTimeoutMs = crl::time(20'000); // 20 s
constexpr auto kTransportName = "Type3/WS";

// NFR25 backoff cap is 60 s per story 1.3 §7.2.
constexpr int kNfr25CapMs = 60000;

// Default inner silent-close delay when t3_silent_close_delay_sample_ns returns
// non-T3_OK (e.g., T3_ERR_INVALID_ARG when callbacks not yet bound, or T3_ERR_RNG).
// Median of the AR-C2 [50, 200] ms uniform range (story 2.6 Dev Notes §NFR25-backoff-layering).
constexpr uint64_t kSilentCloseDelayDefaultNs = 125'000'000ULL; // 125 ms

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
	std::deque<mtpBuffer> inheritedQueue,
	int initialBackoffMs)
: AbstractConnection(thread, proxy)
, _instance(instance)
, _pendingQueue(std::move(inheritedQueue))
, _backoffNextAttemptMs(initialBackoffMs)
, _backoffStepMs(initialBackoffMs > 0 ? initialBackoffMs : 1000) {
	for (const auto &buf : _pendingQueue) {
		_pendingQueueBytes += int(buf.size()) * int(sizeof(mtpPrime));
	}

	// Story 2-9 (macOS dev-build): DevBuildOnly self-check removed from .cpp.
	// NSBundle access requires Objective-C++; moved to separate .mm TU if needed.

	// Platform-specific network observer (AC3).
	// Observer calls onNetworkChanged() directly via QTimer::singleShot.
	_networkObserver = Tdesktop::Teleproto3::createNetworkObserver(this);
}

ConnectionTeleproto3::~ConnectionTeleproto3() {
	teardownSession();
}

ConnectionPointer ConnectionTeleproto3::clone(const ProxyData &proxy) {
	// Auth state owned by mtproto_auth_key; transport swap does not touch it.
	t3_retry_state_t tier = T3_RETRY_OK;
	if (_t3session) {
		t3_retry_record_close(_t3session, nowMonotonicNs(), &tier);
	}
	teardownSession();
	_status = Status::Finished;
	auto inherited = std::move(_pendingQueue);
	_pendingQueueBytes = 0;

	int backoffMs = 0;
	switch (tier) {
	case T3_RETRY_OK: break;
	case T3_RETRY_TIER1: backoffMs = 1000; break;
	case T3_RETRY_TIER2: backoffMs = std::min(_backoffStepMs * 2, 60000); break;
	case T3_RETRY_TIER3: backoffMs = 60000; break;
	}

	return ConnectionPointer::New<ConnectionTeleproto3>(
		_instance,
		thread(),
		proxy,
		std::move(inherited),
		backoffMs);
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
		// [T3-disco] marker — connect timeout; no WS or transport error code available.
		const auto stateStr = (_status == Status::Negotiating)
			? u"Negotiating"_q
			: u"Connecting"_q;
		emitDiscoMarker(stateStr, u"-"_q, u"-"_q, u"-"_q);
		teardownSession();
		Q_EMIT error(kErrorCodeOther);
	}
}

void ConnectionTeleproto3::connectToServer(
		const QString &ip,
		int port,
		const bytes::vector &protocolSecret,
		int16 protocolDcId,
		bool protocolForFiles) {
	// For Type3/Mtproto proxies, session_private passes empty ip/0 port.
	// Use the proxy's own host:port for the TLS/WS connection.
	_connectAddress = _proxy.host;
	_connectPort = _proxy.port;
	_connectProtocolSecret = protocolSecret;
	_connectProtocolDcId = protocolDcId;
	_connectProtocolForFiles = protocolForFiles;

	if (_backoffNextAttemptMs > 0) {
		const auto delay = int(_backoffNextAttemptMs);
		_backoffNextAttemptMs = 0;
		const auto weak = QPointer<ConnectionTeleproto3>(this);
		QTimer::singleShot(delay, this, [weak] {
			if (!weak) return;
			if (weak->_status == Status::Waiting) {
				weak->doConnect();
			}
		});
	} else {
		doConnect();
	}
}

void ConnectionTeleproto3::doConnect() {
	teardownSession();
	_status = Status::Connecting;

	// Decode proxy password to raw bytes for t3_secret_parse.
	const auto rawPwd = decodeProxyPassword(_proxy.password);
	if (rawPwd.size() < 18 || static_cast<uint8_t>(rawPwd[0]) != 0xff) {
		logError(u"Type3 secret decode failed"_q);
		_status = Status::Finished;
		Q_EMIT error(kErrorCodeOther);
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
		Q_EMIT error(kErrorCodeOther);
		return;
	}

	// Extract domain+path from the Type3 secret (bytes 17+).
	// Format: 0xff | 16-byte-key | domain[/path]
	const auto domainPathRaw = QString::fromLatin1(
		rawPwd.constData() + 17, rawPwd.size() - 17);
	const auto slashIdx = domainPathRaw.indexOf('/');
	const auto secretDomain = (slashIdx >= 0)
		? domainPathRaw.left(slashIdx)
		: domainPathRaw;
	const auto secretPath = (slashIdx >= 0)
		? domainPathRaw.mid(slashIdx)
		: QString();

	// Prefer path from secret, fallback to _proxy.wsPath.
	const auto wsPath = !secretPath.isEmpty()
		? secretPath
		: (!_proxy.wsPath.isEmpty()
			? (_proxy.wsPath.startsWith('/') ? _proxy.wsPath : '/' + _proxy.wsPath)
			: QString());

	// Use secretDomain for TLS SNI (overrides _connectAddress which may lack the secret's domain).
	const auto tlsHost = !secretDomain.isEmpty() ? secretDomain : _connectAddress;

	const auto host = tlsHost.contains(':')
		? '[' + tlsHost + ']'
		: tlsHost;
	// Create QSslSocket for the TLS layer.
	_tls = new QSslSocket(this);
	_tls->setPeerVerifyMode(QSslSocket::VerifyNone);

	// Create the MiniWebSocket framer on top of the TLS socket.
	_ws = new Tdesktop::Teleproto3::MiniWebSocket(
		_tls,
		tlsHost + ':' + QString::number(_connectPort),
		wsPath.isEmpty() ? QStringLiteral("/") : wsPath,
		this);

	QObject::connect(_ws, &Tdesktop::Teleproto3::MiniWebSocket::connected,
		this, &ConnectionTeleproto3::onWsConnected);
	QObject::connect(_ws, &Tdesktop::Teleproto3::MiniWebSocket::disconnected,
		this, &ConnectionTeleproto3::onWsDisconnected);
	QObject::connect(_ws, &Tdesktop::Teleproto3::MiniWebSocket::errorOccurred,
		this, &ConnectionTeleproto3::onWsError);
	QObject::connect(_ws, &Tdesktop::Teleproto3::MiniWebSocket::binaryMessageReceived,
		this, &ConnectionTeleproto3::onWsBinaryMessage);

	// Connect TLS, then initiate WS upgrade once encrypted.
	QObject::connect(_tls, &QSslSocket::encrypted, _ws, &Tdesktop::Teleproto3::MiniWebSocket::open);
	_tls->connectToHostEncrypted(tlsHost, _connectPort);

	// Pre-create the session (before WS connects) so we have the secret available.
	t3_session_t *sess = nullptr;
	const auto sessRc = t3_session_new(secret, &sess);
	if (sessRc != T3_OK) {
		logError(u"t3_session_new: "_q + QString::fromUtf8(t3_strerror(sessRc)));
		_tls->disconnectFromHost();
		_ws->deleteLater();
		_ws = nullptr;
		_tls->deleteLater();
		_tls = nullptr;
		_status = Status::Finished;
		Q_EMIT error(kErrorCodeOther);
		return;
	}
	_t3session = sess;
}

void ConnectionTeleproto3::onWsConnected() {
	if (_status != Status::Connecting) return;

	Q_ASSERT(_tls);

	// H6 fix (story 2-12): bind Qt-bridged callbacks here, before the first encrypted
	// frame. lower_send / lower_recv need a connected socket; binding in doConnect()
	// would hand the bridge a Connecting-state _ws.
	_bridgeCtx = Tdesktop::Teleproto3::createContext(_tls, _ws);
	if (!_bridgeCtx) {
		logError(u"t3 createContext failed"_q);
		teardownSession();
		_status = Status::Finished;
		Q_EMIT error(kErrorCodeOther);
		return;
	}
	_callbacks = Tdesktop::Teleproto3::makeCallbacks(_bridgeCtx);
	const auto bindRc = t3_session_bind_callbacks(_t3session, &_callbacks);
	if (bindRc != T3_OK) {
		logError(u"t3_session_bind_callbacks: "_q + QString::fromUtf8(t3_strerror(bindRc)));
		teardownSession();
		_status = Status::Finished;
		Q_EMIT error(kErrorCodeOther);
		return;
	}

	// Standard MTProto obfuscated DD handshake over WebSocket.
	// Generate 64-byte random nonce.
	char nonceBytes[64];
	auto nonce = bytes::make_span(reinterpret_cast<bytes::type*>(nonceBytes), 64);
	do {
		bytes::set_random(nonce);
	} while (nonceBytes[0] == char(0xef)
		|| *reinterpret_cast<uint32_t*>(nonceBytes) == 0x44414548
		|| *reinterpret_cast<uint32_t*>(nonceBytes) == 0x54534F50
		|| *reinterpret_cast<uint32_t*>(nonceBytes) == 0x20544547
		|| *reinterpret_cast<uint32_t*>(nonceBytes) == 0xEEEEEEEE
		|| *reinterpret_cast<uint32_t*>(nonceBytes) == 0xDDDDDDDD);

	// Decode proxy secret (should be just 16 bytes key from the ff-prefixed secret).
	const auto rawPwd = decodeProxyPassword(_proxy.password);
	// Extract the 16-byte key (bytes 1-16 after 0xff prefix).
	const auto keyStart = (rawPwd.size() >= 17 && static_cast<uint8_t>(rawPwd[0]) == 0xff) ? 1 : 0;
	const auto proxyKey = bytes::make_span(
		reinterpret_cast<const bytes::type*>(rawPwd.constData() + keyStart), 16);

	// Send key: SHA256(nonce[8..40] + secret) — server obfs2_parse_header uses
	// header[8..40] (32 bytes), not header[8..56]. IV: nonce[40..56].
	{
		auto sendSource = bytes::vector(32 + 16);
		bytes::copy(bytes::make_span(sendSource).subspan(0, 32), nonce.subspan(8, 32));
		bytes::copy(bytes::make_span(sendSource).subspan(32, 16), proxyKey);
		const auto hash = openssl::Sha256(sendSource);
		bytes::copy(bytes::make_span(_obfSendKey), bytes::make_span(hash).subspan(0, 32));
		bytes::copy(bytes::make_span(_obfSendState.ivec), nonce.subspan(40, 16));
	}

	// Recv key: SHA256(reverse(nonce[24..56]) + secret) — server reverses
	// header[55..24] (write_key[i]=header[55-i], i=0..31) then SHA256(32+16).
	// Recv IV: reverse(nonce[8..24]) — server write_iv[i]=header[23-i], i=0..15.
	{
		auto reversedKey = bytes::vector(32);
		bytes::copy(bytes::make_span(reversedKey), nonce.subspan(24, 32));
		std::reverse(reversedKey.begin(), reversedKey.end());
		auto recvSource = bytes::vector(32 + 16);
		bytes::copy(bytes::make_span(recvSource).subspan(0, 32), bytes::make_span(reversedKey));
		bytes::copy(bytes::make_span(recvSource).subspan(32, 16), proxyKey);
		const auto hash = openssl::Sha256(recvSource);
		bytes::copy(bytes::make_span(_obfRecvKey), bytes::make_span(hash).subspan(0, 32));
		auto reversedIv = bytes::vector(16);
		bytes::copy(bytes::make_span(reversedIv), nonce.subspan(8, 16));
		std::reverse(reversedIv.begin(), reversedIv.end());
		bytes::copy(bytes::make_span(_obfRecvState.ivec), bytes::make_span(reversedIv));
	}

	// Write DD protocol ID and DC ID into nonce.
	*reinterpret_cast<uint32_t*>(nonceBytes + 56) = 0xDDDDDDDDU;
	*reinterpret_cast<int16_t*>(nonceBytes + 60) = _connectProtocolDcId;

	// Encrypt the full encNonce using _obfSendState (advances CTR by 64 bytes = 4 blocks).
	// Server calls evp_crypt(read_aeskey, header, header, 64) after init, advancing its
	// persistent read context by 4 blocks — subsequent data (PQ request) is decrypted
	// at block 4. We must encrypt PQ at block 4 too, so advance _obfSendState here.
	auto encNonce = bytes::vector(64);
	bytes::copy(bytes::make_span(encNonce), nonce);
	aesCtrEncrypt(bytes::make_span(encNonce), _obfSendKey, &_obfSendState);
	// Restore bytes 0..55: those are sent in plaintext (server derives keys from them).
	bytes::copy(bytes::make_span(encNonce).subspan(0, 56), nonce.subspan(0, 56));

	// Send the 64-byte obfuscated init as a single WS binary frame.
	_ws->sendBinaryMessage(QByteArray(reinterpret_cast<const char*>(encNonce.data()), 64));
	_connectionStarted = true;

	// Now send a fake PQ request to probe connection.
	_checkNonce = base::RandomValue<MTPint128>();
	auto pqBuffer = preparePQFake(_checkNonce);
	_pingTimeMs = crl::now();

	// Finalize and encrypt the PQ packet using DD protocol.
	// DD framing: 4-byte length prefix + data + padding.
	const auto intsSize = uint32(pqBuffer.size() - 2);
	const auto padding = base::RandomValue<uint32>() & 0x0F;
	const auto bytesSize = intsSize * sizeof(mtpPrime) + padding;
	pqBuffer[1] = bytesSize;
	for (uint32 added = 0; added < padding; added += 4) {
		pqBuffer.push_back(base::RandomValue<mtpPrime>());
	}
	auto pqBytes = bytes::make_span(pqBuffer).subspan(4, 4 + bytesSize);
	aesCtrEncrypt(pqBytes, _obfSendKey, &_obfSendState);

	_ws->sendBinaryMessage(QByteArray(
		reinterpret_cast<const char*>(pqBytes.data()), pqBytes.size()));

	_status = Status::Negotiating;
	CONNECTION_LOG_INFO(u"MTProto DD obfuscated handshake sent over WS"_q);
}

void ConnectionTeleproto3::onWsBinaryMessage(const QByteArray &data) {
	if (_status == Status::Negotiating) {
		// Decrypt the response.
		auto decrypted = bytes::vector(data.size());
		bytes::copy(bytes::make_span(decrypted),
			bytes::make_span(reinterpret_cast<const bytes::type*>(data.constData()), data.size()));
		aesCtrEncrypt(bytes::make_span(decrypted), _obfRecvKey, &_obfRecvState);

		// Parse DD framing: first 4 bytes = length.
		if (decrypted.size() < 8) {
			logError(u"Obfuscated response too short: "_q + QString::number(decrypted.size()));
			teardownSession();
			Q_EMIT error(kErrorCodeOther);
			return;
		}
		const auto msgLen = *reinterpret_cast<const uint32_t*>(decrypted.data()) + 4;
		if (msgLen < 8 || msgLen > decrypted.size()) {
			logError(u"Bad DD packet length: "_q + QString::number(msgLen));
			teardownSession();
			Q_EMIT error(kErrorCodeOther);
			return;
		}
		// The payload after the 4-byte length is MTProto data.
		const auto payload = bytes::make_span(decrypted).subspan(4, msgLen - 4);
		const auto ints = gsl::make_span(
			reinterpret_cast<const mtpPrime*>(payload.data()),
			payload.size() / sizeof(mtpPrime));
		if (ints.size() < 3) {
			if (ints.size() >= 1 && ints[0] != 0) {
				logError(u"Error packet in handshake, code="_q + QString::number(ints[0]));
			}
			teardownSession();
			Q_EMIT error(kErrorCodeOther);
			return;
		}
		auto result = mtpBuffer(ints.size());
		memcpy(result.data(), ints.data(), ints.size() * sizeof(mtpPrime));

		if (const auto res_pq = readPQFakeReply(result)) {
			const auto &pqData = res_pq->c_resPQ();
			if (pqData.vnonce() == _checkNonce) {
				CONNECTION_LOG_INFO(u"Valid PQ response via MTProto DD over WS"_q);
				_status = Status::Ready;
				_pingTimeMs = crl::now() - _pingTimeMs;
				Q_EMIT connected();
				drainPendingQueue();
			} else {
				logError(u"Wrong nonce in PQ response"_q);
				teardownSession();
				Q_EMIT error(kErrorCodeOther);
			}
		} else {
			logError(u"Could not parse PQ response"_q);
			teardownSession();
			Q_EMIT error(kErrorCodeOther);
		}
		return;
	}

	if (_status != Status::Ready) return;

	// Normal data frame — decrypt and deliver.
	auto decrypted = bytes::vector(data.size());
	bytes::copy(bytes::make_span(decrypted),
		bytes::make_span(reinterpret_cast<const bytes::type*>(data.constData()), data.size()));
	aesCtrEncrypt(bytes::make_span(decrypted), _obfRecvKey, &_obfRecvState);

	// DD framing: 4-byte length + payload (minimum 8 bytes total).
	// Exception: exactly 4 bytes with a negative int32 value is a transport error
	// code sent by the server (encrypted in-stream, decoded here). Emit [T3-disco]
	// and reconnect rather than silently dropping the frame.
	if (decrypted.size() == 4) {
		int32_t code = 0;
		std::memcpy(&code, decrypted.data(), sizeof(code));
		if (code < 0) {
			const auto tierStr = [this]() -> QString {
				if (!_t3session) return u"-"_q;
				switch (t3_retry_get_state(_t3session)) {
				case T3_RETRY_OK:    return u"0"_q;
				case T3_RETRY_TIER1: return u"1"_q;
				case T3_RETRY_TIER2: return u"2"_q;
				case T3_RETRY_TIER3: return u"3"_q;
				default:             return u"-"_q;
				}
			}();
			emitDiscoMarker(u"Ready"_q, u"-"_q, QString::number(code), tierStr);
			teardownSession();
			Q_EMIT error(kErrorCodeOther);
		} else {
			LOG(("[T3] unexpected 4-byte frame, code=%1 (not transport error)").arg(code));
		}
		return;
	}
	if (decrypted.size() < 8) return;
	const auto msgLen = *reinterpret_cast<const uint32_t*>(decrypted.data()) + 4;
	if (msgLen < 8 || msgLen > decrypted.size()) return;
	const auto payload = bytes::make_span(decrypted).subspan(4, msgLen - 4);
	const auto ints = gsl::make_span(
		reinterpret_cast<const mtpPrime*>(payload.data()),
		payload.size() / sizeof(mtpPrime));
	if (ints.empty()) return;

	auto buf = mtpBuffer(ints.size());
	std::memcpy(buf.data(), ints.data(), ints.size() * sizeof(mtpPrime));
	_receivedQueue.push_back(std::move(buf));
	Q_EMIT receivedSome();
	Q_EMIT receivedData();
}

void ConnectionTeleproto3::onWsDisconnected() {
	if (_status == Status::Finished) return;
	logError(u"WS disconnected"_q);
	const auto wasReady = (_status == Status::Ready);

	// W5 + Task 1: Record close event and compute reconnect delay BEFORE teardown frees
	// _t3session and clears _callbacks.
	t3_retry_state_t tier = T3_RETRY_OK;
	int reconnectDelayMs = 0;
	if (wasReady) {
		if (_t3session) {
			t3_retry_record_close(_t3session, nowMonotonicNs(), &tier);
		}
		emitRetryState(tier);  // rpl push + tier-3 toast guard
		reconnectDelayMs = computeReconnectDelayMs();  // samples inner + outer delay before teardown

		// [T3-disco] marker — WS closed on Ready session (server-initiated close or reset).
		// ws_close=1006 is RFC 6455's reserved "abnormal closure" code (never transmitted on
		// the wire). MiniWebSocket does not surface the actual close frame code; 1006 honestly
		// signals "WS layer closed without a code we can read" rather than falsely claiming 1000.
		const auto tierStr = [&]() -> QString {
			switch (tier) {
			case T3_RETRY_OK:    return u"0"_q;
			case T3_RETRY_TIER1: return u"1"_q;
			case T3_RETRY_TIER2: return u"2"_q;
			case T3_RETRY_TIER3: return u"3"_q;
			default:             return u"-"_q;
			}
		}();
		emitDiscoMarker(u"Ready"_q, u"1006"_q, u"-"_q, tierStr);
	} else {
		// [T3-disco] marker — WS disconnected before Ready (Connecting or Negotiating).
		const auto stateStr = (_status == Status::Negotiating)
			? u"Negotiating"_q
			: u"Connecting"_q;
		emitDiscoMarker(stateStr, u"-"_q, u"-"_q, u"-"_q);
	}

	teardownSession();
	Q_EMIT disconnected();

	if (!wasReady) {
		// Connection failure during Connecting/Negotiating — let session layer handle retry.
		Q_EMIT error(kErrorCodeOther);
		return;
	}

	// W5 reconnect gate: server-initiated WS close on Ready session.
	// Schedule self-heal without emitting error(); session stays logically connected.
	// Composite delay = silent-close inner layer + NFR25 backoff outer layer (story 2.6 Dev Notes).
	if (!_connectAddress.isEmpty()) {
		const auto weak = QPointer<ConnectionTeleproto3>(this);
		QTimer::singleShot(reconnectDelayMs, this, [weak] {
			if (!weak) return;
			if (weak->_status == Status::Waiting) {
				weak->_backoffStepMs = std::min(weak->_backoffStepMs * 2, kNfr25CapMs);
				weak->doConnect();
			}
		});
	}
}

void ConnectionTeleproto3::onWsError(int err) {
	if (_status == Status::Finished || _status == Status::Waiting) return;
	logError(u"WS socket error: "_q + QString::number(err));
	// [T3-disco] marker — `err:<N>` prefix typifies this slot's value as a Qt socket-error
	// code (QAbstractSocket::SocketError range), distinct from RFC 6455 WS close codes
	// emitted from onWsDisconnected. Operators grep `ws_close=err:` vs `ws_close=[0-9]`.
	const auto stateStr = [this]() -> QString {
		switch (_status) {
		case Status::Connecting:  return u"Connecting"_q;
		case Status::Negotiating: return u"Negotiating"_q;
		case Status::Ready:       return u"Ready"_q;
		default:                  return u"-"_q;
		}
	}();
	const auto tierStr = [this]() -> QString {
		if (!_t3session) return u"-"_q;
		switch (t3_retry_get_state(_t3session)) {
		case T3_RETRY_OK:    return u"0"_q;
		case T3_RETRY_TIER1: return u"1"_q;
		case T3_RETRY_TIER2: return u"2"_q;
		case T3_RETRY_TIER3: return u"3"_q;
		default:             return u"-"_q;
		}
	}();
	emitDiscoMarker(stateStr, u"err:"_q + QString::number(err), u"-"_q, tierStr);
	teardownSession();
	Q_EMIT error(kErrorCodeOther);
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
			const auto guard = QPointer<ConnectionTeleproto3>(this);
			Q_EMIT error(kErrorCodeOther);
			if (!guard || _status == Status::Finished) return;
		}
		_pendingQueueBytes += bytes;
		_pendingQueue.push_back(std::move(buffer));
		return;
	}
	sendImmediate(buffer);
}

void ConnectionTeleproto3::sendImmediate(const mtpBuffer &buffer) {
	// DD protocol framing: 4-byte length + data + padding, AES-CTR encrypted.
	auto outBuf = mtpBuffer(buffer.size());
	std::memcpy(outBuf.data(), buffer.data(), buffer.size() * sizeof(mtpPrime));

	const auto intsSize = uint32(outBuf.size() - 2);
	const auto padding = base::RandomValue<uint32>() & 0x0F;
	const auto bytesSize = intsSize * sizeof(mtpPrime) + padding;
	outBuf[1] = bytesSize;
	for (uint32 added = 0; added < padding; added += 4) {
		outBuf.push_back(base::RandomValue<mtpPrime>());
	}
	auto pqBytes = bytes::make_span(outBuf).subspan(4, 4 + bytesSize);
	aesCtrEncrypt(pqBytes, _obfSendKey, &_obfSendState);
	_ws->sendBinaryMessage(QByteArray(
		reinterpret_cast<const char*>(pqBytes.data()), pqBytes.size()));
}

void ConnectionTeleproto3::drainPendingQueue() {
	while (!_pendingQueue.empty()) {
		sendImmediate(_pendingQueue.front());
		_pendingQueueBytes -= int(_pendingQueue.front().size()) * int(sizeof(mtpPrime));
		_pendingQueue.pop_front();
	}
}

void ConnectionTeleproto3::disconnectFromServer() {
	if (_status == Status::Finished) return;
	if (_t3session) {
		t3_retry_state_t state;
		t3_retry_record_close(_t3session, nowMonotonicNs(), &state);
	}
	teardownSession();
	_status = Status::Finished;
}

void ConnectionTeleproto3::onNetworkChanged() {
	CONNECTION_LOG_INFO(u"network path changed — reconnecting"_q);

	t3_retry_state_t tier = T3_RETRY_OK;
	if (_t3session) {
		t3_retry_record_close(_t3session, nowMonotonicNs(), &tier);
		emitRetryState(tier);
	}

	// Compute delay before teardown (silent-close sampling needs live _callbacks).
	const auto hadConnect = !_connectAddress.isEmpty();
	const auto reconnectDelayMs = hadConnect ? computeReconnectDelayMs() : 0;

	teardownSession();
	Q_EMIT disconnected();

	if (tier == T3_RETRY_TIER3) {
		// Tier-3: continue retrying per NFR25 backoff; toast already surfaced by emitRetryState.
		// Do NOT permanently stop — the user can dismiss the toast and retry or switch.
		// Fallthrough to reconnect scheduling below (same as tier-1/2 path).
	}

	if (hadConnect) {
		const auto weak = QPointer<ConnectionTeleproto3>(this);
		QTimer::singleShot(reconnectDelayMs, this, [weak] {
			if (!weak) return;
			if (weak->_status == Status::Waiting) {
				weak->_backoffStepMs = std::min(weak->_backoffStepMs * 2, kNfr25CapMs);
				weak->doConnect();
			}
		});
	}
}

void ConnectionTeleproto3::teardownSession() {
	_status = Status::Waiting;
	_negotiatedVersion = 0;
	// _tier3ToastVisible intentionally NOT cleared here — persistent across teardown.
	// Only userRetry() clears it (D2 resolution: toast fires once per user-retry cycle).

	// Zero callbacks first: defangs any callback re-entry into freed session/bridge ctx
	// before the lib has a chance to invoke them during cleanup. Order matters.
	_callbacks = {};
	if (_t3session) {
		t3_session_free(_t3session);
		_t3session = nullptr;
	}
	if (_bridgeCtx) {
		Tdesktop::Teleproto3::destroyContext(_bridgeCtx);
		_bridgeCtx = nullptr;
	}
	if (_ws) {
		_ws->disconnect(); // Qt disconnect all signals
		_ws->deleteLater();
		_ws = nullptr;
	}
	if (_tls) {
		_tls->disconnect();
		_tls->disconnectFromHost();
		_tls->deleteLater();
		_tls = nullptr;
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

// Story 2.6 Task 1 — rpl push channel implementation.
rpl::producer<Tdesktop::Teleproto3::RetryStatePayload>
ConnectionTeleproto3::retryStateChanges() const {
	return _retryStateStream.events();
}

// Story 2.6 Task 2 — "Try again" from the proxy-list dialog.
// Q_INVOKABLE: safe to call via QMetaObject::invokeMethod from the main thread.
void ConnectionTeleproto3::userRetry() {
	Q_ASSERT(QThread::currentThread() == thread());
	if (_t3session) {
		t3_retry_user_retry(_t3session);
	}
	_tier3ToastVisible = false;
	_backoffStepMs = 1000;
}

// Emit retry state rpl event and, on first T3_RETRY_TIER3, fire the tier3Reached() Qt signal
// which the main-thread subscriber uses to show Ui::Toast::Show() (story 2.6 Dev Notes).
void ConnectionTeleproto3::emitRetryState(t3_retry_state_t state) {
	using namespace std::chrono;
	const auto now_ns = static_cast<uint64_t>(
		duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
	const int tier = [&] {
		switch (state) {
		case T3_RETRY_OK:    return 0;
		case T3_RETRY_TIER1: return 1;
		case T3_RETRY_TIER2: return 2;
		case T3_RETRY_TIER3: return 3;
		default:             return -1;
		}
	}();
	const auto payload = Tdesktop::Teleproto3::RetryStatePayload{ tier, now_ns };
	_retryStateStream.fire_copy(payload);
	Q_EMIT retryStateChanged(payload);

	// Tier-3 toast: single-instance guard per Dev Notes §tier-3-toast-ux.
	// Do not re-emit if a toast is already visible for this session.
	if (state == T3_RETRY_TIER3 && !_tier3ToastVisible) {
		_tier3ToastVisible = true;
		Q_EMIT tier3Reached();  // → main-thread subscriber calls Ui::Toast::Show()
	}
}

// Returns composite reconnect delay in ms:
//   inner layer = t3_silent_close_delay_sample_ns (AR-C2 timing-uniformity)
//   outer layer = NFR25 backoff × uniform [0.8, 1.2] jitter
// Advances _backoffStepMs along NFR25 sequence on each call.
int ConnectionTeleproto3::computeReconnectDelayMs() {
	// Inner layer: silent-close delay.
	uint64_t silentNs = kSilentCloseDelayDefaultNs;
	if (_t3session) {  // session available = context live enough to sample
		uint64_t sampledNs = 0;
		const auto rc = t3_silent_close_delay_sample_ns(_t3session, &sampledNs);
		if (rc == T3_OK) {
			silentNs = sampledNs;
		} else {
			// Non-T3_OK: default to 125 ms; do NOT abort (story 2.6 Dev Notes §NFR25).
			// Common cause: T3_ERR_INVALID_ARG when callbacks not yet bound (t3_session_bind_callbacks not called).
			LOG(("[T3] t3_silent_close_delay_sample_ns: %1, defaulting to 125 ms").arg(t3_strerror(rc)));
		}
	}
	const auto silentMs = static_cast<int>(silentNs / 1'000'000ULL);

	// Outer layer: NFR25 exponential backoff with jitter.
	const double jitter = 0.8 + QRandomGenerator::system()->generateDouble() * 0.4;
	const auto backoffMs = static_cast<int>(std::min(
		static_cast<double>(_backoffStepMs) * jitter,
		static_cast<double>(kNfr25CapMs)));
	// Backoff step is advanced by the timer callback after confirmed doConnect(),
	// not here — avoids consuming a step when reconnect is skipped.

	return silentMs + backoffMs;
}

void ConnectionTeleproto3::emitDiscoMarker(
		const QString &state,
		const QString &wsClose,
		const QString &transportErr,
		const QString &tier) {
	LOG(("[T3-disco] state=%1 ws_close=%2 transport_err=%3 tier=%4")
		.arg(state)
		.arg(wsClose)
		.arg(transportErr)
		.arg(tier));
}

} // namespace details
} // namespace MTP
