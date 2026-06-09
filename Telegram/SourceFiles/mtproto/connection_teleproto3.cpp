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

#include <QtCore/QSocketNotifier>
#include <QPointer>
#include <QRandomGenerator>
#include <QThread>
#include <QTimer>
#include <chrono>
#include <cstring>
#include <limits>
#include <vector>

// Story 2-9 (macOS dev-build): DevBuildOnly runtime self-check moved to .mm file.
// Foundation.h cannot be included from .cpp; NSBundle access requires Objective-C++.

// ABI version-pin is in teleproto3_bridge.cpp (Epic 2 style-guide §3 single-TU rule).
// This file includes the bridge header; the static_assert is thus reachable at compile time.

// Anti-pattern §12.9: Every transport transition in this file is driven by an explicit
// user action (clone) or an explicit OS network-change event (onNetworkChanged).
// There is NO code path that auto-selects a different proxy on Type3 failure.
//
// Post-migration (canonical t3_client_* API): the Type3 protocol — TLS, obfs2
// init, AES-256-CTR, 4-byte length + 0-15 byte padding framing, and HTTP-chunk
// framing — is owned entirely by libteleproto3. This TU no longer re-implements
// any of it; it only drives the client fd and shuttles MTProto payloads.

namespace {

constexpr auto kFullConnectTimeoutMs = crl::time(20'000); // 20 s
constexpr auto kTransportName = "Type3/HTTP";

// NFR25 backoff cap is 60 s per story 1.3 §7.2.
constexpr int kNfr25CapMs = 60000;

// Default inner silent-close delay. Post-t3_client_* migration the library no
// longer exposes a per-session silent-close sampler, so we use the fixed median
// of the AR-C2 [50, 200] ms uniform range (story 2.6 Dev Notes §NFR25-backoff-layering).
constexpr uint64_t kSilentCloseDelayDefaultNs = 125'000'000ULL; // 125 ms

// Upper bound for a single decrypted MTProto message returned by t3_client_read.
// Must be large enough to hold any one server message; 1 MiB matches the Android
// READ_BUFFER_SIZE used by the tgnet t3_client integration.
constexpr size_t kReadBufferSize = 1 * 1024 * 1024; // 1 MiB

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
	// Record this close on the C++-side retry counter (replaces t3_retry_record_close):
	// increment first, then read the resulting tier — matching the old record_close
	// semantics (tier reflects the state AFTER this close) and handleTransportError().
	if (_status == Status::Ready) {
		++_consecutiveCloses;
	}
	const auto tier = currentRetryTier();
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
	// Story 2-13: cache write — connect-attempt epoch for ms_since_connect.
	_connectToServerAtMs = crl::now();

	// For Type3/Mtproto proxies, session_private passes empty ip/0 port.
	// Use the proxy's own host:port for the TLS connection.
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

	// Decode proxy password to raw bytes. Format: 0xff | 16-byte-key | domain[/path].
	const auto rawPwd = decodeProxyPassword(_proxy.password);
	if (rawPwd.size() < 18 || static_cast<uint8_t>(rawPwd[0]) != 0xff) {
		logError(u"Type3 secret decode failed"_q);
		_status = Status::Finished;
		Q_EMIT error(kErrorCodeOther);
		return;
	}

	// Extract domain+path from the Type3 secret (bytes 17+).
	const auto domainPathRaw = QString::fromLatin1(
		rawPwd.constData() + 17, rawPwd.size() - 17);
	const auto slashIdx = domainPathRaw.indexOf('/');
	const auto secretDomain = (slashIdx >= 0)
		? domainPathRaw.left(slashIdx)
		: domainPathRaw;
	const auto secretPath = (slashIdx >= 0)
		? domainPathRaw.mid(slashIdx)
		: QString();

	// Prefer path from secret, fallback to _proxy.wsPath, default to "/".
	const auto path = !secretPath.isEmpty()
		? secretPath
		: (!_proxy.wsPath.isEmpty()
			? (_proxy.wsPath.startsWith('/') ? _proxy.wsPath : '/' + _proxy.wsPath)
			: u"/"_q);

	// Use secretDomain for TLS SNI (overrides _connectAddress which may lack the secret's domain).
	const auto tlsHost = !secretDomain.isEmpty() ? secretDomain : _connectAddress;

	// HTTP-stream endpoint only. Never construct a wss:// URL.
	const auto endpointUrl = u"https://"_q
		+ tlsHost
		+ u":"_q
		+ QString::number(_connectPort)
		+ (path.isEmpty() ? u"/"_q : path);

	// Extract the 16-byte key (bytes 1..16 after the 0xff prefix).
	uint8_t key16[16] = {};
	std::memcpy(key16, rawPwd.constData() + 1, 16);

	// Create the libteleproto3 client stream. The library owns the TLS socket,
	// obfs2 init, AES-CTR, padding and HTTP-chunk framing.
	const auto createRc = t3_client_create(
		endpointUrl.toUtf8().constData(),
		key16,
		_connectProtocolDcId,
		&_client);
	if (createRc != T3_OK || !_client) {
		logError(u"t3_client_create: "_q + QString::fromUtf8(t3_strerror(createRc)));
		if (_client) {
			t3_client_destroy(_client);
			_client = nullptr;
		}
		_status = Status::Finished;
		Q_EMIT error(kErrorCodeOther);
		return;
	}

	_clientFd = t3_client_get_fd(_client);
	if (_clientFd < 0) {
		logError(u"t3_client_get_fd returned -1"_q);
		t3_client_destroy(_client);
		_client = nullptr;
		_clientFd = -1;
		_status = Status::Finished;
		Q_EMIT error(kErrorCodeOther);
		return;
	}

	// Drive the client fd. The library pumps its own state machine on readability;
	// the initial TLS connect may already be writable, so kick it once below.
	_readNotifier = new QSocketNotifier(_clientFd, QSocketNotifier::Read, this);
	QObject::connect(_readNotifier, &QSocketNotifier::activated,
		this, &ConnectionTeleproto3::onClientReadable);

	// Start the ping clock; promotion to Ready computes the delta (see onClientReadable).
	_pingTimeMs = crl::now();

	CONNECTION_LOG_INFO(u"Type3 client created over HTTP stream"_q);

	// Kick the pump once — the connect/TLS handshake may already be ready to advance.
	onClientReadable();
}

void ConnectionTeleproto3::onClientReadable() {
	if (!_client) return;

	t3_client_pump(_client);

	const auto st = t3_client_get_state(_client);
	if (st == T3_CLIENT_STATE_ERROR || st == T3_CLIENT_STATE_CLOSED) {
		logError(u"Type3 client error: "_q
			+ QString::fromUtf8(t3_client_last_error(_client)));
		handleTransportError();
		return;
	}

	if (_status == Status::Connecting && st == T3_CLIENT_STATE_READY) {
		_status = Status::Ready;
		_pingTimeMs = crl::now() - _pingTimeMs;
		// Reset the consecutive-close counter on a successful Ready (retry tier 0).
		_consecutiveCloses = 0;
		CONNECTION_LOG_INFO(u"Type3 client READY over HTTP stream"_q);
		Q_EMIT connected();
		drainPendingQueue();
	}

	if (_status == Status::Ready) {
		// Read every available message. t3_client_read returns exactly ONE message
		// per call (libteleproto3 was fixed for this); loop until BUF_TOO_SMALL.
		static thread_local std::vector<char> buf;
		for (;;) {
			buf.resize(kReadBufferSize);
			size_t outLen = 0;
			const auto rc = t3_client_read(
				_client,
				reinterpret_cast<uint8_t*>(buf.data()),
				buf.size(),
				&outLen);
			if (rc == T3_ERR_BUF_TOO_SMALL || outLen == 0) {
				break;
			}
			if (rc != T3_OK) {
				logError(u"t3_client_read: "_q
					+ QString::fromUtf8(t3_strerror(rc)));
				handleTransportError();
				return;
			}

			// Story 2-13: cache write — last binary recv timestamp.
			_lastBinaryRecvAtMs = crl::now();

			// The library returns the decrypted MTProto payload (framing and any
			// 0-15 trailing pad bytes already stripped/handled by libteleproto3).
			// Wrap whole mtpPrime ints; any trailing partial bytes are ignored.
			const auto ints = outLen / sizeof(mtpPrime);
			if (ints == 0) {
				continue;
			}
			auto mtp = mtpBuffer(ints);
			std::memcpy(mtp.data(), buf.data(), ints * sizeof(mtpPrime));
			_receivedQueue.push_back(std::move(mtp));
			Q_EMIT receivedSome();
			Q_EMIT receivedData();
		}
	}
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
	if (!_client) {
		return;
	}
	// The mtpBuffer has 2 reserved header ints at the front (legacy DD framing used
	// outBuf[1] as the byte-length and started the frame at byte offset 4). The actual
	// MTProto payload is ints [2 .. end]. libteleproto3 adds the 4-byte length, 0-15
	// padding, AES-256-CTR and HTTP-chunk framing internally — we send ONLY the raw
	// MTProto payload, and exactly one t3_client_write per message (never bundle).
	if (buffer.size() < 2) {
		return;
	}
	const auto payload = reinterpret_cast<const uint8_t*>(buffer.data())
		+ 2 * sizeof(mtpPrime);
	const auto payloadLen = (buffer.size() - 2) * sizeof(mtpPrime);

	const auto rc = t3_client_write(_client, payload, payloadLen);
	if (rc != T3_OK) {
		logError(u"t3_client_write: "_q + QString::fromUtf8(t3_strerror(rc)));
		handleTransportError();
	}
}

void ConnectionTeleproto3::drainPendingQueue() {
	while (!_pendingQueue.empty()) {
		// sendImmediate may trigger handleTransportError() on a write failure,
		// which tears down the session and resets _status — stop draining then.
		sendImmediate(_pendingQueue.front());
		if (_status != Status::Ready) {
			return;
		}
		_pendingQueueBytes -= int(_pendingQueue.front().size()) * int(sizeof(mtpPrime));
		_pendingQueue.pop_front();
	}
}

void ConnectionTeleproto3::handleTransportError() {
	if (_status == Status::Finished || _status == Status::Waiting) return;
	const auto wasReady = (_status == Status::Ready);

	// Record this close on the C++-side retry counter (replaces t3_retry_record_close)
	// and compute the reconnect delay BEFORE teardown.
	t3_retry_state_t tier = T3_RETRY_OK;
	int reconnectDelayMs = 0;
	if (wasReady) {
		++_consecutiveCloses;
		tier = currentRetryTier();
		emitRetryState(tier);  // rpl push + tier-3 toast guard
		reconnectDelayMs = computeReconnectDelayMs();

		// [T3-disco] marker — transport closed on a Ready session. ws_close=1006 is
		// retained for log-grep continuity with the pre-migration WS layer (RFC 6455
		// "abnormal closure"); the HTTP-stream layer surfaces no wire close code.
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
		// [T3-disco] marker — transport failed before Ready (Connecting/Negotiating).
		const auto stateStr = (_status == Status::Negotiating)
			? u"Negotiating"_q
			: u"Connecting"_q;
		emitDiscoMarker(stateStr, u"-"_q, u"-"_q, u"-"_q);
	}

	teardownSession();
	Q_EMIT disconnected();

	if (!wasReady) {
		// Connection failure during Connecting — let the session layer handle retry.
		Q_EMIT error(kErrorCodeOther);
		return;
	}

	// Reconnect gate: server-initiated close on a Ready session. Schedule self-heal
	// without emitting error(); the session stays logically connected.
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

void ConnectionTeleproto3::disconnectFromServer() {
	if (_status == Status::Finished) return;
	if (_status == Status::Ready) {
		++_consecutiveCloses;
	}
	teardownSession();
	_status = Status::Finished;
}

void ConnectionTeleproto3::onNetworkChanged() {
	CONNECTION_LOG_INFO(u"network path changed — reconnecting"_q);

	t3_retry_state_t tier = T3_RETRY_OK;
	if (_status == Status::Ready) {
		++_consecutiveCloses;
		tier = currentRetryTier();
		emitRetryState(tier);
	}

	// Compute delay before teardown.
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

	if (_readNotifier) {
		_readNotifier->setEnabled(false);
		_readNotifier->deleteLater();
		_readNotifier = nullptr;
	}
	if (_client) {
		t3_client_destroy(_client);
		_client = nullptr;
	}
	_clientFd = -1;
}

uint64_t ConnectionTeleproto3::nowMonotonicNs() const {
	// Post-migration the Qt-bridged callbacks are gone; use steady_clock directly.
	using namespace std::chrono;
	static const auto kEpoch = steady_clock::now();
	const auto delta = duration_cast<nanoseconds>(steady_clock::now() - kEpoch).count();
	return (delta < 0) ? 0 : static_cast<uint64_t>(delta);
}

t3_retry_state_t ConnectionTeleproto3::currentRetryTier() const {
	// C++-side retry-tier mapping (replaces t3_retry_get_state). Preserves the
	// t3_retry_state_t enum values so emitRetryState / the keepalive snapshot
	// produce unchanged UI signal payloads.
	switch (_consecutiveCloses) {
	case 0:  return T3_RETRY_OK;
	case 1:  return T3_RETRY_TIER1;
	case 2:  return T3_RETRY_TIER2;
	default: return T3_RETRY_TIER3; // >= 3
	}
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
	_consecutiveCloses = 0;
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

	// Story 2-13: cache write — latest retry tier for last_retry_tier snapshot field.
	// D3 (party-mode): flip the sentinel so the snapshot can distinguish a real
	// tier transition from the default-init T3_RETRY_TIER1 value.
	_lastRetryTier = state;
	_lastRetryTierEverSet = true;

	// Tier-3 toast: single-instance guard per Dev Notes §tier-3-toast-ux.
	// Do not re-emit if a toast is already visible for this session.
	if (state == T3_RETRY_TIER3 && !_tier3ToastVisible) {
		_tier3ToastVisible = true;
		Q_EMIT tier3Reached();  // → main-thread subscriber calls Ui::Toast::Show()
	}
}

// Returns composite reconnect delay in ms:
//   inner layer = fixed silent-close delay (AR-C2 timing-uniformity, 125 ms)
//   outer layer = NFR25 backoff × uniform [0.8, 1.2] jitter
// Advances _backoffStepMs along NFR25 sequence on each call (via the timer callback).
int ConnectionTeleproto3::computeReconnectDelayMs() {
	// Inner layer: silent-close delay. Post-t3_client_* migration the library no
	// longer exposes a per-session sampler, so this is the fixed 125 ms default.
	const uint64_t silentNs = kSilentCloseDelayDefaultNs;
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

// Story 2-13: populate Type3-specific snapshot fields for the [T3-keepalive]
// block. Per-Connection cache fields (`last_retry_tier`) emit unconditionally,
// gated by their own `*EverSet` sentinel per D3 — render `-` until the field
// has actually been written.
//
// Post-t3_client_* migration: the AES-CTR obf send/recv counters and the
// per-session silent-close sample are no longer observable — the crypto state
// now lives inside libteleproto3 and is not surfaced. Those snapshot fields are
// left as std::nullopt (rendered as "-").
AbstractConnection::KeepaliveSnapshot
ConnectionTeleproto3::collectKeepaliveSnapshot() const {
	KeepaliveSnapshot snap;

	snap.backoff_step_ms = _backoffStepMs;
	snap.status = [&]() -> QString {
		switch (_status) {
		case Status::Waiting:     return u"Waiting"_q;
		case Status::Connecting:  return u"Connecting"_q;
		case Status::Negotiating: return u"Negotiating"_q;
		case Status::Ready:       return u"Ready"_q;
		case Status::Finished:    return u"Finished"_q;
		}
		return u"-"_q;
	}();
	snap.pending_queue_size = static_cast<int>(_pendingQueue.size());
	snap.pending_queue_bytes = _pendingQueueBytes;

	// D2: per-Connection cache, emit unconditionally with D3 sentinel gate.
	if (_lastRetryTierEverSet) {
		snap.last_retry_tier = [&]() -> int {
			switch (_lastRetryTier) {
			case T3_RETRY_OK:    return 0;
			case T3_RETRY_TIER1: return 1;
			case T3_RETRY_TIER2: return 2;
			case T3_RETRY_TIER3: return 3;
			default:             return -1;
			}
		}();
	}

	// obf_send_counter / obf_recv_counter / last_silent_close_ns are no longer
	// surfaced post-t3_client_* migration (crypto state is internal to
	// libteleproto3). They remain std::nullopt → rendered as "-".

	// P12 (party-mode): clamp deltas to >=0 — defensive against clock anomaly
	// (long sleep, clock-jump). crl::time is signed; underflow renders absurd
	// 19-digit values that mislead operator triage.
	if (_connectToServerAtMs > 0) {
		snap.ms_since_connect = std::max<crl::time>(
			0, crl::now() - _connectToServerAtMs);
	}
	if (_lastBinaryRecvAtMs > 0) {
		snap.ms_since_binary_recv = std::max<crl::time>(
			0, crl::now() - _lastBinaryRecvAtMs);
	}

	return snap;
}

} // namespace details
} // namespace MTP
