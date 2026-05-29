/*
 * connection_teleproto3_http.cpp — HTTP stream transport framer implementation.
 *
 * Implements chunked HTTP/1.1 upload/download framer over QSslSocket.
 */

#include "mtproto/connection_teleproto3_http.h"

#include <t3.h>

namespace Tdesktop::Teleproto3 {

HttpStreamFramer::HttpStreamFramer(
	QSslSocket *tls,
	const QString &host,
	const QString &path,
	QObject *parent)
	: IType3Transport(parent), _tls(tls), _host(host), _path(path) {
	QObject::connect(_tls, &QSslSocket::readyRead, this, &HttpStreamFramer::onReadyRead);
	QObject::connect(_tls, &QSslSocket::disconnected, this, &HttpStreamFramer::onDisconnected);
}

void HttpStreamFramer::open() {
	// P1: guard against double-open (e.g. spurious second encrypted signal).
	if (_connected) return;
	// 12-5-DEF1: isEncrypted() is the correct predicate for QSslSocket —
	// state() == ConnectedState is true during TLS handshake before encryption.
	if (!_tls->isEncrypted()) return;

	QString req = QString(
		"POST %1 HTTP/1.1\r\n"
		"Host: %2\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Transfer-Encoding: chunked\r\n\r\n")
		.arg(_path, _host);
	_tls->write(req.toUtf8());
}

qint64 HttpStreamFramer::sendBinaryMessage(const QByteArray &msg) {
	if (!_connected) return -1;
	if (msg.isEmpty()) return 0;

	// Calculate capability limit: hex_len + CRLF + data_len + CRLF.
	// A safe upper bound is msg.size() + 64.
	QByteArray chunk;
	chunk.resize(msg.size() + 64);

	size_t written = 0;
	t3_result_t rc = t3_http_chunk_write(
		reinterpret_cast<uint8_t*>(chunk.data()),
		static_cast<size_t>(chunk.size()),
		reinterpret_cast<const uint8_t*>(msg.constData()),
		static_cast<size_t>(msg.size()),
		&written);

	if (rc != T3_OK) {
		// P2: emit errorOccurred so caller is not silently stranded.
		Q_EMIT errorOccurred(QAbstractSocket::NetworkError);
		_tls->disconnectFromHost();
		return -1;
	}

	chunk.resize(static_cast<int>(written));
	return _tls->write(chunk);
}

QAbstractSocket::SocketState HttpStreamFramer::state() const {
	return _connected ? QAbstractSocket::ConnectedState : _tls->state();
}

void HttpStreamFramer::onReadyRead() {
	_buffer.append(_tls->readAll());

	if (!_connected) {
		int headerEnd = _buffer.indexOf("\r\n\r\n");
		if (headerEnd == -1) return;

		QByteArray header = _buffer.left(headerEnd);
		_buffer.remove(0, headerEnd + 4);

		// P4: require trailing space to avoid matching "HTTP/1.1 2001 Custom" etc.
		if (header.startsWith("HTTP/1.1 200 ")) {
			_connected = true;
			Q_EMIT connected();
		} else {
			// P5: use RemoteHostClosedError for non-200 (server closed/rejected).
			Q_EMIT errorOccurred(QAbstractSocket::RemoteHostClosedError);
			_tls->disconnectFromHost();
			return;
		}
	}

	while (!_buffer.isEmpty()) {
		const uint8_t *dataPtr = nullptr;
		size_t dataLen = 0;
		size_t consumed = 0;
		t3_result_t rc = t3_http_chunk_parse(
			reinterpret_cast<const uint8_t*>(_buffer.constData()),
			static_cast<size_t>(_buffer.size()),
			&dataPtr,
			&dataLen,
			&consumed);

		if (rc == T3_ERR_BUF_TOO_SMALL) {
			break;
		} else if (rc == T3_OK) {
			if (dataLen == 0) {
				// Terminal chunk (0\r\n\r\n) — P3: reset _connected before signalling.
				_connected = false;
				_tls->disconnectFromHost();
				break;
			}
			QByteArray payload(reinterpret_cast<const char*>(dataPtr), static_cast<int>(dataLen));
			_buffer.remove(0, static_cast<int>(consumed));
			Q_EMIT binaryMessageReceived(payload);
		} else {
			// Malformed chunked encoding — P5: use NetworkError for protocol-level failure.
			Q_EMIT errorOccurred(QAbstractSocket::NetworkError);
			_tls->disconnectFromHost();
			break;
		}
	}
}

void HttpStreamFramer::onDisconnected() {
	// P3: always clear _connected so state() and sendBinaryMessage() are correct
	// after the TLS socket closes (terminal chunk or TCP RST / TLS close_notify).
	_connected = false;
	Q_EMIT disconnected();
}

} // namespace Tdesktop::Teleproto3
