/*
 * connection_teleproto3_http.h — HTTP stream transport framer for Type3.
 *
 * Implements IType3Transport to provide a streaming, chunked HTTP/1.1
 * connection over QSslSocket. Implements low-latency chunked uploads and
 * chunked downloads using libteleproto3's chunking API helpers.
 */

#ifndef CONNECTION_TELEPROTO3_HTTP_H
#define CONNECTION_TELEPROTO3_HTTP_H

#include "mtproto/teleproto3_bridge.h"

#include <QByteArray>
#include <QString>
#include <QtNetwork/QSslSocket>

namespace Tdesktop::Teleproto3 {

class HttpStreamFramer : public IType3Transport {
	Q_OBJECT
public:
	HttpStreamFramer(
		QSslSocket *tls,
		const QString &host,
		const QString &path,
		QObject *parent = nullptr);

	void open() override;
	qint64 sendBinaryMessage(const QByteArray &msg) override;
	QAbstractSocket::SocketState state() const override;

private Q_SLOTS:
	void onReadyRead();
	void onDisconnected();

private:
	void parseResponseHeaders();
	void parsePayloadChunks();

	QSslSocket *_tls;
	QString _host;
	QString _path;
	QByteArray _buffer;
	bool _connected = false;
};

} // namespace Tdesktop::Teleproto3

#endif // CONNECTION_TELEPROTO3_HTTP_H
