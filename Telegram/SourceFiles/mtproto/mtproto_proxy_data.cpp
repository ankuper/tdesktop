/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/mtproto_proxy_data.h"

#include "mtproto/teleproto3_bridge.h"

#include "base/qthelp_url.h"
#include "base/qt/qt_string_view.h"

#include <openssl/crypto.h>

namespace MTP {
namespace {

[[nodiscard]] bool IsHexMtprotoPassword(const QString &password) {
	const auto size = password.size();
	if (size < 32 || size % 2 == 1) {
		return false;
	}
	const auto bad = [](QChar ch) {
		const auto code = ch.unicode();
		return (code < 'a' || code > 'f')
			&& (code < 'A' || code > 'F')
			&& (code < '0' || code > '9');
	};
	const auto i = std::find_if(password.begin(), password.end(), bad);
	return (i == password.end());
}

[[nodiscard]] ProxyData::Status HexMtprotoPasswordStatus(
		const QString &password) {
	const auto size = password.size() / 2;
	const auto type1 = password[0].toLower();
	const auto type2 = password[1].toLower();
	const auto valid = (size == 16)
		|| (size == 17 && (type1 == 'd') && (type2 == 'd'))
		|| (size >= 21 && (type1 == 'e') && (type2 == 'e'));
	if (valid) {
		return ProxyData::Status::Valid;
	} else if (size < 16) {
		return ProxyData::Status::Invalid;
	}
	return ProxyData::Status::Unsupported;
}

[[nodiscard]] bytes::vector SecretFromHexMtprotoPassword(
		const QString &password) {
	Expects(password.size() % 2 == 0);

	const auto size = password.size() / 2;
	const auto fromHex = [](QChar ch) -> int {
		const auto code = int(ch.unicode());
		if (code >= '0' && code <= '9') {
			return (code - '0');
		} else if (code >= 'A' && code <= 'F') {
			return 10 + (code - 'A');
		} else if (ch >= 'a' && ch <= 'f') {
			return 10 + (code - 'a');
		}
		Unexpected("Code in ProxyData fromHex.");
	};
	auto result = bytes::vector(size);
	for (auto i = 0; i != size; ++i) {
		const auto high = fromHex(password[2 * i]);
		const auto low = fromHex(password[2 * i + 1]);
		if (high < 0 || low < 0) {
			return {};
		}
		result[i] = static_cast<bytes::type>(high * 16 + low);
	}
	return result;
}

[[nodiscard]] QStringView Base64UrlInner(const QString &password) {
	Expects(password.size() > 2);

	// Skip one or two '=' at the end of the string.
	return base::StringViewMid(password, 0, [&] {
		auto result = password.size();
		for (auto i = 0; i != 2; ++i) {
			const auto prev = result - 1;
			if (password[prev] != '=') {
				break;
			}
			result = prev;
		}
		return result;
	}());
}

[[nodiscard]] bool IsBase64UrlMtprotoPassword(const QString &password) {
	const auto size = password.size();
	if (size < 22 || size % 4 == 1) {
		return false;
	}
	const auto bad = [](QChar ch) {
		const auto code = ch.unicode();
		return (code < 'a' || code > 'z')
			&& (code < 'A' || code > 'Z')
			&& (code < '0' || code > '9')
			&& (code != '_')
			&& (code != '-');
	};
	const auto inner = Base64UrlInner(password);
	const auto begin = inner.data();
	const auto end = begin + inner.size();
	return (std::find_if(begin, end, bad) == end);
}

[[nodiscard]] ProxyData::Status Base64UrlMtprotoPasswordStatus(
		const QString &password) {
	// IncorrectSecret
	const auto inner = Base64UrlInner(password);
	const auto size = (inner.size() * 3) / 4;
	const auto valid = (size == 16)
		|| (size == 17
			&& (password[0] == '3')
			&& ((password[1] >= 'Q' && password[1] <= 'Z')
				|| (password[1] >= 'a' && password[1] <= 'f')))
		|| (size >= 21
			&& (password[0] == '7')
			&& (password[1] >= 'g')
			&& (password[1] <= 'v'));
	const auto incorrect = (size >= 21
		&& password[0].toLower() == 'e'
		&& password[1].toLower() == 'e');
	if (size < 16) {
		return ProxyData::Status::Invalid;
	} else if (valid) {
		return ProxyData::Status::Valid;
	} else if (incorrect) {
		return ProxyData::Status::IncorrectSecret;
	}
	return ProxyData::Status::Unsupported;
}

[[nodiscard]] bytes::vector SecretFromBase64UrlMtprotoPassword(
		const QString &password) {
	const auto result = QByteArray::fromBase64(
		password.toLatin1(),
		QByteArray::Base64UrlEncoding);
	return bytes::make_vector(bytes::make_span(result));
}

// Decodes hex or base64url-encoded password string to raw bytes.
// Returns empty vector on failure.
[[nodiscard]] bytes::vector DecodeProxyPassword(const QString &password) {
	if (IsHexMtprotoPassword(password)) {
		return SecretFromHexMtprotoPassword(password);
	} else if (IsBase64UrlMtprotoPassword(password)) {
		return SecretFromBase64UrlMtprotoPassword(password);
	}
	return {};
}

} // namespace

bool ProxyData::valid() const {
	return status() == Status::Valid;
}

ProxyData::Status ProxyData::status() const {
	if (type == Type::None || host.isEmpty() || !port) {
		return Status::Invalid;
	} else if (type == Type::Mtproto) {
		return MtprotoPasswordStatus(password);
	} else if (type == Type::Mtproto3) {
		const auto raw = DecodeProxyPassword(password);
		if (raw.size() < 18
			|| static_cast<uint8_t>(raw[0]) != 0xff) {
			return Status::IncorrectSecret;
		}
		t3_secret_t *rawSecret = nullptr;
		const auto rc = t3_secret_parse(
			reinterpret_cast<const uint8_t *>(raw.data()),
			raw.size(),
			&rawSecret);
		const Tdesktop::Teleproto3::SecretGuard guard(rawSecret);
		switch (rc) {
		case T3_OK:
			break;
		case T3_ERR_MALFORMED:
		case T3_ERR_UNSUPPORTED_VERSION:
			return Status::IncorrectSecret;
		case T3_ERR_INVALID_ARG:
			return Status::Invalid;
		default:
			return Status::IncorrectSecret;
		}
		return Status::Valid;
	}
	return Status::Valid;
}

bool ProxyData::supportsCalls() const {
#if TDESKTOP_TYPE3_CALLS
	// P9: every field must be present before this returns true — caller in
	// calls_call.cpp will otherwise attempt ShimOpen with empty host/wsPath
	// and we'd take the D5 abort path even though the proxy is "selected".
	return type == Type::Mtproto3
		&& !host.isEmpty()
		&& port > 0
		&& !password.isEmpty();
#else
	return false;
#endif
}

bool ProxyData::tryCustomResolve() const {
	static const auto RegExp = QRegularExpression(
		QStringLiteral("^\\d+\\.\\d+\\.\\d+\\.\\d+$")
	);
	return (type == Type::Socks5
		|| type == Type::Mtproto
		|| type == Type::Mtproto3)
		&& !qthelp::is_ipv6(host)
		&& !RegExp.match(host).hasMatch();
}

bytes::vector ProxyData::secretFromMtprotoPassword() const {
	Expects(type == Type::Mtproto);

	if (IsHexMtprotoPassword(password)) {
		return SecretFromHexMtprotoPassword(password);
	} else if (IsBase64UrlMtprotoPassword(password)) {
		return SecretFromBase64UrlMtprotoPassword(password);
	}
	return {};
}

bytes::vector ProxyData::secretFromType3Password() const {
	Expects(type == Type::Mtproto3);

	const auto raw = DecodeProxyPassword(password);
	// Minimum: 0xff marker + 16 key bytes + 1 domain byte = 18
	if (raw.size() < 18 || static_cast<uint8_t>(raw[0]) != 0xff) {
		return {};
	}
	t3_secret_t *rawSecret = nullptr;
	const auto rc = t3_secret_parse(
		reinterpret_cast<const uint8_t *>(raw.data()),
		raw.size(),
		&rawSecret);
	const Tdesktop::Teleproto3::SecretGuard guard(rawSecret);
	if (rc != T3_OK) {
		return {};
	}
	// Return 0xff marker + 16 key octets (17 bytes total)
	return bytes::vector(raw.begin(), raw.begin() + 17);
}

bytes::vector ProxyData::type3KeyOctets() const {
	if (type != Type::Mtproto3) {
		return {};
	}
	const auto raw = DecodeProxyPassword(password);
	if (raw.size() < 18 || static_cast<uint8_t>(raw[0]) != 0xff) {
		return {};
	}
	t3_secret_t *rawSecret = nullptr;
	const auto rc = t3_secret_parse(
		reinterpret_cast<const uint8_t *>(raw.data()),
		raw.size(),
		&rawSecret);
	const Tdesktop::Teleproto3::SecretGuard guard(rawSecret);
	if (rc != T3_OK) {
		return {};
	}
	// Return ONLY the 16 raw key octets (bytes [1..16])
	return bytes::vector(raw.begin() + 1, raw.begin() + 17);
}

bool ProxyData::sameType3Key(const ProxyData &other) const {
	if (type != Type::Mtproto3 || other.type != Type::Mtproto3) {
		return false;
	}
	auto myKey = type3KeyOctets();
	auto otherKey = other.type3KeyOctets();
	if (myKey.size() != 16 || otherKey.size() != 16) {
		return false;
	}
	const auto equal = (CRYPTO_memcmp(
		myKey.data(),
		otherKey.data(),
		16) == 0);
	OPENSSL_cleanse(myKey.data(), 16);
	OPENSSL_cleanse(otherKey.data(), 16);
	return equal;
}

ProxyData::operator bool() const {
	return valid();
}

bool ProxyData::operator==(const ProxyData &other) const {
	if (!valid()) {
		return !other.valid();
	}
	return (type == other.type)
		&& (host == other.host)
		&& (port == other.port)
		&& (user == other.user)
		&& (password == other.password)
		&& (wsPath == other.wsPath);
}

bool ProxyData::operator!=(const ProxyData &other) const {
	return !(*this == other);
}

bool ProxyData::ValidMtprotoPassword(const QString &password) {
	return MtprotoPasswordStatus(password) == Status::Valid;
}

ProxyData::Status ProxyData::MtprotoPasswordStatus(const QString &password) {
	if (IsHexMtprotoPassword(password)) {
		return HexMtprotoPasswordStatus(password);
	} else if (IsBase64UrlMtprotoPassword(password)) {
		return Base64UrlMtprotoPasswordStatus(password);
	}
	return Status::Invalid;
}

ProxyData ToDirectIpProxy(const ProxyData &proxy, int ipIndex) {
	if (!proxy.tryCustomResolve()
		|| ipIndex < 0
		|| ipIndex >= proxy.resolvedIPs.size()) {
		return proxy;
	}
	return {
		proxy.type,
		proxy.resolvedIPs[ipIndex],
		proxy.port,
		proxy.user,
		proxy.password,
		proxy.wsPath
	};
}

QNetworkProxy ToNetworkProxy(const ProxyData &proxy) {
	if (proxy.type == ProxyData::Type::None) {
		return QNetworkProxy::DefaultProxy;
	} else if (proxy.type == ProxyData::Type::Mtproto
		|| proxy.type == ProxyData::Type::Mtproto3) {
		return QNetworkProxy::NoProxy;
	}
	return QNetworkProxy(
		(proxy.type == ProxyData::Type::Socks5
			? QNetworkProxy::Socks5Proxy
			: QNetworkProxy::HttpProxy),
		proxy.host,
		proxy.port,
		proxy.user,
		proxy.password);
}

// EXTEND from story 2.4 — write-authority owned by story 2.2.
// At app startup (before any UI), call IsType3SecureStorageReady().
// If false, the client MUST refuse to start, surface lng_t3_secure_storage_unavailable,
// and exit cleanly (NFR13, NFR20, anti-pattern §12.3, epic-2-style-guide §7).
//
// CALL-SITE WIRING: forward-citation to story 2.9 (macOS dev-build startup).
// Story 2.9 is responsible for adding the early-init hook that calls
// IsType3SecureStorageReady() before Application::run() instantiates any UI.
// The hook should: (a) call this function, (b) on false, log via Logs::Main()
// then return EXIT_FAILURE, (c) on true, proceed normally. No retry loop.
// (Story 2.9 spec must include this gate; tracked in 2-9-macos-release follow-up.)
bool IsType3SecureStorageReady() {
	return Tdesktop::Teleproto3::SecureStore::isAvailable();
}

bool StoreType3SecretKey(const ProxyData &proxy, const QString &account) {
	if (proxy.type != ProxyData::Type::Mtproto3) {
		return false;
	}
	const auto key = proxy.type3KeyOctets();
	if (key.size() != 16) {
		return false;
	}
	const auto qkey = QByteArray(
		reinterpret_cast<const char*>(key.data()),
		static_cast<int>(key.size()));
	return Tdesktop::Teleproto3::SecureStore::store(qkey, account);
}

bytes::vector LoadType3SecretKey(const QString &account) {
	const auto qkey = Tdesktop::Teleproto3::SecureStore::load(account);
	return bytes::make_vector(bytes::make_span(qkey));
}

} // namespace MTP
