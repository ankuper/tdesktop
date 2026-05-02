/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtNetwork/QNetworkProxy>

namespace MTP {

struct ProxyData {
	enum class Settings {
		System,
		Enabled,
		Disabled,
	};
	enum class Type {
		None,
		Socks5,
		Http,
		Mtproto,
		Mtproto3,
	};
	enum class Status {
		Valid,
		Unsupported,
		IncorrectSecret,
		Invalid,
	};

	Type type = Type::None;
	QString host;
	uint32 port = 0;
	QString user, password;
	QString wsPath;

	std::vector<QString> resolvedIPs;
	crl::time resolvedExpireAt = 0;

	[[nodiscard]] bool valid() const;
	[[nodiscard]] Status status() const;
	[[nodiscard]] bool supportsCalls() const;
	[[nodiscard]] bool tryCustomResolve() const;
	[[nodiscard]] bytes::vector secretFromMtprotoPassword() const;

	// Type3-specific helpers (AC-1, AC-2; story 2-2)
	// Returns the 17-byte 0xff + 16-key prefix; empty on parse failure.
	[[nodiscard]] bytes::vector secretFromType3Password() const;
	// Returns only the 16 raw key octets; empty on parse failure or non-Mtproto3 type.
	[[nodiscard]] bytes::vector type3KeyOctets() const;
	// Constant-time comparison of the 16 raw key octets via CRYPTO_memcmp.
	// Both records must be Type::Mtproto3 and parse successfully; returns false otherwise.
	[[nodiscard]] bool sameType3Key(const ProxyData &other) const;

	[[nodiscard]] explicit operator bool() const;
	[[nodiscard]] bool operator==(const ProxyData &other) const;
	[[nodiscard]] bool operator!=(const ProxyData &other) const;

	[[nodiscard]] static bool ValidMtprotoPassword(const QString &password);
	[[nodiscard]] static Status MtprotoPasswordStatus(
		const QString &password);

};

[[nodiscard]] ProxyData ToDirectIpProxy(
	const ProxyData &proxy,
	int ipIndex = 0);
[[nodiscard]] QNetworkProxy ToNetworkProxy(const ProxyData &proxy);

// EXTEND from story 2.4 — write-authority owned by story 2.2 (mtproto_proxy_data).
// At app startup (before any UI), call IsType3SecureStorageReady().
// If returns false, the client MUST refuse to start (NFR13, NFR20, anti-pattern §12.3).
// Per epic-2-style-guide §7: OS-native secure storage (Keychain / Credential Manager / libsecret).
[[nodiscard]] bool IsType3SecureStorageReady();

// Store a Type3 secret key in platform-specific secure storage.
// account param should be unique per proxy (e.g., proxy host:port hash).
// Returns true on success; false if unavailable or storage fails.
bool StoreType3SecretKey(const ProxyData &proxy, const QString &account);

// Load a Type3 secret key from platform-specific secure storage.
// Returns 16-byte raw key on success; empty on failure / not found.
[[nodiscard]] bytes::vector LoadType3SecretKey(const QString &account);

} // namespace MTP
