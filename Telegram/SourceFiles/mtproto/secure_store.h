/*
 * secure_store.h — OS-native secure storage bridge for Type3 secrets (Story 2.4).
 *
 * Wires to: Win Credential Manager / macOS Keychain / Linux libsecret.
 * Platform guards in secure_store_{win.cpp,mac.mm,linux.cpp} ensure one impl per platform.
 * Anti-pattern §12.3: no plaintext fallback; refuse-to-start if unavailable.
 */

#ifndef SECURE_STORE_H
#define SECURE_STORE_H

#include <QByteArray>
#include <QString>

namespace Tdesktop::Teleproto3::SecureStore {

// Returns true if the OS-native secure storage is available (Keychain / Credential Manager / libsecret).
// Per epic-2-style-guide §7: MUST be called before any UI is shown.
// If false, the client MUST refuse to start (NFR13, NFR20, anti-pattern §12.3).
bool isAvailable();

// Store key16 (16 raw bytes) under account name in OS-native secure storage.
// Returns true on success; false if unavailable or write fails.
// Windows: CRED_PERSIST_LOCAL_MACHINE (no roaming).
// macOS: kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
// Linux: per-user collection with SECRET_SCHEMA_NONE.
bool store(const QByteArray &key16, const QString &account);

// Load key16 bytes from OS-native secure storage under account name.
// Returns 16-byte array on success; empty array on failure or not found.
QByteArray load(const QString &account);

// Remove the entry for account from OS-native secure storage.
// Returns true on success; false on failure or if entry does not exist.
bool wipe(const QString &account);

}  // namespace Tdesktop::Teleproto3::SecureStore

#endif  // SECURE_STORE_H
