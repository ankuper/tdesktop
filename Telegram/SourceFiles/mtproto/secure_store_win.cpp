/*
 * secure_store_win.cpp — Windows Credential Manager backend for secure storage.
 * Story 2.4: Type3 secret persistence via WinAPI CredWrite/CredRead.
 */

#include "mtproto/secure_store.h"

#ifdef Q_OS_WIN

#include <windows.h>
#include <wincred.h>

#include <cstring>

namespace Tdesktop::Teleproto3::SecureStore {

bool isAvailable() {
    // Probe by attempting to read a credential that doesn't exist.
    // ERROR_NOT_FOUND means Credential Manager is available but the entry is absent.
    // Any other error means Credential Manager is unavailable.
    PCREDENTIALW cred = nullptr;
    DWORD err = 0;
    if (!CredReadW(L"teleproto3:probe", CRED_TYPE_GENERIC, 0, &cred)) {
        err = GetLastError();
    } else if (cred) {
        CredFree(cred);
    }
    return (err == ERROR_NOT_FOUND || err == 0);
}

bool store(const QByteArray &key16, const QString &account) {
    if (key16.size() != 16) {
        return false;
    }

    CREDENTIALW cred{};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<LPWSTR>(
        reinterpret_cast<LPCWSTR>(account.utf16()));
    cred.CredentialBlobSize = key16.size();
    cred.CredentialBlob = reinterpret_cast<LPBYTE>(
        const_cast<char*>(key16.constData()));
    // AC #5: no roaming. CRED_PERSIST_ENTERPRISE = per-user, no domain roaming.
    // (CRED_PERSIST_LOCAL_MACHINE requires SeTcbPrivilege; non-elevated processes
    // would fail with ERROR_PRIVILEGE_NOT_HELD. ENTERPRISE satisfies the no-roaming
    // contract for non-roaming-profile users.)
    cred.Persist = CRED_PERSIST_ENTERPRISE;

    BOOL ok = CredWriteW(&cred, 0);
    return (ok != 0);
}

QByteArray load(const QString &account) {
    PCREDENTIALW cred = nullptr;
    if (!CredReadW(reinterpret_cast<LPCWSTR>(account.utf16()),
                   CRED_TYPE_GENERIC, 0, &cred)) {
        return {};
    }

    QByteArray result;
    if (cred && cred->CredentialBlob && cred->CredentialBlobSize == 16) {
        result = QByteArray(
            reinterpret_cast<const char*>(cred->CredentialBlob),
            static_cast<int>(cred->CredentialBlobSize));
    }
    if (cred) {
        CredFree(cred);
    }
    return result;
}

bool wipe(const QString &account) {
    BOOL ok = CredDeleteW(
        reinterpret_cast<LPCWSTR>(account.utf16()),
        CRED_TYPE_GENERIC, 0);
    return (ok != 0);
}

}  // namespace Tdesktop::Teleproto3::SecureStore

#endif  // Q_OS_WIN
// CMake compiles this file ONLY on Windows ($<$<BOOL:${WIN32}>:...>).
// Non-Windows builds never see this TU; no #else stub needed.
