/*
 * secure_store_linux.cpp — Linux libsecret backend for secure storage.
 * Story 2.4: Type3 secret persistence via Secret Service D-Bus API.
 */

#include "mtproto/secure_store.h"

#ifdef Q_OS_LINUX

#include <libsecret/secret.h>
#include <glib.h>

namespace Tdesktop::Teleproto3::SecureStore {

// Static schema for all Type3 secrets (per AC #5: per-user collection).
static const SecretSchema kSchema = {
    "org.teleproto3.tdesktop",
    SECRET_SCHEMA_NONE,
    {
        {"account", SECRET_SCHEMA_ATTRIBUTE_STRING},
        {NULL, (SecretSchemaAttributeType)0}
    }
};

bool isAvailable() {
    // Probe by attempting to get the default collection handle.
    // If Secret Service is not running, this fails.
    GError *err = nullptr;
    SecretService *svc = secret_service_get_sync(
        SECRET_SERVICE_NONE, NULL, &err);
    if (err) {
        g_error_free(err);
        return false;
    }
    if (svc) {
        g_object_unref(svc);
    }
    return true;
}

bool store(const QByteArray &key16, const QString &account) {
    if (key16.size() != 16) {
        return false;
    }

    // libsecret expects a NUL-terminated string, so Base64-encode the 16 raw bytes.
    QByteArray encoded = key16.toBase64();

    GError *err = nullptr;
    gboolean ok = secret_password_store_sync(
        &kSchema,
        SECRET_COLLECTION_DEFAULT,
        "teleproto3 secret",                         // label
        encoded.constData(),                         // password (Base64-encoded key)
        NULL,                                        // cancellable
        &err,
        "account", account.toUtf8().constData(),    // attribute
        NULL);                                       // terminator

    if (err) {
        g_error_free(err);
        return false;
    }
    return (ok != 0);
}

QByteArray load(const QString &account) {
    GError *err = nullptr;
    gchar *password = secret_password_lookup_sync(
        &kSchema,
        NULL,                                        // cancellable
        &err,
        "account", account.toUtf8().constData(),    // attribute
        NULL);                                       // terminator

    if (err) {
        g_error_free(err);
        return {};
    }
    if (!password) {
        return {};
    }

    // Decode from Base64 back to raw 16 bytes.
    // AbortOnBase64DecodingErrors prevents lenient mode from yielding a
    // deterministic all-zero key on a corrupted entry (P11 / story 2.4 review).
    QByteArray encoded(password);
    auto decoded = QByteArray::fromBase64Encoding(
        encoded,
        QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    secret_password_free(password);

    if (!decoded || decoded.decoded.size() != 16) {
        return {};  // Corrupted, wrong length, or invalid Base64
    }
    return decoded.decoded;
}

bool wipe(const QString &account) {
    GError *err = nullptr;
    gboolean ok = secret_password_clear_sync(
        &kSchema,
        NULL,                                        // cancellable
        &err,
        "account", account.toUtf8().constData(),    // attribute
        NULL);                                       // terminator

    if (err) {
        g_error_free(err);
        return false;
    }
    // P17: post-condition "key absent" holds whether or not an entry existed;
    // returning ok==FALSE on missing-entry would be inconsistent with macOS
    // (which treats errSecItemNotFound as success). Treat both as success.
    (void)ok;
    return true;
}

}  // namespace Tdesktop::Teleproto3::SecureStore

#endif  // Q_OS_LINUX
// CMake compiles this file ONLY on Linux ($<$<BOOL:${LINUX}>:...>).
// Non-Linux builds never see this TU; no #else stub needed.
