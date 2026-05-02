/*
 * secure_store_mac.mm — macOS Keychain backend for secure storage.
 * Story 2.4: Type3 secret persistence via Security.framework SecItem API.
 */

#include "mtproto/secure_store.h"

#ifdef Q_OS_MAC

#import <Security/Security.h>

namespace Tdesktop::Teleproto3::SecureStore {

bool isAvailable() {
    // Probe by attempting a simple Keychain read. If the API is available,
    // SecItemCopyMatching will return errSecItemNotFound for a nonexistent entry.
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"org.teleproto3.tdesktop",
        (__bridge id)kSecAttrAccount: @"probe",
    };
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
    // errSecItemNotFound (item doesn't exist) means Keychain is available.
    // Success also means it's available. Any other error means unavailable.
    return (status == errSecSuccess || status == errSecItemNotFound);
}

bool store(const QByteArray &key16, const QString &account) {
    if (key16.size() != 16) {
        return false;
    }

    // Delete any existing entry first (avoid duplicates).
    NSDictionary *delQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"org.teleproto3.tdesktop",
        (__bridge id)kSecAttrAccount: account.toNSString(),
    };
    SecItemDelete((__bridge CFDictionaryRef)delQuery);

    // Add new entry with ACL per AC #5.
    NSDictionary *attrs = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"org.teleproto3.tdesktop",
        (__bridge id)kSecAttrAccount: account.toNSString(),
        (__bridge id)kSecValueData: [NSData dataWithBytes:key16.constData()
                                                   length:key16.size()],
        (__bridge id)kSecAttrAccessible:
            (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
    return (status == errSecSuccess);
}

QByteArray load(const QString &account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"org.teleproto3.tdesktop",
        (__bridge id)kSecAttrAccount: account.toNSString(),
        (__bridge id)kSecReturnData: @YES,
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) {
        return {};
    }

    NSData *data = (__bridge NSData *)result;
    QByteArray key(reinterpret_cast<const char*>(data.bytes), data.length);
    CFRelease(result);
    return key;
}

bool wipe(const QString &account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"org.teleproto3.tdesktop",
        (__bridge id)kSecAttrAccount: account.toNSString(),
    };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    // errSecItemNotFound is OK (already deleted).
    return (status == errSecSuccess || status == errSecItemNotFound);
}

}  // namespace Tdesktop::Teleproto3::SecureStore

#endif  // Q_OS_MAC
// CMake compiles this file ONLY on Apple ($<$<BOOL:${APPLE}>:...>).
// Non-Apple builds never see this TU; no #else stub needed.
