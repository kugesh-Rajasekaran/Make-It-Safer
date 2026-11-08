//go:build darwin

package keyring

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// SecKeychainOpen is deprecated, but a SecKeychainRef is the only way to name
// a keychain for kSecUseKeychain and kSecMatchSearchList.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// openLogin opens your login keychain by its path. Every operation is pinned
// to it: SecItemAdd would otherwise write to the *default* keychain, which any
// program running as you can switch to one whose password it knows.
static OSStatus openLogin(SecKeychainRef *kc) {
	struct passwd pw, *found = NULL;
	char buf[4096], path[PATH_MAX];
	if (getpwuid_r(getuid(), &pw, buf, sizeof buf, &found) != 0 || found == NULL) {
		return errSecNoSuchKeychain;
	}
	if (snprintf(path, sizeof path, "%s/Library/Keychains/login.keychain-db", pw.pw_dir) >= (int)sizeof path) {
		return errSecNoSuchKeychain;
	}
	return SecKeychainOpen(path, kc);
}

// query matches one generic password by service and account, in kc only.
static CFMutableDictionaryRef query(SecKeychainRef kc, const char *service, const char *account) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef s = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
	CFStringRef a = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
	CFArrayRef list = CFArrayCreate(NULL, (const void **)&kc, 1, &kCFTypeArrayCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, s);
	CFDictionarySetValue(q, kSecAttrAccount, a);
	CFDictionarySetValue(q, kSecMatchSearchList, list);
	CFRelease(list);
	CFRelease(s);
	CFRelease(a);
	return q;
}

// set replaces the item in the login keychain. The new item trusts only the
// calling program.
static OSStatus set(const char *service, const char *account, const UInt8 *data, CFIndex len) {
	SecKeychainRef kc = NULL;
	OSStatus st = openLogin(&kc);
	if (st != errSecSuccess) {
		return st;
	}
	CFMutableDictionaryRef q = query(kc, service, account);
	SecItemDelete(q);
	CFDictionaryRemoveValue(q, kSecMatchSearchList);
	CFDataRef value = CFDataCreateWithBytesNoCopy(NULL, data, len, kCFAllocatorNull);
	CFStringRef label = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
	CFDictionarySetValue(q, kSecUseKeychain, kc);
	CFDictionarySetValue(q, kSecAttrLabel, label);
	CFDictionarySetValue(q, kSecValueData, value);
	st = SecItemAdd(q, NULL);
	CFRelease(label);
	CFRelease(value);
	CFRelease(q);
	CFRelease(kc);
	return st;
}

// get copies the item's secret into out (cap bytes) and its length into n.
static OSStatus get(const char *service, const char *account, UInt8 *out, CFIndex cap, CFIndex *n) {
	SecKeychainRef kc = NULL;
	OSStatus st = openLogin(&kc);
	if (st != errSecSuccess) {
		return st;
	}
	CFMutableDictionaryRef q = query(kc, service, account);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef r = NULL;
	st = SecItemCopyMatching(q, &r);
	CFRelease(q);
	CFRelease(kc);
	if (st != errSecSuccess) {
		return st;
	}
	*n = CFDataGetLength((CFDataRef)r);
	if (*n <= cap) {
		memcpy(out, CFDataGetBytePtr((CFDataRef)r), *n);
	}
	CFRelease(r);
	return errSecSuccess;
}

static OSStatus del(const char *service, const char *account) {
	SecKeychainRef kc = NULL;
	OSStatus st = openLogin(&kc);
	if (st != errSecSuccess) {
		return st;
	}
	CFMutableDictionaryRef q = query(kc, service, account);
	st = SecItemDelete(q);
	CFRelease(q);
	CFRelease(kc);
	return st;
}

// message returns macOS's text for a status code; the caller frees it.
static char *message(OSStatus st) {
	CFStringRef s = SecCopyErrorMessageString(st, NULL);
	if (s == NULL) {
		return NULL;
	}
	CFIndex size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *buf = malloc(size);
	if (buf != NULL && !CFStringGetCString(s, buf, size, kCFStringEncodingUTF8)) {
		buf[0] = 0;
	}
	CFRelease(s);
	return buf;
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// maxSecret bounds what Get reads back; the unlock key is 32 bytes.
const maxSecret = 64

// Available reports whether this computer has a supported secret store.
func Available() bool { return true }

// Set stores secret, replacing any earlier value. macOS lets only this
// program read it back without asking you.
func (i Item) Set(secret []byte) error {
	if len(secret) == 0 || len(secret) > maxSecret {
		return apperr.New(apperr.KeyringFailed, fmt.Sprintf("a secret must be 1 to %d bytes", maxSecret))
	}
	service, account := C.CString(i.Service), C.CString(i.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	data := C.CBytes(secret) // C memory, so macOS never holds a Go pointer
	defer C.free(data)
	defer C.memset(data, 0, C.size_t(len(secret)))
	return check(C.set(service, account, (*C.UInt8)(data), C.CFIndex(len(secret))), "save the unlock key in your Keychain")
}

// Get returns the secret.
//
// macOS trusts only the exact build of mis that saved the item; mis is
// ad-hoc signed, so every update is a new build. After an update macOS asks
// you to allow access, and "Always Allow" doesn't last for ad-hoc builds.
// So Get saves the item again, which makes this build its owner: macOS asks
// once per update, then never again.
func (i Item) Get() ([]byte, error) {
	secret, err := i.read()
	if err != nil {
		return nil, err
	}
	// Best effort: the read worked. If saving fails, macOS asks again next
	// time, or (if it failed after removing the old item) the next start
	// stays locked and mis doctor says to turn auto-unlock on again.
	_ = i.Set(secret)
	return secret, nil
}

func (i Item) read() ([]byte, error) {
	service, account := C.CString(i.Service), C.CString(i.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	buf := C.malloc(maxSecret)
	defer C.free(buf)
	defer C.memset(buf, 0, maxSecret)
	var n C.CFIndex
	if err := check(C.get(service, account, (*C.UInt8)(buf), maxSecret, &n), "read the unlock key from your Keychain"); err != nil {
		return nil, err
	}
	if n < 1 || n > maxSecret {
		return nil, apperr.New(apperr.KeyringFailed, "the unlock key in your Keychain has the wrong size")
	}
	return C.GoBytes(buf, C.int(n)), nil
}

// Delete removes the item. A missing item is not an error.
func (i Item) Delete() error {
	service, account := C.CString(i.Service), C.CString(i.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	err := check(C.del(service, account), "remove the unlock key from your Keychain")
	if apperr.Is(err, apperr.KeyringItemMissing) {
		return nil
	}
	return err
}

// check turns a Security framework status into an apperr.
func check(st C.OSStatus, doing string) error {
	switch st {
	case C.errSecSuccess:
		return nil
	case C.errSecItemNotFound:
		return apperr.New(apperr.KeyringItemMissing, "the unlock key isn't in your Keychain; turn auto-unlock on again: mis auto-unlock on")
	case C.errSecUserCanceled, C.errSecAuthFailed:
		return apperr.New(apperr.KeyringFailed, "cannot "+doing+": access was denied")
	case C.errSecInteractionNotAllowed:
		return apperr.New(apperr.KeyringFailed, "cannot "+doing+": the Keychain is locked")
	}
	text := ""
	if m := C.message(st); m != nil {
		text = ": " + C.GoString(m)
		C.free(unsafe.Pointer(m))
	}
	return apperr.New(apperr.KeyringFailed, fmt.Sprintf("cannot %s (macOS error %d%s)", doing, int(st), text))
}
