package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
)

// memStore stands in for the macOS Keychain.
type memStore struct {
	secret []byte
	setErr error
}

func (m *memStore) Get() ([]byte, error) {
	if m.secret == nil {
		return nil, apperr.New(apperr.KeyringItemMissing, "no item")
	}
	return bytes.Clone(m.secret), nil
}

func (m *memStore) Set(s []byte) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.secret = bytes.Clone(s)
	return nil
}

func (m *memStore) Delete() error { m.secret = nil; return nil }

// enableAuto creates a key and turns auto-unlock on for it.
func enableAuto(t *testing.T) (keyPath, autoPath string, store *memStore) {
	t.Helper()
	dir, _ := createKey(t)
	keyPath, autoPath, store = filepath.Join(dir, "key.enc"), filepath.Join(dir, "key.auto"), &memStore{}
	key, err := Unlock(keyPath, secret.Bytes(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if err := EnableAutoUnlock(autoPath, key, store); err != nil {
		t.Fatal(err)
	}
	return keyPath, autoPath, store
}

// Turning auto-unlock on again replaces the unlock key first. If key.auto
// can't be written afterwards, auto-unlock must end up off, not half on.
func TestEnableAutoUnlockWriteFailure(t *testing.T) {
	keyPath, autoPath, store := enableAuto(t)
	// A directory where key.auto goes makes the write fail.
	if err := os.Remove(autoPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(autoPath, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := Unlock(keyPath, secret.Bytes(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if err := EnableAutoUnlock(autoPath, key, store); err == nil {
		t.Fatal("EnableAutoUnlock succeeded although key.auto can't be written")
	}
	if AutoUnlockEnabled(autoPath) || store.secret != nil {
		t.Fatalf("after a failed write: enabled = %v, unlock key stored = %v; want both off", AutoUnlockEnabled(autoPath), store.secret != nil)
	}
}

func TestAutoUnlockRoundTrip(t *testing.T) {
	keyPath, autoPath, store := enableAuto(t)
	if !AutoUnlockEnabled(autoPath) || len(store.secret) != 32 {
		t.Fatalf("enabled = %v, unlock key %d bytes; want on and 32 bytes", AutoUnlockEnabled(autoPath), len(store.secret))
	}
	if info, err := os.Stat(autoPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key.auto mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	data, _ := os.ReadFile(autoPath)
	if bytes.Contains(data, store.secret) {
		t.Fatal("key.auto contains the unlock key")
	}

	key, err := AutoUnlock(keyPath, autoPath, store)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	want, _ := PublicKeyFromFile(keyPath)
	if AuthorizedKey(key.PublicKey()) != AuthorizedKey(want) {
		t.Fatal("auto-unlock opened a different key")
	}
	if _, err := key.Signer().Sign(nil, []byte("x")); err != nil {
		t.Fatalf("the key can't sign: %v", err)
	}
}

func TestAutoUnlockRejects(t *testing.T) {
	cases := map[string]struct {
		code   string
		mutate func(t *testing.T, keyPath, autoPath string, store *memStore)
	}{
		"off": {apperr.VaultAutoUnlockOff, func(t *testing.T, _, autoPath string, _ *memStore) {
			if err := os.Remove(autoPath); err != nil {
				t.Fatal(err)
			}
		}},
		"unlock key missing": {apperr.KeyringItemMissing, func(_ *testing.T, _, _ string, store *memStore) {
			store.secret = nil
		}},
		"other unlock key": {apperr.VaultAutoUnlockFailed, func(_ *testing.T, _, _ string, store *memStore) {
			store.secret = bytes.Repeat([]byte{7}, 32)
		}},
		"unlock key of the wrong size": {apperr.VaultAutoUnlockFailed, func(_ *testing.T, _, _ string, store *memStore) {
			store.secret = []byte("short")
		}},
		"tampered ciphertext": {apperr.VaultAutoUnlockFailed, func(t *testing.T, _, autoPath string, _ *memStore) {
			editAuto(t, autoPath, func(f *autoFile) { f.Ciphertext[0] ^= 1 })
		}},
		"tampered header": {apperr.VaultAutoUnlockFailed, func(t *testing.T, _, autoPath string, _ *memStore) {
			editAuto(t, autoPath, func(f *autoFile) { f.Header.Nonce[0] ^= 1 })
		}},
		"key.auto of an older key": {apperr.VaultAutoUnlockFailed, func(t *testing.T, keyPath, _ string, _ *memStore) {
			if err := os.Remove(keyPath); err != nil {
				t.Fatal(err)
			}
			if _, err := Create(keyPath, filepath.Join(filepath.Dir(keyPath), "key.pub"), secret.Bytes(testPassphrase), testParams); err != nil {
				t.Fatal(err)
			}
		}},
		"unknown format": {apperr.VaultKeyFileInvalid, func(t *testing.T, _, autoPath string, _ *memStore) {
			editAuto(t, autoPath, func(f *autoFile) { f.Header.Format = "mis-auto-v9" })
		}},
		"readable by others": {apperr.ConfigPermissionsTooOpen, func(t *testing.T, _, autoPath string, _ *memStore) {
			if err := os.Chmod(autoPath, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			keyPath, autoPath, store := enableAuto(t)
			tc.mutate(t, keyPath, autoPath, store)
			key, err := AutoUnlock(keyPath, autoPath, store)
			if err == nil {
				key.Destroy()
			}
			if !apperr.Is(err, tc.code) {
				t.Fatalf("got %v, want %s", err, tc.code)
			}
		})
	}
}

func TestEnableAutoUnlockLeavesNothingWhenTheStoreFails(t *testing.T) {
	dir, _ := createKey(t)
	autoPath := filepath.Join(dir, "key.auto")
	key, err := Unlock(filepath.Join(dir, "key.enc"), secret.Bytes(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	store := &memStore{setErr: apperr.New(apperr.KeyringFailed, "denied")}
	if err := EnableAutoUnlock(autoPath, key, store); !apperr.Is(err, apperr.KeyringFailed) {
		t.Fatalf("got %v, want KEYRING_FAILED", err)
	}
	if AutoUnlockEnabled(autoPath) {
		t.Fatal("key.auto was written although the Keychain refused the unlock key")
	}
}

func TestDisableAutoUnlock(t *testing.T) {
	_, autoPath, store := enableAuto(t)
	for range 2 { // turning it off twice is fine
		if err := DisableAutoUnlock(autoPath, store); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(autoPath); !errors.Is(err, os.ErrNotExist) || store.secret != nil {
		t.Fatalf("key.auto: %v, unlock key: %x; want both gone", err, store.secret)
	}
}

func TestEnableAutoUnlockNeedsAnUnlockedKey(t *testing.T) {
	dir, _ := createKey(t)
	key, err := Unlock(filepath.Join(dir, "key.enc"), secret.Bytes(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	if err := EnableAutoUnlock(filepath.Join(dir, "key.auto"), key, &memStore{}); !apperr.Is(err, apperr.VaultLocked) {
		t.Fatalf("got %v, want VAULT_LOCKED", err)
	}
}

func editAuto(t *testing.T, autoPath string, edit func(*autoFile)) {
	t.Helper()
	data, err := os.ReadFile(autoPath)
	if err != nil {
		t.Fatal(err)
	}
	var f autoFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	edit(&f)
	if data, err = json.Marshal(f); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(autoPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
