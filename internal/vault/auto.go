package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Auto-unlock (docs/design.md §4.2, ADR 0002): key.auto holds the private
// key encrypted with a random 256-bit unlock key, and the OS secret store
// (the macOS login Keychain) holds that unlock key. Either the passphrase
// (key.enc) or the unlock key (key.auto) opens the same key; the passphrase
// itself is never stored.

// SecretStore keeps the unlock key. keyring.Item is the real one.
type SecretStore interface {
	Get() ([]byte, error)
	Set(secret []byte) error
	Delete() error
}

const autoFormat = "mis-auto-v1"

// autoFile is the JSON layout of key.auto. The header is authenticated.
type autoFile struct {
	Header     autoHeader `json:"header"`
	Ciphertext []byte     `json:"ciphertext"`
}

type autoHeader struct {
	Format    string `json:"format"`
	Cipher    string `json:"cipher"`
	Nonce     []byte `json:"nonce"`
	PublicKey string `json:"public_key"` // must match key.enc's
}

// AutoUnlockEnabled reports whether auto-unlock is on (key.auto exists).
func AutoUnlockEnabled(autoPath string) bool {
	_, err := os.Stat(autoPath)
	return err == nil
}

// EnableAutoUnlock lets key be opened without the passphrase: it saves a new
// unlock key in store and key.auto at autoPath. It replaces an earlier setup.
func EnableAutoUnlock(autoPath string, key *Key, store SecretStore) error {
	seed, err := key.seed()
	if err != nil {
		return err
	}
	defer clear(seed)
	unlockKey := make([]byte, chacha20poly1305.KeySize)
	defer clear(unlockKey)
	h := autoHeader{Format: autoFormat, Cipher: cipherName, Nonce: make([]byte, chacha20poly1305.NonceSizeX), PublicKey: AuthorizedKey(key.PublicKey())}
	if _, err := rand.Read(unlockKey); err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot read random bytes")
	}
	if _, err := rand.Read(h.Nonce); err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot read random bytes")
	}
	aead, err := chacha20poly1305.NewX(unlockKey)
	if err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot set up encryption")
	}
	aad, err := json.Marshal(h)
	if err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot encode the key header")
	}
	data, err := json.MarshalIndent(autoFile{Header: h, Ciphertext: aead.Seal(nil, h.Nonce, seed, aad)}, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot encode key.auto")
	}
	if err := store.Set(unlockKey); err != nil {
		return err
	}
	if err := config.WriteFileAtomic(autoPath, append(data, '\n')); err != nil {
		_ = store.Delete()
		return err
	}
	return nil
}

// AutoUnlock opens the key with the unlock key from store, without the
// passphrase. It fails with VAULT_AUTO_UNLOCK_OFF when auto-unlock is off.
func AutoUnlock(keyPath, autoPath string, store SecretStore) (*Key, error) {
	f, err := readAuto(autoPath)
	if err != nil {
		return nil, err
	}
	pub, err := PublicKeyFromFile(keyPath)
	if err != nil {
		return nil, err
	}
	if AuthorizedKey(pub) != f.Header.PublicKey {
		return nil, apperr.New(apperr.VaultAutoUnlockFailed, "key.auto belongs to an older key; turn auto-unlock on again: mis auto-unlock on")
	}
	unlockKey, err := store.Get()
	if err != nil {
		return nil, err
	}
	defer clear(unlockKey)
	aead, err := chacha20poly1305.NewX(unlockKey)
	if err != nil {
		return nil, apperr.New(apperr.VaultAutoUnlockFailed, "the unlock key in your Keychain is invalid; turn auto-unlock on again: mis auto-unlock on")
	}
	aad, err := json.Marshal(f.Header)
	if err != nil {
		return nil, apperr.Wrap(apperr.VaultKeyFileInvalid, err, "cannot encode the key header")
	}
	seed, err := aead.Open(nil, f.Header.Nonce, f.Ciphertext, aad)
	if err != nil {
		return nil, apperr.New(apperr.VaultAutoUnlockFailed, "the unlock key in your Keychain doesn't open key.auto; turn auto-unlock on again: mis auto-unlock on")
	}
	return keyFromSeed(seed, f.Header.PublicKey, "key.auto")
}

// DisableAutoUnlock turns auto-unlock off: it deletes key.auto, then the
// unlock key in store. Once key.auto is gone, auto-unlock is off even if the
// store can't be cleaned up.
func DisableAutoUnlock(autoPath string, store SecretStore) error {
	if err := os.Remove(autoPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot remove "+autoPath)
	}
	return store.Delete()
}

func readAuto(autoPath string) (*autoFile, error) {
	if err := config.CheckPrivate(autoPath); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(autoPath) //nolint:gosec // path comes from our own Paths layout
	if errors.Is(err, fs.ErrNotExist) {
		return nil, apperr.New(apperr.VaultAutoUnlockOff, "auto-unlock is off; turn it on with: mis auto-unlock on")
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read "+autoPath)
	}
	var f autoFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, apperr.Wrap(apperr.VaultKeyFileInvalid, err, "key.auto is not a Make-It-Safer key file")
	}
	h := f.Header
	if h.Format != autoFormat || h.Cipher != cipherName || len(h.Nonce) != chacha20poly1305.NonceSizeX ||
		len(f.Ciphertext) != ed25519.SeedSize+chacha20poly1305.Overhead {
		return nil, apperr.New(apperr.VaultKeyFileInvalid, "key.auto has an unsupported format")
	}
	return &f, nil
}
