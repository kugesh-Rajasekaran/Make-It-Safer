package vault

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"runtime/debug"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/unicode/norm"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
)

// Params are the Argon2id costs, stored in key.enc so they can be raised later.
type Params struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

var (
	// ParamsStrong is RFC 9106's first recommended option: 2 GiB, 1 pass, 4 lanes.
	ParamsStrong = Params{Time: 1, MemoryKiB: 2 << 20, Threads: 4}
	// ParamsLowMemory is RFC 9106's second option for smaller machines: 64 MiB, 3 passes, 4 lanes.
	ParamsLowMemory = Params{Time: 3, MemoryKiB: 64 << 10, Threads: 4}
)

// DefaultParams picks the RFC 9106 option this machine can afford.
func DefaultParams() Params {
	if totalMemory() >= 8<<30 {
		return ParamsStrong
	}
	return ParamsLowMemory
}

const (
	keyFormat  = "mis-key-v1"
	kdfName    = "argon2id"
	cipherName = "xchacha20-poly1305"
	saltSize   = 16
	keyComment = "make-it-safer"
)

// keyFile is the JSON layout of key.enc. The header is authenticated: any
// change to it makes decryption fail.
type keyFile struct {
	Header     header `json:"header"`
	Ciphertext []byte `json:"ciphertext"`
}

type header struct {
	Format    string `json:"format"`
	KDF       string `json:"kdf"`
	Params    Params `json:"params"`
	Salt      []byte `json:"salt"`
	Cipher    string `json:"cipher"`
	Nonce     []byte `json:"nonce"`
	PublicKey string `json:"public_key"` // authorized_keys format; checked after decryption
}

// Create generates a new Ed25519 key, writes it to keyPath encrypted with the
// passphrase, writes the public key to pubPath and returns the public key.
func Create(keyPath, pubPath string, passphrase secret.Bytes, p Params) (ssh.PublicKey, error) {
	if _, err := os.Stat(keyPath); err == nil {
		return nil, apperr.New(apperr.VaultKeyExists, "a key already exists at "+keyPath+"; to change its passphrase run: mis passphrase change")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot generate a key")
	}
	defer clear(priv)
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot encode the public key")
	}
	seed := priv.Seed()
	defer clear(seed)
	if err := write(keyPath, seed, sshPub, passphrase, p); err != nil {
		return nil, err
	}
	if err := config.WriteFileAtomic(pubPath, []byte(AuthorizedKey(sshPub))); err != nil {
		return nil, err
	}
	return sshPub, nil
}

// Unlock decrypts key.enc with the passphrase and returns the key in locked
// memory. A wrong passphrase and a damaged file look the same on purpose.
func Unlock(keyPath string, passphrase secret.Bytes) (*Key, error) {
	f, err := read(keyPath)
	if err != nil {
		return nil, err
	}
	seed, err := open(f, passphrase)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	derived, err := ssh.NewPublicKey(priv.Public())
	if err != nil || AuthorizedKey(derived) != f.Header.PublicKey {
		clear(priv)
		return nil, apperr.New(apperr.VaultKeyFileInvalid, "key.enc does not match its public key; it may have been tampered with")
	}
	return newKey(priv, derived), nil // takes ownership of priv and wipes it
}

// ChangePassphrase re-encrypts the key with a new passphrase and fresh salt.
func ChangePassphrase(keyPath string, current, next secret.Bytes, p Params) error {
	f, err := read(keyPath)
	if err != nil {
		return err
	}
	seed, err := open(f, current)
	if err != nil {
		return err
	}
	defer clear(seed)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(f.Header.PublicKey))
	if err != nil {
		return apperr.Wrap(apperr.VaultKeyFileInvalid, err, "key.enc has an invalid public key")
	}
	return write(keyPath, seed, pub, next, p)
}

// PublicKeyFromFile reads the public key stored in key.enc without the passphrase.
func PublicKeyFromFile(keyPath string) (ssh.PublicKey, error) {
	f, err := read(keyPath)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(f.Header.PublicKey))
	if err != nil {
		return nil, apperr.Wrap(apperr.VaultKeyFileInvalid, err, "key.enc has an invalid public key")
	}
	return pub, nil
}

// AuthorizedKey formats a public key as one authorized_keys line.
func AuthorizedKey(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + keyComment + "\n"
}

func write(keyPath string, seed []byte, pub ssh.PublicKey, passphrase secret.Bytes, p Params) error {
	h := header{
		Format: keyFormat, KDF: kdfName, Params: p, Cipher: cipherName,
		Salt: make([]byte, saltSize), Nonce: make([]byte, chacha20poly1305.NonceSizeX),
		PublicKey: AuthorizedKey(pub),
	}
	if _, err := rand.Read(h.Salt); err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot read random bytes")
	}
	if _, err := rand.Read(h.Nonce); err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot read random bytes")
	}
	aead, err := newAEAD(passphrase, h)
	if err != nil {
		return err
	}
	aad, err := json.Marshal(h)
	if err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot encode the key header")
	}
	data, err := json.MarshalIndent(keyFile{Header: h, Ciphertext: aead.Seal(nil, h.Nonce, seed, aad)}, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot encode the key file")
	}
	return config.WriteFileAtomic(keyPath, append(data, '\n'))
}

func read(keyPath string) (*keyFile, error) {
	if err := config.CheckPrivate(keyPath); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(keyPath) //nolint:gosec // path comes from our own Paths layout
	if errors.Is(err, fs.ErrNotExist) {
		return nil, apperr.New(apperr.VaultKeyMissing, "no key found; run: mis init")
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read "+keyPath)
	}
	var f keyFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, apperr.Wrap(apperr.VaultKeyFileInvalid, err, "key.enc is not a Make-It-Safer key file")
	}
	h, p := f.Header, f.Header.Params
	valid := h.Format == keyFormat && h.KDF == kdfName && h.Cipher == cipherName &&
		len(h.Salt) == saltSize && len(h.Nonce) == chacha20poly1305.NonceSizeX &&
		len(f.Ciphertext) == ed25519.SeedSize+chacha20poly1305.Overhead &&
		p.Time >= 1 && p.Time <= 10 && p.MemoryKiB >= 8<<10 && p.MemoryKiB <= 4<<20 && p.Threads >= 1 && p.Threads <= 16
	if !valid {
		return nil, apperr.New(apperr.VaultKeyFileInvalid, "key.enc has an unsupported format or settings")
	}
	return &f, nil
}

func open(f *keyFile, passphrase secret.Bytes) ([]byte, error) {
	aead, err := newAEAD(passphrase, f.Header)
	if err != nil {
		return nil, err
	}
	aad, err := json.Marshal(f.Header)
	if err != nil {
		return nil, apperr.Wrap(apperr.VaultKeyFileInvalid, err, "cannot encode the key header")
	}
	seed, err := aead.Open(nil, f.Header.Nonce, f.Ciphertext, aad)
	if err != nil {
		return nil, apperr.New(apperr.VaultUnlockFailed, "wrong passphrase, or key.enc is damaged")
	}
	return seed, nil
}

// newAEAD derives the encryption key from the passphrase with Argon2id.
func newAEAD(passphrase secret.Bytes, h header) (cipher.AEAD, error) {
	normalized := norm.NFC.Bytes(passphrase)
	defer wipeIfCopy(normalized, passphrase)
	k := argon2.IDKey(normalized, h.Salt, h.Params.Time, h.Params.MemoryKiB, h.Params.Threads, chacha20poly1305.KeySize)
	defer clear(k)
	defer debug.FreeOSMemory() // hand Argon2's large working memory back to the OS
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, apperr.Wrap(apperr.VaultKeyCreateFailed, err, "cannot set up encryption")
	}
	return aead, nil
}
