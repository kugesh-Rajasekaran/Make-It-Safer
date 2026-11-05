package vault

import (
	"crypto/ed25519"
	"io"
	"sync"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// Key is the unlocked private key. Its bytes live in locked memory (never
// swapped to disk) and are wiped by Destroy. Signing after Destroy returns
// a VAULT_LOCKED error instead of touching freed memory.
type Key struct {
	mu  sync.Mutex
	buf *memguard.LockedBuffer // 64-byte Ed25519 private key
	pub ssh.PublicKey
}

// newKey moves priv into locked memory and wipes the original slice.
func newKey(priv ed25519.PrivateKey, pub ssh.PublicKey) *Key {
	return &Key{buf: memguard.NewBufferFromBytes(priv), pub: pub}
}

// PublicKey returns the public half, safe to share.
func (k *Key) PublicKey() ssh.PublicKey { return k.pub }

// Signer returns an ssh.Signer backed by the locked key.
func (k *Key) Signer() ssh.Signer { return keySigner{k} }

// Destroy wipes the key. It is safe to call more than once.
func (k *Key) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.buf != nil {
		k.buf.Destroy()
		k.buf = nil
	}
}

// Alive reports whether the key is still unlocked.
func (k *Key) Alive() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.buf != nil && k.buf.IsAlive()
}

type keySigner struct{ k *Key }

func (s keySigner) PublicKey() ssh.PublicKey { return s.k.pub }

func (s keySigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	s.k.mu.Lock()
	defer s.k.mu.Unlock()
	if s.k.buf == nil || !s.k.buf.IsAlive() {
		return nil, apperr.New(apperr.VaultLocked, "Make-It-Safer is locked; run: mis unlock")
	}
	// crypto/ed25519 caches keys by their heap address and can't sign from
	// memory outside the Go heap, so sign with a short-lived copy that is
	// wiped straight after. The long-lived key stays in locked memory.
	priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(priv, s.k.buf.Bytes())
	defer clear(priv)
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: ed25519.Sign(priv, data)}, nil
}
