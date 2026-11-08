package daemon

import (
	"bytes"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// keychain stands in for the macOS Keychain.
type keychain struct {
	mu     sync.Mutex
	secret []byte
}

func (k *keychain) Get() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.secret == nil {
		return nil, apperr.New(apperr.KeyringItemMissing, "no item")
	}
	return bytes.Clone(k.secret), nil
}

func (k *keychain) Set(s []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.secret = bytes.Clone(s)
	return nil
}

func (k *keychain) Delete() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.secret = nil
	return nil
}

// turnOnAutoUnlock turns auto-unlock on for the test install.
func turnOnAutoUnlock(t *testing.T, paths config.Paths) *keychain {
	t.Helper()
	key, err := vault.Unlock(paths.KeyFile, secret.Bytes(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	store := &keychain{}
	if err := vault.EnableAutoUnlock(paths.AutoKey, key, store); err != nil {
		t.Fatal(err)
	}
	return store
}

func status(t *testing.T, paths config.Paths) Status {
	t.Helper()
	var s Status
	if err := Call(paths, Request{Op: OpStatus}, &s, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	return s
}

// eventually waits up to 2 s for ok.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 100 {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting until %s", what)
}

func TestAutoUnlockAtStart(t *testing.T) {
	paths := newInstall(t)
	store := turnOnAutoUnlock(t, paths)
	rec := newRecorder()
	startDaemonWith(t, paths, rec, io.Discard, func(d *Daemon) { d.secrets = store })

	eventually(t, "it unlocks itself", func() bool { return !status(t, paths).Locked })
	if s := status(t, paths); !s.AutoUnlock {
		t.Fatal("status doesn't say auto-unlock is on")
	}
	if slices.Contains(rec.ids(), lockNoticeID) {
		t.Fatal("showed the locked notice although it unlocked itself")
	}

	// mis lock still locks it, until mis unlock or the next start.
	if err := Call(paths, Request{Op: OpLock}, nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !status(t, paths).Locked {
		t.Fatal("unlocked itself again after mis lock")
	}
}

func TestAutoUnlockFailureShowsTheLockedNotice(t *testing.T) {
	paths := newInstall(t)
	store := turnOnAutoUnlock(t, paths)
	if err := store.Delete(); err != nil { // e.g. removed in Keychain Access
		t.Fatal(err)
	}
	rec := newRecorder()
	startDaemonWith(t, paths, rec, io.Discard, func(d *Daemon) { d.secrets = store })

	eventually(t, "the locked notice shows", func() bool { return slices.Contains(rec.ids(), lockNoticeID) })
	if !status(t, paths).Locked {
		t.Fatal("unlocked without the unlock key")
	}
}

func TestAutoUnlockRequest(t *testing.T) {
	paths := newInstall(t)
	store := &keychain{}
	rec := newRecorder()
	startDaemonWith(t, paths, rec, io.Discard, func(d *Daemon) { d.secrets = store })

	// Turned on while the service runs (mis auto-unlock on): it unlocks now.
	key, err := vault.Unlock(paths.KeyFile, secret.Bytes(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if err := vault.EnableAutoUnlock(paths.AutoKey, key, store); err != nil {
		t.Fatal(err)
	}
	if err := Call(paths, Request{Op: OpAutoUnlock}, nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if status(t, paths).Locked {
		t.Fatal("still locked")
	}
	rec.mu.Lock()
	removed := slices.Contains(rec.removed, lockNoticeID)
	rec.mu.Unlock()
	if !removed {
		t.Fatal("the locked notice stayed")
	}
}

func TestLockWinsOverAnUnlockInProgress(t *testing.T) {
	paths := newInstall(t)
	d := startDaemon(t, paths, newRecorder())
	key, err := vault.Unlock(paths.KeyFile, secret.Bytes(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	locks := d.lockCount()
	d.lock() // mis lock arrives while the key is still being opened
	if err := d.install(key, locks, "test"); !apperr.Is(err, apperr.VaultLocked) {
		t.Fatalf("got %v, want VAULT_LOCKED", err)
	}
	if key.Alive() || d.unlocked() {
		t.Fatal("the late key was kept")
	}
}
