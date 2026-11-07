package daemon

import (
	"fmt"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// The daemon is locked (no key in memory) or unlocked. It unlocks with your
// passphrase (mis unlock), or by itself with the unlock key in your
// Keychain when auto-unlock is on. A lock always wins over an unlock that
// was still in progress.

func (d *Daemon) unlocked() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.key != nil && d.key.Alive()
}

func (d *Daemon) currentKey() *vault.Key {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.key
}

// unlockAtStart shows the "locked" notice, or with auto-unlock on, unlocks
// with the Keychain in the background (macOS may first ask you to allow
// access) and shows the notice only if that fails.
func (d *Daemon) unlockAtStart() {
	if !vault.AutoUnlockEnabled(d.paths.AutoKey) {
		d.showLockNotice()
		return
	}
	go func() {
		if d.autoUnlock() != nil {
			d.showLockNotice()
		}
	}()
}

// unlock opens the key with your passphrase. One attempt runs at a time
// (each can use 2 GiB of memory), and failed attempts slow down.
func (d *Daemon) unlock(passphrase []byte) error {
	p := secret.Bytes(passphrase)
	defer p.Wipe()
	d.unlocking.Lock()
	defer d.unlocking.Unlock()
	if wait := d.limiter.Wait(); wait > 0 {
		return apperr.New(apperr.VaultUnlockRateLimited, fmt.Sprintf("too many failed attempts; try again in %s", wait.Round(time.Second)))
	}
	locks := d.lockCount()
	key, err := vault.Unlock(d.paths.KeyFile, p)
	if err != nil {
		if apperr.Is(err, apperr.VaultUnlockFailed) {
			d.limiter.Failure()
		}
		d.log.Warn("unlock", "mode", "passphrase", "status", "error", "code", apperr.CodeOf(err))
		return err
	}
	d.limiter.Success()
	return d.install(key, locks, "passphrase")
}

// autoUnlock opens the key with the unlock key in your Keychain. macOS may
// first ask you to allow access (after an update of mis).
func (d *Daemon) autoUnlock() error {
	locks := d.lockCount()
	key, err := vault.AutoUnlock(d.paths.KeyFile, d.paths.AutoKey, d.secrets)
	if err != nil {
		d.log.Warn("unlock", "mode", "auto", "status", "error", "code", apperr.CodeOf(err))
		return err
	}
	return d.install(key, locks, "auto")
}

// install makes key the unlocked key, unless a lock came in while it was
// being opened (locks changed): then the lock wins and key is wiped.
func (d *Daemon) install(key *vault.Key, locks uint64, mode string) error {
	d.mu.Lock()
	if d.locks != locks {
		d.mu.Unlock()
		key.Destroy()
		return apperr.New(apperr.VaultLocked, "Make-It-Safer was locked while unlocking; run: mis unlock")
	}
	wasLocked := d.key == nil
	if d.key != nil {
		d.key.Destroy()
	}
	d.key = key
	d.mu.Unlock()
	d.log.Info("unlock", "mode", mode, "status", "success")
	if wasLocked {
		_ = d.notifier.Remove(lockNoticeID)
		d.sched.trigger("refresh")
	}
	return nil
}

// lock wipes the key from memory. It stays locked until the next unlock.
func (d *Daemon) lock() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.locks++
	if d.key != nil {
		d.key.Destroy()
		d.key = nil
		d.log.Info("lock", "status", "success")
	}
}

func (d *Daemon) lockCount() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.locks
}
