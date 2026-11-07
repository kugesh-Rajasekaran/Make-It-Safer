package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/keyring"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

func (a *app) autoUnlockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auto-unlock",
		Short: "Let the background service unlock itself when you log in (macOS Keychain)",
		Long: `With auto-unlock on, the background service unlocks itself when you log in to
your computer, with an unlock key kept in your macOS login Keychain. Your
passphrase is still never stored. mis lock still locks it, until mis unlock or
your next login.`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(&cobra.Command{
		Use: "on", Short: "Turn auto-unlock on (asks for your passphrase once)", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return a.runAutoUnlockOn() },
	}, &cobra.Command{
		Use: "off", Short: "Turn auto-unlock off and remove the unlock key from your Keychain", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return a.runAutoUnlockOff() },
	})
	return cmd
}

type autoUnlockResult struct {
	AutoUnlock bool `json:"auto_unlock"`
	Unlocked   bool `json:"unlocked"` // the background service unlocked with it just now
}

func (a *app) runAutoUnlockOn() error {
	paths, _, err := a.setup()
	if err != nil {
		return err
	}
	if err := keyring.Require(); err != nil {
		return err
	}
	_ = vault.Harden()
	pass, err := vault.ReadPassphrase(a.stdin, a.stderr, "Passphrase: ")
	if err != nil {
		return err
	}
	defer pass.Wipe()
	key, err := vault.Unlock(paths.KeyFile, pass)
	if err != nil {
		return err
	}
	defer key.Destroy()
	res, err := a.enableAutoUnlock(paths, key)
	if err != nil {
		return err
	}
	return a.emit(res, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, "✓ Auto-unlock is on: the background service unlocks itself when you log in.")
	})
}

func (a *app) runAutoUnlockOff() error {
	paths, _, err := a.setup()
	if err != nil {
		return err
	}
	if err := vault.DisableAutoUnlock(paths.AutoKey, keyring.AutoUnlock(paths.Home)); err != nil {
		return err
	}
	return a.emit(autoUnlockResult{}, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, "✓ Auto-unlock is off. After each restart, unlock with: mis unlock")
	})
}

// enableAutoUnlock turns auto-unlock on for an unlocked key. If the
// background service runs, it unlocks with the Keychain right away, so any
// macOS "allow access" prompt shows now, while you're here.
func (a *app) enableAutoUnlock(paths config.Paths, key *vault.Key) (autoUnlockResult, error) {
	if err := vault.EnableAutoUnlock(paths.AutoKey, key, keyring.AutoUnlock(paths.Home)); err != nil {
		return autoUnlockResult{}, err
	}
	res := autoUnlockResult{AutoUnlock: true}
	if daemon.Running(paths) {
		if err := daemon.Call(paths, daemon.Request{Op: daemon.OpAutoUnlock}, nil, 2*time.Minute); err != nil {
			a.say("⚠ The background service couldn't use it yet: %s\n  Check with: mis doctor\n", apperr.MessageOf(err))
		} else {
			res.Unlocked = true
		}
	}
	return res, nil
}
