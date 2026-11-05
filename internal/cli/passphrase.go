package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

func (a *app) passphraseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passphrase",
		Short: "Manage your passphrase",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "change",
		Short: "Change your passphrase (your key stays the same)",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return a.runPassphraseChange() },
	})
	return cmd
}

func (a *app) runPassphraseChange() error {
	paths, cfg, err := a.setup()
	if err != nil {
		return err
	}
	_ = vault.Harden()

	current, err := vault.ReadPassphrase(a.stdin, a.stderr, "Current passphrase: ")
	if err != nil {
		return err
	}
	defer current.Wipe()
	key, err := vault.Unlock(paths.KeyFile, current) // check it before asking for a new one
	if err != nil {
		return err
	}
	key.Destroy()

	next, err := a.newPassphrase(cfg)
	if err != nil {
		return err
	}
	defer next.Wipe()
	a.say("Re-encrypting your key…\n")
	if err := vault.ChangePassphrase(paths.KeyFile, current, next, vault.DefaultParams()); err != nil {
		return err
	}
	return a.emit(struct {
		Changed bool `json:"changed"`
	}{true}, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, "✓ Passphrase changed. Use the new one from now on.")
	})
}
