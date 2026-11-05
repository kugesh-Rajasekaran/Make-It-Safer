package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

type initResult struct {
	Home      string `json:"home"`
	PublicKey string `json:"public_key"`
}

func (a *app) initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Set up Make-It-Safer: choose your passphrase and create your key",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return a.runInit() },
	}
}

func (a *app) runInit() error {
	paths, err := config.DefaultPaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(paths.KeyFile); err == nil {
		return apperr.New(apperr.VaultKeyExists, "Make-It-Safer is already set up; to change your passphrase run: mis passphrase change")
	}
	if err := paths.Ensure(); err != nil {
		return err
	}
	if err := paths.CheckPermissions(); err != nil {
		return err
	}
	cfg := config.Default()
	if paths.Initialized() {
		loaded, err := config.Load(paths.Config)
		if err != nil {
			return err
		}
		cfg = *loaded
	} else if err := cfg.Save(paths.Config); err != nil {
		return err
	}
	_ = vault.Harden()

	a.say("Make-It-Safer keeps its files in %s\n(only you can read them; nothing is synced anywhere).\n\n", paths.Home)
	pass, err := a.newPassphrase(&cfg)
	if err != nil {
		return err
	}
	defer pass.Wipe()

	a.say("Creating your key (this takes a few seconds)…\n")
	pub, err := vault.Create(paths.KeyFile, paths.PublicKey, pass, vault.DefaultParams())
	if err != nil {
		return err
	}
	res := initResult{Home: paths.Home, PublicKey: strings.TrimSpace(vault.AuthorizedKey(pub))}
	return a.emit(res, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "✓ Key created and encrypted with your passphrase.\n  Public key: %s\n\nNext: add a server with: mis server add\n", res.PublicKey)
	})
}
