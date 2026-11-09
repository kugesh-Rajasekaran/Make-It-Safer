package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

type initResult struct {
	Home         string   `json:"home"`
	PublicKey    string   `json:"public_key"`
	Servers      []string `json:"servers"`
	ThisComputer bool     `json:"this_computer"` // this computer is checked too
	Service      bool     `json:"service"`       // the background service runs
	Unlocked     bool     `json:"unlocked"`      // and is unlocked
	AutoUnlock   bool     `json:"auto_unlock"`   // it unlocks itself when you log in
}

// configRestored is the result of mis init when it only re-created config.yaml.
type configRestored struct {
	Home           string `json:"home"`
	ConfigRestored bool   `json:"config_restored"`
}

func (a *app) initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Set up Make-It-Safer: passphrase, terminal, alerts, servers and the background service",
		Long: `A guided setup. Every step after the passphrase can be skipped and done
later; each step says how.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return a.runInit() },
	}
}

func (a *app) runInit() error {
	paths, err := config.DefaultPaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(paths.KeyFile); err == nil {
		if !paths.Initialized() {
			return a.restoreConfig(paths)
		}
		return apperr.New(apperr.VaultKeyExists, "Make-It-Safer is already set up; to change your passphrase run: mis passphrase change")
	}
	if err := paths.Ensure(); err != nil {
		return err
	}
	if err := paths.CheckPermissions(); err != nil {
		return err
	}
	// A key.auto without key.enc is left over from a deleted key; it can't open the new one.
	if err := os.Remove(paths.AutoKey); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot remove "+paths.AutoKey)
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

	a.say("Make-It-Safer keeps its files in %s\n(only you can read them; nothing is synced anywhere).\n", paths.Home)
	a.say("\n1. Passphrase\n")
	pass, err := a.newPassphrase()
	if err != nil {
		return err
	}
	defer pass.Wipe()

	a.say("Creating your key (this takes a few seconds)…\n")
	pub, err := vault.Create(paths.KeyFile, paths.PublicKey, pass, a.kdf())
	if err != nil {
		return err
	}
	a.say("✓ Key created and encrypted with your passphrase.\n")

	res := initResult{Home: paths.Home, PublicKey: strings.TrimSpace(vault.AuthorizedKey(pub))}
	w := &wizard{a: a, paths: paths, cfg: &cfg, pass: pass}
	defer w.close()
	if err := w.run(&res); err != nil {
		return err
	}
	return a.emit(res, func(out io.Writer) { printInitResult(out, res) })
}

// restoreConfig handles a key without a config.yaml (the file was deleted).
// Every other command says "run: mis init" then, and init must not answer
// "already set up". It writes the default settings and leaves the key alone.
func (a *app) restoreConfig(paths config.Paths) error {
	if err := paths.Ensure(); err != nil {
		return err
	}
	if err := paths.CheckPermissions(); err != nil {
		return err
	}
	cfg := config.Default()
	if err := cfg.Save(paths.Config); err != nil {
		return err
	}
	return a.emit(configRestored{Home: paths.Home, ConfigRestored: true}, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "✓ %s was missing, so it was created again with the default settings.\n"+
			"  Your key and passphrase are unchanged. Servers that were listed in the old file are not:\n"+
			"  add them again with: mis server add. Change settings with: mis config\n", paths.Config)
	})
}

func printInitResult(w io.Writer, res initResult) {
	_, _ = fmt.Fprintln(w, "\n✓ Make-It-Safer is set up.")
	switch {
	case !res.Service:
		_, _ = fmt.Fprintln(w, "  Start the background service when you're ready: mis service install")
	case !res.Unlocked:
		_, _ = fmt.Fprintln(w, "  Unlock the background service: mis unlock")
	default:
		_, _ = fmt.Fprintln(w, "  The background service runs and checks your servers on its own.")
	}
	if len(res.Servers) == 0 {
		_, _ = fmt.Fprintln(w, "  Add a server: mis server add")
	}
	if res.AutoUnlock {
		_, _ = fmt.Fprintln(w, "  After a restart it unlocks itself when you log in.")
	} else {
		_, _ = fmt.Fprintln(w, "  After every restart of your computer, unlock it once: mis unlock")
	}
	_, _ = fmt.Fprintln(w, "  Something off? Run: mis doctor")
}
