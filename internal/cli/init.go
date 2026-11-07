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
	Home      string   `json:"home"`
	PublicKey string   `json:"public_key"`
	Servers   []string `json:"servers"`
	Service   bool     `json:"service"`  // the background service runs
	Unlocked  bool     `json:"unlocked"` // and is unlocked
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
	_, _ = fmt.Fprintln(w, "  After every restart of your computer, unlock it once: mis unlock\n  Something off? Run: mis doctor")
}
