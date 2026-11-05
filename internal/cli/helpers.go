package cli

import (
	"crypto/subtle"
	"fmt"
	"os"
	"os/user"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// say prints progress and prompts. They go to stderr so that stdout only
// carries the result (and stays valid JSON with --json).
func (a *app) say(format string, args ...any) {
	_, _ = fmt.Fprintf(a.stderr, format, args...)
}

// setup returns the paths and configuration of an initialised install.
func (a *app) setup() (config.Paths, *config.Config, error) {
	paths, err := config.DefaultPaths()
	if err != nil {
		return paths, nil, err
	}
	if err := paths.RequireInitialized(); err != nil {
		return paths, nil, err
	}
	cfg, err := config.Load(paths.Config)
	return paths, cfg, err
}

// contextWords are words an attacker would try first in your passphrase.
func contextWords(cfg *config.Config) []string {
	var words []string
	if u, err := user.Current(); err == nil {
		words = append(words, u.Username)
	}
	if h, err := os.Hostname(); err == nil {
		words = append(words, h)
	}
	for _, s := range cfg.Servers {
		words = append(words, s.Name, s.Host)
	}
	return words
}

//nolint:gosec // G101 false positive: help text that mentions passphrases, not a credential
const passphraseHelp = `Choose a passphrase. You'll type it once after every restart of your computer.
  • At least 15 characters. Spaces are fine. Several random words work best.
  • It is never saved anywhere, so keep it in your password manager.
  • Leave it empty and press Enter to get a generated one.

`

// newPassphrase asks for a passphrase until one meets the policy, then asks
// to confirm it. An empty answer offers a generated passphrase.
func (a *app) newPassphrase(cfg *config.Config) (secret.Bytes, error) {
	a.say(passphraseHelp)
	for {
		p, err := vault.ReadPassphrase(a.stdin, a.stderr, "New passphrase: ")
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			if p, err = vault.GeneratePassphrase(); err != nil {
				return nil, err
			}
			a.say("\nYour generated passphrase (save it in your password manager, then clear your screen):\n\n    ")
			_, _ = a.stderr.Write(p) // raw bytes: formatting a secret.Bytes prints [redacted]
			a.say("\n\n")
		} else if err := vault.CheckPassphrase(p, contextWords(cfg)); err != nil {
			p.Wipe()
			a.say("✗ %s. Please try another one.\n\n", apperr.MessageOf(err))
			continue
		}

		confirm, err := vault.ReadPassphrase(a.stdin, a.stderr, "Type it again to confirm: ")
		if err != nil {
			p.Wipe()
			return nil, err
		}
		same := subtle.ConstantTimeCompare(p, confirm) == 1
		confirm.Wipe()
		if same {
			return p, nil
		}
		p.Wipe()
		a.say("✗ The two entries don't match. Let's start again.\n\n")
	}
}
