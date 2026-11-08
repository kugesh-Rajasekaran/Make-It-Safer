package cli

import (
	"bufio"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// ask reads one line of ordinary (non-secret) input, offering a default.
func (a *app) ask(question, def string) (string, error) {
	if def != "" {
		a.say("%s [%s]: ", question, def)
	} else {
		a.say("%s: ", question)
	}
	if a.in == nil {
		if a.stdin == nil {
			return "", apperr.New(apperr.CLIInputAborted, "no input available; pass the value as a flag")
		}
		a.in = bufio.NewReader(a.stdin)
	}
	line, err := a.in.ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil && line == "" {
		return "", apperr.New(apperr.CLIInputAborted, "input ended")
	}
	if line == "" {
		return def, nil
	}
	return line, nil
}

// confirm asks a yes/no question.
func (a *app) confirm(question string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	answer, err := a.ask(question+" ("+hint+")", "")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(answer) {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// unlockKey asks for the passphrase and unlocks the key for this command.
// The caller must Destroy the key.
func (a *app) unlockKey(paths config.Paths) (*vault.Key, error) {
	_ = vault.Harden()
	pass, err := vault.ReadPassphrase(a.stdin, a.stderr, "Passphrase: ")
	if err != nil {
		return nil, err
	}
	defer pass.Wipe()
	return vault.Unlock(paths.KeyFile, pass)
}
