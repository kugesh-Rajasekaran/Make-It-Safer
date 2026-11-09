package cli

import (
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/keyring"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/setup"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/termlaunch"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// wizard walks through the setup steps after the key exists. A failed step
// is reported and skipped (each says how to do it later); only a closed
// input stops the wizard.
type wizard struct {
	a     *app
	paths config.Paths
	cfg   *config.Config
	pass  secret.Bytes // owned (and wiped) by runInit
}

func (w *wizard) run(res *initResult) error {
	if err := w.terminal(); err != nil {
		return err
	}
	if err := w.rules(); err != nil {
		return err
	}
	if err := w.cfg.Save(w.paths.Config); err != nil {
		return err
	}
	servers, err := w.servers()
	res.Servers = servers
	if err != nil {
		return err
	}
	if res.Service, res.Unlocked, err = w.service(); err != nil {
		return err
	}
	if res.AutoUnlock, err = w.autoUnlock(); err != nil {
		return err
	}
	if res.Service {
		if err := w.notifyTest(); err != nil {
			return err
		}
	}
	res.ThisComputer = w.cfg.ThisComputer
	if res.Service && (res.Unlocked || len(servers) == 0) && (len(servers) > 0 || w.cfg.ThisComputer) {
		w.firstCheck()
	}
	return nil
}

// thisComputer asks whether to check the computer mis runs on, too.
func (w *wizard) thisComputer() error {
	a := w.a
	what := "its packages, like a server's"
	if runtime.GOOS == "darwin" {
		what = "macOS and Safari updates with the vulnerabilities they fix, and Homebrew"
	}
	a.say("It can also check %s: %s. Nothing is installed or changed for that.\n", lower(config.LocalLabel()), what)
	ok, err := a.confirm("Check "+lower(config.LocalLabel())+" too?", true)
	if err != nil {
		return err
	}
	w.cfg.ThisComputer = ok
	return w.cfg.Save(w.paths.Config)
}

// lower lowercases the first letter: "This Mac" → "this Mac".
func lower(s string) string { return strings.ToLower(s[:1]) + s[1:] }

// close wipes the key the wizard unlocked for adding servers.
func (w *wizard) close() {
	if w.a.unlocked != nil {
		w.a.unlocked.Destroy()
		w.a.unlocked = nil
	}
}

func (w *wizard) terminal() error {
	a := w.a
	a.say("\n2. Terminal\nA notification's server button opens an SSH session in this app, with the fix typed in.\n")
	apps := config.TerminalChoices(runtime.GOOS)
	a.say("Choices: %s (\"default\" is %s)\n", strings.Join(apps, ", "), config.DefaultTerminalName(runtime.GOOS))
	for {
		app, err := a.ask("Terminal app", w.cfg.Terminal.App)
		if err != nil {
			return err
		}
		if !slices.Contains(apps, app) {
			a.say("Please pick one of the choices.\n")
			continue
		}
		t := config.Terminal{App: app}
		if app == "custom" {
			if t.Command, err = a.ask("Command that opens a script in your terminal, with {script} for its path (e.g. foot {script}). Separate parts with spaces; quotes are not understood, so use names without spaces", ""); err != nil {
				return err
			}
			if !strings.Contains(t.Command, "{script}") {
				a.say("The command needs {script} in it.\n")
				continue
			}
		}
		if err := (termlaunch.Launcher{Terminal: t}).Available(); err != nil {
			a.say("⚠ %s. Choose another, or install it later.\n", apperr.MessageOf(err))
			keep, err := a.confirm("Keep this choice anyway?", false)
			if err != nil {
				return err
			}
			if !keep {
				continue
			}
		}
		w.cfg.Terminal = t
		return nil
	}
}

func (w *wizard) rules() error {
	a, r := w.a, &w.cfg.Rules
	a.say("\n3. Alerts\nActively exploited vulnerabilities, and fixable ones with CVSS 9 or more, are always urgent.\n")
	min, err := w.askScore("Also alert for fixable vulnerabilities from CVSS", r.AlertWhen.MinSeverity, false)
	if err != nil {
		return err
	}
	r.AlertWhen.MinSeverity = min
	a.say("Early warnings come before your distro confirms a vulnerability, matched by product name.\n")
	early, err := w.askScore("Early warnings from CVSS (or \"off\")", r.EarlyWarning.MinSeverity, true)
	if err != nil {
		return err
	}
	r.EarlyWarning.Enabled = early >= 0
	if early >= 0 {
		r.EarlyWarning.MinSeverity = early
	}
	sound, err := a.confirm("Play a sound with alerts?", w.cfg.Notifications.Sound)
	if err != nil {
		return err
	}
	w.cfg.Notifications.Sound = sound
	return nil
}

// askScore asks for a CVSS score from 0 to 10; with offOK, "off" gives -1.
func (w *wizard) askScore(question string, def float64, offOK bool) (float64, error) {
	for {
		answer, err := w.a.ask(question, strconv.FormatFloat(def, 'f', 1, 64))
		if err != nil {
			return 0, err
		}
		if offOK && strings.EqualFold(answer, "off") {
			return -1, nil
		}
		if v, err := strconv.ParseFloat(answer, 64); err == nil && v >= 0 && v <= 10 {
			return v, nil
		}
		w.a.say("Please type a number from 0 to 10.\n")
	}
}

func (w *wizard) servers() ([]string, error) {
	a := w.a
	a.say("\n4. Servers\n")
	if err := w.thisComputer(); err != nil {
		return nil, err
	}
	a.say("\nFor each server, a read-only \"mis\" user is created through your own ssh login.\n" +
		"Have your usual `ssh` login ready (keys or password: Make-It-Safer never sees it).\n")
	added := []string{} // not nil: it becomes the JSON list "servers"
	for {
		question := "Add a server now?"
		if len(added) > 0 {
			question = "Add another server?"
		}
		more, err := a.confirm(question, len(added) == 0)
		if err != nil || !more {
			return added, err
		}
		if a.unlocked == nil { // unlock once, with the passphrase from step 1
			if a.unlocked, err = vault.Unlock(w.paths.KeyFile, w.pass); err != nil {
				return added, err
			}
		}
		reports, err := a.addServer("", addOptions{port: 22})
		if len(reports) > 0 {
			writeReports(a.stderr, reports)
			added = append(added, reports[0].Server)
		}
		switch {
		case apperr.Is(err, apperr.CLIInputAborted) && len(reports) == 0:
			a.say("Skipped. Add it later with: mis server add\n")
		case err != nil:
			a.say("✗ %s\n", apperr.MessageOf(err))
		case slices.ContainsFunc(reports, func(r *setup.Report) bool { return !r.OK }):
			a.say("⚠ Some checks failed (✗ above). Check again later with: mis server verify\n")
		}
	}
}

// service installs and starts the background service, and unlocks it with
// the passphrase from step 1.
func (w *wizard) service() (running, unlocked bool, err error) {
	a := w.a
	a.say("\n5. Background service\nMake-It-Safer runs in the background: it checks on a schedule and shows\n" +
		"notifications. It starts every time you log in.\n")
	ok, err := a.confirm("Install and start it now?", true)
	if err != nil {
		return false, false, err
	}
	if !ok {
		a.say("Later: mis service install\n")
		return false, false, nil
	}
	if _, err := a.installService(w.paths); err != nil {
		a.say("✗ %s\n  Try again later: mis service install\n", apperr.MessageOf(err))
		return false, false, nil
	}
	for range 50 {
		if daemon.Running(w.paths) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !daemon.Running(w.paths) {
		a.say("✗ The background service didn't start. See: mis service logs\n")
		return false, false, nil
	}
	pass := slices.Clone([]byte(w.pass)) // Call wipes what it sends
	if err := daemon.Call(w.paths, daemon.Request{Op: daemon.OpUnlock, Passphrase: pass}, nil, 2*time.Minute); err != nil {
		a.say("✗ %s\n  Unlock it later: mis unlock\n", apperr.MessageOf(err))
		return true, false, nil
	}
	a.say("✓ Running and unlocked.\n")
	return true, true, nil
}

// autoUnlock offers to let the background service unlock itself when you
// log in (macOS only, ADR 0002). It reports whether auto-unlock is on.
func (w *wizard) autoUnlock() (bool, error) {
	a := w.a
	if !keyring.Available() {
		return false, nil
	}
	a.say("\nAfter a restart, it needs unlocking before it can log in to your servers.\n" +
		"  • Yes: it unlocks itself when you log in. An unlock key is kept in your macOS\n" +
		"    Keychain; your passphrase is still never stored.\n" +
		"  • No: you type your passphrase once after each restart (mis unlock).\n")
	ok, err := a.confirm("Unlock automatically after a restart?", true)
	if err != nil {
		return false, err
	}
	if !ok {
		a.say("OK: after each restart, run mis unlock. To change it later: mis auto-unlock on\n")
		return false, nil
	}
	if a.unlocked == nil {
		if a.unlocked, err = vault.Unlock(w.paths.KeyFile, w.pass); err != nil {
			a.say("✗ %s\n  Try again later: mis auto-unlock on\n", apperr.MessageOf(err))
			return false, nil
		}
	}
	if _, err := a.enableAutoUnlock(w.paths, a.unlocked); err != nil {
		a.say("✗ %s\n  Try again later: mis auto-unlock on\n", apperr.MessageOf(err))
		return false, nil
	}
	a.say("✓ Done: after a restart it unlocks itself when you log in.\n")
	return true, nil
}

func (w *wizard) notifyTest() error {
	a := w.a
	a.say("\n6. Notifications\n")
	if runtime.GOOS == "darwin" {
		a.say("macOS needs your OK before Make-It-Safer can show alerts.\n")
	}
	_, err := a.setUpNotifications(w.paths)
	return err
}

func (w *wizard) firstCheck() {
	a := w.a
	a.say("\n7. First check (the first one can take a few minutes)\n")
	var res daemon.CheckResult
	err := a.withSpinner("Reading package lists and matching them", func() error {
		return daemon.Call(w.paths, daemon.Request{Op: daemon.OpCheck, Refresh: true}, &res, 10*time.Minute)
	})
	if err != nil {
		a.say("✗ %s\n  Try again later: mis check\n", apperr.MessageOf(err))
		return
	}
	printCheck(a.stderr, &res)
}
