package termlaunch

import (
	"cmp"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Launcher opens scripts in your terminal app.
type Launcher struct {
	Terminal config.Terminal
	TempDir  string
	GOOS     string                                  // defaults to runtime.GOOS
	Start    func(name string, args ...string) error // defaults to starting the process
	LookPath func(string) (string, error)            // defaults to exec.LookPath
}

// Open writes the script to a private temporary file (it deletes itself
// when it runs) and opens it in a new terminal window.
func (l Launcher) Open(script string) error {
	l.removeStale()
	f, err := os.CreateTemp(l.TempDir, "mis-*.command")
	if err != nil {
		return apperr.Wrap(apperr.TerminalFailed, err, "cannot create a launcher script")
	}
	path := f.Name()
	_, err = f.WriteString(script)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(path, 0o700) //nolint:gosec // owner-only, executable: the terminal runs it
	}
	if err != nil {
		_ = os.Remove(path)
		return apperr.Wrap(apperr.TerminalFailed, err, "cannot write a launcher script")
	}
	name, args, err := l.argv(path)
	if err == nil {
		err = l.start(name, args...)
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// How long a terminal gets to report failure. macOS `open` returns once the
// request is accepted (or refused: no such app), so it is waited for. Every
// other terminal keeps running while its window is open: only one that
// exits right away with an error has failed. Variables so tests can shorten them.
var (
	openTimeout = 10 * time.Second
	exitGrace   = 500 * time.Millisecond
)

func (l Launcher) goos() string { return cmp.Or(l.GOOS, runtime.GOOS) }

func (l Launcher) start(name string, args ...string) error {
	if l.Start != nil {
		return l.Start(name, args...)
	}
	if l.goos() == "darwin" && filepath.Base(name) == "open" {
		ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
		defer cancel()
		var stderr headBuffer
		cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // a terminal app chosen in your config, running our own script
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return launchFailed(name, err, stderr.String())
		}
		return nil
	}
	var stderr headBuffer
	cmd := exec.Command(name, args...) //nolint:gosec // a terminal app chosen in your config, running our own script
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return apperr.Wrap(apperr.TerminalFailed, err, "cannot open the terminal "+name)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			return launchFailed(name, err, stderr.String())
		}
	case <-time.After(exitGrace): // still running: its window is open
	}
	return nil
}

// launchFailed describes a terminal that did not open, with what it said.
func launchFailed(name string, err error, said string) error {
	msg := "cannot open the terminal " + name
	if said = printable(strings.Join(strings.Fields(said), " ")); said != "" {
		msg += ": " + said
	} else {
		msg += ": " + err.Error()
	}
	return apperr.Wrap(apperr.TerminalFailed, err, msg)
}

// headBuffer keeps the first bytes written to it and discards the rest, so a
// terminal's chatter can't grow without bound.
type headBuffer struct{ b []byte }

const headBufferMax = 512

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := headBufferMax - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (h *headBuffer) String() string { return string(h.b) }

// argv returns the command that opens path in the configured terminal.
func (l Launcher) argv(path string) (string, []string, error) {
	app := l.Terminal.App
	if app == "custom" {
		fields := strings.Fields(l.Terminal.Command)
		if len(fields) == 0 {
			return "", nil, apperr.New(apperr.TerminalNotFound, "terminal.command is empty")
		}
		for i, f := range fields {
			fields[i] = strings.ReplaceAll(f, "{script}", path)
		}
		return fields[0], fields[1:], nil
	}
	if l.goos() == "darwin" {
		return macArgv(app, path)
	}
	return l.linuxArgv(app, path)
}

func macArgv(app, path string) (string, []string, error) {
	switch app {
	case "default", "terminal":
		return "open", []string{"-a", "Terminal", path}, nil
	case "iterm2":
		return "open", []string{"-a", "iTerm", path}, nil
	case "ghostty":
		return "open", []string{"-na", "Ghostty", "--args", "-e", path}, nil
	case "kitty":
		return "open", []string{"-na", "kitty", "--args", path}, nil
	case "alacritty":
		return "open", []string{"-na", "Alacritty", "--args", "-e", path}, nil
	case "wezterm":
		return "open", []string{"-na", "WezTerm", "--args", "start", "--", path}, nil
	}
	return "", nil, apperr.New(apperr.TerminalNotFound, "terminal "+app+" isn't available on macOS; set terminal.app in config.yaml")
}

type linuxTerminal struct {
	name string
	args []string
}

// linuxTerminals lists terminals and how to make them run a script, in the
// order the default choice tries them.
var linuxTerminals = []linuxTerminal{
	{"x-terminal-emulator", []string{"-e"}}, // Debian/Ubuntu's configured default
	{"gnome-terminal", []string{"--"}},
	{"konsole", []string{"-e"}},
	{"xfce4-terminal", []string{"-x"}},
	{"kgx", []string{"-e"}},
	{"kitty", nil},
	{"alacritty", []string{"-e"}},
	{"wezterm", []string{"start", "--"}},
	{"ghostty", []string{"-e"}},
	{"xterm", []string{"-e"}},
}

func (l Launcher) linuxArgv(app, path string) (string, []string, error) {
	look := l.LookPath
	if look == nil {
		look = exec.LookPath
	}
	if app == "default" {
		if t := os.Getenv("TERMINAL"); t != "" && !strings.ContainsAny(t, " /") {
			if _, err := look(t); err == nil {
				args := []string{"-e"} // the usual way; the table knows the terminals that differ
				if i := slices.IndexFunc(linuxTerminals, func(lt linuxTerminal) bool { return lt.name == t }); i >= 0 {
					args = linuxTerminals[i].args
				}
				return t, append(append([]string{}, args...), path), nil
			}
		}
		for _, t := range linuxTerminals {
			if _, err := look(t.name); err == nil {
				return t.name, append(append([]string{}, t.args...), path), nil
			}
		}
		return "", nil, apperr.New(apperr.TerminalNotFound, "no terminal app found; set terminal.app in config.yaml")
	}
	for _, t := range linuxTerminals {
		if t.name == app {
			return t.name, append(append([]string{}, t.args...), path), nil
		}
	}
	return "", nil, apperr.New(apperr.TerminalNotFound, "terminal "+app+" isn't available on Linux; set terminal.app in config.yaml")
}

// macApps are the app bundles of the macOS terminals (Terminal ships with macOS).
var macApps = map[string]string{"iterm2": "iTerm.app", "ghostty": "Ghostty.app", "kitty": "kitty.app", "alacritty": "Alacritty.app", "wezterm": "WezTerm.app"}

// Available reports whether the configured terminal can be opened here.
func (l Launcher) Available() error {
	name, _, err := l.argv(filepath.Join(os.TempDir(), "mis-check.command"))
	if err != nil {
		return err
	}
	look := l.LookPath
	if look == nil {
		look = exec.LookPath
	}
	if l.goos() == "darwin" && l.Terminal.App != "custom" {
		bundle, ok := macApps[l.Terminal.App]
		if !ok {
			return nil // Terminal
		}
		home, _ := os.UserHomeDir()
		for _, dir := range []string{"/Applications", filepath.Join(home, "Applications")} {
			if _, err := os.Stat(filepath.Join(dir, bundle)); err == nil {
				return nil
			}
		}
		return apperr.New(apperr.TerminalNotFound, bundle+" isn't installed in /Applications or ~/Applications")
	}
	if _, err := look(name); err != nil {
		return apperr.New(apperr.TerminalNotFound, name+" isn't installed (not found in PATH)")
	}
	return nil
}

// removeStale deletes launcher scripts left behind (e.g. a terminal that
// never started). Scripts normally delete themselves.
func (l Launcher) removeStale() {
	old, _ := filepath.Glob(filepath.Join(l.TempDir, "mis-*.command"))
	for _, f := range old {
		if info, err := os.Stat(f); err == nil && time.Since(info.ModTime()) > time.Hour {
			_ = os.Remove(f)
		}
	}
}
