package termlaunch

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func (l Launcher) start(name string, args ...string) error {
	if l.Start != nil {
		return l.Start(name, args...)
	}
	cmd := exec.Command(name, args...) //nolint:gosec // a terminal app chosen in your config, running our own script
	if err := cmd.Start(); err != nil {
		return apperr.Wrap(apperr.TerminalFailed, err, "cannot open the terminal "+name)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

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
	goos := l.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos == "darwin" {
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

// linuxTerminals lists terminals and how to make them run a script, in the
// order the default choice tries them.
var linuxTerminals = []struct {
	name string
	args []string
}{
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
				return t, []string{"-e", path}, nil
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
