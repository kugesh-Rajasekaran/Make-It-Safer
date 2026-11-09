package termlaunch

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/fixcmd"
)

// fakeProgram writes an executable shell script called name into a new
// directory and returns the directory.
func fakeProgram(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func noScriptsLeft(t *testing.T, dir string) {
	t.Helper()
	if left, _ := filepath.Glob(filepath.Join(dir, "mis-*.command")); len(left) > 0 {
		t.Errorf("launcher scripts left behind after a failed launch: %v", left)
	}
}

// macOS opens every terminal through `open`, which refuses with an exit
// status when the app is gone. That must reach the caller: the daemon then
// shows an error instead of a ✓ and follow-up checks for a window that
// never opened.
func TestOpenReportsAMacTerminalThatDidNotOpen(t *testing.T) {
	// open answers after the grace other terminals get, so only waiting for it shows the failure
	t.Setenv("PATH", fakeProgram(t, "open", `sleep 0.3; echo "Unable to find application named 'iTerm'" >&2; exit 1`)+":/usr/bin:/bin")
	defer func(orig time.Duration) { exitGrace = orig }(exitGrace)
	exitGrace = 50 * time.Millisecond
	temp := t.TempDir()
	l := Launcher{GOOS: "darwin", Terminal: config.Terminal{App: "iterm2"}, TempDir: temp}
	err := l.Open("#!/bin/sh\n")
	if !apperr.Is(err, apperr.TerminalFailed) || !strings.Contains(apperr.MessageOf(err), "Unable to find application named 'iTerm'") {
		t.Fatalf("Open() = %v, want TERMINAL_FAILED carrying open's message", err)
	}
	noScriptsLeft(t, temp)
}

func TestOpenSucceedsWhenOpenAcceptsTheRequest(t *testing.T) {
	t.Setenv("PATH", fakeProgram(t, "open", "exit 0"))
	l := Launcher{GOOS: "darwin", Terminal: config.Terminal{App: "default"}, TempDir: t.TempDir()}
	if err := l.Open("#!/bin/sh\n"); err != nil {
		t.Fatal(err)
	}
}

func TestOpenGivesUpOnAnOpenThatNeverAnswers(t *testing.T) {
	t.Setenv("PATH", fakeProgram(t, "open", "exec sleep 30")+":/usr/bin:/bin")
	defer func(orig time.Duration) { openTimeout = orig }(openTimeout)
	openTimeout = 200 * time.Millisecond
	l := Launcher{GOOS: "darwin", Terminal: config.Terminal{App: "default"}, TempDir: t.TempDir()}
	start := time.Now()
	err := l.Open("#!/bin/sh\n")
	if !apperr.Is(err, apperr.TerminalFailed) {
		t.Fatalf("Open() = %v, want TERMINAL_FAILED", err)
	}
	if took := time.Since(start); took < openTimeout || took > 10*time.Second {
		t.Fatalf("Open took %s; it should give up when the timeout (%s) runs out", took, openTimeout)
	}
}

// Other terminals live as long as their window: Open can't wait for them,
// but one that exits at once with an error (no display, bad option) has failed.
func TestOpenReportsALinuxTerminalThatExitsAtOnce(t *testing.T) {
	defer func(orig time.Duration) { exitGrace = orig }(exitGrace)
	exitGrace = 5 * time.Second
	for _, tc := range []struct {
		name, body string
		wantErr    string // "" = success
	}{
		{"fails at once", `echo "cannot open display" >&2; exit 1`, "cannot open display"},
		{"hands over to a server and exits", "exit 0", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := filepath.Join(fakeProgram(t, "fake-term", tc.body), "fake-term")
			temp := t.TempDir()
			l := Launcher{GOOS: "linux", Terminal: config.Terminal{App: "custom", Command: term + " {script}"}, TempDir: temp}
			err := l.Open("#!/bin/sh\n")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !apperr.Is(err, apperr.TerminalFailed) || !strings.Contains(apperr.MessageOf(err), tc.wantErr) {
				t.Fatalf("Open() = %v, want TERMINAL_FAILED carrying %q", err, tc.wantErr)
			}
			noScriptsLeft(t, temp)
		})
	}
}

// A terminal that hands over to a window process of its own and exits keeps
// the stderr pipe: closing our end would kill that process with SIGPIPE at
// its first warning.
func TestHandedOverTerminalCanStillWriteToStderr(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "alive")
	body := `( sleep 3; echo warning >&2; echo alive > "` + mark + `" ) >/dev/null & exit 0`
	term := filepath.Join(fakeProgram(t, "fake-term", body), "fake-term")
	defer func(orig time.Duration) { exitGrace = orig }(exitGrace)
	exitGrace = 100 * time.Millisecond
	l := Launcher{GOOS: "linux", Terminal: config.Terminal{App: "custom", Command: term + " {script}"}, TempDir: t.TempDir()}
	if err := l.Open("#!/bin/sh\n"); err != nil {
		t.Fatal(err)
	}
	for range 100 { // the background process writes after three seconds
		if _, err := os.Stat(mark); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the terminal's window process was killed when it wrote to stderr")
}

func TestOpenDoesNotWaitForARunningTerminal(t *testing.T) {
	term := filepath.Join(fakeProgram(t, "fake-term", "exec sleep 3"), "fake-term")
	defer func(orig time.Duration) { exitGrace = orig }(exitGrace)
	exitGrace = 100 * time.Millisecond
	l := Launcher{GOOS: "linux", Terminal: config.Terminal{App: "custom", Command: term + " {script}"}, TempDir: t.TempDir()}
	start := time.Now()
	if err := l.Open("#!/bin/sh\n"); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Open waited for the terminal window to close")
	}
}

// $TERMINAL gets the arguments its terminal needs, from the same table as
// the terminals you can pick; only an unknown one gets the usual -e.
func TestTerminalFromTheEnvironmentUsesTheTable(t *testing.T) {
	path := "/tmp/mis-1.command"
	look := func(string) (string, error) { return "/usr/bin/x", nil }
	for _, tc := range []struct{ terminal, want string }{
		{"wezterm", "wezterm start -- " + path},
		{"kitty", "kitty " + path},
		{"gnome-terminal", "gnome-terminal -- " + path},
		{"xfce4-terminal", "xfce4-terminal -x " + path},
		{"foot", "foot -e " + path}, // not in the table
	} {
		t.Run(tc.terminal, func(t *testing.T) {
			t.Setenv("TERMINAL", tc.terminal)
			name, args, err := Launcher{GOOS: "linux", Terminal: config.Terminal{App: "default"}, LookPath: look}.argv(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(append([]string{name}, args...), " "); got != tc.want {
				t.Fatalf("argv = %q, want %q", got, tc.want)
			}
		})
	}
	t.Setenv("TERMINAL", "wezterm")
	notInstalled := func(n string) (string, error) {
		if n == "xterm" {
			return "/usr/bin/xterm", nil
		}
		return "", exec.ErrNotFound
	}
	if name, _, _ := (Launcher{GOOS: "linux", Terminal: config.Terminal{App: "default"}, LookPath: notInstalled}).argv(path); name != "xterm" {
		t.Fatalf("a $TERMINAL that isn't installed should fall back to the usual choice, got %q", name)
	}
}

// Text from outside (a version string in a feed) must not be able to
// reorder or hide what the banner shows.
func TestPrintableDropsInvisibleFormatting(t *testing.T) {
	for in, want := range map[string]string{
		"1.2-3":                        "1.2-3",
		"caf\u00e9 \u65e5\u672c":       "caf\u00e9 \u65e5\u672c",
		"a\u202eb\u202cc":              "abc",   // right-to-left override and its end
		"x\u2066y\u2067z\u2068w\u2069": "xyzw",  // isolates
		"1\u200b.\u200d2\ufeff":        "1.2",   // zero-width space, joiner, byte order mark
		"a\u2028b\u2029c":              "abc",   // line and paragraph separators
		"a\x1b[2Jb\x07":                "a[2Jb", // control characters, as before
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
	}
}

// The version a vulnerability is fixed in comes from a feed; the banner
// shows it without the characters that could disguise it.
func TestBannerShowsFixedVersionWithoutFormattingCharacters(t *testing.T) {
	f := &findings.Finding{Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1:9.6p1-3", Fixed: "1:9.6p1-4\u202e2.0-9"}
	cmd := &fixcmd.Command{Sudo: "true", Root: "true"}
	lines := Banner("web", []*findings.Finding{f}, cmd)
	for _, text := range append(lines, RemoteScript(lines, cmd)) {
		if strings.ContainsRune(text, '\u202e') {
			t.Fatalf("a right-to-left override reached the banner: %q", text)
		}
	}
	if !strings.Contains(strings.Join(lines, "\n"), "fixed in 1:9.6p1-42.0-9") {
		t.Fatalf("banner = %q", lines)
	}
}
