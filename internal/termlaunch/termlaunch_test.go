package termlaunch

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/fixcmd"
)

var server = config.Server{Name: "ovh-web-1", Host: "203.0.113.10", Port: 2222, AdminSSH: "ubuntu@203.0.113.10"}

func TestRemoteScriptAndCommand(t *testing.T) {
	cmd := &fixcmd.Command{Sudo: "sudo apt-get update && sudo apt-get install --only-upgrade openssh-server", Root: "apt-get update && apt-get install --only-upgrade openssh-server", Notes: []string{"it's fine"}}
	banner := Banner("ovh-web-1", []*findings.Finding{{Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1:9.6p1-3ubuntu13.5", Fixed: "1:9.6p1-3ubuntu13.8", KEV: true}}, cmd)
	banner = append(banner, "evil \x1b[2J escape")
	script := RemoteScript(banner, cmd)
	if strings.Contains(script, "\x1b") {
		t.Fatal("escape codes must not reach the terminal")
	}
	if out, err := exec.Command("bash", "-n", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("remote script is not valid bash: %v\n%s\n%s", err, out, script)
	}
	if !strings.Contains(script, `read -r -e -i "$c"`) || !strings.Contains(script, "(actively exploited)") {
		t.Fatalf("script lacks the prefill or banner:\n%s", script)
	}

	remote := RemoteCommand(script)
	b64 := strings.TrimSuffix(strings.TrimPrefix(remote, `bash -c "$(printf %s `), ` | base64 -d)"`)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || string(decoded) != script {
		t.Fatalf("RemoteCommand does not carry the script intact: %v", err)
	}
}

// TestPrefillRunsOnlyWithEnter runs the real prefill logic in bash with
// input coming from a pipe: without a terminal, nothing must run.
func TestPrefillRunsOnlyWithEnter(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	cmd := &fixcmd.Command{Root: "touch " + marker, Sudo: "touch " + marker}
	script := strings.Replace(RemoteScript([]string{"test"}, cmd), `exec "${SHELL:-/bin/bash}" -l`, "true", 1)
	run := exec.Command("bash", "-c", script)
	run.Stdin = strings.NewReader("") // input ends: like Ctrl-D
	_ = run.Run()
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command ran without Enter")
	}
}

func TestFixLauncherRunsYourSSH(t *testing.T) {
	dir := t.TempDir()
	fakeSSH := filepath.Join(dir, "ssh")
	if err := os.WriteFile(fakeSSH, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\"; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "mis-x.command")
	if err := os.WriteFile(launcher, []byte(FixLauncher(server, "REMOTE 'quoted' $(not run)")), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(launcher)
	cmd.Env = append(os.Environ(), "PATH="+dir+":/usr/bin:/bin")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := "[-t][-p][2222][--][ubuntu@203.0.113.10][REMOTE 'quoted' $(not run)]"; string(out) != want {
		t.Fatalf("ssh got %s, want %s", out, want)
	}
	if _, err := os.Stat(launcher); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the launcher script must delete itself")
	}
}

func TestTerminalChoice(t *testing.T) {
	path := "/tmp/mis-1.command"
	mac := Launcher{GOOS: "darwin", Terminal: config.Terminal{App: "default"}}
	if name, args, _ := mac.argv(path); name != "open" || strings.Join(args, " ") != "-a Terminal "+path {
		t.Fatalf("mac default = %s %v", name, args)
	}
	found := func(names ...string) func(string) (string, error) {
		return func(n string) (string, error) {
			for _, x := range names {
				if x == n {
					return "/usr/bin/" + n, nil
				}
			}
			return "", exec.ErrNotFound
		}
	}
	t.Setenv("TERMINAL", "")
	linux := Launcher{GOOS: "linux", Terminal: config.Terminal{App: "default"}, LookPath: found("konsole", "xterm")}
	if name, args, _ := linux.argv(path); name != "konsole" || strings.Join(args, " ") != "-e "+path {
		t.Fatalf("linux default = %s %v", name, args)
	}
	custom := Launcher{Terminal: config.Terminal{App: "custom", Command: "foot --hold {script}"}}
	if name, args, _ := custom.argv(path); name != "foot" || strings.Join(args, " ") != "--hold "+path {
		t.Fatalf("custom = %s %v", name, args)
	}
	none := Launcher{GOOS: "linux", Terminal: config.Terminal{App: "default"}, LookPath: found()}
	if _, _, err := none.argv(path); !apperr.Is(err, apperr.TerminalNotFound) {
		t.Fatalf("no terminal: %v", err)
	}
}

func TestOpenWritesPrivateScript(t *testing.T) {
	dir := t.TempDir()
	var got []string
	l := Launcher{TempDir: dir, GOOS: "darwin", Terminal: config.Terminal{App: "default"}, Start: func(name string, args ...string) error {
		got = append([]string{name}, args...)
		return nil
	}}
	if err := l.Open(LocalLauncher("/usr/local/bin/mis", "unlock")); err != nil {
		t.Fatal(err)
	}
	script := got[len(got)-1]
	info, err := os.Stat(script)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("script %s mode %v, %v", script, info.Mode().Perm(), err)
	}
	data, _ := os.ReadFile(script)
	if !strings.Contains(string(data), "/usr/local/bin/mis unlock") {
		t.Fatalf("script:\n%s", data)
	}
}

func TestAvailable(t *testing.T) {
	look := func(name string) (string, error) {
		if name == "kitty" || name == "foot" {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
	for _, tc := range []struct {
		goos string
		term config.Terminal
		ok   bool
	}{
		{"linux", config.Terminal{App: "default"}, true}, // kitty is in the default chain
		{"linux", config.Terminal{App: "kitty"}, true},
		{"linux", config.Terminal{App: "konsole"}, false},
		{"linux", config.Terminal{App: "custom", Command: "foot {script}"}, true},
		{"linux", config.Terminal{App: "custom", Command: "nope {script}"}, false},
		{"darwin", config.Terminal{App: "default"}, true},
		{"darwin", config.Terminal{App: "iterm2"}, false}, // no iTerm.app on this machine
		{"darwin", config.Terminal{App: "konsole"}, false},
	} {
		err := Launcher{Terminal: tc.term, GOOS: tc.goos, LookPath: look}.Available()
		if (err == nil) != tc.ok {
			t.Errorf("%s %+v: %v, want ok=%v", tc.goos, tc.term, err, tc.ok)
		}
	}
}
