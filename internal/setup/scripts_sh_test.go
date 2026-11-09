package setup

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests run parts of the real scripts under dash, the /bin/sh of
// Debian and Ubuntu, with stub commands and temp paths. They need no server
// and no root; the Docker tests in integration_test.go run the whole thing.

func dashPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	return p
}

// runShell runs program under dash with args and returns its output and exit
// code (-1 when a signal killed it).
func runShell(t *testing.T, dir string, env []string, program string, args ...string) (string, int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "program.sh")
	if err := os.WriteFile(path, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(dashPath(t), append([]string{path}, args...)...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return string(out), 0
}

var plainEnv = []string{"PATH=/usr/bin:/bin"}

// between returns the part of s from the start marker up to the end marker.
func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	j := strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatalf("script no longer has the markers %q ... %q", start, end)
	}
	return s[i:j]
}

// shellFunc returns the definition of a top-level shell function: from
// "name() {" to the next line that is just "}".
func shellFunc(t *testing.T, s, name string) string {
	t.Helper()
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != name+"() {" {
			continue
		}
		for j := i; j < len(lines); j++ {
			if lines[j] == "}" {
				return strings.Join(lines[i:j+1], "\n") + "\n"
			}
		}
	}
	t.Fatalf("script has no function %s", name)
	return ""
}

func renderedScript(t *testing.T) string {
	t.Helper()
	script, err := Script(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func TestSetupPatternMatching(t *testing.T) {
	cases := []struct {
		word, patterns string
		want           bool
	}{
		{"mis", "mis", true},
		{"mis", "admin mis", true},
		{"mis", "admin mis-admin", false}, // a longer name is not a match
		{"mis", "admin m*", true},
		{"mis", "*", true},
		{"mis", "m?s", true},
		{"mis", "mi", false},
		{"mis", "mis@203.0.113.*", true}, // only the user part is compared
		{"mis", "!mis *", true},          // sshd reads "!" in these lists as an ordinary character
		{"mis", "* !mis", true},
		{"mis", "!root *", true},
		{"mis", "!root", false},
		{"mis", "!mis", false}, // a name that starts with "!" is not "mis"
		{"!mis", "!mis", true},
		{"mis", "", false},
		{"ssh-users", "sudo ssh-*", true},
	}
	script := renderedScript(t)
	program := "set -eu\n" + shellFunc(t, script, "matches") +
		`if matches "$1" "$2"; then echo match; else echo nomatch; fi` + "\n"
	cwd := t.TempDir() // a file called "admin" must not make * expand
	if err := os.WriteFile(filepath.Join(cwd, "admin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.word+"/"+tc.patterns, func(t *testing.T) {
			out, code := runShell(t, cwd, plainEnv, program, tc.word, tc.patterns)
			got := strings.TrimSpace(out) == "match"
			if code != 0 || got != tc.want {
				t.Fatalf("matches %q %q = %v (exit %d, %q), want %v", tc.word, tc.patterns, got, code, out, tc.want)
			}
		})
	}
}

func TestSetupChecksSSHAccessRules(t *testing.T) {
	cases := []struct {
		name     string
		settings string // sshd -T lines for the mis user
		blocked  string // text of the failure, empty when setup may go on
	}{
		{"no rules", "", ""},
		{"AllowUsers without mis", "allowusers admin", "AllowUsers"},
		{"AllowUsers lookalike", "allowusers admin mis-admin", "AllowUsers"},
		{"AllowUsers pattern", "allowusers admin m*", ""},
		{"AllowUsers star", "allowusers *", ""},
		{"AllowUsers with host", "allowusers mis@203.0.113.*", ""},
		{"DenyUsers mis", "denyusers mis", "DenyUsers"},
		{"DenyUsers pattern", "denyusers m?s", "DenyUsers"},
		{"DenyUsers lookalike", "denyusers mis-admin root", ""},
		{"AllowGroups without mis", "allowgroups wheel", "AllowGroups"},
		{"AllowGroups with mis", "allowgroups sudo mis", ""},
		{"AllowGroups pattern", "allowgroups m*", ""},
		{"AllowGroups with a !pattern", "allowgroups !mis *", ""}, // "!" is not a negation in sshd's lists
		{"AllowGroups only a !pattern", "allowgroups !staff", "AllowGroups"},
		{"AllowUsers only a !pattern", "allowusers !mis", "AllowUsers"},
		{"DenyUsers only a !pattern", "denyusers !mis", ""},
		{"DenyGroups star but !mis", "denygroups * !mis", "DenyGroups"},
		{"DenyGroups mis", "denygroups mis", "DenyGroups"},
		{"DenyGroups other", "denygroups ssh-users", ""},
		{"Allow and Deny together", "allowusers mis\ndenygroups mi*", "DenyGroups"},
	}
	script := renderedScript(t)
	program := "set -eu\n" +
		"fail() { printf 'ERROR: %s\\n' \"$*\" >&2; exit 1; }\n" +
		"MIS_USER=mis\nMIS_GROUPS=mis\nMIS_SETTINGS=$1\n" +
		shellFunc(t, script, "matches") + shellFunc(t, script, "check_access") +
		"check_access\necho ok\n"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runShell(t, t.TempDir(), plainEnv, program, tc.settings)
			switch {
			case tc.blocked == "" && (code != 0 || !strings.Contains(out, "ok")):
				t.Fatalf("setup should go on, got exit %d: %s", code, out)
			case tc.blocked != "" && (code != 1 || !strings.Contains(out, tc.blocked)):
				t.Fatalf("setup should stop mentioning %s, got exit %d: %s", tc.blocked, code, out)
			}
		})
	}
}

// signalsWork reports whether this environment lets a shell trap sig (a
// signal ignored when the test process started cannot be trapped).
func signalsWork(t *testing.T, sig string) bool {
	t.Helper()
	_, code := runShell(t, t.TempDir(), plainEnv, "trap 'exit 7' "+sig+"\nkill -"+sig+" $$\nexit 0\n")
	return code == 7
}

// rollbackHarness is the script's rollback and trap setup with the system
// commands replaced by stubs that log to dir/log. say fails, like a terminal
// that has hung up.
func rollbackHarness(t *testing.T, dir string) string {
	t.Helper()
	machinery := between(t, renderedScript(t), "CREATED_USER=no", "# 1. The user")
	return "set -eu\n" +
		"LOG=" + filepath.Join(dir, "log") + "\n" +
		"MIS_USER=mis\nMIS_HOME=" + filepath.Join(dir, "home") + "\nLIB_DIR=" + filepath.Join(dir, "lib") + "\n" +
		"MAIN=" + filepath.Join(dir, "sshd_config") + "\nDROPIN=" + filepath.Join(dir, "50-mis.conf") + "\nBLOCK=block\n" +
		"say() { echo \"say: $*\" >> \"$LOG\"; return 1; }\n" +
		"fail() { printf 'ERROR: %s\\n' \"$*\" >&2; exit 1; }\n" +
		"reload_sshd() { echo reload >> \"$LOG\"; }\n" +
		"userdel() { echo \"userdel $*\" >> \"$LOG\"; }\n" +
		machinery
}

func TestSetupRollsBackWhenSessionEnds(t *testing.T) {
	for _, sig := range []string{"HUP", "TERM", "INT"} {
		t.Run(sig, func(t *testing.T) {
			if !signalsWork(t, sig) {
				t.Skip(sig + " is ignored in this environment")
			}
			dir := t.TempDir()
			program := rollbackHarness(t, dir) +
				"CREATED_USER=yes\nDROPIN_STATE=new\n" +
				"mkdir -p \"$MIS_HOME\" \"$LIB_DIR\"\n: > \"$DROPIN\"\n" +
				"kill -" + sig + " $$\n" +
				"echo not-reached >> \"$LOG\"\n"
			_, code := runShell(t, dir, plainEnv, program)
			logged, _ := os.ReadFile(filepath.Join(dir, "log"))
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if !strings.Contains(string(logged), "userdel mis") {
				t.Errorf("the mis user was not removed, log:\n%s", logged)
			}
			if strings.Contains(string(logged), "not-reached") {
				t.Errorf("the script went on after %s", sig)
			}
			for _, name := range []string{"home", "lib", "50-mis.conf"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
					t.Errorf("%s was left behind", name)
				}
			}
		})
	}
}

// A failed or partial backup of sshd_config must never be moved back over
// the real file by the rollback.
func TestSetupBackupFailureKeepsSSHDConfig(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(main, []byte("Port 22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	step3 := between(t, renderedScript(t), "# 3. sshd:", "# 4. Prove it")
	program := rollbackHarness(t, dir) +
		"cp() { printf partial > \"$3\"; return 1; }\n" + // a copy that dies half-way
		step3
	out, code := runShell(t, dir, plainEnv, program)
	if code != 1 || !strings.Contains(out, "cannot back up") {
		t.Fatalf("exit %d, output %q; want a failure naming the backup", code, out)
	}
	if got, _ := os.ReadFile(main); string(got) != "Port 22\n" {
		t.Errorf("sshd_config is now %q", got)
	}
	if _, err := os.Stat(main + ".mis-bak"); err == nil {
		t.Error("the partial backup was left behind")
	}
}

func TestTeardownKeepsMarkerWhenUserCannotBeRemoved(t *testing.T) {
	for _, userdelFails := range []bool{true, false} {
		t.Run("userdel fails="+strconv.FormatBool(userdelFails), func(t *testing.T) {
			dir := t.TempDir()
			script := TeardownScript()
			for old, now := range map[string]string{
				"MIS_HOME=/var/lib/mis":                     "MIS_HOME=" + dir + "/home",
				"LIB_DIR=/usr/local/lib/mis":                "LIB_DIR=" + dir + "/lib",
				"DROPIN=/etc/ssh/sshd_config.d/50-mis.conf": "DROPIN=" + dir + "/50-mis.conf",
				"MAIN=/etc/ssh/sshd_config":                 "MAIN=" + dir + "/sshd_config",
				"[ -f /run/sshd.pid ]":                      "[ -f " + dir + "/sshd.pid ]",
			} {
				if strings.Count(script, old) != 1 {
					t.Fatalf("teardown no longer contains %q exactly once", old)
				}
				script = strings.Replace(script, old, now, 1)
			}
			stubs := filepath.Join(dir, "bin")
			if err := os.Mkdir(stubs, 0o700); err != nil {
				t.Fatal(err)
			}
			userdel := "exit 0"
			if userdelFails {
				userdel = "echo 'userdel: user mis is currently used by process 4242' >&2\nexit 8"
			}
			for name, body := range map[string]string{
				"id":        "if [ \"$1\" = -u ]; then echo 0; fi\nexit 0", // root, and the mis user exists
				"sshd":      "exit 0",
				"pkill":     "exit 0",
				"pgrep":     "exit 1", // no process left
				"systemctl": "exit 1", // not active
				"userdel":   userdel,
			} {
				if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(dir, "home", ".managed-by-make-it-safer")
			if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marker, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			out, code := runShell(t, dir, []string{"PATH=" + stubs + ":/usr/bin:/bin"}, script)
			_, markerErr := os.Stat(marker)
			if userdelFails {
				if code == 0 || strings.Contains(out, "done") || markerErr != nil {
					t.Fatalf("teardown must fail and keep the marker: exit %d, marker error %v, output %q", code, markerErr, out)
				}
				return
			}
			if code != 0 || !strings.Contains(out, "mis-teardown: done") || markerErr == nil {
				t.Fatalf("teardown should finish and remove everything: exit %d, marker error %v, output %q", code, markerErr, out)
			}
		})
	}
}
