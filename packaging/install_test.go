//go:build unix

package packaging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeMis stands in for the real binary: the installer calls it to ask
// whether the background service is installed, to restart it, and for its version.
const fakeMis = `#!/bin/sh
case "$1" in
service)
	case "$2" in
	status) echo '{"installed":true}' ;;
	install)
		[ -n "$FAKE_RESTART_FAILS" ] && { echo "fake: cannot start the service" >&2; exit 1; }
		[ -n "$FAKE_RESTART_MARKER" ] && { : > "$FAKE_RESTART_MARKER"; sleep 30; }
		exit 0
		;;
	esac
	;;
version) echo "mis fake" ;;
esac
`

// installRig is install.sh pointed at a release in a temp dir (file://), with
// HOME, PREFIX and TMPDIR in the temp dir too. Nothing real is touched.
type installRig struct {
	t                     *testing.T
	dir, script, tmp, bin string
}

func newInstallRig(t *testing.T) *installRig {
	t.Helper()
	for _, tool := range []string{"curl", "tar", "awk", "install", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s isn't installed", tool)
		}
	}
	// The installer picks its archive by what uname says (which can differ
	// from GOARCH, for example under Rosetta).
	uname := func(flag string) string {
		out, err := exec.Command("uname", flag).Output()
		if err != nil {
			t.Skipf("uname: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	arch := map[string]string{"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}[uname("-m")]
	osName := map[string]string{"Linux": "linux", "Darwin": "darwin"}[uname("-s")]
	if arch == "" || osName == "" {
		t.Skipf("install.sh doesn't support %s %s", uname("-s"), uname("-m"))
	}

	dir := t.TempDir()
	r := &installRig{t: t, dir: dir, tmp: filepath.Join(dir, "tmp"), bin: filepath.Join(dir, "prefix", "bin")}
	for _, d := range []string{r.tmp, filepath.Join(dir, "home"), filepath.Join(dir, "release"), filepath.Join(dir, "stage")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// A release archive with the members listed the way release.yml lists them.
	stage := filepath.Join(dir, "stage")
	members := []string{"mis", "LICENSE", "README.md"}
	write := func(name, content string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(stage, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("mis", fakeMis, 0o755)
	write("LICENSE", "license\n", 0o644)
	write("README.md", "readme\n", 0o644)
	if osName == "darwin" {
		app := filepath.Join(stage, "Make-It-Safer Notifier.app", "Contents", "MacOS")
		if err := os.MkdirAll(app, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(app, "Notifier"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		members = append(members, "Make-It-Safer Notifier.app")
	}
	asset := fmt.Sprintf("mis_%s_%s.tar.gz", osName, arch)
	archive := filepath.Join(dir, "release", asset)
	if out, err := exec.Command("tar", append([]string{"-czf", archive, "-C", stage}, members...)...).CombinedOutput(); err != nil {
		t.Fatalf("tar: %v\n%s", err, out)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x  %s\n", sha256.Sum256(data), asset)
	if err := os.WriteFile(filepath.Join(dir, "release", "checksums.txt"), []byte(sum), 0o600); err != nil {
		t.Fatal(err)
	}

	// install.sh with the download address and the https-only curl flags swapped for the local release.
	src, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(src)
	for _, swap := range [][2]string{
		{`base="https://github.com/$repo/releases/latest/download"`, `base="file://` + filepath.Join(dir, "release") + `"`},
		{`--proto '=https' --tlsv1.2 `, ``},
	} {
		if !strings.Contains(script, swap[0]) {
			t.Fatalf("install.sh no longer contains %q; update this test", swap[0])
		}
		script = strings.ReplaceAll(script, swap[0], swap[1])
	}
	r.script = filepath.Join(dir, "install.sh")
	if err := os.WriteFile(r.script, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *installRig) command(ctx context.Context, env ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "sh", r.script)
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Join(r.dir, "home"),
		"PREFIX=" + filepath.Join(r.dir, "prefix"),
		"TMPDIR=" + r.tmp,
	}, env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // so a signal can reach the whole script, like Ctrl-C
	return cmd
}

// leftovers lists what the installer left in its temp dir.
func (r *installRig) leftovers() []string {
	entries, _ := os.ReadDir(r.tmp)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestInstallScriptInstalls(t *testing.T) {
	r := newInstallRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := r.command(ctx)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("install.sh: %v\nstdout:\n%s\nstderr:\n%s", err, &stdout, &stderr)
	}
	info, err := os.Stat(filepath.Join(r.bin, "mis"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("mis not installed as 0755: %v, %v", info, err)
	}
	for _, want := range []string{"Checksum matches", "Restarted the background service", "Next: run  mis init"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, &stdout)
		}
	}
	if left := r.leftovers(); len(left) > 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

// If the service can't be restarted, the new version is not running: the
// installer must say so and fail instead of finishing as if all was well.
func TestInstallScriptReportsAFailedRestart(t *testing.T) {
	r := newInstallRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := r.command(ctx, "FAKE_RESTART_FAILS=1")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	var exit *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Fatalf("exit = %v, want a non-zero exit code\nstdout:\n%s\nstderr:\n%s", err, &stdout, &stderr)
	}
	if !strings.Contains(stderr.String(), "could not be restarted") || !strings.Contains(stderr.String(), "service install") {
		t.Errorf("stderr doesn't say what to do:\n%s", &stderr)
	}
	if strings.Contains(stdout.String(), "Next:") {
		t.Errorf("printed the success epilogue:\n%s", &stdout)
	}
}

// Ctrl-C and kill during the restart must stop the installer. Without a
// trap that exits, it ran on, printed "Next: run mis init" and exited 0.
func TestInstallScriptStopsOnSignals(t *testing.T) {
	for _, tc := range []struct {
		name string
		sig  syscall.Signal
		code int
	}{
		{"interrupt", syscall.SIGINT, 130},
		{"terminate", syscall.SIGTERM, 143},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newInstallRig(t)
			marker := filepath.Join(r.dir, "restarting")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var stdout bytes.Buffer
			cmd := r.command(ctx, "FAKE_RESTART_MARKER="+marker)
			cmd.Stdout = &stdout
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
				if _, err := os.Stat(marker); err == nil {
					break
				}
				if time.Now().After(deadline) {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					t.Fatalf("the installer never reached the restart\nstdout:\n%s", &stdout)
				}
			}
			if err := syscall.Kill(-cmd.Process.Pid, tc.sig); err != nil {
				t.Fatal(err)
			}
			var exit *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exit) || exit.ExitCode() != tc.code {
				t.Fatalf("wait: %v, want exit code %d\nstdout:\n%s", err, tc.code, &stdout)
			}
			if strings.Contains(stdout.String(), "Next:") {
				t.Errorf("ran on after the signal:\n%s", &stdout)
			}
			if left := r.leftovers(); len(left) > 0 {
				t.Errorf("temp files left behind: %v", left)
			}
		})
	}
}

// install.sh unpacks into a 0700 temp dir. An archive that starts with a "./"
// entry makes GNU tar loosen that dir to 0755, so release archives list their
// members by name.
func TestReleaseArchivesListMembers(t *testing.T) {
	data, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "tar -czf") {
			continue
		}
		found++
		fields := strings.Fields(line)
		if last := fields[len(fields)-1]; last == "." || last == "./" {
			t.Errorf("archives the whole directory instead of listing members: %s", strings.TrimSpace(line))
		}
	}
	if found != 2 {
		t.Errorf("found %d tar commands in release.yml, want 2 (Linux and macOS)", found)
	}
}
