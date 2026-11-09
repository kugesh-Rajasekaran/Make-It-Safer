package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Removing the background service must work when config.yaml is missing or
// broken (make uninstall runs it, then deletes the binary). The fake keeps
// the test away from the real LaunchAgent or systemd unit.
func TestServiceUninstallNeedsNoConfig(t *testing.T) {
	for name, prepare := range map[string]func(config.Paths){
		"no config":      func(config.Paths) {},
		"invalid config": func(p config.Paths) { writeFile(t, p.Config, "version: 1\nschedule:\n  servers: 30m\n") },
		"not yaml":       func(p config.Paths) { writeFile(t, p.Config, "{{{ not yaml") },
	} {
		t.Run(name, func(t *testing.T) {
			paths := config.PathsAt(filepath.Join(t.TempDir(), "mis"))
			t.Setenv(config.EnvHome, paths.Home)
			if err := paths.Ensure(); err != nil {
				t.Fatal(err)
			}
			prepare(paths)

			var out, errOut bytes.Buffer
			a := newApp([]string{"service", "uninstall", "--json"}, nil, &out, &errOut)
			var removed []config.Paths
			a.uninstallService = func(p config.Paths) error { removed = append(removed, p); return nil }
			if code := a.execute([]string{"service", "uninstall", "--json"}); code != 0 {
				t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
			}
			if e := decode(t, out.String()); !e.OK {
				t.Fatalf("envelope: %s", out.String())
			}
			if len(removed) != 1 || removed[0].Home != paths.Home {
				t.Errorf("uninstallService calls = %+v, want one for %s", removed, paths.Home)
			}
		})
	}
}

func TestServiceUninstallReportsFailure(t *testing.T) {
	t.Setenv(config.EnvHome, filepath.Join(t.TempDir(), "mis"))
	var out, errOut bytes.Buffer
	a := newApp(nil, nil, &out, &errOut)
	a.uninstallService = func(config.Paths) error { return errors.New("launchctl failed") }
	if code := a.execute([]string{"service", "uninstall"}); code != 1 {
		t.Fatalf("exit %d, want 1: %s%s", code, out.String(), errOut.String())
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
