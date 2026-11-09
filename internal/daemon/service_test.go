package daemon

import (
	"html"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

func TestServiceFiles(t *testing.T) {
	v := serviceValues{Label: launchLabel, Binary: "/Users/me/My Tools/mis", Log: "/Users/me/Library/Logs/MakeItSafer/daemon.log", Home: "/tmp/a&b"}
	plist, err := renderLaunchAgent(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<string>/Users/me/My Tools/mis</string>", "<string>daemon</string>", "<key>RunAtLoad</key>", "/tmp/a&amp;b"} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
	if html.UnescapeString(plist) == plist {
		t.Error("plist values should be XML-escaped")
	}
	unit, err := renderSystemdUnit(serviceValues{Binary: "/home/me/go/bin/mis"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`ExecStart="/home/me/go/bin/mis" daemon`, "WantedBy=graphical-session.target", "Restart=on-failure"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "MIS_HOME") {
		t.Error("MIS_HOME should only be set when it was set")
	}
}

// The service starts without your shell's environment, so a home that came
// from the environment has to be written into it.
func TestServiceKeepsAHomeFromTheEnvironment(t *testing.T) {
	home := filepath.Join(t.TempDir(), "mis")
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"nothing set", nil, ""},
		{"MIS_HOME", map[string]string{config.EnvHome: home}, home},
		{"XDG_CONFIG_HOME", map[string]string{"XDG_CONFIG_HOME": filepath.Dir(home)}, home},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.EnvHome, "")
			t.Setenv("XDG_CONFIG_HOME", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			v, err := valuesFor(config.PathsAt(home))
			if err != nil {
				t.Fatal(err)
			}
			if v.Home != tc.want {
				t.Fatalf("Home = %q, want %q", v.Home, tc.want)
			}
		})
	}
}

// Characters that would break out of a service file are refused.
func TestServiceRefusesUnsafePaths(t *testing.T) {
	t.Setenv(config.EnvHome, "set")
	for _, bad := range []string{`/tmp/a"b`, `/tmp/a\b`, "/tmp/100%", "/tmp/a\nb"} {
		if _, err := valuesFor(config.PathsAt(bad)); err == nil {
			t.Errorf("home %q was accepted", bad)
		}
	}
	if _, err := valuesFor(config.PathsAt("/tmp/fine path")); err != nil {
		t.Errorf("a space is fine: %v", err)
	}
}
