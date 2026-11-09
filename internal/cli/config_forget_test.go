package cli

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Turning this_computer off must not leave its findings behind: they would
// be reminded forever, with fix buttons that fail.
func TestConfigSetThisComputerOffForgetsItsFindings(t *testing.T) {
	local := config.LocalName()
	paths := newConfigHome(t)
	withServers(t, paths, true, "web")
	seedFindings(t, paths, "web", local)

	if code, out, _ := runCLI(t, "config", "set", "notifications.sound", "no"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if loadFindings(t, paths).Find(testFindingID(local)) == nil {
		t.Fatal("an unrelated setting dropped this computer's finding")
	}

	if code, out, _ := runCLI(t, "config", "set", "this_computer", "no"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	st := loadFindings(t, paths)
	if st.Find(testFindingID(local)) != nil || !st.Checked[local].IsZero() {
		t.Error("this computer's finding or check time is still stored")
	}
	if st.Find(testFindingID("web")) == nil {
		t.Error("web's finding was dropped")
	}
}

func screenRowFor(t *testing.T, s *screen, key string) {
	t.Helper()
	for i, r := range s.rows {
		if r.setting != nil && r.setting.Key == key {
			s.cur = i
			return
		}
	}
	t.Fatalf("no row for %s", key)
}

func TestConfigScreenThisComputerOffForgetsItsFindings(t *testing.T) {
	local := config.LocalName()
	paths := newConfigHome(t)
	withServers(t, paths, true, "web")
	seedFindings(t, paths, "web", local)
	cfg, err := config.Load(paths.Config)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	a := newApp(nil, nil, &out, &out)
	s := newScreen(false)
	screenRowFor(t, s, "this_computer")
	if _, saved, err := a.change(paths, cfg, s, nil); err != nil || !saved || cfg.ThisComputer {
		t.Fatalf("saved %v, err %v, this_computer %v", saved, err, cfg.ThisComputer)
	}
	st := loadFindings(t, paths)
	if st.Find(testFindingID(local)) != nil || st.Find(testFindingID("web")) == nil {
		t.Error("only this computer's findings should have been dropped")
	}
}

// The screen's question says "type none to clear the list"; Enter keeps the
// current list, so "none" is the only way to empty it there.
func TestConfigScreenClearsIgnoreLists(t *testing.T) {
	for _, key := range []string{"rules.ignore.packages", "rules.ignore.cves"} {
		t.Run(key, func(t *testing.T) {
			paths := newConfigHome(t)
			cfg := config.Default()
			cfg.Rules.Ignore = config.Ignore{Packages: []string{"tzdata", "linux-firmware"}, CVEs: []string{"CVE-2024-6387"}}
			if err := cfg.Save(paths.Config); err != nil {
				t.Fatal(err)
			}

			var out bytes.Buffer
			a := newApp(nil, nil, &out, &out)
			a.in = bufio.NewReader(strings.NewReader("none\n"))
			s := newScreen(false)
			screenRowFor(t, s, key)
			status, saved, err := a.change(paths, &cfg, s, nil)
			if err != nil || !saved || !strings.Contains(status, "Saved") {
				t.Fatalf("status %q, saved %v, err %v", status, saved, err)
			}
			got, err := config.Load(paths.Config)
			if err != nil {
				t.Fatal(err)
			}
			list := got.Rules.Ignore.Packages
			if key == "rules.ignore.cves" {
				list = got.Rules.Ignore.CVEs
			}
			if len(list) != 0 {
				t.Errorf("%s = %v, want it emptied", key, list)
			}
		})
	}
}
