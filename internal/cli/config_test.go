package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// newConfigHome creates an initialised install with the default settings.
func newConfigHome(t *testing.T) config.Paths {
	t.Helper()
	paths := config.PathsAt(filepath.Join(t.TempDir(), "mis"))
	t.Setenv(config.EnvHome, paths.Home)
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestConfigGet(t *testing.T) {
	newConfigHome(t)
	code, out, _ := runCLI(t, "config", "get", "--json")
	var all []settingValue
	if e := decode(t, out); code != 0 || !e.OK || json.Unmarshal(e.Data, &all) != nil {
		t.Fatalf("exit %d: %s", code, out)
	}
	if len(all) != len(config.Settings()) {
		t.Fatalf("got %d settings, want %d", len(all), len(config.Settings()))
	}

	code, out, _ = runCLI(t, "config", "get", "rules.remind.high")
	if code != 0 || out != "1d\n" {
		t.Fatalf("exit %d, output %q", code, out)
	}

	code, out, _ = runCLI(t, "config", "get", "rules.nope", "--json")
	if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "CONFIG_UNKNOWN_SETTING" {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestConfigSetSavesAndValidates(t *testing.T) {
	paths := newConfigHome(t)
	code, out, _ := runCLI(t, "config", "set", "rules.remind.high", "10m")
	if code != 0 || !strings.Contains(out, "rules.remind.high = 10m") {
		t.Fatalf("exit %d, output %q", code, out)
	}
	if cfg, err := config.Load(paths.Config); err != nil || config.FormatDuration(time.Duration(cfg.Rules.Remind.High)) != "10m" {
		t.Fatalf("not saved: %v", err)
	}

	before, _ := os.ReadFile(paths.Config)
	code, out, _ = runCLI(t, "config", "set", "rules.alert_when.min_severity", "11", "--json")
	if e := decode(t, out); code != 1 || e.Error == nil || e.Error.Code != "CONFIG_INVALID" {
		t.Fatalf("exit %d: %s", code, out)
	}
	if after, _ := os.ReadFile(paths.Config); string(after) != string(before) {
		t.Fatal("a rejected value changed config.yaml")
	}
}

func TestConfigWithoutTerminalPrintsTheList(t *testing.T) {
	newConfigHome(t)
	code, out, _ := runCLI(t, "config")
	if code != 0 || !strings.Contains(out, "rules.alert_when.min_severity") || !strings.Contains(out, "mis config set") {
		t.Fatalf("exit %d, output %q", code, out)
	}
}

func TestScreenScrollsTenRowsAtATime(t *testing.T) {
	noColor = true
	s := newScreen(true)
	want := 0
	for _, setting := range config.Settings() {
		if !setting.Hidden {
			want++
		}
	}
	if len(s.rows) != want+1 { // + auto-unlock
		t.Fatalf("%d rows, want %d", len(s.rows), want+1)
	}
	value := func(screenRow) string { return "v" }

	hidden := len(s.rows) - screenRows
	first := s.render(value, "")
	if !strings.Contains(first, "› ") || strings.Contains(first, "↑ ") || !strings.Contains(first, fmt.Sprintf("↓ %d more", hidden)) {
		t.Fatalf("first screen:\n%s", first)
	}
	if got := strings.Count(first, " v\r\n"); got != screenRows {
		t.Fatalf("%d rows shown, want %d:\n%s", got, screenRows, first)
	}

	for range screenRows { // one past the bottom scrolls by one
		s.move(1)
	}
	if s.cur != screenRows || s.top != 1 {
		t.Fatalf("cur %d top %d, want %d and 1", s.cur, s.top, screenRows)
	}
	if out := s.render(value, ""); !strings.Contains(out, "↑ 1 more") || !strings.Contains(out, fmt.Sprintf("↓ %d more", hidden-1)) {
		t.Fatalf("scrolled screen:\n%s", out)
	}

	s.move(100)
	if s.cur != len(s.rows)-1 || s.top != len(s.rows)-screenRows {
		t.Fatalf("bottom: cur %d top %d", s.cur, s.top)
	}
	s.move(-100)
	if s.cur != 0 || s.top != 0 {
		t.Fatalf("top: cur %d top %d", s.cur, s.top)
	}
}

func TestReadKey(t *testing.T) {
	cases := map[string]key{
		"\x1b[A": keyUp, "\x1b[B": keyDown, "\x1bOA": keyUp, "\x1bOB": keyDown,
		"\r": keyEnter, "\n": keyEnter, "q": keyQuit, "\x03": keyQuit,
		"\x1b": keyEsc, "k": keyUp, "j": keyDown, "x": keyNone, "\x1b[C": keyNone,
	}
	for in, want := range cases {
		got, err := readKey(bufio.NewReader(strings.NewReader(in)))
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := readKey(bufio.NewReader(strings.NewReader(""))); err == nil {
		t.Error("closed input should end the screen")
	}
}
