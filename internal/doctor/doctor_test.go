package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/termlaunch"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func want(t *testing.T, name string, r Result, level Level, detail string) {
	t.Helper()
	if r.Level != level || !strings.Contains(r.Detail, detail) {
		t.Errorf("%s: %s %q, want %s containing %q", name, r.Level, r.Detail, level, detail)
	}
	if r.Level != OK && r.Detail == "" {
		t.Errorf("%s: no detail", name)
	}
}

func TestFiles(t *testing.T) {
	paths := config.PathsAt(filepath.Join(t.TempDir(), "h"))
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	want(t, "private", Files(paths), OK, "private")
	if err := os.Chmod(paths.Home, 0o755); err != nil { // too open, on purpose
		t.Fatal(err)
	}
	if r := Files(paths); r.Level != Fail || r.Fix == "" {
		t.Errorf("open folder: %+v", r)
	}
}

func TestNotSynced(t *testing.T) {
	home := "/Users/me"
	for _, tc := range []struct {
		dir   string
		level Level
	}{
		{"/Users/me/Library/Application Support/Make-It-Safer", OK},
		{"/home/me/.config/mis", OK},
		{"/Users/me/Library/Mobile Documents/com~apple~CloudDocs/mis", Fail},
		{"/Users/me/Library/CloudStorage/OneDrive-Personal/mis", Fail},
		{"/home/me/Dropbox/mis", Fail},
		{"/Users/me/Documents/mis", Warn},
		{"/Users/me/Documentsx/mis", OK},
	} {
		if r := NotSynced(tc.dir, home); r.Level != tc.level {
			t.Errorf("%s: %+v, want %s", tc.dir, r, tc.level)
		}
	}
}

func TestService(t *testing.T) {
	want(t, "not installed", Service(&daemon.ServiceInfo{}, nil), Fail, "not installed")
	want(t, "not running", Service(&daemon.ServiceInfo{Installed: true}, nil), Fail, "not running")
	want(t, "locked", Service(&daemon.ServiceInfo{Installed: true}, &daemon.Status{Locked: true}), Warn, "locked")
	want(t, "unlocked", Service(&daemon.ServiceInfo{Installed: true}, &daemon.Status{Version: "1.0"}), OK, "unlocked")
}

func TestNotifications(t *testing.T) {
	want(t, "no service", Notifications(nil), Warn, "isn't running")
	want(t, "banners", Notifications(&daemon.Status{Notifier: "macOS: banner style; choose Alerts"}), Fail, "choose Alerts")
	want(t, "ready", Notifications(&daemon.Status{Notifier: "macOS (Alerts style)", Ready: true}), OK, "Alerts")
}

func TestTerminal(t *testing.T) {
	found := func(string) (string, error) { return "/usr/bin/xterm", nil }
	missing := func(string) (string, error) { return "", os.ErrNotExist }
	l := termlaunch.Launcher{Terminal: config.Terminal{App: "kitty"}, GOOS: "linux", LookPath: found}
	want(t, "installed", Terminal(l), OK, "kitty")
	l.LookPath = missing
	want(t, "missing", Terminal(l), Fail, "isn't installed")
}

func TestDesktop(t *testing.T) {
	want(t, "wayland", Desktop([]string{"HOME=/home/me", "WAYLAND_DISPLAY=wayland-0"}), OK, "open windows")
	want(t, "x11", Desktop([]string{"DISPLAY=:0"}), OK, "open windows")
	want(t, "none", Desktop([]string{"HOME=/home/me", "XDISPLAY=x"}), Warn, "doesn't see your desktop")
}

func TestReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			http.Error(w, "gone", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	fc := feeds.NewForTest(srv.URL)
	up := []Source{{"A", srv.URL + "/a", true}, {"B", srv.URL + "/b", false}}
	want(t, "all up", Reachable(context.Background(), fc, up), OK, "all 2 answer")
	r := Reachable(context.Background(), fc, append(up, Source{"C", srv.URL + "/down", false}))
	want(t, "one down", r, Fail, "C: ")
	if !strings.Contains(r.Fix, strings.TrimPrefix(srv.URL, "http://")) {
		t.Errorf("fix doesn't name the hosts: %q", r.Fix)
	}
	if len(Sources) != 6 {
		t.Errorf("%d sources; keep this list in step with docs/design.md §4.9", len(Sources))
	}
	for _, s := range Sources { // the real list only uses allowlisted hosts
		if !slices.Contains(feeds.AllowedHosts, host(s.URL)) {
			t.Errorf("%s isn't on the allowlist", s.URL)
		}
	}
}

func TestServers(t *testing.T) {
	servers := []config.Server{{Name: "web"}, {Name: "db"}}
	want(t, "none", Servers(nil, nil, now), Warn, "no servers")
	want(t, "fresh", Servers(servers, map[string]time.Time{"web": now.Add(-time.Hour), "db": now.Add(-13 * time.Hour)}, now), OK, "all 2")
	want(t, "stale", Servers(servers, map[string]time.Time{"web": now.Add(-48 * time.Hour)}, now), Warn, "db: never checked")
}

func TestData(t *testing.T) {
	jobs := func(match, early *daemon.JobState) *daemon.Status {
		return &daemon.Status{Jobs: map[string]*daemon.JobState{"match": match, "early": early}}
	}
	want(t, "no service", Data(nil, now), Warn, "isn't running")
	want(t, "never", Data(jobs(&daemon.JobState{}, nil), now), Warn, "no successful check")
	want(t, "stale", Data(jobs(&daemon.JobState{LastOK: now.Add(-30 * time.Hour), LastError: "offline"}, nil), now), Fail, "offline")
	want(t, "early failing", Data(jobs(&daemon.JobState{LastOK: now.Add(-time.Hour)}, &daemon.JobState{LastOK: now.Add(-2 * time.Hour), LastError: "CVE List down"}), now), Warn, "CVE List down")
	want(t, "fine", Data(jobs(&daemon.JobState{LastOK: now.Add(-time.Hour)}, &daemon.JobState{LastOK: now.Add(-10 * time.Minute)}), now), OK, "last check 1h0m0s ago")
}

func host(u string) string {
	rest, _ := strings.CutPrefix(u, "https://")
	h, _, _ := strings.Cut(rest, "/")
	return h
}
