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

func TestAutoUnlock(t *testing.T) {
	want(t, "off", AutoUnlock(false, &daemon.Status{}), OK, "off")
	want(t, "on", AutoUnlock(true, &daemon.Status{}), OK, "unlocks itself")
	want(t, "on, no service", AutoUnlock(true, nil), OK, "unlocks itself")
	want(t, "on but locked", AutoUnlock(true, &daemon.Status{Locked: true}), Warn, "locked")
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

func TestDialogs(t *testing.T) {
	want(t, "zenity", Dialogs(true), OK, "opens its details")
	want(t, "no zenity", Dialogs(false), Warn, "opens the terminal instead")
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
	if len(Sources) != 6 { // the Mac-only source comes on top (SourcesFor)
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
	const day = 26 * time.Hour // the limit with a refresh every 12 hours
	want(t, "none", Servers(nil, nil, day, now), Warn, "no servers")
	want(t, "fresh", Servers(servers, map[string]time.Time{"web": now.Add(-time.Hour), "db": now.Add(-13 * time.Hour)}, day, now), OK, "all 2")
	want(t, "no list", Servers(servers, map[string]time.Time{"web": now.Add(-time.Hour)}, day, now), Warn, "db: no package list yet")
	// The list's age counts, however recently the server was matched.
	want(t, "old list", Servers(servers, map[string]time.Time{"web": now.Add(-time.Hour), "db": now.Add(-72 * time.Hour)}, day, now), Warn, "db: package list is 72h0m0s old")
}

// The limit follows the schedule: servers read every two days are not stale
// after 30 hours, as the background service already judges them.
func TestServersFollowTheSchedule(t *testing.T) {
	servers := []config.Server{{Name: "web"}}
	limit := config.Schedule{Servers: config.Duration(48 * time.Hour)}.ListStaleAfter()
	want(t, "between refreshes", Servers(servers, map[string]time.Time{"web": now.Add(-30 * time.Hour)}, limit, now), OK, "all 1")
	want(t, "missed", Servers(servers, map[string]time.Time{"web": now.Add(-100 * time.Hour)}, limit, now), Warn, "web: package list is 100h0m0s old")
}

// This computer's list is read at every match, not by the refresh job.
func TestServersLeavesOutThisComputer(t *testing.T) {
	servers := []config.Server{{Name: "this-mac", Local: true}, {Name: "web"}}
	got := Servers(servers, map[string]time.Time{"this-mac": now.Add(-500 * time.Hour), "web": now.Add(-time.Hour)}, 26*time.Hour, now)
	want(t, "old local list", got, OK, "all 1")
	only := Servers([]config.Server{{Name: "this-mac", Local: true}}, map[string]time.Time{}, 26*time.Hour, now)
	want(t, "only this computer", only, OK, "only this computer is checked")
}

func TestData(t *testing.T) {
	jobs := func(match, early *daemon.JobState) *daemon.Status {
		return &daemon.Status{Jobs: map[string]*daemon.JobState{"match": match, "early": early}}
	}
	want(t, "no service", Data(nil, now), Warn, "isn't running")
	want(t, "never", Data(jobs(&daemon.JobState{}, nil), now), Warn, "no successful check")
	want(t, "stale", Data(jobs(&daemon.JobState{LastOK: now.Add(-30 * time.Hour), LastError: "offline"}, nil), now), Fail, "offline")
	if r := Data(jobs(&daemon.JobState{LastOK: now.Add(-30 * time.Hour)}, nil), now); strings.Contains(r.Detail, "()") {
		t.Errorf("stale without an error: %q has an empty ()", r.Detail)
	}
	want(t, "early failing", Data(jobs(&daemon.JobState{LastOK: now.Add(-time.Hour)}, &daemon.JobState{LastOK: now.Add(-2 * time.Hour), LastError: "CVE List down"}), now), Warn, "CVE List down")
	want(t, "fine", Data(jobs(&daemon.JobState{LastOK: now.Add(-time.Hour)}, &daemon.JobState{LastOK: now.Add(-10 * time.Minute)}), now), OK, "last check 1h0m0s ago")
}

func host(u string) string {
	rest, _ := strings.CutPrefix(u, "https://")
	h, _, _ := strings.Cut(rest, "/")
	return h
}

// Every host Make-It-Safer may connect to is one doctor probes, on a Mac that
// checks itself (Apple's security notes are used there only).
func TestSourcesCoverTheAllowlist(t *testing.T) {
	probed := func(sources []Source) []string {
		var hosts []string
		for _, s := range sources {
			hosts = append(hosts, host(s.URL))
		}
		return hosts
	}
	mac := probed(SourcesFor("darwin", true))
	for _, h := range feeds.AllowedHosts {
		if !slices.Contains(mac, h) {
			t.Errorf("mis doctor never tries %s", h)
		}
	}
	for _, tc := range []struct {
		goos         string
		thisComputer bool
		n            int
	}{{"darwin", true, 7}, {"darwin", false, 6}, {"linux", true, 6}, {"linux", false, 6}} {
		if got := SourcesFor(tc.goos, tc.thisComputer); len(got) != tc.n {
			t.Errorf("SourcesFor(%s, %v) has %d sources, want %d", tc.goos, tc.thisComputer, len(got), tc.n)
		}
	}
	if len(Sources) != 6 {
		t.Errorf("SourcesFor changed the shared list: %d sources", len(Sources))
	}
}
