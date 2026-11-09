package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
)

var noon = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// The match job succeeds on whatever package lists exist, so a list that
// stopped refreshing (locked service, a server that won't answer) has to be
// noticed by its own age.
func TestOldPackageListsAreReported(t *testing.T) {
	for _, tc := range []struct {
		name      string
		listAge   time.Duration
		matchAge  time.Duration // since the match job last succeeded
		local     bool          // the list belongs to this computer
		refresh   time.Duration // schedule.servers; 0 = the default
		wantTitle string
		wantBody  []string
	}{
		{name: "three days old", listAge: 72 * time.Hour, wantTitle: "Package lists are getting old", wantBody: []string{"web (3 days old)", "mis check"}},
		{name: "just over a day", listAge: 25 * time.Hour, wantTitle: "Package lists are getting old", wantBody: []string{"web (25 hours old)"}},
		{name: "fresh", listAge: 3 * time.Hour},
		{name: "one missed refresh", listAge: 23 * time.Hour},
		{name: "this computer is read at every match", listAge: 72 * time.Hour, local: true},
		{name: "refreshing every two days", listAge: 72 * time.Hour, refresh: 48 * time.Hour},
		{name: "refreshing every two days, missed", listAge: 100 * time.Hour, refresh: 48 * time.Hour, wantTitle: "Package lists are getting old", wantBody: []string{"web (4 days old)"}},
		{name: "matching stopped too", listAge: 72 * time.Hour, matchAge: 30 * time.Hour, wantTitle: "Vulnerability data is getting old",
			wantBody: []string{"last successful check was 30 hours ago", "web (3 days old)"}},
		{name: "only matching stopped", listAge: time.Hour, matchAge: 30 * time.Hour, wantTitle: "Vulnerability data is getting old",
			wantBody: []string{"last successful check was 30 hours ago"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecorder()
			d, paths := testDaemon(t, rec, nil, io.Discard)
			d.now = func() time.Time { return noon }
			matched := noon.Add(-tc.matchAge)
			d.sched = newScheduler([]*job{{name: "match", every: time.Hour, run: func(context.Context) error { return nil }}},
				filepath.Join(paths.State, "schedule.json"), func() time.Time { return matched }, d.unlocked, d.log)
			d.sched.runDue(context.Background()) // the match job succeeded at "matched"

			if tc.local {
				cfg, _ := config.Load(paths.Config)
				cfg.ThisComputer = true
				if err := cfg.Save(paths.Config); err != nil {
					t.Fatal(err)
				}
				inv := &inventory.Inventory{CollectedAt: noon.Add(-tc.listAge), OSID: "ubuntu", OSVersion: "24.04", Kernel: "6.8.0-49-generic"}
				if err := inventory.Save(paths, config.LocalName(), inv); err != nil {
					t.Fatal(err)
				}
			} else {
				addServer(t, paths, "web", noon.Add(-tc.listAge))
			}
			if tc.refresh > 0 {
				cfg, _ := config.Load(paths.Config)
				cfg.Schedule.Servers = config.Duration(tc.refresh)
				if err := cfg.Save(paths.Config); err != nil {
					t.Fatal(err)
				}
			}

			if err := d.remind(); err != nil {
				t.Fatal(err)
			}
			rec.mu.Lock()
			shown := slices.Clone(rec.shown)
			rec.mu.Unlock()
			if tc.wantTitle == "" {
				if len(shown) != 0 {
					t.Fatalf("nothing is old, but %+v was shown", shown)
				}
				return
			}
			if len(shown) != 1 || shown[0].ID != staleID || shown[0].Title != tc.wantTitle {
				t.Fatalf("want one %q notification, got %+v", tc.wantTitle, shown)
			}
			for _, w := range tc.wantBody {
				if !strings.Contains(shown[0].Body, w) {
					t.Errorf("body %q lacks %q", shown[0].Body, w)
				}
			}

			// Once a day, not at every reminder.
			d.now = func() time.Time { return noon.Add(time.Hour) }
			_ = d.remind()
			if got := len(rec.ids()); got != 1 {
				t.Fatalf("the warning came again after an hour: %v", rec.ids())
			}
		})
	}
}

// Locked, the service can't refresh the servers; the notice shown at start
// comes back once a day until you unlock it.
func TestLockNoticeComesBackWhileLocked(t *testing.T) {
	rec := newRecorder()
	d, _ := testDaemon(t, rec, nil, io.Discard)
	now := noon
	d.now = func() time.Time { return now }
	locked := func() int { return strings.Count(strings.Join(rec.ids(), " "), lockNoticeID) }

	d.showLockNotice() // at the start of the service
	for _, step := range []struct {
		after time.Duration
		want  int
	}{{time.Hour, 1}, {23 * time.Hour, 1}, {25 * time.Hour, 2}, {47 * time.Hour, 2}, {50 * time.Hour, 3}} {
		now = noon.Add(step.after)
		if err := d.remind(); err != nil {
			t.Fatal(err)
		}
		if got := locked(); got != step.want {
			t.Fatalf("%s after the start: lock notice shown %d times, want %d", step.after, got, step.want)
		}
	}

	if err := d.unlock([]byte(passphrase)); err != nil {
		t.Fatal(err)
	}
	now = noon.Add(100 * time.Hour)
	if err := d.remind(); err != nil {
		t.Fatal(err)
	}
	if got := locked(); got != 3 {
		t.Fatalf("shown again after unlocking: %d times", got)
	}
}

// When a group is fixed its notification says what was done, whatever kind
// of finding it was.
func TestDoneNotificationsFitTheKind(t *testing.T) {
	rec := newRecorder()
	d, _ := testDaemon(t, rec, nil, io.Discard)
	me := config.LocalName()
	resolved := func(f *findings.Finding) *findings.Finding {
		f.State, f.NotifiedAt, f.ResolvedAt = findings.StateResolved, noon.Add(-time.Hour), noon
		return f
	}
	cases := []struct {
		f           *findings.Finding
		title, body string
	}{
		{&findings.Finding{Server: me, Kind: findings.KindVulnerability, CVE: "CVE-2026-1001", Source: "macos", Fixed: "15.8.2"},
			"✅ macOS 15.8.2 installed", "Fixed on " + config.LocalLabel() + "."},
		{&findings.Finding{Server: "web", Kind: findings.KindReboot},
			"✅ web restarted", "The pending restart is done."},
		{&findings.Finding{Server: "web", Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh"},
			"✅ CVE-2024-6387 · openssh", "Fixed on all servers."},
		{&findings.Finding{Server: "web", Kind: findings.KindEndOfLife, Installed: "20.04"},
			"✅ web: end of support resolved", "It no longer runs a release that is out of support."},
		{&findings.Finding{Server: "web", Kind: findings.KindUpdates, Installed: "187 outdated"},
			"✅ web: packages up to date", "No outdated packages are left."},
	}
	var done []*findings.Finding
	for _, tc := range cases {
		done = append(done, resolved(tc.f))
	}
	d.alert(&engine.Result{Changes: findings.Changes{Resolved: done}})

	rec.mu.Lock()
	defer rec.mu.Unlock()
	byID := map[string]notify.Notification{}
	for _, n := range rec.shown {
		byID[n.ID] = n
	}
	for _, tc := range cases {
		n, ok := byID[groupKey(tc.f)]
		if !ok || n.Title != tc.title || n.Body != tc.body {
			t.Errorf("%s: got %q | %q, want %q | %q", groupKey(tc.f), n.Title, n.Body, tc.title, tc.body)
		}
	}
}

// failSecond is a notifier whose second Show fails.
type failSecond struct {
	*recorder
	calls int
}

func (f *failSecond) Show(n notify.Notification) error {
	f.calls++
	if f.calls == 2 {
		return errors.New("the notification server went away")
	}
	return f.recorder.Show(n)
}

// A notification that can't be shown is tried again at the next reminder; it
// must not make the service forget the ones it did show.
func TestRemindKeepsWhatItShowedWhenOneFails(t *testing.T) {
	rec := &failSecond{recorder: newRecorder()}
	d, paths := testDaemon(t, rec, nil, io.Discard)
	now := d.now()
	_ = findings.Update(paths, func(st *findings.Store) error {
		var found []*findings.Finding
		for _, cve := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
			found = append(found, &findings.Finding{ID: findings.MakeID("web", findings.KindVulnerability, cve+"/p"), Server: "web",
				Kind: findings.KindVulnerability, CVE: cve, Source: "p", Installed: "1", Fixed: "2", Priority: findings.High})
		}
		st.Merge("web", found, []findings.Kind{findings.KindVulnerability}, now)
		return nil
	})

	if err := d.remind(); err != nil {
		t.Fatalf("remind: %v", err)
	}
	if got := len(rec.ids()); got != 2 {
		t.Fatalf("shown %d notifications, want 2 (the second failed)", got)
	}
	st, _ := findings.Load(paths)
	var notified, waiting int
	for _, f := range st.Findings {
		switch f.State {
		case findings.StateNotified:
			notified++
		case findings.StateNew:
			waiting++
		}
	}
	if notified != 2 || waiting != 1 {
		t.Fatalf("%d notified, %d still waiting; want the two shown recorded and the failed one waiting", notified, waiting)
	}

	if err := d.remind(); err != nil {
		t.Fatal(err)
	}
	if got := len(rec.ids()); got != 3 {
		t.Fatalf("the failed notification wasn't shown at the next reminder: %v", rec.ids())
	}
}

// fix() records a button click while notifications are being built from the
// same map (run with -race).
func TestGroupNotificationWhileButtonsAreClicked(t *testing.T) {
	d, _ := testDaemon(t, newRecorder(), nil, io.Discard)
	cfg := config.Default()
	finding := func(server string) *findings.Finding {
		return &findings.Finding{Server: server, Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Fixed: "2", Priority: findings.High}
	}
	group := []*findings.Finding{finding("a"), finding("b")}
	const key = "cve:CVE-2024-6387"
	d.markClicked(key, "a")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 2000 {
			d.markClicked(key, fmt.Sprint("server-", i%50))
		}
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			d.groupNotification(key, group, 0, &cfg)
		}
	}()
	wg.Wait()

	var labels []string
	for _, b := range d.groupNotification(key, group, 0, &cfg).Buttons {
		labels = append(labels, b.Title)
	}
	if strings.Join(labels, "|") != "a ✓|b|All servers…" {
		t.Fatalf("buttons = %v", labels)
	}
}
