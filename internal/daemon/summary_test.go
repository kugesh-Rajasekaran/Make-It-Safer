package daemon

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
)

// The weekly summary counts the updates that are waiting for you: not the
// ones you snoozed (until the snooze ends), accepted or fixed.
func TestWeeklySummaryCountsOnlyWhatIsWaiting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup map[string]func(f *findings.Finding, now time.Time) // by CVE number
		want  string                                              // "" = no summary
	}{
		{name: "mixed", setup: map[string]func(*findings.Finding, time.Time){
			"2": func(f *findings.Finding, now time.Time) { // snoozed for a day
				_ = f.Transition(findings.StateSnoozed, now)
				f.SnoozedUntil = now.Add(24 * time.Hour)
			},
			"3": func(f *findings.Finding, now time.Time) { _ = f.Transition(findings.StateAccepted, now) },
			"4": func(f *findings.Finding, now time.Time) { // the snooze ended
				_ = f.Transition(findings.StateSnoozed, now)
				f.SnoozedUntil = now.Add(-time.Hour)
			},
			"5": func(f *findings.Finding, now time.Time) { _ = f.Transition(findings.StateResolved, now) },
		}, want: "2 updates with a fix are waiting"},
		{name: "all snoozed", setup: map[string]func(*findings.Finding, time.Time){
			"1": func(f *findings.Finding, now time.Time) {
				_ = f.Transition(findings.StateSnoozed, now)
				f.SnoozedUntil = now.Add(24 * time.Hour)
			},
			"2": func(f *findings.Finding, now time.Time) {
				_ = f.Transition(findings.StateSnoozed, now)
				f.SnoozedUntil = now.Add(24 * time.Hour)
			},
			"3": func(f *findings.Finding, now time.Time) { _ = f.Transition(findings.StateAccepted, now) },
			"4": func(f *findings.Finding, now time.Time) { _ = f.Transition(findings.StateAccepted, now) },
			"5": func(f *findings.Finding, now time.Time) { _ = f.Transition(findings.StateResolved, now) },
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecorder()
			d, paths := testDaemon(t, rec, nil, io.Discard)
			now := d.now()
			_ = findings.Update(paths, func(st *findings.Store) error {
				var all []*findings.Finding
				for i := 1; i <= 5; i++ {
					cve := fmt.Sprintf("CVE-2024-000%d", i)
					all = append(all, &findings.Finding{ID: findings.MakeID("web", findings.KindVulnerability, cve+"/p"), Server: "web",
						Kind: findings.KindVulnerability, CVE: cve, Source: "p", Installed: "1", Fixed: "2", Priority: findings.Normal})
				}
				st.Merge("web", all, []findings.Kind{findings.KindVulnerability}, now)
				for i, f := range all {
					if change := tc.setup[fmt.Sprint(i+1)]; change != nil {
						change(f, now)
					}
				}
				return nil
			})
			if err := d.remind(); err != nil {
				t.Fatal(err)
			}
			var body string
			for _, n := range rec.shown {
				if n.ID == summaryID {
					body = n.Body
				}
			}
			if tc.want == "" && body != "" || !strings.Contains(body, tc.want) {
				t.Fatalf("summary = %q, want one containing %q", body, tc.want)
			}
		})
	}
}

// A terminal that doesn't open is an error you are told about: no ✓ on the
// button and no follow-up checks of a fix that was never started.
func TestFixButtonWithATerminalThatFails(t *testing.T) {
	rec := newRecorder()
	d, paths := testDaemon(t, rec, nil, io.Discard)
	d.followUpEvery = time.Hour
	addServer(t, paths, "web", d.now())
	cfg, _ := config.Load(paths.Config)
	cfg.Terminal = config.Terminal{App: "custom", Command: "false {script}"} // exits with an error at once
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	_ = findings.Update(paths, func(st *findings.Store) error {
		st.Merge("web", []*findings.Finding{{ID: findings.MakeID("web", findings.KindVulnerability, "CVE-2024-6387/openssh"), Server: "web",
			Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1:9.6p1-3ubuntu13.5", Fixed: "2", Priority: findings.High}},
			[]findings.Kind{findings.KindVulnerability}, d.now())
		return nil
	})

	d.onClick(notify.Event{NotificationID: "cve:CVE-2024-6387", Action: "fix:web"})

	if ids := rec.ids(); len(ids) != 1 || ids[0] != "error" {
		t.Fatalf("want only the error notification, got %v", ids)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.clicked) != 0 {
		t.Fatalf("the button was marked as used: %v", d.clicked)
	}
}
