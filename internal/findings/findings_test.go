package findings

import (
	"os"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

var t0 = time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)

func TestTransitions(t *testing.T) {
	all := []State{StateNew, StateNotified, StateSnoozed, StateAccepted, StateResolved}
	allowed := map[[2]State]bool{}
	for from, tos := range transitions {
		for _, to := range tos {
			allowed[[2]State{from, to}] = true
		}
	}
	for _, from := range all {
		for _, to := range all {
			f := &Finding{ID: "x", State: from}
			err := f.Transition(to, t0)
			if allowed[[2]State{from, to}] != (err == nil) {
				t.Errorf("%s → %s: err = %v", from, to, err)
			}
			if err != nil && !apperr.Is(err, apperr.FindingsInvalidTransition) {
				t.Errorf("%s → %s: wrong error %v", from, to, err)
			}
		}
	}
	f := &Finding{State: StateResolved, ResolvedAt: t0, AckReason: "x"}
	if err := f.Transition(StateNew, t0); err != nil || !f.ResolvedAt.IsZero() || f.AckReason != "" {
		t.Fatalf("reopening must clear resolution and acknowledgement: %+v", f)
	}
}

func TestClassify(t *testing.T) {
	rules := config.Default().Rules
	cases := []struct {
		name string
		f    Finding
		want Priority
	}{
		{"exploited, no fix yet", Finding{Kind: KindVulnerability, KEV: true}, Urgent},
		{"critical with fix", Finding{Kind: KindVulnerability, Fixed: "2", Score: 9.8}, Urgent},
		{"critical without fix", Finding{Kind: KindVulnerability, Score: 9.8}, Silent},
		{"high with fix", Finding{Kind: KindVulnerability, Fixed: "2", Score: 7.5}, High},
		{"likely exploited", Finding{Kind: KindVulnerability, Fixed: "2", Score: 4, EPSS: 0.4}, High},
		{"medium with fix", Finding{Kind: KindVulnerability, Fixed: "2", Score: 5}, Normal},
		{"distro says high", Finding{Kind: KindVulnerability, Fixed: "2", DistroPriority: "high"}, High},
		{"distro says critical", Finding{Kind: KindVulnerability, Fixed: "2", DistroPriority: "critical"}, Urgent},
		{"ignored CVE", Finding{Kind: KindVulnerability, CVE: "CVE-2024-6387", KEV: true}, Silent},
		{"fresh reboot", Finding{Kind: KindReboot, FirstSeen: t0}, Normal},
		{"old reboot", Finding{Kind: KindReboot, FirstSeen: t0.Add(-4 * 24 * time.Hour)}, High},
		{"end of life keeps its priority", Finding{Kind: KindEndOfLife, Priority: Urgent}, Urgent},
	}
	rules.Ignore.CVEs = []string{"CVE-2024-6387"}
	for _, tc := range cases {
		if got := Classify(&tc.f, rules, t0); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	rules.Unfixed = config.UnfixedAll
	if got := Classify(&Finding{Kind: KindVulnerability, Score: 8}, rules, t0); got != High {
		t.Errorf("unfixed: all → got %s, want high", got)
	}
}

func TestReminderDue(t *testing.T) {
	rules := config.Default().Rules
	urgent := &Finding{Priority: Urgent, State: StateNotified, NotifiedAt: t0}
	if ReminderDue(urgent, rules, t0.Add(time.Hour)) || !ReminderDue(urgent, rules, t0.Add(4*time.Hour)) {
		t.Fatal("urgent findings remind every 4h")
	}
	if !ReminderDue(&Finding{Priority: High, State: StateNew}, rules, t0) {
		t.Fatal("a new finding is due immediately")
	}
	snoozed := &Finding{Priority: High, State: StateSnoozed, SnoozedUntil: t0.Add(24 * time.Hour)}
	if ReminderDue(snoozed, rules, t0) || !ReminderDue(snoozed, rules, t0.Add(25*time.Hour)) {
		t.Fatal("snoozed findings come back after the snooze")
	}
	for _, f := range []*Finding{{Priority: Silent, State: StateNew}, {Priority: Urgent, State: StateAccepted}, {Priority: Urgent, State: StateResolved}} {
		if ReminderDue(f, rules, t0) {
			t.Fatalf("not due: %+v", f)
		}
	}
}

func vuln(cve string, p Priority) *Finding {
	return &Finding{ID: MakeID("web", KindVulnerability, cve+"/openssh"), Server: "web", Kind: KindVulnerability, CVE: cve, Priority: p}
}

func TestMerge(t *testing.T) {
	s := &Store{Checked: map[string]time.Time{}}
	kinds := []Kind{KindVulnerability}

	ch := s.Merge("web", []*Finding{vuln("CVE-1", Normal), vuln("CVE-2", Normal)}, kinds, t0)
	if len(ch.New) != 2 || s.Find("web/vulnerability/CVE-1/openssh").State != StateNew {
		t.Fatalf("first merge: %+v", ch)
	}
	_ = s.Find("web/vulnerability/CVE-2/openssh").Transition(StateAccepted, t0)

	// CVE-1 fixed; CVE-2 becomes actively exploited (urgent) after being accepted.
	ch = s.Merge("web", []*Finding{vuln("CVE-2", Urgent)}, kinds, t0.Add(time.Hour))
	if len(ch.Resolved) != 1 || len(ch.Escalated) != 1 || s.Find("web/vulnerability/CVE-2/openssh").State != StateNew {
		t.Fatalf("second merge: %+v", ch)
	}

	// CVE-1 comes back (e.g. package downgraded).
	ch = s.Merge("web", []*Finding{vuln("CVE-1", Normal), vuln("CVE-2", Urgent)}, kinds, t0.Add(2*time.Hour))
	if len(ch.Reopened) != 1 || len(ch.New) != 0 {
		t.Fatalf("third merge: %+v", ch)
	}

	// Kinds that weren't evaluated stay as they are; other servers too.
	s.Findings = append(s.Findings, &Finding{ID: "web/reboot/kernel", Server: "web", Kind: KindReboot, State: StateNew},
		&Finding{ID: "db/vulnerability/CVE-9/x", Server: "db", Kind: KindVulnerability, State: StateNew})
	ch = s.Merge("web", nil, kinds, t0.Add(3*time.Hour))
	if s.Find("web/reboot/kernel").State != StateNew || s.Find("db/vulnerability/CVE-9/x").State != StateNew || len(ch.Resolved) != 2 {
		t.Fatalf("merge touched the wrong findings: %+v", ch)
	}
}

func TestUpdatePersistsAndPrunes(t *testing.T) {
	paths := config.PathsAt(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	err := Update(paths, func(s *Store) error {
		s.Merge("web", []*Finding{vuln("CVE-1", High)}, []Kind{KindVulnerability}, t0)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(paths)
	if err != nil || len(s.Findings) != 1 || s.Findings[0].Priority != High || s.Checked["web"].IsZero() {
		t.Fatalf("Load() = %+v, %v", s, err)
	}
	s.Merge("web", nil, []Kind{KindVulnerability}, t0)
	s.Prune(t0.Add(31 * 24 * time.Hour))
	if len(s.Findings) != 0 {
		t.Fatal("old resolved findings should be pruned")
	}
}

func TestEarlyWarningFindings(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	rules := config.Default().Rules
	f := &Finding{ID: "web/early-warning/CVE-2026-0001/openssh", Server: "web", Kind: KindEarlyWarning, CVE: "CVE-2026-0001", Source: "openssh", Score: 9.8}
	if p := Classify(f, rules, now); p != High {
		t.Errorf("priority = %s, want high", p)
	}
	f.Priority = High

	st := &Store{Checked: map[string]time.Time{}, Notes: map[string]time.Time{}}
	if added := st.Add([]*Finding{f}, now); len(added) != 1 || f.State != StateNew || !f.FirstSeen.Equal(now) {
		t.Fatalf("Add = %v, %+v", added, f)
	}
	if added := st.Add([]*Finding{{ID: f.ID}}, now); len(added) != 0 || len(st.Findings) != 1 {
		t.Fatal("Add added a known finding again")
	}
	if len(st.Checked) != 0 {
		t.Fatal("Add marked the server checked")
	}

	// Shown once, then never reminded.
	if !ReminderDue(f, rules, now) {
		t.Fatal("not due before it was shown")
	}
	_ = f.Transition(StateNotified, now)
	if ReminderDue(f, rules, now.Add(30*24*time.Hour)) {
		t.Fatal("an early warning was reminded")
	}

	// Resolved with a reason; reopening clears it.
	_ = f.Transition(StateResolved, now)
	f.Resolution = ResolutionNotAffected
	if err := f.Transition(StateNew, now); err != nil || f.Resolution != "" {
		t.Fatalf("reopened: %+v, %v", f, err)
	}
}

// A restart that is pending again after an earlier one was done gets its
// three days' grace again, instead of being High from the start.
func TestReopenedRebootFindingGetsGraceAgain(t *testing.T) {
	rules := config.Default().Rules
	s := &Store{Checked: map[string]time.Time{}}
	const id = "web/reboot/kernel"
	day := 24 * time.Hour
	// check does what a check does: classify with the first-seen time of the
	// finding if it is still open, then merge.
	check := func(now time.Time, pending bool) Changes {
		var current []*Finding
		if pending {
			f := &Finding{ID: id, Server: "web", Kind: KindReboot, FirstSeen: now}
			if old := s.Find(id); old != nil && old.Open() {
				f.FirstSeen = old.FirstSeen
			}
			f.Priority = Classify(f, rules, now)
			current = append(current, f)
		}
		return s.Merge("web", current, []Kind{KindReboot}, now)
	}

	check(t0, true)
	if ch := check(t0.Add(4*day), true); len(ch.Escalated) != 1 || s.Find(id).Priority != High {
		t.Fatalf("pending for four days: %+v, priority %s", ch, s.Find(id).Priority)
	}
	if ch := check(t0.Add(5*day), false); len(ch.Resolved) != 1 { // restarted
		t.Fatalf("after the restart: %+v", ch)
	}

	reopened := t0.Add(10 * day) // a new kernel is installed
	if ch := check(reopened, true); len(ch.Reopened) != 1 || !s.Find(id).FirstSeen.Equal(reopened) {
		t.Fatalf("reopened: %+v, first seen %v", ch, s.Find(id).FirstSeen)
	}
	if ch := check(reopened.Add(30*time.Minute), true); len(ch.Escalated) != 0 || s.Find(id).Priority != Normal {
		t.Fatalf("30 minutes later: %+v, priority %s; want normal during the grace period", ch, s.Find(id).Priority)
	}
	if ch := check(reopened.Add(4*day), true); len(ch.Escalated) != 1 || s.Find(id).Priority != High {
		t.Fatalf("after the grace period: %+v, priority %s", ch, s.Find(id).Priority)
	}
}

// An escalation of an acknowledged finding must not restart the clock: only
// a finding that had been resolved is a new occurrence.
func TestEscalationKeepsFirstSeen(t *testing.T) {
	s := &Store{Checked: map[string]time.Time{}}
	kinds := []Kind{KindVulnerability}
	s.Merge("web", []*Finding{vuln("CVE-1", Normal)}, kinds, t0)
	f := s.Find("web/vulnerability/CVE-1/openssh")
	_ = f.Transition(StateSnoozed, t0)
	s.Merge("web", []*Finding{vuln("CVE-1", Urgent)}, kinds, t0.Add(time.Hour))
	if f.State != StateNew || !f.FirstSeen.Equal(t0) {
		t.Fatalf("state %s, first seen %v; want new and %v", f.State, f.FirstSeen, t0)
	}
}

// A hand-edited file with null entries must not crash the daemon.
func TestLoadDropsNullFindings(t *testing.T) {
	paths := config.PathsAt(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	data := `{"version":1,"findings":[null,{"id":"web/vulnerability/CVE-1/openssh","server":"web","kind":"vulnerability","state":"new"},null]}`
	if err := os.WriteFile(file(paths), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(paths)
	if err != nil || len(s.Findings) != 1 || s.Find("web/vulnerability/CVE-1/openssh") == nil {
		t.Fatalf("Load() = %+v, %v", s, err)
	}
	err = Update(paths, func(s *Store) error {
		s.Prune(t0)
		s.Forget("db")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
