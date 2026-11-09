package findings

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Store is state/findings.json.
type Store struct {
	Version  int        `json:"version"`
	Findings []*Finding `json:"findings"`
	// Checked records when each server was last matched against the data.
	Checked map[string]time.Time `json:"checked"`
	// Notes records when occasional notifications were last shown.
	Notes map[string]time.Time `json:"notes"`
}

// Changes says what a merge changed, for notifications.
type Changes struct {
	New       []*Finding `json:"new"`
	Reopened  []*Finding `json:"reopened"`
	Escalated []*Finding `json:"escalated"`
	Resolved  []*Finding `json:"resolved"`
}

// Load reads the store (empty if it doesn't exist yet).
func Load(paths config.Paths) (*Store, error) {
	data, err := os.ReadFile(file(paths))
	if errors.Is(err, fs.ErrNotExist) {
		return &Store{Version: 1, Checked: map[string]time.Time{}, Notes: map[string]time.Time{}}, nil
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read findings")
	}
	s := &Store{}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, apperr.Wrap(apperr.FindingsStateDamaged, err, "state/findings.json is damaged; move it away and run: mis check")
	}
	s.Findings = slices.DeleteFunc(s.Findings, func(f *Finding) bool { return f == nil }) // "null" entries in a hand-edited file
	if s.Checked == nil {
		s.Checked = map[string]time.Time{}
	}
	if s.Notes == nil {
		s.Notes = map[string]time.Time{}
	}
	return s, nil
}

// Update locks the store, applies fn and saves the result. The CLI and the
// daemon both use it, so their changes never overwrite each other.
func Update(paths config.Paths, fn func(*Store) error) error {
	unlock, err := config.Lock(filepath.Join(paths.State, ".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	s, err := Load(paths)
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot encode findings")
	}
	return config.WriteFileAtomic(file(paths), data)
}

func file(paths config.Paths) string { return filepath.Join(paths.State, "findings.json") }

// Find returns a finding by ID.
func (s *Store) Find(id string) *Finding {
	i := slices.IndexFunc(s.Findings, func(f *Finding) bool { return f.ID == id })
	if i < 0 {
		return nil
	}
	return s.Findings[i]
}

// Merge records what a check found for one server. kinds lists the finding
// kinds the check evaluated: open findings of those kinds that weren't found
// again are resolved; other kinds are left alone.
func (s *Store) Merge(server string, current []*Finding, kinds []Kind, now time.Time) Changes {
	var ch Changes
	seen := map[string]bool{}
	for _, cur := range current {
		seen[cur.ID] = true
		old := s.Find(cur.ID)
		if old == nil {
			cur.State, cur.FirstSeen, cur.LastSeen = StateNew, now, now
			s.Findings = append(s.Findings, cur)
			ch.New = append(ch.New, cur)
			continue
		}
		wasResolved, oldPriority := old.State == StateResolved, old.Priority
		old.Installed, old.Fixed, old.ProOnly = cur.Installed, cur.Fixed, cur.ProOnly
		old.Summary, old.DistroPriority, old.VulnID = cur.Summary, cur.DistroPriority, cur.VulnID
		old.Score, old.EPSS, old.KEV, old.Priority = cur.Score, cur.EPSS, cur.KEV, cur.Priority
		old.LastSeen = now
		switch {
		case wasResolved:
			old.FirstSeen = now // a new occurrence: the reboot grace period starts again
			_ = old.Transition(StateNew, now)
			ch.Reopened = append(ch.Reopened, old)
		case old.Priority > oldPriority && old.Priority >= High:
			if old.State == StateAccepted || old.State == StateSnoozed { // escalation overrides an acknowledgement
				_ = old.Transition(StateNew, now)
			}
			ch.Escalated = append(ch.Escalated, old)
		}
	}
	for _, f := range s.Findings {
		if f.Server == server && f.Open() && !seen[f.ID] && slices.Contains(kinds, f.Kind) {
			_ = f.Transition(StateResolved, now)
			ch.Resolved = append(ch.Resolved, f)
		}
	}
	s.Checked[server] = now
	return ch
}

// Add records findings that aren't known yet, without resolving or
// changing others (early warnings). It returns the ones it added.
func (s *Store) Add(fs []*Finding, now time.Time) []*Finding {
	var added []*Finding
	for _, f := range fs {
		if s.Find(f.ID) != nil {
			continue
		}
		f.State, f.FirstSeen, f.LastSeen = StateNew, now, now
		s.Findings = append(s.Findings, f)
		added = append(added, f)
	}
	return added
}

// Forget drops everything about a server.
func (s *Store) Forget(server string) {
	s.Findings = slices.DeleteFunc(s.Findings, func(f *Finding) bool { return f.Server == server })
	delete(s.Checked, server)
}

// Prune drops findings resolved more than a month ago.
func (s *Store) Prune(now time.Time) {
	s.Findings = slices.DeleteFunc(s.Findings, func(f *Finding) bool {
		return f.State == StateResolved && now.Sub(f.ResolvedAt) > 30*24*time.Hour
	})
}
