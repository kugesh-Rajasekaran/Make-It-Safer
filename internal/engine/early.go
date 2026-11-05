package engine

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/osv"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/match"
)

const (
	// A CVE that names installed software but isn't severe yet, or doesn't
	// name any product yet, is looked at again when it changes (scores and
	// products often arrive later from CISA), for this long.
	watchFor = 7 * 24 * time.Hour
	// An early warning without any distro data after this long ends.
	earlyExpiry = 30 * 24 * time.Hour
)

// earlyState is what the early-warning job remembers between runs.
type earlyState struct {
	Since time.Time            `json:"since"` // newest CVE List change set already read
	Watch map[string]time.Time `json:"watch"` // CVE → look at it again until
}

// EarlyWarnings raises early warnings (docs/design.md §4.5): CVEs new in
// the CVE List that are severe or actively exploited, name software
// installed on a server, and that the server's distro hasn't assessed yet.
func (e *Engine) EarlyWarnings(ctx context.Context, servers []config.Server) (*Result, error) {
	res := &Result{}
	rules := e.Rules.EarlyWarning
	if !rules.Enabled {
		return res, nil
	}
	state, err := loadEarlyState(e.Paths)
	if err != nil {
		return nil, err
	}
	delta, err := e.CVE.Changes(ctx, state.Since)
	if err != nil {
		return nil, err
	}
	now := e.Now()
	if delta.Reset { // first run, or offline for over a month: start from now
		e.Log.Info("early warning", "status", "start", "since", delta.Newest)
		state.Since = delta.Newest
		return res, saveEarlyState(e.Paths, state)
	}

	// New CVEs, and watched ones that changed (CISA adds scores, products
	// and KEV status to the record itself).
	var ids []string
	for _, c := range delta.Changes {
		if _, watched := state.Watch[c.ID]; c.New || watched {
			ids = append(ids, c.ID)
		}
	}
	records, err := e.fetchRecords(ctx, ids)
	if err != nil {
		return nil, err // nothing is lost: the next run reads the same changes again
	}

	previous, err := findings.Load(e.Paths)
	if err != nil {
		return nil, err
	}
	invs := map[string]*inventory.Inventory{}
	for _, s := range servers {
		if _, checked := previous.Checked[s.Name]; !checked {
			continue // its first check comes first, with its summary
		}
		if inv, err := inventory.Load(e.Paths, s.Name); err == nil && inv.Supported() {
			invs[s.Name] = inv
		}
	}

	catalog, _ := e.KEV.Cached() // refreshed by the feeds job; nil works as "none"
	var raised []*findings.Finding
	for _, r := range records {
		kev := r.KEV || catalog.Has(r.ID)
		severe := r.Score >= rules.MinSeverity || kev
		named := false
		for name, inv := range invs {
			sources := match.Sources(r.Products, sourceNames(inv))
			named = named || len(sources) > 0
			if len(sources) == 0 || !severe || r.Rejected || e.assessed(ctx, inv, r.ID) {
				continue
			}
			for _, src := range sources {
				f := &findings.Finding{
					ID: findings.MakeID(name, findings.KindEarlyWarning, r.ID+"/"+src), Server: name,
					Kind: findings.KindEarlyWarning, CVE: r.ID, Source: src, Installed: installedVersion(inv, src),
					Summary: cmp.Or(r.Title, r.Description), Score: r.Score, KEV: kev,
				}
				f.Priority = findings.Classify(f, e.Rules, now)
				raised = append(raised, f)
			}
		}
		_, watched := state.Watch[r.ID]
		switch {
		case r.Rejected || (named && severe) || (!named && match.Usable(r.Products)):
			delete(state.Watch, r.ID) // decided, or about nothing installed
		case !watched:
			state.Watch[r.ID] = now.Add(watchFor)
		}
	}
	for id, until := range state.Watch {
		if now.After(until) {
			delete(state.Watch, id)
		}
	}

	err = findings.Update(e.Paths, func(st *findings.Store) error {
		fresh := slices.DeleteFunc(raised, func(f *findings.Finding) bool { return hasCVE(st, f.Server, f.CVE) })
		res.Changes.New = st.Add(fresh, now)
		return nil
	})
	if err != nil {
		return nil, err
	}
	state.Since = delta.Newest
	if err := saveEarlyState(e.Paths, state); err != nil {
		return nil, err
	}
	e.Log.Info("early warning", "status", "success", "changes", len(delta.Changes), "read", len(records), "new", len(res.Changes.New), "watching", len(state.Watch))
	return res, nil
}

// fetchRecords reads the current CVE records, four at a time. A record
// that doesn't exist is skipped; any other failure fails the run, so the
// next run tries the same changes again.
func (e *Engine) fetchRecords(ctx context.Context, ids []string) ([]*cvelist.Record, error) {
	out := make([]*cvelist.Record, len(ids))
	errs := make([]error, len(ids))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i], errs[i] = e.CVE.Fetch(ctx, id)
			if errors.Is(errs[i], feeds.ErrNotFound) {
				e.Log.Warn("early warning", "status", "skipped", "cve", id, "reason", "no such record")
				errs[i] = nil
			}
		}()
	}
	wg.Wait()
	return slices.DeleteFunc(out, func(r *cvelist.Record) bool { return r == nil }), errors.Join(errs...)
}

// assessed reports whether the server's distro has a record for the CVE.
// When OSV can't be asked, it assumes not: better a warning too many.
func (e *Engine) assessed(ctx context.Context, inv *inventory.Inventory, cve string) bool {
	ok, err := e.OSV.Exists(ctx, osv.DistroID(inv.OSID, cve))
	if err != nil {
		e.Log.Warn("early warning", "status", "error", "cve", cve, "error", apperr.MessageOf(err))
	}
	return ok
}

// settleEarlyWarnings decides which open early warnings of the checked
// servers have ended, and how: the distro confirmed the vulnerability (a
// vulnerability finding exists), assessed it as not affecting the server,
// or nothing came for 30 days. It returns finding ID → resolution.
func (e *Engine) settleEarlyWarnings(ctx context.Context, previous *findings.Store, work []*serverWork, current map[string][]*findings.Finding, now time.Time) map[string]string {
	out := map[string]string{}
	for _, w := range work {
		fs, checked := current[w.server.Name]
		if !checked {
			continue
		}
		for _, f := range previous.Findings {
			if f.Server != w.server.Name || f.Kind != findings.KindEarlyWarning || !f.Open() {
				continue
			}
			confirmed := slices.ContainsFunc(append(slices.Clone(fs), previous.Findings...), func(v *findings.Finding) bool {
				return v.Kind == findings.KindVulnerability && v.Server == f.Server && v.CVE == f.CVE
			})
			switch {
			case confirmed:
				out[f.ID] = findings.ResolutionConfirmed
			case e.assessed(ctx, w.inv, f.CVE):
				out[f.ID] = findings.ResolutionNotAffected
			case now.Sub(f.FirstSeen) > earlyExpiry:
				out[f.ID] = findings.ResolutionExpired
			}
		}
	}
	return out
}

// hasCVE reports whether a server has any finding about a CVE yet.
func hasCVE(st *findings.Store, server, cve string) bool {
	return slices.ContainsFunc(st.Findings, func(f *findings.Finding) bool { return f.Server == server && f.CVE == cve })
}

func sourceNames(inv *inventory.Inventory) []string {
	var out []string
	for _, p := range inv.Sources() {
		if !slices.Contains(out, p.Source) {
			out = append(out, p.Source)
		}
	}
	return out
}

// installedVersion is the installed version of a source package (for the
// kernel: the running kernel).
func installedVersion(inv *inventory.Inventory, source string) string {
	if source == match.Kernel {
		return inv.Kernel
	}
	for _, p := range inv.Sources() {
		if p.Source == source {
			return p.SourceVersion
		}
	}
	return ""
}

func earlyFile(paths config.Paths) string { return filepath.Join(paths.State, "early-warning.json") }

func loadEarlyState(paths config.Paths) (*earlyState, error) {
	st := &earlyState{}
	data, err := os.ReadFile(earlyFile(paths))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read the early-warning state")
	default:
		if err := json.Unmarshal(data, st); err != nil {
			return nil, apperr.Wrap(apperr.ConfigUnreadable, err, "the early-warning state is damaged; delete "+earlyFile(paths)+" to start over")
		}
	}
	if st.Watch == nil {
		st.Watch = map[string]time.Time{}
	}
	return st, nil
}

func saveEarlyState(paths config.Paths, st *earlyState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot save the early-warning state")
	}
	return config.WriteFileAtomic(earlyFile(paths), data)
}
