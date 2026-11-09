package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// enrich adds CVSS scores (with the CVE record's vector, weakness and
// description) and EPSS for findings that can alert: those with a fix, or
// all of them when rules.unfixed is "all". When a lookup fails, a
// finding keeps the score it had in previous: storing 0 instead would lower
// its priority, and when the source answered again the rise would count as an
// escalation and bring back findings you had accepted or snoozed. It returns
// warnings for the lookups that failed.
func (e *Engine) enrich(ctx context.Context, all []*findings.Finding, previous *findings.Store) []string {
	need := map[string][]*findings.Finding{}
	for _, f := range all {
		if f.Kind == findings.KindVulnerability && f.CVE != "" && (f.HasFix() || e.Rules.Unfixed == config.UnfixedAll) {
			need[f.CVE] = append(need[f.CVE], f)
		}
	}
	if len(need) == 0 {
		return nil
	}
	var warnings []string
	cves := make([]string, 0, len(need))
	for cve := range need {
		cves = append(cves, cve)
	}
	if scores, err := e.EPSS.Scores(ctx, cves); err != nil {
		e.Log.Warn("epss", "status", "error", "error", err)
		warnings = append(warnings, "EPSS unavailable, using the last known scores: "+apperr.MessageOf(err))
		for _, fs := range need {
			for _, f := range fs {
				if old := previous.Find(f.ID); old != nil {
					f.EPSS = old.EPSS
				}
			}
		}
	} else {
		for cve, s := range scores {
			for _, f := range need[cve] {
				f.EPSS = s
			}
		}
	}

	var (
		wg     sync.WaitGroup
		failed atomic.Int32 // records that could not be read, not counting CVEs the CVE List doesn't have
		slots  = make(chan struct{}, 8)
	)
	for cve, fs := range need {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			r, err := e.CVE.Get(ctx, cve)
			if err != nil {
				e.Log.Debug("cve record", "status", "error", "cve", cve, "error", err)
				if !errors.Is(err, feeds.ErrNotFound) {
					failed.Add(1)
				}
				for _, f := range fs {
					if old := previous.Find(f.ID); old != nil {
						f.Score, f.Vector, f.Weakness, f.Details = old.Score, old.Vector, old.Weakness, old.Details
					}
				}
				return
			}
			for _, f := range fs { // each finding belongs to exactly one CVE
				f.Score, f.Vector, f.Weakness, f.Details = r.Score, r.Vector, r.Weakness, r.Description
			}
		}()
	}
	wg.Wait()
	if n := failed.Load(); n > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CVE records unavailable, using the last known scores", n))
	}
	return warnings
}
