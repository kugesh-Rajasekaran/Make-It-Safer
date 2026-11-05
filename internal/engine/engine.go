// Package engine runs checks: it refreshes package lists over SSH, matches
// them against vulnerability data and records the findings.
package engine

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/eol"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/epss"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/kev"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/osv"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
)

// Engine checks servers against the vulnerability data.
type Engine struct {
	Paths config.Paths
	Rules config.Rules
	OSV   *osv.Client
	KEV   *kev.Client
	EPSS  *epss.Client
	EOL   *eol.Client
	CVE   *cvelist.Client
	Now   func() time.Time
	Log   *slog.Logger
}

// New wires the engine to the real data sources.
func New(paths config.Paths, cfg *config.Config, version string, log *slog.Logger) *Engine {
	fc := feeds.New(version)
	return &Engine{
		Paths: paths, Rules: cfg.Rules,
		OSV: osv.New(fc, paths), KEV: kev.New(fc, paths), EPSS: epss.New(fc), EOL: eol.New(fc), CVE: cvelist.New(fc, paths),
		Now: time.Now, Log: log,
	}
}

// ServerResult summarises one server after a check.
type ServerResult struct {
	Server string         `json:"server"`
	OS     string         `json:"os,omitempty"`
	Code   string         `json:"code,omitempty"` // set when the server couldn't be checked
	Error  string         `json:"error,omitempty"`
	Open   map[string]int `json:"open"` // open findings per priority
}

// Result is what a check found.
type Result struct {
	Servers  []ServerResult   `json:"servers"`
	Changes  findings.Changes `json:"changes"`
	Warnings []string         `json:"warnings,omitempty"`
}

// Refresh logs in to each server as "mis" and saves its package list. It
// returns the servers that failed, with why.
func (e *Engine) Refresh(ctx context.Context, signer ssh.Signer, servers []config.Server) map[string]error {
	hk := sshx.HostKeys{Path: e.Paths.KnownHosts}
	failed := map[string]error{}
	for _, s := range servers {
		e.Log.Debug("refresh", "status", "start", "server", s.Name)
		inv, err := collect(ctx, sshx.TargetOf(s), hk, signer, e.Now())
		if err == nil {
			err = inventory.Save(e.Paths, s.Name, inv)
		}
		if err != nil {
			e.Log.Warn("refresh", "status", "error", "server", s.Name, "error", err)
			failed[s.Name] = err
			continue
		}
		e.Log.Debug("refresh", "status", "success", "server", s.Name, "packages", len(inv.Packages))
	}
	return failed
}

func collect(ctx context.Context, t sshx.Target, hk sshx.HostKeys, signer ssh.Signer, now time.Time) (*inventory.Inventory, error) {
	c, err := sshx.Dial(ctx, t, hk, signer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	out, err := c.Collect(ctx)
	if err != nil {
		return nil, err
	}
	return inventory.Parse(out, now)
}

// Check refreshes package lists when a key is given (nil = use the saved
// lists), then matches them. failed lists servers whose refresh failed.
func (e *Engine) Check(ctx context.Context, signer ssh.Signer, servers []config.Server) (*Result, error) {
	failed := map[string]error{}
	if signer != nil {
		failed = e.Refresh(ctx, signer, servers)
	}
	res, err := e.Match(ctx, servers)
	if err != nil {
		return nil, err
	}
	for i, r := range res.Servers {
		if err, ok := failed[r.Server]; ok && r.Code == "" {
			res.Servers[i].Code, res.Servers[i].Error = apperr.CodeOf(err), "package list not refreshed: "+apperr.MessageOf(err)
		}
	}
	return res, nil
}

// serverWork is one server's inventory and the queries asked for it.
type serverWork struct {
	server  config.Server
	inv     *inventory.Inventory
	queries []osv.Query
	first   int // index of its first query in the batch
	result  ServerResult
}

// Match matches the saved package lists against the vulnerability data and
// records the findings.
func (e *Engine) Match(ctx context.Context, servers []config.Server) (*Result, error) {
	now := e.Now()
	res := &Result{}

	catalog, err := e.KEV.Refresh(ctx)
	if err != nil {
		res.Warnings = append(res.Warnings, "CISA KEV unavailable: "+apperr.MessageOf(err))
	}
	cycles := map[string][]eol.Cycle{}

	// 1. One OSV batch for every server.
	var work []*serverWork
	var queries []osv.Query
	for _, s := range servers {
		w := &serverWork{server: s, result: ServerResult{Server: s.Name, Open: map[string]int{}}}
		work = append(work, w)
		inv, err := inventory.Load(e.Paths, s.Name)
		if err != nil {
			w.result.Code, w.result.Error = apperr.CodeOf(err), apperr.MessageOf(err)
			continue
		}
		w.inv, w.result.OS = inv, inv.OSID+" "+inv.OSVersion
		if !inv.Supported() {
			w.result.Code, w.result.Error = apperr.ServerUnsupportedOS, "only Ubuntu and Debian are supported"
			continue
		}
		if _, ok := cycles[inv.OSID]; !ok {
			c, err := e.EOL.Cycles(ctx, inv.OSID)
			if err != nil {
				res.Warnings = append(res.Warnings, "end-of-life dates unavailable: "+apperr.MessageOf(err))
			}
			cycles[inv.OSID] = c
		}
		w.first = len(queries)
		for _, eco := range osv.Ecosystems(inv.OSID, inv.OSVersion) {
			for _, p := range inv.Sources() {
				w.queries = append(w.queries, osv.Query{Ecosystem: eco, Name: p.Source, Version: p.SourceVersion})
			}
		}
		queries = append(queries, w.queries...)
	}
	refs, err := e.OSV.QueryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	// 2. Read each matched record once.
	vulns, err := e.fetchVulns(ctx, refs)
	if err != nil {
		return nil, err
	}

	// 3. Build, enrich and classify each server's findings.
	current := map[string][]*findings.Finding{}
	var all []*findings.Finding
	for _, w := range work {
		if w.inv == nil || w.result.Code != "" {
			continue
		}
		fs := vulnFindings(w, refs[w.first:w.first+len(w.queries)], vulns, catalog)
		if f := rebootFinding(w.server.Name, w.inv); f != nil {
			fs = append(fs, f)
		}
		if f := eolFinding(w.server.Name, w.inv, cycles[w.inv.OSID], now); f != nil {
			fs = append(fs, f)
		}
		current[w.server.Name] = fs
		all = append(all, fs...)
	}
	e.enrich(ctx, all)
	previous, err := findings.Load(e.Paths)
	if err != nil {
		return nil, err
	}
	for _, f := range all {
		f.FirstSeen = now
		if old := previous.Find(f.ID); old != nil && old.Open() {
			f.FirstSeen = old.FirstSeen // e.g. how long a reboot has been pending
		}
		f.Priority = findings.Classify(f, e.Rules, now)
	}

	// 4. Record them.
	err = findings.Update(e.Paths, func(st *findings.Store) error {
		for _, w := range work {
			fs, ok := current[w.server.Name]
			if !ok {
				continue
			}
			kinds := []findings.Kind{findings.KindVulnerability, findings.KindReboot}
			if cycles[w.inv.OSID] != nil {
				kinds = append(kinds, findings.KindEndOfLife)
			}
			ch := st.Merge(w.server.Name, fs, kinds, now)
			res.Changes.New = append(res.Changes.New, ch.New...)
			res.Changes.Reopened = append(res.Changes.Reopened, ch.Reopened...)
			res.Changes.Escalated = append(res.Changes.Escalated, ch.Escalated...)
			res.Changes.Resolved = append(res.Changes.Resolved, ch.Resolved...)
		}
		st.Prune(now)
		for _, w := range work {
			for _, f := range st.Findings {
				if f.Server == w.server.Name && f.Open() && f.State != findings.StateAccepted {
					w.result.Open[f.Priority.String()]++
				}
			}
			res.Servers = append(res.Servers, w.result)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	e.Log.Info("check", "status", "success", "servers", len(servers), "new", len(res.Changes.New), "resolved", len(res.Changes.Resolved))
	return res, nil
}

// fetchVulns reads every relevant record OSV matched, eight at a time.
func (e *Engine) fetchVulns(ctx context.Context, refs [][]osv.Ref) (map[string]*osv.Vuln, error) {
	unique := map[string]osv.Ref{}
	for _, rs := range refs {
		for _, r := range rs {
			if osv.Relevant(r.ID) {
				unique[r.ID] = r
			}
		}
	}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
		out      = map[string]*osv.Vuln{}
		slots    = make(chan struct{}, 8)
	)
	for _, ref := range unique {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			v, err := e.OSV.Vuln(ctx, ref)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			out[ref.ID] = v
		}()
	}
	wg.Wait()
	return out, firstErr
}

// enrich adds CVSS scores and EPSS for findings that can alert: those with
// a fix, or all of them when rules.unfixed is "all".
func (e *Engine) enrich(ctx context.Context, all []*findings.Finding) {
	need := map[string][]*findings.Finding{}
	for _, f := range all {
		if f.Kind == findings.KindVulnerability && f.CVE != "" && (f.HasFix() || e.Rules.Unfixed == config.UnfixedAll) {
			need[f.CVE] = append(need[f.CVE], f)
		}
	}
	if len(need) == 0 {
		return
	}
	cves := make([]string, 0, len(need))
	for cve := range need {
		cves = append(cves, cve)
	}
	if scores, err := e.EPSS.Scores(ctx, cves); err != nil {
		e.Log.Warn("epss", "status", "error", "error", err)
	} else {
		for cve, s := range scores {
			for _, f := range need[cve] {
				f.EPSS = s
			}
		}
	}

	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for cve, fs := range need {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			r, err := e.CVE.Get(ctx, cve)
			if err != nil {
				e.Log.Debug("cve record", "status", "error", "cve", cve, "error", err)
				return
			}
			for _, f := range fs { // each finding belongs to exactly one CVE
				f.Score = r.Score
			}
		}()
	}
	wg.Wait()
}

// vulnFindings turns one server's OSV matches into findings, one per CVE
// and source package. The standard ecosystem wins over Ubuntu Pro, which
// only adds a fix when the standard archive has none.
func vulnFindings(w *serverWork, refs [][]osv.Ref, vulns map[string]*osv.Vuln, catalog *kev.Catalog) []*findings.Finding {
	byID := map[string]*findings.Finding{}
	var order []string
	for i, q := range w.queries {
		for _, r := range refs[i] {
			v := vulns[r.ID]
			if v == nil || v.CVE() == "" {
				continue
			}
			fixed, proOnly := v.Fix(q.Ecosystem, q.Name, q.Version)
			id := findings.MakeID(w.server.Name, findings.KindVulnerability, v.CVE()+"/"+q.Name)
			if f, ok := byID[id]; ok {
				if !f.HasFix() && fixed != "" {
					f.Fixed, f.ProOnly = fixed, proOnly
				}
				continue
			}
			byID[id] = &findings.Finding{
				ID: id, Server: w.server.Name, Kind: findings.KindVulnerability,
				CVE: v.CVE(), VulnID: v.ID, Source: q.Name, Installed: q.Version,
				Fixed: fixed, ProOnly: proOnly, Summary: shorten(v.Summary, 200),
				DistroPriority: v.DistroPriority(q.Ecosystem, q.Name), KEV: catalog.Has(v.CVE()),
			}
			order = append(order, id)
		}
	}
	out := make([]*findings.Finding, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
