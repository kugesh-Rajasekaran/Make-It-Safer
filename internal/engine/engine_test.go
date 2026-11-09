package engine

import (
	"cmp"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
)

// fakeData serves every data source the engine uses.
type fakeData struct {
	fixed string // openssh fixed version on Ubuntu 24.04
	kev   bool   // whether CVE-2024-6387 is in CISA KEV
	epss  string // EPSS score of CVE-2024-6387; "" = 0.02

	mu      sync.Mutex
	log     string            // CVE List delta log
	records map[string]string // CVE → CVE record
	failing map[string]bool   // sources that answer with an error: "epss", "cve"
	distro  map[string]string // more Ubuntu records (UBUNTU-CVE-…) → openssh fixed version ("" = not affected)
	fetched map[string]int    // CVE record downloads
}

func (d *fakeData) set(f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f()
}

func (d *fakeData) handler(t *testing.T) http.Handler {
	cveRecord, err := os.ReadFile("../feeds/cvelist/testdata/CVE-2024-6387.json")
	if err != nil {
		t.Fatal(err)
	}
	d.set(func() {
		d.records = map[string]string{"CVE-2024-6387": string(cveRecord)}
		d.distro, d.fetched, d.failing = map[string]string{}, map[string]int{}, map[string]bool{}
	})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string }
				Version string
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		d.mu.Lock()
		defer d.mu.Unlock()
		results := make([]map[string]any, len(req.Queries))
		for i, q := range req.Queries {
			results[i] = map[string]any{}
			if q.Package.Name != "openssh" || q.Package.Ecosystem != "Ubuntu:24.04:LTS" {
				continue
			}
			var vulns []map[string]string
			if osv.CompareVersions(q.Version, d.fixed) < 0 {
				vulns = append(vulns, map[string]string{"id": "UBUNTU-CVE-2024-6387", "modified": "2026-11-01T00:00:00Z"})
			}
			for id, fixed := range d.distro {
				if fixed != "" && osv.CompareVersions(q.Version, fixed) < 0 {
					vulns = append(vulns, map[string]string{"id": id, "modified": "2026-11-01T00:00:00Z"})
				}
			}
			if vulns != nil {
				results[i]["vulns"] = vulns
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		id, fixed := r.PathValue("id"), d.fixed
		if id != "UBUNTU-CVE-2024-6387" {
			var ok bool
			if fixed, ok = d.distro[id]; !ok {
				http.NotFound(w, r)
				return
			}
		}
		events := `{"introduced":"0"}`
		if fixed != "" {
			events += `,{"fixed":"` + fixed + `"}`
		}
		_, _ = io.WriteString(w, `{"id":"`+id+`","modified":"2026-11-01T00:00:00Z","upstream":["`+strings.TrimPrefix(id, "UBUNTU-")+`"],
			"summary":"regreSSHion","severity":[{"type":"Ubuntu","score":"high"}],
			"affected":[{"package":{"name":"openssh","ecosystem":"Ubuntu:24.04:LTS"},
			"ranges":[{"type":"ECOSYSTEM","events":[`+events+`]}],
			"ecosystem_specific":{"availability":"No subscription required"}}]}`)
	})
	mux.HandleFunc("GET /kev.json", func(w http.ResponseWriter, _ *http.Request) {
		id := "CVE-2000-0001"
		if d.kev {
			id = "CVE-2024-6387"
		}
		_, _ = io.WriteString(w, `{"catalogVersion":"1","vulnerabilities":[{"cveID":"`+id+`","shortDescription":"OpenSSH lets remote attackers run code."}]}`)
	})
	mux.HandleFunc("GET /epss", func(w http.ResponseWriter, _ *http.Request) {
		d.mu.Lock()
		down, score := d.failing["epss"], cmp.Or(d.epss, "0.02")
		d.mu.Unlock()
		if down {
			http.Error(w, "unavailable", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"cve":"CVE-2024-6387","epss":"`+score+`"}]}`)
	})
	mux.HandleFunc("GET /ubuntu.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"cycle":"24.04","eol":"2029-05-31","extendedSupport":"2036-04-25"},{"cycle":"20.04","eol":"2025-05-29","extendedSupport":"2030-04-02"}]`)
	})
	mux.HandleFunc("GET /cves/deltaLog.json", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		log := d.log
		d.mu.Unlock()
		http.ServeContent(w, r, "deltaLog.json", time.Time{}, strings.NewReader(log))
	})
	mux.HandleFunc("GET /cves/{year}/{dir}/{file}", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		id := strings.TrimSuffix(r.PathValue("file"), ".json")
		if d.failing["cve"] {
			http.Error(w, "unavailable", http.StatusForbidden)
			return
		}
		record, ok := d.records[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		d.fetched[id]++
		_, _ = io.WriteString(w, record)
	})
	return mux
}

func newEngine(t *testing.T, d *fakeData) (*Engine, config.Paths) {
	t.Helper()
	srv := httptest.NewServer(d.handler(t))
	t.Cleanup(srv.Close)
	paths := config.PathsAt(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	fc := feeds.NewForTest(srv.URL)
	e := &Engine{
		Paths: paths, Rules: config.Default().Rules,
		OSV:  &osv.Client{Feeds: fc, API: srv.URL, Cache: paths.Cache + "/osv"},
		KEV:  &kev.Client{Feeds: fc, URLs: []string{srv.URL + "/kev.json"}, Cache: paths.Cache + "/kev.json", ETag: paths.Cache + "/kev.etag"},
		EPSS: &epss.Client{Feeds: fc, API: srv.URL + "/epss"}, EOL: &eol.Client{Feeds: fc, API: srv.URL},
		CVE: &cvelist.Client{Feeds: fc, Base: srv.URL, Cache: paths.Cache + "/cve", Now: time.Now},
		Now: func() time.Time { return time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC) },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return e, paths
}

func saveInventory(t *testing.T, paths config.Paths, server, version, openssh string, kernels ...string) {
	t.Helper()
	inv := &inventory.Inventory{OSID: "ubuntu", OSVersion: version, Kernel: "6.8.0-49-generic", Arch: "amd64",
		Packages: []inventory.Package{
			{Name: "openssh-server", Version: openssh, Source: "openssh", SourceVersion: openssh},
			{Name: "openssh-client", Version: openssh, Source: "openssh", SourceVersion: openssh},
		}}
	for _, k := range kernels {
		name, version, _ := strings.Cut(k, "=")
		inv.Packages = append(inv.Packages, inventory.Package{Name: name, Version: version, Source: "linux-signed", SourceVersion: version})
	}
	if err := inventory.Save(paths, server, inv); err != nil {
		t.Fatal(err)
	}
}

var web = config.Server{Name: "web", Host: "10.0.0.1", Port: 22, AdminSSH: "ubuntu@10.0.0.1"}

func TestMatchFindsFixesAndResolves(t *testing.T) {
	d := &fakeData{fixed: "1:9.6p1-3ubuntu13.8"}
	e, paths := newEngine(t, d)
	saveInventory(t, paths, "web", "24.04", "1:9.6p1-3ubuntu13.5",
		"linux-image-6.8.0-49-generic=6.8.0-49.49", "linux-image-6.8.0-51-generic=6.8.0-51.52")

	res, err := e.Match(context.Background(), []config.Server{web})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes.New) != 2 || len(res.Warnings) != 0 {
		t.Fatalf("want a vulnerability and a reboot finding, got %+v (warnings %v)", res.Changes.New, res.Warnings)
	}
	st, _ := findings.Load(paths)
	v := st.Find("web/vulnerability/CVE-2024-6387/openssh")
	if v == nil || v.Fixed != "1:9.6p1-3ubuntu13.8" || v.Score != 8.1 || v.Priority != findings.High || v.ProOnly {
		t.Fatalf("vulnerability finding = %+v", v)
	}
	// The CVE record's facts are kept, so the risk can be put into words.
	if v.Vector != "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" || v.Weakness != "CWE-364: Signal Handler Race Condition" ||
		!strings.HasPrefix(v.Details, "A security regression") || v.Impact != "" {
		t.Fatalf("facts: vector %q, weakness %q, details %q, impact %q", v.Vector, v.Weakness, v.Details, v.Impact)
	}
	if r := st.Find("web/reboot/kernel"); r == nil || !strings.Contains(r.Summary, "6.8.0-51") {
		t.Fatalf("reboot finding = %+v", r)
	}
	if res.Servers[0].Open["high"] != 1 || res.Servers[0].Open["normal"] != 1 {
		t.Fatalf("counts = %v", res.Servers[0].Open)
	}

	// Attackers start using it: same finding, now urgent.
	d.kev = true
	_ = os.Remove(paths.Cache + "/kev.etag")
	res, _ = e.Match(context.Background(), []config.Server{web})
	if len(res.Changes.Escalated) != 1 || res.Changes.Escalated[0].Priority != findings.Urgent {
		t.Fatalf("escalation = %+v", res.Changes)
	}
	if got := res.Changes.Escalated[0].Impact; got != "OpenSSH lets remote attackers run code." {
		t.Fatalf("CISA's description = %q", got)
	}

	// The server is patched and rebooted.
	saveInventory(t, paths, "web", "24.04", "1:9.6p1-3ubuntu13.8", "linux-image-6.8.0-49-generic=6.8.0-49.49")
	res, _ = e.Match(context.Background(), []config.Server{web})
	if len(res.Changes.Resolved) != 2 || res.Servers[0].Open["urgent"] != 0 {
		t.Fatalf("after the fix: %+v, open %v", res.Changes, res.Servers[0].Open)
	}
}

func TestMatchEndOfLifeAndMissingInventory(t *testing.T) {
	e, paths := newEngine(t, &fakeData{fixed: "1:0"})
	saveInventory(t, paths, "old", "20.04", "1:8.2p1-4ubuntu0.11")
	old := web
	old.Name = "old"
	res, err := e.Match(context.Background(), []config.Server{old, web}) // web has no package list yet
	if err != nil {
		t.Fatal(err)
	}
	st, _ := findings.Load(paths)
	if f := st.Find("old/end-of-life/ubuntu-20.04"); f == nil || f.Priority != findings.High || !strings.Contains(f.Summary, "Ubuntu Pro") {
		t.Fatalf("end-of-life finding = %+v", f)
	}
	if res.Servers[1].Code != "INVENTORY_NOT_FOUND" {
		t.Fatalf("missing inventory: %+v", res.Servers[1])
	}
}

func TestMarkNotRefreshed(t *testing.T) {
	res := &Result{Servers: []ServerResult{
		{Server: "web"}, // refresh failed, older list matched
		{Server: "db"},  // refreshed
		{Server: "old", Code: "INVENTORY_NOT_FOUND", Error: "no package list for old yet"}, // already has its own problem
	}}
	res.MarkNotRefreshed(map[string]error{
		"web": apperr.New(apperr.ServerUnreachable, "cannot log in to web"),
		"old": apperr.New(apperr.ServerUnreachable, "cannot log in to old"),
	})
	if got := res.Servers[0]; got.Code != apperr.ServerUnreachable || got.Error != "package list not refreshed: cannot log in to web" {
		t.Errorf("web = %+v", got)
	}
	if got := res.Servers[1]; got.Code != "" || got.Error != "" {
		t.Errorf("db was refreshed but is marked: %+v", got)
	}
	if got := res.Servers[2]; got.Code != "INVENTORY_NOT_FOUND" || got.Error != "no package list for old yet" {
		t.Errorf("old lost its own error: %+v", got)
	}
}

// A lookup that fails must not be stored as a score of 0: the priority would
// drop, and when the source answered again the rise would be taken for an
// escalation and bring back a finding you had snoozed or accepted.
func TestFailedLookupKeepsTheLastKnownScore(t *testing.T) {
	const id = "web/vulnerability/CVE-2024-6387/openssh"
	for _, tc := range []struct {
		source      string  // what the finding's priority depends on, and what fails
		minSeverity float64 // CVSS: 8.1 meets 8.0, the distro's "high" (7.5) doesn't. EPSS: neither meets 9.5.
		epss        string
		warning     string
	}{
		{source: "epss", minSeverity: 9.5, epss: "0.50", warning: "EPSS unavailable"},
		{source: "cve", minSeverity: 8.0, warning: "1 CVE records unavailable"},
	} {
		for _, ack := range []findings.State{"", findings.StateSnoozed, findings.StateAccepted} {
			t.Run(tc.source+"/"+cmp.Or(string(ack), "not acknowledged"), func(t *testing.T) {
				d := &fakeData{fixed: "1:9.6p1-3ubuntu13.8", epss: tc.epss}
				e, paths := newEngine(t, d)
				e.Rules.AlertWhen.MinSeverity = tc.minSeverity
				saveInventory(t, paths, "web", "24.04", "1:9.6p1-3ubuntu13.5")
				servers := []config.Server{web}
				match := func() (*Result, *findings.Finding) {
					res, err := e.Match(context.Background(), servers)
					if err != nil {
						t.Fatal(err)
					}
					st, _ := findings.Load(paths)
					return res, st.Find(id)
				}

				_, known := match()
				if known.Priority != findings.High {
					t.Fatalf("setup: priority %s, want high (from %s alone)", known.Priority, tc.source)
				}
				state := known.State // the first check counts as announced
				if ack != "" {
					state = ack
					_ = findings.Update(paths, func(st *findings.Store) error { return st.Find(id).Transition(state, e.Now()) })
				}

				d.set(func() { d.failing[tc.source] = true })
				_ = os.RemoveAll(paths.Cache + "/cve") // the saved CVE record has expired
				res, f := match()
				if f.Priority != findings.High || f.Score != known.Score || f.EPSS != known.EPSS || f.State != state || len(res.Changes.Escalated) != 0 {
					t.Fatalf("while %s failed: priority %s score %v epss %v state %s escalated %d; want high, %v, %v, %s, 0",
						tc.source, f.Priority, f.Score, f.EPSS, f.State, len(res.Changes.Escalated), known.Score, known.EPSS, state)
				}
				if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, tc.warning) }) {
					t.Errorf("warnings %q lack %q", res.Warnings, tc.warning)
				}

				d.set(func() { d.failing[tc.source] = false })
				res, f = match()
				if f.Priority != findings.High || f.State != state || len(res.Changes.Escalated) != 0 {
					t.Fatalf("after %s recovered: priority %s state %s escalated %d; want high, %s, 0",
						tc.source, f.Priority, f.State, len(res.Changes.Escalated), state)
				}
			})
		}
	}
}

// With nothing new (the usual run) the change lists are [] in JSON, never
// null, so scripts can loop over them.
func TestResultListsAreJSONArraysWhenNothingChanged(t *testing.T) {
	d := &fakeData{fixed: "1:9.6p1-3ubuntu13.8"}
	e, paths := newEngine(t, d)
	saveInventory(t, paths, "web", "24.04", "1:9.6p1-3ubuntu13.8") // nothing affected
	for range 2 {                                                  // the first check, then one with no news
		res, err := e.Match(context.Background(), []config.Server{web})
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(res.Changes)
		if want := `{"new":[],"reopened":[],"escalated":[],"resolved":[]}`; err != nil || string(data) != want {
			t.Fatalf("changes = %s (%v), want %s", data, err, want)
		}
	}
}
