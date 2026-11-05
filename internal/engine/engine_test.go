package engine

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

	mu      sync.Mutex
	log     string            // CVE List delta log
	records map[string]string // CVE → CVE record
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
		d.distro, d.fetched = map[string]string{}, map[string]int{}
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
		_, _ = io.WriteString(w, `{"catalogVersion":"1","vulnerabilities":[{"cveID":"`+id+`"}]}`)
	})
	mux.HandleFunc("GET /epss", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"cve":"CVE-2024-6387","epss":"0.02"}]}`)
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
