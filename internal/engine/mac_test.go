package engine

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/apple"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/eol"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/epss"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/kev"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/osv"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
)

// The Apple test pages: every release note serves the same six CVEs.
const exploited = "CVE-2026-112525" // listed in the fake CISA KEV

func newMacEngine(t *testing.T, appleDown *atomic.Bool) (*Engine, config.Paths) {
	t.Helper()
	index, err := os.ReadFile("../feeds/apple/testdata/index.html")
	if err != nil {
		t.Fatal(err)
	}
	note, err := os.ReadFile("../feeds/apple/testdata/note.html")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /apple/index", func(w http.ResponseWriter, r *http.Request) {
		if appleDown.Load() {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(index)
	})
	mux.HandleFunc("GET /en-us/{id}", func(w http.ResponseWriter, r *http.Request) {
		if appleDown.Load() {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(note)
	})
	mux.HandleFunc("GET /kev.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"catalogVersion":"1","vulnerabilities":[{"cveID":"`+exploited+`"}]}`)
	})
	mux.HandleFunc("GET /epss", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"data":[]}`) })
	mux.HandleFunc("GET /macos.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"cycle":"15","eol":false},{"cycle":"14","eol":"2026-09-14"}]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	paths := config.PathsAt(t.TempDir())
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	fc := feeds.NewForTest(srv.URL)
	now := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	return &Engine{
		Paths: paths, Rules: config.Default().Rules,
		OSV:  &osv.Client{Feeds: fc, API: srv.URL, Cache: paths.Cache + "/osv"},
		KEV:  &kev.Client{Feeds: fc, URLs: []string{srv.URL + "/kev.json"}, Cache: paths.Cache + "/kev.json", ETag: paths.Cache + "/kev.etag"},
		EPSS: &epss.Client{Feeds: fc, API: srv.URL + "/epss"}, EOL: &eol.Client{Feeds: fc, API: srv.URL},
		CVE:   &cvelist.Client{Feeds: fc, Base: srv.URL, Cache: paths.Cache + "/cve", Now: time.Now},
		Apple: &apple.Client{Feeds: fc, IndexURL: srv.URL + "/apple/index", Base: srv.URL, Cache: paths.Cache + "/apple", Now: func() time.Time { return now }},
		Now:   func() time.Time { return now },
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, paths
}

// macInventory is this Mac on macOS 15.7.7 and Safari 26.6.1, with Apple
// offering Safari 27.2, macOS 15.8.2 and the macOS 27 upgrade.
func macInventory(updates ...inventory.AppleUpdate) *inventory.Inventory {
	if updates == nil {
		updates = []inventory.AppleUpdate{
			{Label: "Safari27.2SequoiaAuto-27.2", Title: "Safari", Version: "27.2"},
			{Label: "macOS Sequoia 15.8.2-24H232", Title: "macOS Sequoia 15.8.2", Version: "15.8.2", Restart: true},
			{Label: "macOS 27.2-26B123", Title: "macOS 27.2", Version: "27.2", Restart: true},
		}
	}
	return &inventory.Inventory{OSID: "macos", OSVersion: "15.7.7", Kernel: "24.6.0", Arch: "arm64", Mac: &inventory.Mac{
		Safari: "26.6.1", Updates: updates,
		Homebrew: []inventory.BrewPackage{{Name: "aom", Installed: "3.11.0", Current: "3.15.3"}, {Name: "curl", Installed: "8.1", Current: "8.11"}},
	}}
}

func TestThisMac(t *testing.T) {
	var down atomic.Bool
	e, paths := newMacEngine(t, &down)
	mac := config.Server{Name: "this-mac", Local: true}
	inv := macInventory()
	e.Local = func(context.Context, time.Time) (*inventory.Inventory, error) { return inv, nil }

	// Refresh reads this computer without any key.
	if failed := e.Refresh(context.Background(), nil, []config.Server{mac}); len(failed) != 0 {
		t.Fatalf("refresh: %v", failed)
	}
	res, err := e.Match(context.Background(), []config.Server{mac})
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Servers[0]; r.Code != "" || r.OS != "macos 15.7.7" {
		t.Fatalf("result: %+v", r)
	}
	st, err := findings.Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range st.Findings {
		counts[f.Source]++
		switch f.Source {
		case "macos":
			if f.Fixed != "15.8.2" || f.Installed != "15.7.7" || !strings.HasPrefix(f.VulnID, "macOS Sequoia 15.") {
				t.Errorf("macOS finding: %+v", f)
			}
		case "safari":
			if f.Fixed != "27.2" || f.Installed != "26.6.1" {
				t.Errorf("Safari finding: %+v", f)
			}
		case "homebrew":
			if f.Kind != findings.KindUpdates || f.Priority != findings.Normal || !strings.Contains(f.Summary, "2 Homebrew packages") {
				t.Errorf("Homebrew finding: %+v", f)
			}
		}
		if f.CVE == exploited && f.Priority != findings.Urgent {
			t.Errorf("actively exploited CVE should be urgent: %+v", f)
		}
	}
	// Six CVEs per product (the macOS 27 upgrade adds none), one Homebrew line, no end-of-life.
	if counts["macos"] != 6 || counts["safari"] != 6 || counts["homebrew"] != 1 || len(st.Findings) != 13 {
		t.Fatalf("findings per source: %v (%d in all)", counts, len(st.Findings))
	}

	// Everything updated: the next check resolves them all.
	inv.Mac.Updates, inv.Mac.Homebrew = nil, nil
	e.Refresh(context.Background(), nil, []config.Server{mac})
	res, err = e.Match(context.Background(), []config.Server{mac})
	if err != nil || len(res.Changes.Resolved) != 13 {
		t.Fatalf("after updating: %d resolved, %v", len(res.Changes.Resolved), err)
	}
}

func TestThisMacKeepsFindingsWhenAppleIsUnreachable(t *testing.T) {
	var down atomic.Bool
	e, paths := newMacEngine(t, &down)
	mac := config.Server{Name: "this-mac", Local: true}
	if err := inventory.Save(paths, mac.Name, macInventory()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Match(context.Background(), []config.Server{mac}); err != nil {
		t.Fatal(err)
	}

	down.Store(true)
	e.Apple.Cache = t.TempDir() // no saved copy of Apple's pages either
	res, err := e.Match(context.Background(), []config.Server{mac})
	if err != nil {
		t.Fatal(err)
	}
	if res.Servers[0].Code == "" || len(res.Changes.Resolved) != 0 {
		t.Fatalf("Apple down must not resolve findings: %+v, %d resolved", res.Servers[0], len(res.Changes.Resolved))
	}
}

func TestThisMacEndOfLife(t *testing.T) {
	var down atomic.Bool
	e, paths := newMacEngine(t, &down)
	mac := config.Server{Name: "this-mac", Local: true}
	old := macInventory([]inventory.AppleUpdate{}...)
	old.OSVersion = "14.8.9"
	if err := inventory.Save(paths, mac.Name, old); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Match(context.Background(), []config.Server{mac}); err != nil {
		t.Fatal(err)
	}
	st, _ := findings.Load(paths)
	f := st.Find("this-mac/end-of-life/macos-14")
	if f == nil || f.Priority != findings.Urgent || !strings.Contains(f.Summary, "macOS 14") {
		t.Fatalf("macOS 14 is past its end of life: %+v", f)
	}
}
