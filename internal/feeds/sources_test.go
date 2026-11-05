package feeds_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/eol"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/epss"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/kev"
)

func serve(t *testing.T, routes map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"1"`)
		if r.Header.Get("If-None-Match") == `"1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	p := config.PathsAt(t.TempDir())
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKEV(t *testing.T) {
	srv, hits := serve(t, map[string]string{
		"/kev.json": `{"catalogVersion":"2026.11.03","vulnerabilities":[{"cveID":"CVE-2024-6387","vulnerabilityName":"OpenSSH regreSSHion","dateAdded":"2026-01-10"}]}`,
	})
	c := kev.New(feeds.NewForTest(srv.URL), testPaths(t))
	c.URLs = []string{srv.URL + "/down", srv.URL + "/kev.json"} // first source fails, mirror answers

	cat, err := c.Refresh(context.Background())
	if err != nil || !cat.Has("CVE-2024-6387") || cat.Has("CVE-2000-0001") {
		t.Fatalf("Refresh() = %+v, %v", cat, err)
	}
	if _, err := c.Refresh(context.Background()); err != nil { // unchanged: ETag answer
		t.Fatal(err)
	}
	before := hits.Load()
	c.URLs = []string{srv.URL + "/down"} // offline: the saved copy is used
	if cat, err := c.Refresh(context.Background()); err != nil || !cat.Has("CVE-2024-6387") || hits.Load() == before {
		t.Fatalf("offline Refresh() = %v, %v", cat, err)
	}
}

func TestEPSS(t *testing.T) {
	srv, _ := serve(t, map[string]string{
		"/epss": `{"status":"OK","data":[{"cve":"CVE-2024-6387","epss":"0.93","percentile":"0.99"},{"cve":"CVE-2000-0001","epss":"bogus"}]}`,
	})
	c := epss.New(feeds.NewForTest(srv.URL))
	c.API = srv.URL + "/epss"
	scores, err := c.Scores(context.Background(), []string{"CVE-2024-6387", "CVE-2000-0001"})
	if err != nil || scores["CVE-2024-6387"] != 0.93 || len(scores) != 1 {
		t.Fatalf("Scores() = %v, %v", scores, err)
	}
}

func TestEOL(t *testing.T) {
	srv, _ := serve(t, map[string]string{
		"/ubuntu.json": `[
			{"cycle":"24.04","lts":true,"eol":"2029-05-31","extendedSupport":"2036-04-25"},
			{"cycle":"20.04","lts":true,"eol":"2025-05-29","extendedSupport":"2030-04-02"},
			{"cycle":"16.04","lts":true,"eol":"2021-04-30","extendedSupport":"2026-04-30"},
			{"cycle":"26.04","lts":true,"eol":false}
		]`,
	})
	c := eol.New(feeds.NewForTest(srv.URL))
	c.API = srv.URL
	cycles, err := c.Cycles(context.Background(), "ubuntu")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	for release, want := range map[string]eol.Status{
		"24.04": eol.Supported, "26.04": eol.Supported, "20.04": eol.ExtendedOnly, "16.04": eol.Unsupported, "18.10": eol.Unknown,
	} {
		if got, _ := eol.StatusOf(cycles, release, now); got != want {
			t.Errorf("StatusOf(%s) = %v, want %v", release, got, want)
		}
	}
}

func TestCVERecord(t *testing.T) {
	record, err := os.ReadFile(filepath.Join("cvelist", "testdata", "CVE-2024-6387.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, hits := serve(t, map[string]string{"/cves/2024/6xxx/CVE-2024-6387.json": string(record)})
	c := cvelist.New(feeds.NewForTest(srv.URL), testPaths(t))
	c.Base = srv.URL
	for range 2 {
		r, err := c.Get(context.Background(), "CVE-2024-6387")
		if err != nil {
			t.Fatal(err)
		}
		if r.Score != 8.1 || !strings.Contains(strings.ToLower(r.Title), "regresshion") || r.Products[0].Package != "OpenSSH" {
			t.Fatalf("record = %+v", r)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("%d fetches, want 1 (second from cache)", hits.Load())
	}
	if _, err := c.Get(context.Background(), "CVE-24-1/../../x"); err == nil {
		t.Fatal("invalid id accepted")
	}
}
