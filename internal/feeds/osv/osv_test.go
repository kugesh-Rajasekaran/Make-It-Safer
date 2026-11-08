package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign
	}{
		{"1.0", "1.1", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1:0.1", "2.0", 1},
		{"1.0-1", "1.0-2", -1},
		{"1.0a", "1.0", 1},
		{"1.0+b1", "1.0", 1},
		{"1.0", "1.00", 0},
		{"1.0-0", "1.0", 0},
		{"2.39-0ubuntu8.9", "2.39-0ubuntu8.10", -1},
		{"1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.8", -1},
		{"1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.7", 1},
		{"3.0.13-0ubuntu3.16", "3.0.13-0ubuntu3.16", 0},
		{"1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2", 1},
		{"6.1.0-26", "6.1.0-28", -1},
	}
	sign := func(n int) int {
		switch {
		case n < 0:
			return -1
		case n > 0:
			return 1
		}
		return 0
	}
	for _, tc := range cases {
		if got := sign(CompareVersions(tc.a, tc.b)); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := sign(CompareVersions(tc.b, tc.a)); got != -tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

// regreSSHion as published by Ubuntu (trimmed).
const ubuntuRecord = `{
 "id": "UBUNTU-CVE-2024-6387", "modified": "2026-02-04T04:18:00Z", "upstream": ["CVE-2024-6387"],
 "summary": "regreSSHion", "severity": [{"type": "Ubuntu", "score": "High"}],
 "affected": [
  {"package": {"name": "openssh", "ecosystem": "Ubuntu:22.04:LTS"},
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:8.9p1-3ubuntu0.10"}]}],
   "versions": ["1:8.9p1-3", "1:8.9p1-3ubuntu0.7"],
   "ecosystem_specific": {"availability": "No subscription required"}},
  {"package": {"name": "openssh", "ecosystem": "Ubuntu:Pro:20.04:LTS"},
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:8.2p1-4ubuntu0.12+esm1"}]}],
   "ecosystem_specific": {"availability": "Available with Ubuntu Pro: https://ubuntu.com/pro"}},
  {"package": {"name": "openssh", "ecosystem": "Ubuntu:24.04:LTS"},
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
 ]}`

func TestVulnHelpers(t *testing.T) {
	var v Vuln
	if err := json.Unmarshal([]byte(ubuntuRecord), &v); err != nil {
		t.Fatal(err)
	}
	if v.CVE() != "CVE-2024-6387" || v.DistroPriority("Ubuntu:22.04:LTS", "openssh") != "high" {
		t.Fatalf("CVE() = %q, priority = %q", v.CVE(), v.DistroPriority("Ubuntu:22.04:LTS", "openssh"))
	}
	cases := []struct {
		eco, installed, fixed string
		pro                   bool
	}{
		{"Ubuntu:22.04:LTS", "1:8.9p1-3ubuntu0.7", "1:8.9p1-3ubuntu0.10", false},
		{"Ubuntu:22.04:LTS", "1:8.9p1-3ubuntu0.10", "", false}, // already fixed
		{"Ubuntu:Pro:20.04:LTS", "1:8.2p1-4ubuntu0.11", "1:8.2p1-4ubuntu0.12+esm1", true},
		{"Ubuntu:24.04:LTS", "1:9.6p1-3ubuntu13", "", false}, // no fix yet
	}
	for _, tc := range cases {
		fixed, pro := v.Fix(tc.eco, "openssh", tc.installed)
		if fixed != tc.fixed || pro != tc.pro {
			t.Errorf("Fix(%s, %s) = %q, %v; want %q, %v", tc.eco, tc.installed, fixed, pro, tc.fixed, tc.pro)
		}
	}
}

func TestEcosystems(t *testing.T) {
	cases := map[[2]string][]string{
		{"ubuntu", "24.04"}: {"Ubuntu:24.04:LTS", "Ubuntu:Pro:24.04:LTS"},
		{"ubuntu", "25.10"}: {"Ubuntu:25.10"},
		{"ubuntu", "23.04"}: {"Ubuntu:23.04"},
		{"debian", "12"}:    {"Debian:12"},
		{"fedora", "41"}:    nil,
	}
	for in, want := range cases {
		got := Ecosystems(in[0], in[1])
		if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) {
			t.Errorf("Ecosystems(%v) = %v, want %v", in, got, want)
		}
	}
	if !Relevant("DEBIAN-CVE-2024-6387") || Relevant("DSA-5724-1") || Relevant("USN-6859-1") {
		t.Error("Relevant() filters the wrong records")
	}
}

func TestQueryBatchPagesAndChunks(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Queries) > batchSize {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var resp batchResponse
		resp.Results = make([]struct {
			Vulns         []Ref  `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		}, len(req.Queries))
		for i, q := range req.Queries {
			if q.Package.Name == "openssh" && q.PageToken == "" {
				resp.Results[i].Vulns = []Ref{{ID: "UBUNTU-CVE-2024-6387"}}
				resp.Results[i].NextPageToken = "page2"
			}
			if q.Package.Name == "openssh" && q.PageToken == "page2" {
				resp.Results[i].Vulns = []Ref{{ID: "UBUNTU-CVE-2023-48795"}}
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	queries := make([]Query, 1500)
	for i := range queries {
		queries[i] = Query{Ecosystem: "Ubuntu:24.04:LTS", Name: "pkg", Version: "1.0"}
	}
	queries[1200] = Query{Ecosystem: "Ubuntu:24.04:LTS", Name: "openssh", Version: "1:9.6p1-3ubuntu13"}
	c := &Client{Feeds: feeds.NewForTest(srv.URL), API: srv.URL}
	out, err := c.QueryBatch(context.Background(), queries)
	if err != nil {
		t.Fatal(err)
	}
	if len(out[1200]) != 2 || len(out[0]) != 0 {
		t.Fatalf("results = %v / %v", out[1200], out[0])
	}
	if requests.Load() != 3 { // 1000 + 500, then one page for openssh
		t.Fatalf("%d requests, want 3", requests.Load())
	}
}

func TestVulnCache(t *testing.T) {
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if r.URL.Path != "/v1/vulns/UBUNTU-CVE-2024-6387" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(ubuntuRecord))
	}))
	defer srv.Close()
	c := &Client{Feeds: feeds.NewForTest(srv.URL), API: srv.URL, Cache: filepath.Join(t.TempDir(), "osv")}
	ref := Ref{ID: "UBUNTU-CVE-2024-6387", Modified: time.Date(2026, 2, 4, 4, 18, 0, 0, time.UTC)}
	for range 2 {
		v, err := c.Vuln(context.Background(), ref)
		if err != nil || v.CVE() != "CVE-2024-6387" {
			t.Fatalf("Vuln() = %v, %v", v, err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("%d fetches, want 1 (second read from cache)", fetches.Load())
	}
	cached, _ := os.ReadFile(filepath.Join(c.Cache, ref.ID+".json"))
	if len(cached) == 0 || json.Valid(cached) == false {
		t.Fatal("record not cached")
	}
	ref.Modified = ref.Modified.Add(time.Hour) // OSV changed it: fetch again
	if _, err := c.Vuln(context.Background(), ref); err != nil || fetches.Load() != 2 {
		t.Fatalf("stale cache not refreshed: %v, %d fetches", err, fetches.Load())
	}
	if _, err := c.Vuln(context.Background(), Ref{ID: "../../etc/passwd"}); err == nil {
		t.Fatal("unsafe id accepted")
	}
}

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vulns/UBUNTU-CVE-2024-6387":
			_, _ = w.Write([]byte(ubuntuRecord))
		case "/v1/vulns/DEBIAN-CVE-2024-6387":
			http.Error(w, "down", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{Feeds: feeds.NewForTest(srv.URL), API: srv.URL, Cache: filepath.Join(t.TempDir(), "osv")}
	ctx := context.Background()
	if ok, err := c.Exists(ctx, DistroID("ubuntu", "CVE-2024-6387")); !ok || err != nil {
		t.Errorf("assessed record: %v, %v", ok, err)
	}
	if ok, err := c.Exists(ctx, DistroID("ubuntu", "CVE-2026-0001")); ok || err != nil {
		t.Errorf("not assessed yet: %v, %v", ok, err)
	}
	if _, err := c.Exists(ctx, DistroID("debian", "CVE-2024-6387")); err == nil {
		t.Error("an OSV error counts as an answer")
	}
	if DistroID("fedora", "CVE-2024-6387") != "" || DistroID("debian", "CVE-2024-6387") != "DEBIAN-CVE-2024-6387" {
		t.Error("DistroID")
	}
}

// FuzzVersions checks that version comparison never panics and is
// antisymmetric, whatever a feed or server sends.
func FuzzVersions(f *testing.F) {
	f.Add("1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.8")
	f.Add("1.0~rc1", "1.0")
	f.Add("", "0")
	f.Fuzz(func(t *testing.T, a, b string) {
		x, y := CompareVersions(a, b), CompareVersions(b, a)
		if (x < 0) != (y > 0) || (x == 0) != (y == 0) {
			t.Fatalf("CompareVersions(%q, %q) = %d but reversed = %d", a, b, x, y)
		}
	})
}

// FuzzVuln checks that hostile OSV records never crash the helpers.
func FuzzVuln(f *testing.F) {
	f.Add([]byte(ubuntuRecord), "Ubuntu:22.04:LTS", "openssh", "1:8.9p1-3ubuntu0.7")
	f.Fuzz(func(t *testing.T, data []byte, eco, pkg, installed string) {
		var v Vuln
		if json.Unmarshal(data, &v) != nil {
			return
		}
		_ = v.CVE()
		_ = v.DistroPriority(eco, pkg)
		if fixed, _ := v.Fix(eco, pkg, installed); fixed != "" && CompareVersions(fixed, installed) <= 0 {
			t.Fatalf("Fix() returned %q, not newer than %q", fixed, installed)
		}
	})
}
