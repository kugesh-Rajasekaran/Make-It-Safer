package apple

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

func TestParseIndex(t *testing.T) {
	page, err := os.ReadFile("testdata/index.html")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range ParseIndex(page) {
		names = append(names, r.Name+"|"+r.Product+"|"+r.Version)
		if r.URL == "" {
			t.Errorf("%s has no URL", r.Name)
		}
	}
	want := []string{
		"macOS Tahoe 26.7.2|macOS|26.7.2", "macOS Sequoia 15.8.2|macOS|15.8.2", "Safari 27.2|Safari|27.2",
		"macOS Sequoia 15.8.1|macOS|15.8.1", "macOS Sequoia 15.8|macOS|15.8", "Safari 27|Safari|27",
		"Safari 26.6.1|Safari|26.6.1", "macOS Sequoia 15.7.9|macOS|15.7.9", "macOS Sequoia 15.7.8|macOS|15.7.8",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("got  %v\nwant %v (visionOS and other products are skipped)", names, want)
	}

	// Rows without a security note ("no published CVE entries") are skipped.
	noNote := []byte(`<tr><td><p>macOS Sequoia 15.7.9</p><div><p>This update has no published CVE entries.</p></div></td><td><p>macOS Sequoia</p></td><td><p>1 Jan 2026</p></td></tr>`)
	if got := ParseIndex(noNote); len(got) != 0 {
		t.Fatalf("row without a note: %+v", got)
	}
}

func TestParseCVEs(t *testing.T) {
	page, err := os.ReadFile("testdata/note.html")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2026-112525", "CVE-2026-112536", "CVE-2026-113898", "CVE-2026-28991", "CVE-2026-64767", "CVE-2026-86971"}
	if got := ParseCVEs(page); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"15.7.7", "15.8", -1}, {"15.8", "15.8.0", 0}, {"15.10", "15.9", 1}, {"27.2", "26.6.1", 1}, {"15", "15.0.1", -1}}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if Major("15.7.7") != "15" {
		t.Error("Major")
	}
}

func TestClientCachesAndFallsBack(t *testing.T) {
	index, _ := os.ReadFile("testdata/index.html")
	note, _ := os.ReadFile("testdata/note.html")
	var fetches, down atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if down.Load() == 1 {
			http.Error(w, "gone", http.StatusNotFound) // not retried, keeps the test fast
			return
		}
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.URL.Path == "/index" {
			_, _ = w.Write(index)
			return
		}
		_, _ = w.Write(note)
	}))
	defer srv.Close()

	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	c := &Client{Feeds: feeds.NewForTest(srv.URL), IndexURL: srv.URL + "/index", Cache: t.TempDir(), Now: func() time.Time { return now }}
	ctx := context.Background()

	rs, err := c.Releases(ctx)
	if err != nil || len(rs) != 9 {
		t.Fatalf("releases: %d, %v", len(rs), err)
	}
	r := Release{Name: "macOS Sequoia 15.8.2", Product: MacOS, Version: "15.8.2", URL: srv.URL + "/en-us/149523"}
	if cves, err := c.CVEs(ctx, r); err != nil || len(cves) != 6 {
		t.Fatalf("cves: %v, %v", cves, err)
	}

	before := fetches.Load()
	_, _ = c.Releases(ctx)
	_, _ = c.CVEs(ctx, r)
	if fetches.Load() != before {
		t.Fatal("fresh pages were downloaded again")
	}

	now = now.Add(8 * 24 * time.Hour) // both are stale: asked again, answered 304
	if rs, err := c.Releases(ctx); err != nil || len(rs) != 9 {
		t.Fatalf("after 304: %d, %v", len(rs), err)
	}

	now = now.Add(8 * 24 * time.Hour)
	down.Store(1) // Apple is down: the last good copy is used
	if cves, err := c.CVEs(ctx, r); err != nil || len(cves) != 6 {
		t.Fatalf("while down: %v, %v", cves, err)
	}

	empty := &Client{Feeds: feeds.NewForTest(srv.URL), IndexURL: srv.URL + "/index", Cache: t.TempDir(), Now: time.Now}
	if _, err := empty.Releases(ctx); err == nil {
		t.Fatal("no copy and Apple down: want an error, not an empty list")
	}
}
