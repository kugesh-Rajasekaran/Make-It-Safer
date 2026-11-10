package apple

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
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

func TestParseImpacts(t *testing.T) {
	page, err := os.ReadFile("testdata/note.html")
	if err != nil {
		t.Fatal(err)
	}
	got := ParseImpacts(page)
	want := map[string]string{
		"CVE-2026-28991": "An app may crash.", "CVE-2026-86971": "Opening a crafted image may crash the app.",
		"CVE-2026-113898": "An app may read private data.", "CVE-2026-64767": "A remote attacker may crash the system.",
		"CVE-2026-112525": "An app may read kernel memory.", "CVE-2026-112536": "An app may write kernel memory.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("impacts = %v", got)
	}
	// A CVE line before any "Impact:" of its entry gets none; long text is cut.
	odd := []byte(`<p>Available for: macOS</p><p>CVE-2026-0001: someone</p><p>Available for: macOS</p><p>Impact: ` + strings.Repeat("x", 300) + `</p><p>CVE-2026-0002</p>`)
	got = ParseImpacts(odd)
	if _, ok := got["CVE-2026-0001"]; ok || len([]rune(got["CVE-2026-0002"])) != maxImpact {
		t.Fatalf("odd page: %v", got)
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

// pageServer answers every request with whatever body currently holds.
type pageServer struct {
	*httptest.Server
	body atomic.Value // string
}

func newPageServer(t *testing.T, body string) *pageServer {
	t.Helper()
	p := &pageServer{}
	p.body.Store(body)
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(p.body.Load().(string)))
	}))
	t.Cleanup(p.Close)
	return p
}

func cacheFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = string(data)
	}
	return files
}

// A page that lists no CVEs and doesn't say so is an error page or a changed
// layout. It must not be taken for "this release fixes nothing".
func TestNoteWithoutCVEs(t *testing.T) {
	note, _ := os.ReadFile("testdata/note.html")
	const errorPage = "<html>Service unavailable</html>"
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	t.Run("nothing cached", func(t *testing.T) {
		srv := newPageServer(t, errorPage)
		r := Release{Name: "macOS Sequoia 15.8.2", Product: MacOS, Version: "15.8.2", URL: srv.URL + "/en-us/149523"}
		c := &Client{Feeds: feeds.NewForTest(srv.URL), IndexURL: srv.URL, Cache: t.TempDir(), Now: func() time.Time { return now }}
		if cves, err := c.CVEs(ctx, r); !apperr.Is(err, apperr.FeedsInvalidData) {
			t.Fatalf("CVEs() = %v, %v; want %s", cves, err, apperr.FeedsInvalidData)
		}
		if files := cacheFiles(t, c.Cache); len(files) != 0 {
			t.Fatalf("the error page was cached: %v", files)
		}
	})

	t.Run("stale copy is kept", func(t *testing.T) {
		now := now
		srv := newPageServer(t, string(note))
		r := Release{Name: "macOS Sequoia 15.8.2", Product: MacOS, Version: "15.8.2", URL: srv.URL + "/en-us/149523"}
		c := &Client{Feeds: feeds.NewForTest(srv.URL), IndexURL: srv.URL, Cache: t.TempDir(), Now: func() time.Time { return now }}
		if cves, err := c.CVEs(ctx, r); err != nil || len(cves) != 6 {
			t.Fatalf("first read: %v, %v", cves, err)
		}
		before := cacheFiles(t, c.Cache)

		now = now.Add(8 * 24 * time.Hour) // the copy is stale, and the page now fails
		srv.body.Store(errorPage)
		cves, err := c.CVEs(ctx, r)
		if err == nil {
			t.Fatal("the unreadable page was not reported")
		}
		if len(cves) != 6 {
			t.Fatalf("the saved CVEs were lost: %v", cves)
		}
		if after := cacheFiles(t, c.Cache); !reflect.DeepEqual(before, after) {
			t.Fatal("the cached note was overwritten")
		}
	})

	t.Run("a note that says it has no CVEs is fine", func(t *testing.T) {
		srv := newPageServer(t, "<html><p>This update has no published CVE entries.</p></html>")
		r := Release{Name: "macOS Sequoia 15.8.2", Product: MacOS, Version: "15.8.2", URL: srv.URL + "/en-us/149523"}
		c := &Client{Feeds: feeds.NewForTest(srv.URL), IndexURL: srv.URL, Cache: t.TempDir(), Now: func() time.Time { return now }}
		if cves, err := c.CVEs(ctx, r); err != nil || len(cves) != 0 {
			t.Fatalf("CVEs() = %v, %v", cves, err)
		}
	})
}

// When the index page arrives but has no releases (Apple changed its
// layout), the check reports it instead of going on with the old list.
func TestIndexLayoutChangeIsReportedWithOldCopy(t *testing.T) {
	index, _ := os.ReadFile("testdata/index.html")
	srv := newPageServer(t, string(index))
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	c := &Client{Feeds: feeds.NewForTest(srv.URL), IndexURL: srv.URL, Cache: t.TempDir(), Now: func() time.Time { return now }}
	ctx := context.Background()
	if rs, err := c.Releases(ctx); err != nil || len(rs) != 9 {
		t.Fatalf("first read: %d, %v", len(rs), err)
	}

	now = now.Add(7 * time.Hour)
	srv.body.Store("<html><table><tr><td>redesigned</td></tr></table></html>")
	if _, err := c.Releases(ctx); !apperr.Is(err, apperr.FeedsInvalidData) {
		t.Fatalf("Releases() = %v, want %s", err, apperr.FeedsInvalidData)
	}
}

// A note cached by an older version (no impacts) is read again once, even
// though it is still fresh and Apple answers "not modified".
func TestOlderCachedNoteIsReadAgain(t *testing.T) {
	note, _ := os.ReadFile("testdata/note.html")
	var full atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		_, _ = w.Write(note)
	}))
	defer srv.Close()

	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	old := `{"fetched": "2026-11-08T11:00:00Z", "etag": "\"v1\"", "cves": ["CVE-2026-28991"]}`
	if err := os.WriteFile(filepath.Join(dir, "note-149523.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{Feeds: feeds.NewForTest(srv.URL), Cache: dir, Now: func() time.Time { return now }}
	r := Release{Name: "macOS Sequoia 15.8.2", Product: MacOS, Version: "15.8.2", URL: srv.URL + "/en-us/149523"}
	n, err := c.Note(context.Background(), r)
	if err != nil || len(n.CVEs) != 6 || n.Impacts["CVE-2026-28991"] != "An app may crash." || full.Load() != 1 {
		t.Fatalf("note = %+v, %v (full downloads: %d)", n, err, full.Load())
	}
	if _, err := c.Note(context.Background(), r); err != nil || full.Load() != 1 {
		t.Fatalf("the upgraded copy should be used from now on: %v, downloads %d", err, full.Load())
	}
}
