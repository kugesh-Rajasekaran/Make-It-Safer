package cvelist

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
)

// testdata/deltaLog.json holds the first six change sets of the real log.
const (
	newest = "2026-11-05T08:38:07.805Z"
	third  = "2026-11-05T07:59:00.914Z"
)

func at(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// logServer serves a delta log with range support, like raw.githubusercontent.com.
func logServer(t *testing.T, log []byte) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cves/deltaLog.json" {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, "deltaLog.json", time.Time{}, bytes.NewReader(log))
	}))
	t.Cleanup(srv.Close)
	return &Client{Feeds: feeds.NewForTest(srv.URL), Base: srv.URL, Cache: t.TempDir(), Now: time.Now}
}

func TestChanges(t *testing.T) {
	log, err := os.ReadFile("testdata/deltaLog.json")
	if err != nil {
		t.Fatal(err)
	}
	old := readSizes
	readSizes = []int64{512, 4096, 0} // small reads, to go through the growing ones
	defer func() { readSizes = old }()
	c := logServer(t, log)
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		since   time.Time
		reset   bool
		changes int
	}{
		{"first run starts from now", time.Time{}, true, 0},
		{"nothing new", at(t, newest), false, 0},
		{"two change sets", at(t, third), false, 5}, // 1 updated + (2 new, 2 updated)
		{"older than the log", at(t, "2026-10-01T00:00:00Z"), true, 0},
	} {
		d, err := c.Changes(ctx, tc.since)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if d.Reset != tc.reset || len(d.Changes) != tc.changes || !d.Newest.Equal(at(t, newest)) {
			t.Errorf("%s: reset %v, %d changes %v, newest %s", tc.name, d.Reset, len(d.Changes), d.Changes, d.Newest)
		}
	}

	d, _ := c.Changes(ctx, at(t, third))
	news := 0
	for _, ch := range d.Changes {
		if ch.New {
			news++
		}
	}
	if news != 2 {
		t.Errorf("new = %d, want 2: %v", news, d.Changes)
	}
}

func TestChangesIgnoresBadIDsAndRepeats(t *testing.T) {
	log := `[
	{"fetchTime":"2026-11-05T10:00:00Z","new":[{"cveId":"CVE-2026-0002"}],"updated":[{"cveId":"$(reboot)"},{"cveId":"CVE-2026-0001"}]},
	{"fetchTime":"2026-11-05T09:50:00Z","new":[{"cveId":"CVE-2026-0001"}],"updated":[]},
	{"fetchTime":"2026-11-05T09:40:00Z","new":[{"cveId":"CVE-2026-0000"}],"updated":[]}
	]`
	c := logServer(t, []byte(log))
	d, err := c.Changes(context.Background(), at(t, "2026-11-05T09:40:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{{ID: "CVE-2026-0002", New: true}, {ID: "CVE-2026-0001", New: true}}
	if !slices.Equal(d.Changes, want) {
		t.Fatalf("changes = %v, want %v", d.Changes, want)
	}
}

func TestParseLogCutOff(t *testing.T) {
	full := `[{"fetchTime":"2026-11-05T10:00:00Z","new":[{"cveId":"CVE-2026-0002"}]},{"fetchTime":"2026-11-05T09:50:00Z","new":[{"cveId":"CVE-2026-0001"}]}]`
	if sets, whole := parseLog([]byte(full)); len(sets) != 2 || !whole {
		t.Fatalf("full log: %d sets, whole %v", len(sets), whole)
	}
	for n := range len(full) - 1 {
		sets, whole := parseLog([]byte(full[:n]))
		if whole || len(sets) > 2 {
			t.Fatalf("cut at %d: %d sets, whole %v", n, len(sets), whole)
		}
	}
	if sets, _ := parseLog([]byte(`{"not":"a list"}`)); sets != nil {
		t.Fatal("parsed something that isn't a list")
	}
}

func TestParseRecord(t *testing.T) {
	record := `{
	  "cveMetadata": {"cveId": "CVE-2026-1234", "state": "PUBLISHED", "datePublished": "2026-11-05T08:00:00.000Z"},
	  "containers": {
	    "cna": {
	      "title": "  Heap   overflow in\nexample  ",
	      "descriptions": [{"lang": "de", "value": "Ein Fehler"}, {"lang": "en", "value": "` + strings.Repeat("A long description. ", 40) + `"}],
	      "metrics": [{"cvssV3_1": {"baseScore": 7.5}}],
	      "affected": [
	        {"vendor": "OpenBSD", "product": "OpenSSH"},
	        {"vendor": "OpenBSD", "product": "OpenSSH"},
	        {"vendor": "x", "product": "` + strings.Repeat("y", 300) + `"}
	      ]
	    },
	    "adp": [{"metrics": [{"cvssV4_0": {"baseScore": 9.3}}, {"cvssV3_1": {"baseScore": 99}}, {"other": {"type": "kev", "content": {"dateAdded": "2026-11-05"}}}],
	             "affected": [{"vendor": "openbsd", "product": "openssh", "packageName": "openssh", "collectionURL": "https://www.openssh.com/"}]}]
	  }
	}`
	r, err := Parse([]byte(record), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "CVE-2026-1234" || r.Title != "Heap overflow in example" || r.Score != 9.3 || !r.KEV || r.Rejected {
		t.Errorf("record = %+v", r)
	}
	if n := len([]rune(r.Description)); n != maxText || !strings.HasPrefix(r.Description, "A long description.") {
		t.Errorf("description (%d runes) = %q", n, r.Description)
	}
	want := []Product{{Vendor: "OpenBSD", Product: "OpenSSH"}, {Vendor: "openbsd", Product: "openssh", Package: "openssh", CollectionURL: "https://www.openssh.com/"}}
	if !slices.Equal(r.Products, want) {
		t.Errorf("products = %+v", r.Products)
	}

	rejected := `{"cveMetadata": {"cveId": "CVE-2026-9999", "state": "REJECTED"}, "containers": {"cna": {"metrics": [{"other": {"type": "ssvc"}}]}}}`
	if r, err := Parse([]byte(rejected), time.Now()); err != nil || !r.Rejected || r.KEV {
		t.Errorf("rejected record = %+v, %v", r, err)
	}
	for _, bad := range []string{`[]`, `{"cveMetadata": {"cveId": "../../etc/passwd"}}`, `{`} {
		if _, err := Parse([]byte(bad), time.Now()); err == nil {
			t.Errorf("Parse(%s) accepted it", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"cveMetadata":{"cveId":"CVE-2026-1234"},"containers":{"cna":{"affected":[{"vendor":"a","product":"b"}]}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(data, time.Now())
		if err != nil {
			return
		}
		if !idPattern.MatchString(r.ID) || len(r.Products) > maxProducts || r.Score < 0 || r.Score > 10 {
			t.Fatalf("unexpected record %+v", r)
		}
	})
}

func FuzzParseLog(f *testing.F) {
	f.Add([]byte(`[{"fetchTime":"2026-11-05T10:00:00Z","new":[{"cveId":"CVE-2026-0002"}]}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		sets, _ := parseLog(data)
		d := &Delta{}
		index := map[string]int{}
		for _, s := range sets {
			d.add(s, index)
		}
		for _, c := range d.Changes {
			if !idPattern.MatchString(c.ID) {
				t.Fatalf("invalid id %q", c.ID)
			}
		}
	})
}
