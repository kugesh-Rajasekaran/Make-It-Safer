package cvelist

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
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

// The CVSS vector of the chosen score and the first CWE are kept, so the
// risk can be put into words later. A malformed vector is dropped.
func TestParseRecordVectorAndWeakness(t *testing.T) {
	data, err := os.ReadFile("testdata/CVE-2024-6387.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(data, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.Score != 8.1 || r.Vector != "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" || r.Weakness != "CWE-364: Signal Handler Race Condition" {
		t.Errorf("score %v, vector %q, weakness %q", r.Score, r.Vector, r.Weakness)
	}

	record := func(t *testing.T, metrics, problems string) *Record {
		t.Helper()
		r, err := Parse([]byte(`{"cveMetadata": {"cveId": "CVE-2026-0001"}, "containers": {"cna": {"metrics": `+metrics+`, "problemTypes": `+problems+`}}}`), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := []struct {
		name, metrics, problems, vector, weakness string
	}{
		{"v4 beats a lower v3", `[{"cvssV3_1": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}}, {"cvssV4_0": {"baseScore": 9.3, "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]`, `[]`,
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", ""},
		{"garbled vector dropped", `[{"cvssV3_1": {"baseScore": 9.8, "vectorString": "AV:N; rm -rf /"}}]`, `[]`, "", ""},
		{"no vector", `[{"cvssV3_1": {"baseScore": 5}}]`, `[]`, "", ""},
		{"CWE with its id in the name", `[]`, `[{"descriptions": [{"cweId": "CWE-79", "description": "CWE-79: Cross-site Scripting"}]}]`, "", "CWE-79: Cross-site Scripting"},
		{"CWE without a name", `[]`, `[{"descriptions": [{"cweId": "CWE-20"}]}]`, "", "CWE-20"},
		{"text without a CWE id", `[]`, `[{"descriptions": [{"description": "Buffer overflow"}]}]`, "", ""},
		{"CWE id repeated after the name", `[]`, `[{"descriptions": [{"cweId": "CWE-190", "description": "Integer Overflow or Wraparound CWE-190"}]}]`, "", "CWE-190: Integer Overflow or Wraparound"},
		{"only other CWE ids", `[]`, `[{"descriptions": [{"cweId": "CWE-787", "description": "(CWE-787|CWE-125)"}]}]`, "", "CWE-787"},
		{"an arrow to another CWE", `[]`, `[{"descriptions": [{"cweId": "CWE-665", "description": "->CWE-281"}]}]`, "", "CWE-665"},
		{"hyphens in a name stay", `[]`, `[{"descriptions": [{"cweId": "CWE-787", "description": "Out-of-bounds Write"}]}]`, "", "CWE-787: Out-of-bounds Write"},
		{"v4 supplemental values", `[{"cvssV4_0": {"baseScore": 9.3, "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Amber"}}]`, `[]`,
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Amber", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := record(t, c.metrics, c.problems)
			if r.Vector != c.vector || r.Weakness != c.weakness {
				t.Errorf("vector %q, weakness %q; want %q, %q", r.Vector, r.Weakness, c.vector, c.weakness)
			}
		})
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

// A record cached before the vector and weakness were kept is read again;
// if the CVE List can't be reached, the older copy is still used.
func TestOlderCachedRecordIsReadAgain(t *testing.T) {
	data, err := os.ReadFile("testdata/CVE-2024-6387.json")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if down.Load() {
			http.Error(w, "gone", http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	}))
	defer srv.Close()
	now := time.Now()
	c := &Client{Feeds: feeds.NewForTest(srv.URL), Base: srv.URL, Cache: t.TempDir(), Now: func() time.Time { return now }}
	old := `{"id": "CVE-2024-6387", "score": 8.1, "fetched": "` + now.Add(-time.Hour).Format(time.RFC3339) + `"}`
	path := filepath.Join(c.Cache, "CVE-2024-6387.json")
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}

	down.Store(true)
	r, err := c.Get(context.Background(), "CVE-2024-6387")
	if err != nil || r.Score != 8.1 || r.Vector != "" {
		t.Fatalf("offline: the older copy should be used: %+v, %v", r, err)
	}
	down.Store(false)
	r, err = c.Get(context.Background(), "CVE-2024-6387")
	if err != nil || r.Vector == "" || r.Weakness == "" {
		t.Fatalf("online: the record should be read again: %+v, %v", r, err)
	}
	before := calls.Load()
	if _, err := c.Get(context.Background(), "CVE-2024-6387"); err != nil || calls.Load() != before {
		t.Fatalf("the new copy should be used from now on: %v, %d calls", err, calls.Load()-before)
	}
}
