package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// cveRecord is a minimal CVE JSON 5 record. products are "vendor|product".
func cveRecord(id string, score float64, kev bool, products ...string) string {
	var affected []string
	for _, p := range products {
		vendor, product, _ := strings.Cut(p, "|")
		affected = append(affected, fmt.Sprintf(`{"vendor":%q,"product":%q}`, vendor, product))
	}
	adp := `[]`
	if kev {
		adp = `[{"metrics":[{"other":{"type":"kev","content":{"dateAdded":"2026-11-05"}}}]}]`
	}
	return fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":"PUBLISHED","datePublished":"2026-11-05T08:00:00Z"},
		"containers":{"cna":{"title":"test flaw","descriptions":[{"lang":"en","value":"A test flaw."}],
		"metrics":[{"cvssV3_1":{"baseScore":%v,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],"affected":[%s]},"adp":%s}}`,
		id, score, strings.Join(affected, ","), adp)
}

// changeSet is one delta-log entry: "time new:CVE,CVE updated:CVE".
func deltaLog(sets ...string) string {
	var out []string
	for _, s := range sets {
		fields := strings.Fields(s)
		list := func(prefix string) string {
			var ids []string
			for _, f := range fields[1:] {
				if rest, ok := strings.CutPrefix(f, prefix); ok {
					for _, id := range strings.Split(rest, ",") {
						ids = append(ids, fmt.Sprintf(`{"cveId":%q}`, id))
					}
				}
			}
			return "[" + strings.Join(ids, ",") + "]"
		}
		out = append(out, fmt.Sprintf(`{"fetchTime":%q,"new":%s,"updated":%s}`, fields[0], list("new:"), list("updated:")))
	}
	return "[" + strings.Join(out, ",") + "]"
}

func TestEarlyWarnings(t *testing.T) {
	d := &fakeData{fixed: "1:9.6p1-3ubuntu13.8"}
	e, paths := newEngine(t, d)
	ctx := context.Background()
	saveInventory(t, paths, "web", "24.04", "1:9.6p1-3ubuntu13.5")
	servers := []config.Server{web}

	// First run: start from the newest change set, raise nothing.
	d.set(func() { d.log = deltaLog("2026-11-05T08:00:00Z new:CVE-2026-0009") })
	if res, err := e.EarlyWarnings(ctx, servers); err != nil || len(res.Changes.New) != 0 {
		t.Fatalf("first run: %+v, %v", res, err)
	}
	// The server's first check comes before any early warning.
	if _, err := e.Match(ctx, servers); err != nil {
		t.Fatal(err)
	}

	d.set(func() {
		d.records["CVE-2026-0001"] = cveRecord("CVE-2026-0001", 9.8, false, "OpenBSD|OpenSSH") // severe, installed
		d.records["CVE-2026-0002"] = cveRecord("CVE-2026-0002", 5.0, false, "OpenBSD|OpenSSH") // installed, not severe: watched
		d.records["CVE-2026-0003"] = cveRecord("CVE-2026-0003", 9.9, false, "n/a|n/a")         // no product yet: watched
		d.records["CVE-2026-0004"] = cveRecord("CVE-2026-0004", 9.9, false, "F5|nginx")        // not installed
		d.records["CVE-2026-0005"] = cveRecord("CVE-2026-0005", 9.1, false, "OpenBSD|OpenSSH") // will expire
		d.records["CVE-2024-6387"] = cveRecord("CVE-2024-6387", 8.1, true, "OpenBSD|OpenSSH")  // already confirmed
		d.log = deltaLog(
			"2026-11-05T08:20:00Z new:CVE-2026-0001,CVE-2026-0002,CVE-2026-0003,CVE-2026-0004,CVE-2026-0005,CVE-2024-6387,CVE-2026-0404",
			"2026-11-05T08:00:00Z new:CVE-2026-0009",
		)
	})
	res, err := e.EarlyWarnings(ctx, servers) // CVE-2026-0404 has no record: skipped, not fatal
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*findings.Finding{}
	for _, f := range res.Changes.New {
		got[f.CVE] = f
	}
	f := got["CVE-2026-0001"]
	if len(got) != 2 || f == nil || got["CVE-2026-0005"] == nil {
		t.Fatalf("raised %v, want CVE-2026-0001 and CVE-2026-0005", got)
	}
	if f.Kind != findings.KindEarlyWarning || f.Source != "openssh" || f.Installed != "1:9.6p1-3ubuntu13.5" ||
		f.Priority != findings.High || f.Score != 9.8 || f.ID != "web/early-warning/CVE-2026-0001/openssh" {
		t.Errorf("early warning = %+v", f)
	}
	if f.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" || f.Details != "A test flaw." { // so mis show can explain it
		t.Errorf("early warning facts: vector %q, details %q", f.Vector, f.Details)
	}
	state, _ := loadEarlyState(paths)
	if len(state.Watch) != 2 || state.Watch["CVE-2026-0002"].IsZero() || state.Watch["CVE-2026-0003"].IsZero() {
		t.Errorf("watching %v, want CVE-2026-0002 and CVE-2026-0003", state.Watch)
	}

	// Later: CISA marks the watched CVE-2026-0002 exploited; CVE-2026-0004
	// changes too but isn't watched, so it isn't downloaded again.
	d.set(func() {
		d.records["CVE-2026-0002"] = cveRecord("CVE-2026-0002", 5.0, true, "OpenBSD|OpenSSH")
		d.log = deltaLog("2026-11-05T08:40:00Z updated:CVE-2026-0002,CVE-2026-0004", "2026-11-05T08:20:00Z new:CVE-2026-0001")
	})
	res, err = e.EarlyWarnings(ctx, servers)
	if err != nil || len(res.Changes.New) != 1 || res.Changes.New[0].CVE != "CVE-2026-0002" || !res.Changes.New[0].KEV {
		t.Fatalf("after the KEV update: %+v, %v", res, err)
	}
	d.set(func() {
		if d.fetched["CVE-2026-0004"] != 1 || d.fetched["CVE-2026-0002"] != 2 {
			t.Errorf("downloads = %v", d.fetched)
		}
	})
	// Nothing new: nothing raised twice.
	if res, err := e.EarlyWarnings(ctx, servers); err != nil || len(res.Changes.New) != 0 {
		t.Fatalf("nothing new: %+v, %v", res, err)
	}

	// Ubuntu assesses them: 0001 doesn't affect this version, 0002 does.
	d.set(func() {
		d.distro["UBUNTU-CVE-2026-0001"] = ""
		d.distro["UBUNTU-CVE-2026-0002"] = "1:9.6p1-3ubuntu13.9"
	})
	res, err = e.Match(ctx, servers)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := findings.Load(paths)
	for id, want := range map[string]string{
		"web/early-warning/CVE-2026-0001/openssh": findings.ResolutionNotAffected,
		"web/early-warning/CVE-2026-0002/openssh": findings.ResolutionConfirmed,
		"web/early-warning/CVE-2026-0005/openssh": "",
	} {
		f := st.Find(id)
		if f == nil || f.Resolution != want || f.Open() != (want == "") {
			t.Errorf("%s = %+v, want resolution %q", id, f, want)
		}
	}
	if f := st.Find("web/vulnerability/CVE-2026-0002/openssh"); f == nil || !f.Open() {
		t.Errorf("confirmed vulnerability = %+v", f)
	}
	if len(res.Changes.Resolved) != 2 {
		t.Errorf("resolved = %v", res.Changes.Resolved)
	}

	// A month without distro data: CVE-2026-0005 expires.
	e.Now = func() time.Time { return time.Date(2026, 12, 6, 9, 0, 0, 0, time.UTC) }
	if _, err := e.Match(ctx, servers); err != nil {
		t.Fatal(err)
	}
	st, _ = findings.Load(paths)
	if f := st.Find("web/early-warning/CVE-2026-0005/openssh"); f == nil || f.Open() || f.Resolution != findings.ResolutionExpired {
		t.Errorf("after a month: %+v", f)
	}
}

func TestEarlyWarningsOff(t *testing.T) {
	d := &fakeData{fixed: "1:9.6p1-3ubuntu13.8"}
	e, _ := newEngine(t, d)
	e.Rules.EarlyWarning.Enabled = false
	if res, err := e.EarlyWarnings(context.Background(), []config.Server{web}); err != nil || len(res.Changes.New) != 0 {
		t.Fatalf("disabled: %+v, %v", res, err)
	}
	d.set(func() {
		if len(d.fetched) != 0 {
			t.Errorf("downloaded %v while disabled", d.fetched)
		}
	})
}

// The CVE List and OSV record caches get one file per record; old files are
// deleted, but only once a day.
func TestEarlyWarningsPrunesOldCacheFiles(t *testing.T) {
	d := &fakeData{}
	e, _ := newEngine(t, d)
	ctx := context.Background()
	now := e.Now()
	d.set(func() { d.log = deltaLog("2026-11-05T08:00:00Z new:CVE-2026-0009") })
	if _, err := e.EarlyWarnings(ctx, nil); err != nil { // the first run only notes where the log is
		t.Fatal(err)
	}

	write := func(dir, name string, age time.Duration) string {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		return p
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	day := 24 * time.Hour
	oldCVE := write(e.CVE.Cache, "CVE-2026-0001.json", 40*day)
	newCVE := write(e.CVE.Cache, "CVE-2026-0002.json", 2*day)
	oldOSV := write(e.OSV.Cache, "UBUNTU-CVE-2026-0001.json", 40*day)

	if _, err := e.EarlyWarnings(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if exists(oldCVE) || exists(oldOSV) || !exists(newCVE) {
		t.Fatalf("after the run: old CVE record kept=%v, old OSV record kept=%v, recent record kept=%v", exists(oldCVE), exists(oldOSV), exists(newCVE))
	}

	// Within the same day nothing is cleaned again; the next day it is.
	again := write(e.CVE.Cache, "CVE-2026-0003.json", 40*day)
	if _, err := e.EarlyWarnings(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !exists(again) {
		t.Fatal("the caches were cleaned twice in one day")
	}
	e.Now = func() time.Time { return now.Add(25 * time.Hour) }
	if _, err := e.EarlyWarnings(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if exists(again) {
		t.Fatal("the caches were not cleaned the next day")
	}
}
