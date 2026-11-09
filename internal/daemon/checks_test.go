package daemon

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// mis check through the service must say which servers could not be logged
// in to, as it does without the service, instead of passing off an old
// package list as this check's answer.
func TestCheckReportsServersThatCouldNotBeRefreshed(t *testing.T) {
	rec := newRecorder()
	d, paths := testDaemon(t, rec, newFeedServer(t, "CVE-2024-0001", "CVE-2024-0002"), io.Discard)
	addServer(t, paths, "web", d.now()) // has a saved list; the host key was never pinned, so the login fails
	if err := d.unlock([]byte(passphrase)); err != nil {
		t.Fatal(err)
	}
	res, err := d.check(context.Background(), Request{Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Servers) != 1 || res.Servers[0].Code == "" || !strings.Contains(res.Servers[0].Error, "package list not refreshed") {
		t.Fatalf("server result = %+v, want the failed refresh reported", res.Servers)
	}
	// It was the first check of this server, so it is announced as one.
	if ids := rec.ids(); !slices.Equal(ids, []string{"baseline:web"}) {
		t.Fatalf("notifications = %v, want only the first-check summary", ids)
	}
}

// A first check is a baseline: it is announced once ("is now monitored"),
// not with a notification per vulnerability, whether the service or the
// command line (while the service is locked) ran it.
func TestFirstCheckOutsideTheServiceStaysQuiet(t *testing.T) {
	f := newFeedServer(t, "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")
	rec := newRecorder()
	d, paths := testDaemon(t, rec, f, io.Discard)
	d.now = time.Now
	addServer(t, paths, "web", d.now())
	cfg, err := config.Load(paths.Config)
	if err != nil {
		t.Fatal(err)
	}

	res, err := d.newEngine(cfg).Match(context.Background(), cfg.Checked()) // not d.check: the service never sees it
	if err != nil {
		t.Fatal(err)
	}
	if !res.Servers[0].First || len(res.Changes.New) != 3 {
		t.Fatalf("want a first check with 3 new findings, got %+v", res)
	}
	if err := d.remind(); err != nil {
		t.Fatal(err)
	}
	if ids := rec.ids(); len(ids) != 0 {
		t.Fatalf("the baseline was announced per finding: %v", ids)
	}

	f.set("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004")
	if _, err := d.newEngine(cfg).Match(context.Background(), cfg.Checked()); err != nil {
		t.Fatal(err)
	}
	if err := d.remind(); err != nil {
		t.Fatal(err)
	}
	if ids := rec.ids(); !slices.Equal(ids, []string{"cve:CVE-2024-0004"}) {
		t.Fatalf("a vulnerability found after the baseline should be announced alone, got %v", ids)
	}
}

func TestAlertSummarisesAFirstCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server engine.ServerResult
		want   bool
	}{
		{"first check", engine.ServerResult{Server: "web", First: true, Open: map[string]int{"high": 2, "normal": 1}}, true},
		{"later check", engine.ServerResult{Server: "web", Open: map[string]int{"high": 2}}, false},
		// matched on the older saved list, because logging in failed
		{"first check, refresh failed", engine.ServerResult{Server: "web", First: true, Code: "SERVER_UNREACHABLE", Error: "package list not refreshed: connection refused", Open: map[string]int{"high": 2, "normal": 1}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecorder()
			d, paths := testDaemon(t, rec, nil, io.Discard)
			now := d.now()
			_ = findings.Update(paths, func(st *findings.Store) error { // what a check leaves behind
				for _, cve := range []string{"CVE-2024-0001", "CVE-2024-0002"} {
					st.Merge("web", []*findings.Finding{{ID: findings.MakeID("web", findings.KindVulnerability, cve+"/p"), Server: "web",
						Kind: findings.KindVulnerability, CVE: cve, Source: "p", Installed: "1", Fixed: "2", Priority: findings.High}},
						[]findings.Kind{findings.KindVulnerability}, now)
				}
				return nil
			})

			d.alert(&engine.Result{Servers: []engine.ServerResult{tc.server}})

			rec.mu.Lock()
			defer rec.mu.Unlock()
			var baseline []string
			for _, n := range rec.shown {
				if n.ID == "baseline:web" {
					baseline = append(baseline, n.Title+" | "+n.Body)
				}
			}
			if tc.want {
				if want := "web is now monitored | Open now: 2 high, 1 normal. Click to see them."; !slices.Equal(baseline, []string{want}) {
					t.Fatalf("baseline notification = %q, want %q", baseline, want)
				}
				for _, n := range rec.shown {
					if strings.HasPrefix(n.ID, "cve:") {
						t.Errorf("a baselined vulnerability was announced as well: %+v", n)
					}
				}
			} else if len(baseline) > 0 {
				t.Fatalf("unexpected baseline notification %q", baseline)
			}
		})
	}
}

// The jobs run unattended: what a check could not use (CISA's catalog,
// end-of-life dates) is in the log, since nobody sees the result.
func TestJobsLogWhatTheyCouldNotUse(t *testing.T) {
	logs := &syncBuffer{}
	d, paths := testDaemon(t, newRecorder(), newFeedServer(t), logs) // no catalog, no end-of-life dates
	addServer(t, paths, "web", d.now())
	cfg, err := config.Load(paths.Config) // and a server that was never read
	if err != nil {
		t.Fatal(err)
	}
	cfg.Servers = append(cfg.Servers, config.Server{Name: "db", Host: "127.0.0.1", Port: 1, AdminSSH: "u@127.0.0.1"})
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}

	if err := d.jobMatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CISA KEV unavailable", "end-of-life dates unavailable"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log lacks %q:\n%s", want, logs.String())
		}
	}

	if want := "server=db code=INVENTORY_NOT_FOUND"; !strings.Contains(logs.String(), want) {
		t.Errorf("the log lacks %q:\n%s", want, logs.String())
	}

	logs.buf.Reset()
	if err := d.jobFeeds(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "msg=kev status=error") {
		t.Errorf("the feeds job didn't log the failed catalog download:\n%s", logs.String())
	}
}

// A state file that says null (damaged, or edited by hand) used to crash the
// feeds job with a write into a nil map.
func TestFeedsJobSurvivesAnEmptyStateFile(t *testing.T) {
	for _, content := range []string{"null", "{not json"} {
		t.Run(content, func(t *testing.T) {
			logs := &syncBuffer{}
			d, paths := testDaemon(t, newRecorder(), newFeedServer(t), logs)
			path := filepath.Join(paths.Cache, "feed-etags.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := d.jobFeeds(context.Background()); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), "modified_id.csv") {
				t.Fatalf("the ETags weren't saved again: %q, %v", data, err)
			}
			if content != "null" && !strings.Contains(logs.String(), "msg=feeds status=error") {
				t.Errorf("the damaged state file wasn't logged:\n%s", logs.String())
			}
		})
	}
}
