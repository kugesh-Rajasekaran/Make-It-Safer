package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// Unit tests never go online: by default a CVE record is "not found".
func init() {
	lookupCVE = func(context.Context, *engine.Engine, string) (*cvelist.Record, error) { return nil, feeds.ErrNotFound }
}

// mis show leads with when to act and why, then the facts, the servers and
// the fix. A finding without a CVE record gets it looked up.
func TestShowExplainsTheRisk(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")
	putFindings(t, paths, openVuln("web"))
	orig := lookupCVE
	t.Cleanup(func() { lookupCVE = orig })
	lookupCVE = func(_ context.Context, _ *engine.Engine, id string) (*cvelist.Record, error) {
		return &cvelist.Record{ID: id, Score: 8.1, Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Weakness: "CWE-364: Signal Handler Race Condition", Description: "A race condition in sshd's signal handler."}, nil
	}

	code, out, _ := runCLI(t, "show", testCVE)
	for _, want := range []string{
		"CVE-2024-6387 · openssh",
		"— can be triggered remotely, no login · could take it over",
		"What an attacker could do  Could take it over",
		"Severity                   CVSS 8.1 of 10",
		"How it's triggered         Can be triggered remotely, no login · no user", // wrapped at 80 columns
		"action · hard to pull off",
		"Your servers               web  openssh",
		"Fix                        mis fix web CVE-2024-6387",
		"Details                    A race condition in sshd's signal handler.",
		"Weakness                   CWE-364: Signal Handler Race Condition",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code != 0 {
		t.Fatalf("exit %d", code)
	}

	code, out, _ = runCLI(t, "show", testCVE, "--json")
	var views []struct {
		Verdict string `json:"verdict"`
		Why     string `json:"why"`
		Facts   []struct {
			Label string `json:"label"`
		} `json:"facts"`
	}
	if code != 0 || json.Unmarshal(decode(t, out).Data, &views) != nil || len(views) != 1 || views[0].Why == "" || len(views[0].Facts) != 4 {
		t.Fatalf("json: exit %d, %s", code, out)
	}
}

// The page is about what's still open: a fixed server doesn't headline it,
// every fixable server gets its fix line, and lines fit in 80 columns.
func TestShowHeadlineFixesAndLayout(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "db", "web")
	resolved := openVuln("db")
	resolved.Priority, resolved.State, resolved.KEV = findings.Urgent, findings.StateResolved, true
	web, other := openVuln("web"), openVuln("web")
	other.ID, other.Source = other.ID+"-x", "openssh-client"
	web.Details = strings.Repeat("A long description of the flaw. ", 8)
	putFindings(t, paths, resolved, web, other)

	code, out, _ := runCLI(t, "show", testCVE)
	if code != 0 || strings.Contains(out, "ACT NOW") || !strings.Contains(out, "THIS WEEK") {
		t.Fatalf("the resolved urgent finding must not headline the page: exit %d\n%s", code, out)
	}
	if n := strings.Count(out, "mis fix web "+testCVE); n != 1 {
		t.Errorf("one fix line per server, got %d:\n%s", n, out)
	}
	for _, l := range strings.Split(out, "\n") {
		if n := len([]rune(l)); n > 80 && !strings.Contains(l, "https://") {
			t.Errorf("line of %d columns: %q", n, l)
		}
	}

	web.State, other.State = findings.StateResolved, findings.StateResolved
	if err := findings.Update(paths, func(st *findings.Store) error {
		st.Findings = []*findings.Finding{resolved, web, other}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, out, _ := runCLI(t, "show", testCVE); !strings.Contains(out, "FIXED — no open findings for it") {
		t.Errorf("all fixed:\n%s", out)
	}
}

// Offline, the page says the record couldn't be loaded instead of nothing.
func TestShowOffline(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")
	putFindings(t, paths, openVuln("web"))
	if _, out, _ := runCLI(t, "show", testCVE); !strings.Contains(out, "not available: the CVE record couldn't be loaded") {
		t.Errorf("offline:\n%s", out)
	}
}
