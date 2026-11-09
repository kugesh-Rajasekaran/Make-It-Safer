package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
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
		"— can be triggered remotely, no login · could gain full control",
		"What an attacker could do  Could gain full control",
		"How it's triggered         Can be triggered remotely, no login · no user action · hard to pull off",
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
	if code != 0 || json.Unmarshal(decode(t, out).Data, &views) != nil || len(views) != 1 || views[0].Why == "" || len(views[0].Facts) != 3 {
		t.Fatalf("json: exit %d, %s", code, out)
	}
}
