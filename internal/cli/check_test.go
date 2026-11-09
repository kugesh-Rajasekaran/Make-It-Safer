package cli

import (
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

func TestLine(t *testing.T) {
	for _, tc := range []struct {
		f    findings.Finding
		want []string
	}{
		{findings.Finding{Server: "web", Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1", Fixed: "2", Priority: findings.Urgent, KEV: true},
			[]string{"🔴 urgent web", "CVE-2024-6387 (openssh)  1 → 2", "(actively exploited)"}},
		{findings.Finding{Server: "web", Kind: findings.KindEarlyWarning, CVE: "CVE-2026-0001", Source: "openssh", Score: 9.8, Priority: findings.High},
			[]string{"🟡 early  web", "CVE-2026-0001 (openssh)  unconfirmed: your distro hasn't assessed it yet · CVSS 9.8"}},
		{findings.Finding{Server: "this-mac", Kind: findings.KindUpdates, Source: "homebrew", Summary: "3 Homebrew packages can be updated: a, b, c", Priority: findings.Normal},
			[]string{"🟡 normal this-mac", "Homebrew updates — 3 Homebrew packages"}},
		// Text from a data feed never reaches the terminal with control characters.
		{findings.Finding{Server: "web", Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1", Fixed: "2\x1b]0;x\x07", Priority: findings.High},
			[]string{"1 → 2]0;x"}},
	} {
		got := line(&tc.f)
		if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
			t.Errorf("line() = %q has control characters", got)
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("line() = %q, missing %q", got, w)
			}
		}
	}
}

func TestShowCleansFeedText(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")
	f := openVuln("web")
	f.Fixed, f.DistroPriority = "2\x1b[2J", "high\x1b]0;x\x07"
	putFindings(t, paths, f)

	code, out, _ := runCLI(t, "show", testCVE)
	if code != 0 || !strings.Contains(out, "Severity: high") || strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("exit %d, output %q", code, out)
	}
}
