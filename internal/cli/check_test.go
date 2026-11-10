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
			[]string{"🔴 Act now    web", "CVE-2024-6387 (openssh)  1 → 2"}},
		{findings.Finding{Server: "web", Kind: findings.KindEarlyWarning, CVE: "CVE-2026-0001", Source: "openssh", Score: 9.8, Priority: findings.High},
			[]string{"🟡 Heads-up   web", "CVE-2026-0001 (openssh)  unconfirmed: your distro hasn't assessed it yet · CVSS 9.8"}},
		{findings.Finding{Server: "this-mac", Kind: findings.KindUpdates, Source: "homebrew", Summary: "3 Homebrew packages can be updated: a, b, c", Priority: findings.Normal},
			[]string{"🟡 Can wait   this-mac", "Homebrew updates — 3 Homebrew packages"}},
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

// A vulnerability's entry has a second line saying why it matters.
func TestEntry(t *testing.T) {
	f := &findings.Finding{Server: "web", Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1", Fixed: "2",
		Priority: findings.Urgent, KEV: true, Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	got := strings.Split(entry(f, "  "), "\n")
	if len(got) != 2 || !strings.HasPrefix(got[0], "  🔴 Act now") ||
		got[1] != "       being exploited · can be triggered remotely, no login · could take it over" {
		t.Fatalf("entry = %q", got)
	}
	if e := entry(&findings.Finding{Server: "web", Kind: findings.KindReboot, Priority: findings.High}, ""); strings.Contains(e, "\n") {
		t.Errorf("a non-vulnerability gets one line: %q", e)
	}
}

func TestShowCleansFeedText(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false, "web")
	f := openVuln("web")
	f.Fixed, f.DistroPriority = "2\x1b[2J", "high\x1b]0;x\x07"
	putFindings(t, paths, f)

	code, out, _ := runCLI(t, "show", testCVE)
	if code != 0 || !strings.Contains(out, "openssh 1 → 2 [2J") || strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("exit %d, output %q", code, out)
	}
}
