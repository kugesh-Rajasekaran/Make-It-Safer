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
	} {
		got := line(&tc.f)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("line() = %q, missing %q", got, w)
			}
		}
	}
}
