package daemon

import (
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// Notifications say in plain words why a vulnerability matters: a server
// CVE by how it's reached and what it allows, an Apple update by its worst
// fix in Apple's words.
func TestNotificationsSayWhy(t *testing.T) {
	d := New(config.PathsAt(t.TempDir()), "test", nil, newRecorder())
	cfg := config.Default()

	cve := []*findings.Finding{{Server: "web", Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Fixed: "2",
		Priority: findings.Urgent, KEV: true, Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	n := d.groupNotification(groupKey(cve[0]), cve, 0, &cfg)
	if want := "Can be triggered remotely, no login · could take it over\n1 server affected · fix available"; n.Body != want {
		t.Errorf("CVE body = %q, want %q", n.Body, want)
	}

	me := config.LocalName()
	apple := []*findings.Finding{
		{Server: me, Kind: findings.KindVulnerability, CVE: "CVE-2026-1001", Source: "macos", Fixed: "15.8.2", Priority: findings.High,
			Impact: "An app may be able to read kernel memory."},
		{Server: me, Kind: findings.KindVulnerability, CVE: "CVE-2026-1002", Source: "macos", Fixed: "15.8.2", Priority: findings.Urgent, KEV: true,
			Impact: "An app may be able to gain root privileges."},
	}
	n = d.groupNotification(groupKey(apple[0]), apple, 0, &cfg)
	if want := "Worst: An app may be able to gain root privileges\nInstall it in System Settings › Software Update."; n.Body != want {
		t.Errorf("Apple body = %q, want %q", n.Body, want)
	}

	// The most severe CVE has no Apple sentence: the worst one Apple described is used.
	apple = append(apple, &findings.Finding{Server: me, Kind: findings.KindVulnerability, CVE: "CVE-2026-1003", Source: "macos", Fixed: "15.8.2",
		Priority: findings.Urgent, KEV: true, Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
	n = d.groupNotification(groupKey(apple[0]), apple, 0, &cfg)
	if want := "Worst: An app may be able to gain root privileges\nInstall it in System Settings › Software Update."; n.Body != want {
		t.Errorf("Apple body without the worst one's sentence = %q", n.Body)
	}

	plain := []*findings.Finding{{Server: "web", Kind: findings.KindVulnerability, CVE: "CVE-2026-2000", Source: "zlib", Fixed: "2", Priority: findings.High}}
	if n := d.groupNotification(groupKey(plain[0]), plain, 0, &cfg); n.Body != "1 server affected · fix available" {
		t.Errorf("nothing known: body = %q", n.Body)
	}
}
