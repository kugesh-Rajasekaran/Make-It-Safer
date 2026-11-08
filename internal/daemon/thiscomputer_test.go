package daemon

import (
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// This Mac gets one notification per Apple update, with a "This Mac" button,
// instead of one per CVE.
func TestAppleUpdateNotification(t *testing.T) {
	me := config.LocalName()
	group := []*findings.Finding{
		{Server: me, Kind: findings.KindVulnerability, CVE: "CVE-2026-1001", Source: "macos", Fixed: "15.8.2", Priority: findings.High},
		{Server: me, Kind: findings.KindVulnerability, CVE: "CVE-2026-1002", Source: "macos", Fixed: "15.8.2", Priority: findings.Urgent, KEV: true},
		{Server: me, Kind: findings.KindVulnerability, CVE: "CVE-2026-1003", Source: "macos", Fixed: "15.8.2", Priority: findings.Normal},
	}
	key := groupKey(group[0])
	for _, f := range group {
		if groupKey(f) != key || !isApple(f) {
			t.Fatalf("all CVEs of one update share a notification: %q vs %q", groupKey(f), key)
		}
	}
	safari := &findings.Finding{Server: me, Kind: findings.KindVulnerability, CVE: "CVE-2026-1001", Source: "safari", Fixed: "27.2"}
	if groupKey(safari) == key {
		t.Fatal("Safari's update is a separate notification")
	}
	server := &findings.Finding{Server: "web", Kind: findings.KindVulnerability, CVE: "CVE-2026-1001", Source: "openssl", Fixed: "3.0.1"}
	if isApple(server) || groupKey(server) != "cve:CVE-2026-1001" {
		t.Fatal("servers keep one notification per CVE")
	}

	d := New(config.PathsAt(t.TempDir()), "test", nil, newRecorder())
	cfg := config.Default()
	n := d.groupNotification(key, group, 0, &cfg)
	if !strings.Contains(n.Title, "macOS 15.8.2 · fixes 3 vulnerabilities · 1 actively exploited") || !n.Urgent {
		t.Fatalf("title %q urgent %v", n.Title, n.Urgent)
	}
	if len(n.Buttons) != 1 || n.Buttons[0].Title != config.LocalLabel() || n.Buttons[0].ID != "fix:"+me {
		t.Fatalf("buttons: %+v", n.Buttons)
	}
	if !strings.Contains(n.Body, "Software Update") {
		t.Fatalf("body: %q", n.Body)
	}
}

func TestThisComputerLabel(t *testing.T) {
	if serverLabel(config.LocalName()) != config.LocalLabel() || serverLabel("web") != "web" {
		t.Fatal("this computer is shown by its label; servers by name")
	}
	f := &findings.Finding{Server: config.LocalName(), Kind: findings.KindUpdates, Installed: "187 outdated"}
	if got := title(f); got != config.LocalLabel()+": 187 outdated packages" {
		t.Fatalf("title %q", got)
	}
}
