package daemon

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
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

// Clicking an Apple update notification, on its button or on the
// notification itself, opens Software Update.
func TestAppleUpdateClick(t *testing.T) {
	paths := newInstall(t)
	cfg, _ := config.Load(paths.Config)
	cfg.ThisComputer = true
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	me := config.LocalName()
	if err := inventory.Save(paths, me, &inventory.Inventory{OSID: "macos", OSVersion: "15.7.7", Mac: &inventory.Mac{}}); err != nil {
		t.Fatal(err)
	}
	f := &findings.Finding{ID: findings.MakeID(me, findings.KindVulnerability, "CVE-2026-1002/macos"), Server: me, Kind: findings.KindVulnerability,
		CVE: "CVE-2026-1002", Source: "macos", Installed: "15.7.7", Fixed: "15.8.2", Priority: findings.Urgent}
	_ = findings.Update(paths, func(st *findings.Store) error {
		st.Merge(me, []*findings.Finding{f}, []findings.Kind{findings.KindVulnerability}, time.Now())
		return nil
	})

	opened := 0
	defer func(orig func() error) { openSoftwareUpdate = orig }(openSoftwareUpdate)
	openSoftwareUpdate = func() error { opened++; return nil }

	rec := newRecorder()
	d := New(paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), rec)
	d.followUpEvery = time.Hour // don't follow up during the test
	key := groupKey(f)
	d.onClick(notify.Event{NotificationID: key, Action: "fix:" + me})
	d.onClick(notify.Event{NotificationID: key, Action: notify.Default})

	if opened != 2 {
		t.Fatalf("Software Update opened %d times, want 2", opened)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, n := range rec.shown {
		if n.ID != key {
			t.Fatalf("unexpected notification %+v (an error?)", n)
		}
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
