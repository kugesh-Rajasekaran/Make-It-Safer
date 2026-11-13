package daemon

import (
	"errors"
	"fmt"
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

// twoServers sets up web and db with the same open vulnerability, and a
// "terminal" that just exits.
func twoServers(t *testing.T) config.Paths {
	t.Helper()
	paths := newInstall(t)
	cfg, _ := config.Load(paths.Config)
	cfg.Servers = []config.Server{{Name: "web", Host: "10.0.0.1", Port: 22, AdminSSH: "ubuntu@10.0.0.1"}, {Name: "db", Host: "10.0.0.2", Port: 22, AdminSSH: "ubuntu@10.0.0.2"}}
	cfg.Terminal = config.Terminal{App: "custom", Command: "true {script}"}
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"web", "db"} {
		inv := &inventory.Inventory{OSID: "ubuntu", OSVersion: "24.04", Kernel: "6.8", Packages: []inventory.Package{{Name: "openssh-server", Version: "1", Source: "openssh", SourceVersion: "1"}}}
		if err := inventory.Save(paths, s, inv); err != nil {
			t.Fatal(err)
		}
	}
	_ = findings.Update(paths, func(st *findings.Store) error {
		for _, s := range []string{"web", "db"} {
			st.Merge(s, []*findings.Finding{{ID: findings.MakeID(s, findings.KindVulnerability, "CVE-2024-6387/openssh"), Server: s,
				Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1", Fixed: "2", Priority: findings.High}},
				[]findings.Kind{findings.KindVulnerability}, time.Now())
		}
		return nil
	})
	return paths
}

// dialogs is a Notifier that opens dialogs, or fails to (no helper app,
// no zenity).
type dialogs struct {
	*recorder
	fail   bool
	opened []notify.Dialog
}

func (r *dialogs) ShowDialog(d notify.Dialog) error {
	if r.fail {
		return errors.New("zenity isn't installed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened = append(r.opened, d)
	return nil
}

func rows(d notify.Dialog) string {
	var out []string
	for _, r := range d.Rows {
		button := ""
		if r.Button != nil {
			button = r.Button.ID + "=" + r.Button.Title
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%v|%s", r.Name, r.Detail, button, r.Opened, r.Command))
	}
	return strings.Join(out, "\n")
}

func TestDialog(t *testing.T) {
	paths := twoServers(t)
	rec := &dialogs{recorder: newRecorder()}
	d := New(paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), rec)
	d.followUpEvery = time.Hour // don't follow up during the test
	key := "cve:CVE-2024-6387"

	// A click on the notification opens its dialog; an Update button there
	// opens the fix and updates the dialog with a ✓, and the notification
	// doesn't pop up again.
	d.onClick(notify.Event{NotificationID: key, Action: notify.Default})
	d.onClick(notify.Event{NotificationID: key, Action: "fix:web", FromDialog: true})
	if len(rec.opened) != 2 || len(rec.shown) != 0 || rec.opened[0].Refresh || !rec.opened[1].Refresh {
		t.Fatalf("dialogs %+v, notifications %+v", rec.opened, rec.shown)
	}
	dg := rec.opened[1]
	if dg.Title != "CVE-2024-6387 · openssh" || dg.Verdict != "This week" || dg.Level != "high" || len(dg.Facts) == 0 ||
		dg.Command != "sudo apt-get update && sudo apt-get install --only-upgrade openssh-server" || !strings.Contains(dg.Fix, "until you press Enter") {
		t.Fatalf("dialog = %+v", dg)
	}
	if got, want := rows(dg), "db|openssh 1 → 2|fix:db=Update|false|\nweb|openssh 1 → 2|fix:web=Update|true|"; got != want {
		t.Fatalf("rows =\n%s\nwant\n%s", got, want)
	}

	// Servers that need different commands each show their own.
	_ = inventory.Save(paths, "db", &inventory.Inventory{OSID: "ubuntu", OSVersion: "24.04", Kernel: "6.8", Packages: []inventory.Package{
		{Name: "openssh-client", Version: "1", Source: "openssh", SourceVersion: "1"}, {Name: "openssh-server", Version: "1", Source: "openssh", SourceVersion: "1"}}})
	if dg, err := d.dialog(key); err != nil || dg.Command != "" || !strings.Contains(dg.Rows[0].Command, "openssh-client") || strings.Contains(dg.Rows[1].Command, "openssh-client") {
		t.Fatalf("per-server commands: %+v, %v", dg, err)
	}

	// No fix yet on db: nothing to run there, so no button.
	_ = findings.Update(paths, func(st *findings.Store) error {
		st.Merge("db", []*findings.Finding{{ID: findings.MakeID("db", findings.KindVulnerability, "CVE-2024-6387/openssh"), Server: "db",
			Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1", Priority: findings.High}},
			[]findings.Kind{findings.KindVulnerability}, time.Now())
		return nil
	})
	if dg, err := d.dialog(key); err != nil || !strings.HasPrefix(rows(*dg), "db|openssh 1 → no fix yet||false|\n") {
		t.Fatalf("no fix yet: %s, %v", rows(*dg), err)
	}

	// A restart, and a heads-up (no fix yet: no buttons).
	_ = findings.Update(paths, func(st *findings.Store) error {
		st.Merge("web", []*findings.Finding{
			{ID: findings.MakeID("web", findings.KindReboot, "kernel"), Server: "web", Kind: findings.KindReboot, Source: "linux", Installed: "6.8",
				Summary: "a newer kernel is installed than the one running", Priority: findings.High},
			{ID: findings.MakeID("web", findings.KindEarlyWarning, "CVE-2026-0001/openssh"), Server: "web", Kind: findings.KindEarlyWarning,
				CVE: "CVE-2026-0001", Source: "openssh", Installed: "1", Priority: findings.High},
		}, []findings.Kind{findings.KindReboot, findings.KindEarlyWarning}, time.Now())
		return nil
	})
	if dg, err := d.dialog("reboot:web"); err != nil || dg.Facts[0].Value != "A newer kernel is installed than the one running" || dg.Command != "sudo reboot" ||
		rows(*dg) != "web|running kernel 6.8|fix:web=Restart|false|" {
		t.Fatalf("restart dialog = %+v, %v", dg, err)
	}
	if dg, err := d.dialog("early-warning:CVE-2026-0001"); err != nil || dg.Verdict != "Heads-up" || !strings.HasPrefix(dg.Fix, "No fix") ||
		rows(*dg) != "web|openssh 1 → no fix yet||false|" {
		t.Fatalf("heads-up dialog = %+v, %v", dg, err)
	}

	// Without dialogs (no zenity), the click opens the terminal as before.
	rec.fail = true
	d.onClick(notify.Event{NotificationID: key, Action: notify.Default})
	if len(rec.opened) != 2 || len(rec.shown) != 0 {
		t.Fatalf("fallback: dialogs %d, notifications %+v (an error?)", len(rec.opened), rec.shown)
	}
}
