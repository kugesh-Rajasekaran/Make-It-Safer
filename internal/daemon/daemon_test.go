package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

const passphrase = "glacier rhubarb tandem quiver lantern 77"

// recorder is a Notifier that remembers what it showed.
type recorder struct {
	mu      sync.Mutex
	shown   []notify.Notification
	removed []string
	events  chan notify.Event
}

func newRecorder() *recorder { return &recorder{events: make(chan notify.Event, 4)} }

func (r *recorder) Show(n notify.Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.shown = append(r.shown, n)
	return nil
}

func (r *recorder) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed = append(r.removed, id)
	return nil
}

func (r *recorder) Events() <-chan notify.Event { return r.events }
func (r *recorder) Describe() string            { return "test" }
func (r *recorder) Ready() bool                 { return true }
func (r *recorder) Close() error                { return nil }

func (r *recorder) ids() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids []string
	for _, n := range r.shown {
		ids = append(ids, n.ID)
	}
	return ids
}

// newInstall creates an initialised Make-It-Safer home with a test key.
func newInstall(t *testing.T) config.Paths {
	t.Helper()
	dir, err := os.MkdirTemp("", "mis") // short path: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	paths := config.PathsAt(filepath.Join(dir, "h"))
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Create(paths.KeyFile, paths.PublicKey, secret.Bytes(passphrase), vault.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	return paths
}

func startDaemon(t *testing.T, paths config.Paths, n notify.Notifier) *Daemon {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := New(paths, "test", log, n)
	d.feeds = feeds.NewForTest("http://127.0.0.1:1") // no network in tests
	d.newEngine = func(cfg *config.Config) *engine.Engine {
		e := engine.New(paths, cfg, "test", log)
		e.KEV.Feeds = d.feeds
		return e
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = d.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	for range 100 {
		if Running(paths) {
			return d
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("daemon did not start")
	return nil
}

func TestUnlockLockAndStatus(t *testing.T) {
	paths := newInstall(t)
	rec := newRecorder()
	startDaemon(t, paths, rec)

	info, err := os.Stat(paths.Socket)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	var s Status
	if err := Call(paths, Request{Op: OpStatus}, &s, 5*time.Second); err != nil || !s.Locked {
		t.Fatalf("status = %+v, %v; want locked", s, err)
	}
	if ids := rec.ids(); len(ids) == 0 || ids[0] != lockNoticeID {
		t.Fatalf("no lock notice at start: %v", ids)
	}

	err = Call(paths, Request{Op: OpUnlock, Passphrase: []byte("wrong passphrase, wrong")}, nil, time.Minute)
	if !apperr.Is(err, apperr.VaultUnlockFailed) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	err = Call(paths, Request{Op: OpUnlock, Passphrase: []byte(passphrase)}, nil, time.Minute)
	if !apperr.Is(err, apperr.VaultUnlockRateLimited) {
		t.Fatalf("an immediate retry should be slowed down: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	pass := []byte(passphrase)
	if err := Call(paths, Request{Op: OpUnlock, Passphrase: pass}, nil, time.Minute); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pass), "glacier") {
		t.Fatal("Call must wipe the passphrase it sent")
	}
	if err := Call(paths, Request{Op: OpStatus}, &s, 5*time.Second); err != nil || s.Locked {
		t.Fatalf("status after unlock = %+v, %v", s, err)
	}
	if !contains(rec.removed, lockNoticeID) {
		t.Fatal("lock notice not removed after unlock")
	}

	if err := Call(paths, Request{Op: OpLock}, nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := Call(paths, Request{Op: OpStatus}, &s, 5*time.Second); err != nil || !s.Locked {
		t.Fatalf("status after lock = %+v, %v", s, err)
	}
	if err := Call(paths, Request{Op: "bogus"}, nil, 5*time.Second); !apperr.Is(err, apperr.DaemonBadRequest) {
		t.Fatalf("unknown op: %v", err)
	}
}

func TestOnlyOneDaemon(t *testing.T) {
	paths := newInstall(t)
	startDaemon(t, paths, newRecorder())
	err := New(paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), newRecorder()).Run(context.Background())
	if !apperr.Is(err, apperr.DaemonAlreadyRunning) {
		t.Fatalf("second daemon: %v", err)
	}
}

func TestCallWithoutDaemon(t *testing.T) {
	paths := newInstall(t)
	if err := Call(paths, Request{Op: OpStatus}, nil, time.Second); !apperr.Is(err, apperr.DaemonNotRunning) || !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Call() = %v", err)
	}
}

func TestRemindGroupsAndRespectsIntervals(t *testing.T) {
	paths := newInstall(t)
	rec := newRecorder()
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	d := New(paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), rec)
	d.now = func() time.Time { return now }
	d.sched = newScheduler(nil, filepath.Join(paths.State, "schedule.json"), d.now, d.unlocked, d.log)

	vuln := func(server string) *findings.Finding {
		return &findings.Finding{ID: findings.MakeID(server, findings.KindVulnerability, "CVE-2024-6387/openssh"), Server: server,
			Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Fixed: "2", KEV: true, Priority: findings.Urgent}
	}
	_ = findings.Update(paths, func(st *findings.Store) error {
		st.Merge("web", []*findings.Finding{vuln("web")}, []findings.Kind{findings.KindVulnerability}, now)
		st.Merge("db", []*findings.Finding{vuln("db")}, []findings.Kind{findings.KindVulnerability}, now)
		st.Merge("db", []*findings.Finding{vuln("db"), {ID: "db/vulnerability/CVE-1/x", Server: "db", Kind: findings.KindVulnerability,
			CVE: "CVE-1", Source: "x", Fixed: "2", Priority: findings.Normal}}, []findings.Kind{findings.KindVulnerability}, now)
		return nil
	})

	if err := d.remind(); err != nil {
		t.Fatal(err)
	}
	if len(rec.shown) != 2 || rec.shown[0].ID != "cve:CVE-2024-6387" || !strings.Contains(rec.shown[0].Body, "2 servers affected") ||
		!strings.Contains(rec.shown[0].Title, "actively exploited") || rec.shown[1].ID != summaryID {
		t.Fatalf("want one grouped urgent notification and a summary, got %+v", rec.shown)
	}
	st, _ := findings.Load(paths)
	if f := st.Find("web/vulnerability/CVE-2024-6387/openssh"); f.State != findings.StateNotified {
		t.Fatalf("finding not marked notified: %s", f.State)
	}

	now = now.Add(time.Hour) // urgent reminds every 4h; summary weekly
	_ = d.remind()
	if len(rec.shown) != 2 {
		t.Fatalf("reminded too early: %+v", rec.shown[2:])
	}
	now = now.Add(3 * time.Hour)
	_ = d.remind()
	if len(rec.shown) != 3 || rec.shown[2].ID != "cve:CVE-2024-6387" {
		t.Fatalf("urgent reminder missing after 4h: %+v", rec.shown)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestFixButton(t *testing.T) {
	paths := newInstall(t)
	cfg, _ := config.Load(paths.Config)
	cfg.Servers = []config.Server{{Name: "web", Host: "10.0.0.1", Port: 22, AdminSSH: "ubuntu@10.0.0.1"}, {Name: "db", Host: "10.0.0.2", Port: 22, AdminSSH: "ubuntu@10.0.0.2"}}
	cfg.Terminal = config.Terminal{App: "custom", Command: "true {script}"} // the "terminal" just exits
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"web", "db"} {
		inv := &inventory.Inventory{OSID: "ubuntu", OSVersion: "24.04", Kernel: "6.8", Packages: []inventory.Package{{Name: "openssh-server", Version: "1", Source: "openssh", SourceVersion: "1"}}}
		if err := inventory.Save(paths, s, inv); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	_ = findings.Update(paths, func(st *findings.Store) error {
		for _, s := range []string{"web", "db"} {
			st.Merge(s, []*findings.Finding{{ID: findings.MakeID(s, findings.KindVulnerability, "CVE-2024-6387/openssh"), Server: s,
				Kind: findings.KindVulnerability, CVE: "CVE-2024-6387", Source: "openssh", Installed: "1", Fixed: "2", Priority: findings.High}},
				[]findings.Kind{findings.KindVulnerability}, now)
		}
		return nil
	})

	rec := newRecorder()
	d := New(paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), rec)
	d.followUpEvery = time.Hour // don't follow up during the test
	d.onClick(notify.Event{NotificationID: "cve:CVE-2024-6387", Action: "fix:web"})
	d.onClick(notify.Event{NotificationID: "cve:CVE-2024-6387", Action: "all"})

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.shown) != 1 {
		t.Fatalf("want the notification shown again once, got %+v", rec.shown)
	}
	n := rec.shown[0]
	var labels []string
	for _, b := range n.Buttons {
		labels = append(labels, b.Title)
	}
	if n.ID != "cve:CVE-2024-6387" || strings.Join(labels, "|") != "db|web ✓|All servers…" || n.Sound {
		t.Fatalf("re-shown notification = %+v", n)
	}
}

func TestEarlyWarningNotifications(t *testing.T) {
	paths := newInstall(t)
	cfg, _ := config.Load(paths.Config)
	cfg.Terminal = config.Terminal{App: "custom", Command: "true {script}"}
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var raised []*findings.Finding
	_ = findings.Update(paths, func(st *findings.Store) error {
		for _, s := range []string{"web", "db"} {
			raised = append(raised, &findings.Finding{ID: findings.MakeID(s, findings.KindEarlyWarning, "CVE-2026-0001/openssh"), Server: s,
				Kind: findings.KindEarlyWarning, CVE: "CVE-2026-0001", Source: "openssh", Score: 9.8, Priority: findings.High})
		}
		st.Add(raised, now)
		return nil
	})
	rec := newRecorder()
	d := New(paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), rec)
	d.sched = newScheduler(nil, filepath.Join(paths.State, "schedule.json"), time.Now, d.unlocked, d.log)

	// Shown once, as a heads-up without buttons, and not reminded.
	d.alert(&engine.Result{})
	d.alert(&engine.Result{})
	rec.mu.Lock()
	shown := slices.Clone(rec.shown)
	rec.mu.Unlock()
	if len(shown) != 1 {
		t.Fatalf("shown %d times: %+v", len(shown), shown)
	}
	n := shown[0]
	if n.ID != "early-warning:CVE-2026-0001" || n.Title != "🟡 Heads-up · CVE-2026-0001 · openssh" || len(n.Buttons) != 0 || n.Urgent ||
		!strings.Contains(n.Body, "may affect 2 servers · CVSS 9.8") {
		t.Fatalf("heads-up = %+v", n)
	}

	// The distro: db not affected, web not affected either → ✅.
	var resolved []*findings.Finding
	_ = findings.Update(paths, func(st *findings.Store) error {
		for _, f := range st.Findings {
			_ = f.Transition(findings.StateResolved, now)
			f.Resolution = findings.ResolutionNotAffected
			resolved = append(resolved, f)
		}
		return nil
	})
	d.alert(&engine.Result{Changes: findings.Changes{Resolved: resolved}})
	rec.mu.Lock()
	last := rec.shown[len(rec.shown)-1]
	rec.mu.Unlock()
	if last.ID != "early-warning:CVE-2026-0001" || last.Title != "✅ CVE-2026-0001 · not affected" {
		t.Fatalf("after the distro said not affected: %+v", last)
	}

	// Confirmed instead: the heads-up is removed (the real alert follows).
	resolved[0].Resolution = findings.ResolutionConfirmed
	d.alert(&engine.Result{Changes: findings.Changes{Resolved: resolved}})
	rec.mu.Lock()
	removed := slices.Clone(rec.removed)
	rec.mu.Unlock()
	if !slices.Contains(removed, "early-warning:CVE-2026-0001") {
		t.Fatalf("removed = %v", removed)
	}

	// A click opens mis show.
	d.onClick(notify.Event{NotificationID: "early-warning:CVE-2026-0001", Action: notify.Default})
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, n := range rec.shown {
		if n.ID == "error" {
			t.Fatalf("click failed: %+v", n)
		}
	}
}
