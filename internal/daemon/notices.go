package daemon

import (
	"fmt"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
)

// lockNoticeEvery is how often the lock notice comes back while the
// service stays locked.
const lockNoticeEvery = 24 * time.Hour

// showLockNotice asks you to unlock after a restart.
func (d *Daemon) showLockNotice() {
	if d.unlocked() {
		return
	}
	d.mu.Lock()
	d.lockShown = d.now()
	d.mu.Unlock()
	_ = d.notifier.Show(notify.Notification{
		ID: lockNoticeID, Title: "Make-It-Safer is locked",
		Body: "Unlock it so it can check your servers: click here, or run: mis unlock",
	})
}

// remindToUnlock shows the lock notice again once a day while the service
// stays locked. Locked, it can't refresh the servers' package lists, and the
// notice from the start of the service is easily dismissed and forgotten.
func (d *Daemon) remindToUnlock(now time.Time) {
	d.mu.Lock()
	shown := d.lockShown
	d.mu.Unlock()
	if !shown.IsZero() && now.Sub(shown) >= lockNoticeEvery { // zero: the notice was never due (not started)
		d.showLockNotice()
	}
}

// staleNotice returns the warning for data that is getting old, if any:
// the last successful match is old (offline), or a server's package list is
// (the match job succeeds on whatever list it has, so it can't tell).
func (d *Daemon) staleNotice(cfg *config.Config, now time.Time) (notify.Notification, bool) {
	var parts []string
	title := "Vulnerability data is getting old"
	if last := d.sched.lastOK("match"); len(cfg.Checked()) > 0 && !last.IsZero() && now.Sub(last) > staleAfter {
		parts = append(parts, fmt.Sprintf("The last successful check was %s ago. Check your internet connection, or run: mis check", ageLabel(now.Sub(last))))
	}
	if old := d.oldPackageLists(cfg, now); len(old) > 0 {
		if len(parts) == 0 {
			title = "Package lists are getting old"
		}
		parts = append(parts, "Not refreshed: "+strings.Join(old, ", ")+". Run: mis check, to refresh them or to see why that fails")
	}
	if len(parts) == 0 {
		return notify.Notification{}, false
	}
	return notify.Notification{ID: staleID, Title: title, Body: strings.Join(parts, ". ") + "."}, true
}

// oldPackageLists names the servers whose saved package list is older than
// two refresh intervals (at least a day), each with its age. This computer
// is read again at every match, so it is left out.
func (d *Daemon) oldPackageLists(cfg *config.Config, now time.Time) []string {
	limit := cfg.Schedule.ListStaleAfter()
	var old []string
	for _, s := range cfg.Checked() {
		if s.Local {
			continue
		}
		inv, err := inventory.Load(d.paths, s.Name)
		if err != nil {
			if !apperr.Is(err, apperr.InventoryNotFound) { // not found: a check reports that itself
				d.log.Warn("stale", "status", "error", "server", s.Name, "error", err)
			}
			continue
		}
		if age := now.Sub(inv.CollectedAt); !inv.CollectedAt.IsZero() && age > limit {
			old = append(old, fmt.Sprintf("%s (%s old)", s.Name, ageLabel(age)))
		}
	}
	return old
}

// ageLabel is a duration in hours, or in days from two days on.
func ageLabel(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%d days", int(d.Hours())/24)
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}

// doneNotification replaces a group's notification once everything in it is
// fixed. What "fixed" means depends on the kind: an Apple update is
// installed, a server restarted, a vulnerability fixed on its servers.
func doneNotification(key string, first *findings.Finding) notify.Notification {
	n := notify.Notification{ID: key}
	label := serverLabel(first.Server)
	switch {
	case isApple(first):
		n.Title, n.Body = "✅ "+appleUpdate(first)+" installed", "Fixed on "+label+"."
	case first.Kind == findings.KindReboot:
		n.Title, n.Body = "✅ "+label+" restarted", "The pending restart is done."
	case first.Kind == findings.KindEndOfLife:
		n.Title, n.Body = "✅ "+label+": end of support resolved", "It no longer runs a release that is out of support."
	case first.Kind == findings.KindUpdates:
		n.Title, n.Body = "✅ "+label+": packages up to date", "No outdated packages are left."
	default:
		n.Title, n.Body = "✅ "+title(first), "Fixed on all servers."
	}
	return n
}
