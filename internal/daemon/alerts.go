package daemon

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
)

const (
	lockNoticeID = "lock"
	summaryID    = "summary"
	staleID      = "stale"
	staleAfter   = 24 * time.Hour
)

var icons = map[findings.Priority]string{findings.Urgent: "🔴", findings.High: "🟠", findings.Normal: "🟡"}

// showLockNotice asks you to unlock after a restart.
func (d *Daemon) showLockNotice() {
	if d.unlocked() {
		return
	}
	_ = d.notifier.Show(notify.Notification{
		ID: lockNoticeID, Title: "Make-It-Safer is locked",
		Body: "Unlock it so it can check your servers: click here, or run: mis unlock",
	})
}

// alert reacts to a check. A server's first check gets one summary instead
// of a notification per vulnerability; fixed vulnerabilities replace their
// notification with ✅. Everything else goes through the reminders.
func (d *Daemon) alert(res *engine.Result) {
	now := d.now()
	err := findings.Update(d.paths, func(st *findings.Store) error {
		for _, s := range res.Servers {
			if !s.First || s.Code != "" {
				continue
			}
			for _, f := range st.Findings {
				if f.Server == s.Server && f.Open() && f.State == findings.StateNew {
					markNotified(f, now)
				}
			}
			_ = d.notifier.Show(notify.Notification{
				ID: "baseline:" + s.Server, Title: s.Server + " is now monitored",
				Body: "Open now: " + summaryCounts(s.Open) + ". See them with: mis findings --server " + s.Server,
			})
		}
		for _, key := range groupKeys(res.Changes.Resolved) {
			if slices.ContainsFunc(st.Findings, func(f *findings.Finding) bool { return f.Open() && groupKey(f) == key }) {
				continue
			}
			first := res.Changes.Resolved[slices.IndexFunc(res.Changes.Resolved, func(f *findings.Finding) bool { return groupKey(f) == key })]
			if first.NotifiedAt.IsZero() {
				continue // never shown, so nothing to update
			}
			_ = d.notifier.Show(notify.Notification{ID: key, Title: "✅ " + title(first), Body: "Fixed on all servers."})
		}
		return nil
	})
	if err != nil {
		d.log.Warn("alert", "status", "error", "error", err)
	}
	if err := d.remind(); err != nil {
		d.log.Warn("remind", "status", "error", "error", err)
	}
}

// remind shows what is due: urgent and high findings (grouped per CVE, or
// per server for restarts and end of support), a weekly summary of normal
// ones, and a warning when the data is getting old.
func (d *Daemon) remind() error {
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		return err
	}
	now := d.now()
	return findings.Update(d.paths, func(st *findings.Store) error {
		due := map[string][]*findings.Finding{}
		for _, f := range st.Findings {
			if f.Priority >= findings.High && findings.ReminderDue(f, cfg.Rules, now) {
				due[groupKey(f)] = append(due[groupKey(f)], f)
			}
		}
		for key := range due {
			group := slices.DeleteFunc(slices.Clone(st.Findings), func(f *findings.Finding) bool { return !f.Open() || groupKey(f) != key })
			if err := d.notifier.Show(d.groupNotification(key, group, cfg)); err != nil {
				return err
			}
			for _, f := range due[key] {
				markNotified(f, now)
			}
		}

		normal := 0
		for _, f := range st.Findings {
			if f.Open() && f.Priority == findings.Normal && f.State != findings.StateAccepted {
				normal++
			}
		}
		if normal > 0 && now.Sub(st.Notes[summaryID]) >= time.Duration(cfg.Rules.Remind.Normal) {
			_ = d.notifier.Show(notify.Notification{ID: summaryID, Title: "Weekly summary",
				Body: fmt.Sprintf("%d updates with a fix are waiting. See them with: mis findings", normal)})
			st.Notes[summaryID] = now
		}

		if last := d.sched.lastOK("match"); len(cfg.Servers) > 0 && !last.IsZero() && now.Sub(last) > staleAfter && now.Sub(st.Notes[staleID]) > staleAfter {
			_ = d.notifier.Show(notify.Notification{ID: staleID, Title: "Vulnerability data is getting old",
				Body: fmt.Sprintf("The last successful check was %s ago. Check your internet connection, or run: mis check", now.Sub(last).Round(time.Hour))})
			st.Notes[staleID] = now
		}
		return nil
	})
}

// groupNotification builds the notification for one group of findings.
func (d *Daemon) groupNotification(key string, group []*findings.Finding, cfg *config.Config) notify.Notification {
	top, servers := findings.Silent, []string{}
	kev, fix, proOnly := false, false, false
	for _, f := range group {
		top = max(top, f.Priority)
		kev, fix, proOnly = kev || f.KEV, fix || f.HasFix(), proOnly || f.ProOnly
		if !slices.Contains(servers, f.Server) {
			servers = append(servers, f.Server)
		}
	}
	n := notify.Notification{ID: key, Urgent: top == findings.Urgent, Sound: cfg.Notifications.Sound}
	if len(group) == 0 {
		return n
	}
	n.Title = icons[top] + " " + title(group[0])
	if kev {
		n.Title += " · actively exploited"
	}
	switch {
	case group[0].Kind != findings.KindVulnerability:
		n.Body = group[0].Summary
	case proOnly:
		n.Body = fmt.Sprintf("%s affected · fix needs Ubuntu Pro", plural(len(servers), "server"))
	case fix:
		n.Body = fmt.Sprintf("%s affected · fix available", plural(len(servers), "server"))
	default:
		n.Body = fmt.Sprintf("%s affected · no fix yet", plural(len(servers), "server"))
	}
	return n
}

func title(f *findings.Finding) string {
	switch f.Kind {
	case findings.KindReboot:
		return f.Server + " needs a restart"
	case findings.KindEndOfLife:
		return f.Server + ": " + f.Installed + " support ended"
	}
	return f.CVE + " · " + f.Source
}

// groupKey: one notification per CVE, or per server for restarts and end of support.
func groupKey(f *findings.Finding) string {
	if f.Kind == findings.KindVulnerability {
		return "cve:" + f.CVE
	}
	return string(f.Kind) + ":" + f.Server
}

func groupKeys(fs []*findings.Finding) []string {
	var keys []string
	for _, f := range fs {
		if k := groupKey(f); !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// markNotified records that a finding was just shown.
func markNotified(f *findings.Finding, now time.Time) {
	if f.State == findings.StateSnoozed {
		_ = f.Transition(findings.StateNew, now)
	}
	if f.State == findings.StateNew {
		_ = f.Transition(findings.StateNotified, now)
		return
	}
	f.NotifiedAt = now
}

func summaryCounts(open map[string]int) string {
	var parts []string
	for _, p := range []findings.Priority{findings.Urgent, findings.High, findings.Normal} {
		if n := open[p.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, p))
		}
	}
	if len(parts) == 0 {
		return "nothing to fix"
	}
	return strings.Join(parts, ", ")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// handleClicks reacts to clicks on notifications.
func (d *Daemon) handleClicks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-d.notifier.Events():
			if !ok {
				return
			}
			d.onClick(ev)
		}
	}
}
