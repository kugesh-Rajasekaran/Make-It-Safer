package daemon

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
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

// alert reacts to a check. A server's first check gets one summary instead
// of a notification per vulnerability; fixed vulnerabilities replace their
// notification with ✅. Everything else goes through the reminders.
func (d *Daemon) alert(res *engine.Result) {
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		d.log.Warn("alert", "status", "error", "error", err)
		return
	}
	for _, w := range res.Warnings {
		d.log.Warn("check", "status", "warning", "warning", w)
	}
	for _, s := range res.Servers { // nobody sees these in an unattended check
		if s.Code != "" {
			d.log.Warn("check", "status", "error", "server", s.Server, "code", s.Code, "error", s.Error)
		}
	}
	now := d.now()
	err = findings.Update(d.paths, func(st *findings.Store) error {
		for _, s := range res.Servers {
			if !s.First { // also when a refresh failed: the findings of the older list were baselined all the same
				continue
			}
			for _, f := range st.Findings {
				if f.Server == s.Server && f.Open() && f.State == findings.StateNew {
					markNotified(f, now)
				}
			}
			_ = d.notifier.Show(notify.Notification{
				ID: "baseline:" + s.Server, Title: serverLabel(s.Server) + " is now monitored",
				Body: "Open now: " + summaryCounts(s.Open) + ". Click to see them.",
			})
		}
		for _, key := range groupKeys(res.Changes.Resolved) {
			shown := slices.ContainsFunc(res.Changes.Resolved, func(f *findings.Finding) bool { return groupKey(f) == key && !f.NotifiedAt.IsZero() })
			if !shown {
				continue // never shown, so nothing to update
			}
			open := slices.DeleteFunc(slices.Clone(st.Findings), func(f *findings.Finding) bool { return !f.Open() || groupKey(f) != key })
			if len(open) > 0 { // some servers fixed: show the progress
				n := d.groupNotification(key, open, fixedServers(st, key, now), cfg)
				n.Sound = false
				_ = d.notifier.Show(n)
				continue
			}
			first := res.Changes.Resolved[slices.IndexFunc(res.Changes.Resolved, func(f *findings.Finding) bool { return groupKey(f) == key })]
			if first.Kind == findings.KindEarlyWarning {
				d.earlyWarningEnded(key, first, res.Changes.Resolved)
				continue
			}
			_ = d.notifier.Show(doneNotification(key, first))
			d.mu.Lock()
			delete(d.clicked, key)
			d.mu.Unlock()
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

const hostKeyPrefix = "hostkey:"

// refreshFailed raises an alert for every server whose host key changed:
// the connection was refused because someone may be intercepting it.
func (d *Daemon) refreshFailed(failed map[string]error) {
	for server, err := range failed {
		if !apperr.Is(err, apperr.ServerHostKeyMismatch) {
			continue
		}
		d.log.Warn("refresh", "status", "host key mismatch", "server", server)
		_ = d.notifier.Show(notify.Notification{
			ID: hostKeyPrefix + server, Title: "⚠ " + server + ": host key changed", Urgent: true, Sound: true,
			Body: "Make-It-Safer stopped connecting: someone may be intercepting the connection. " +
				"If you reinstalled the server, remove it and add it again. Click for details.",
		})
	}
}

// earlyWarningEnded replaces a heads-up once the distros have spoken: ✅
// when no server is affected; when one is, the confirmed alert takes over.
func (d *Daemon) earlyWarningEnded(key string, first *findings.Finding, resolved []*findings.Finding) {
	confirmed, notAffected := false, false
	for _, f := range resolved {
		if groupKey(f) == key {
			confirmed = confirmed || f.Resolution == findings.ResolutionConfirmed
			notAffected = notAffected || f.Resolution == findings.ResolutionNotAffected
		}
	}
	if notAffected && !confirmed {
		_ = d.notifier.Show(notify.Notification{ID: key, Title: "✅ " + first.CVE + " · not affected", Body: "Your distro assessed it: your servers aren't affected."})
		return
	}
	_ = d.notifier.Remove(key) // confirmed (its own alert follows) or expired
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
	d.remindToUnlock(now)
	return findings.Update(d.paths, func(st *findings.Store) error {
		due := map[string][]*findings.Finding{}
		for _, f := range st.Findings {
			if f.Priority >= findings.High && findings.ReminderDue(f, cfg.Rules, now) {
				due[groupKey(f)] = append(due[groupKey(f)], f)
			}
		}
		for key := range due {
			group := slices.DeleteFunc(slices.Clone(st.Findings), func(f *findings.Finding) bool { return !f.Open() || groupKey(f) != key })
			if err := d.notifier.Show(d.groupNotification(key, group, fixedServers(st, key, now), cfg)); err != nil {
				d.log.Warn("remind", "status", "error", "group", key, "error", err)
				continue // it's due again at the next pass; the groups already shown are still recorded
			}
			for _, f := range due[key] {
				markNotified(f, now)
			}
		}

		normal := 0
		for _, f := range st.Findings {
			snoozed := f.State == findings.StateSnoozed && now.Before(f.SnoozedUntil)
			if f.Open() && f.Priority == findings.Normal && f.State != findings.StateAccepted && !snoozed {
				normal++
			}
		}
		if normal > 0 && now.Sub(st.Notes[summaryID]) >= time.Duration(cfg.Rules.Remind.Normal) {
			_ = d.notifier.Show(notify.Notification{ID: summaryID, Title: "Weekly summary",
				Body: fmt.Sprintf("%d updates with a fix are waiting. See them with: mis findings", normal)})
			st.Notes[summaryID] = now
		}

		if now.Sub(st.Notes[staleID]) > staleAfter {
			if n, ok := d.staleNotice(cfg, now); ok {
				_ = d.notifier.Show(n)
				st.Notes[staleID] = now
			}
		}
		return nil
	})
}

// groupNotification builds the notification for one group of open findings:
// a button per affected server (✓ once used) and "All servers…" when there
// are more servers than buttons. fixed counts servers already fixed.
func (d *Daemon) groupNotification(key string, group []*findings.Finding, fixed int, cfg *config.Config) notify.Notification {
	top, servers := findings.Silent, []string{}
	kev, fix, proOnly := false, false, false
	for _, f := range group {
		top = max(top, f.Priority)
		kev, fix, proOnly = kev || f.KEV, fix || f.HasFix(), proOnly || f.ProOnly
		if !slices.Contains(servers, f.Server) {
			servers = append(servers, f.Server)
		}
	}
	slices.Sort(servers)
	n := notify.Notification{ID: key, Urgent: top == findings.Urgent, Sound: cfg.Notifications.Sound}
	if len(group) == 0 {
		return n
	}
	if isApple(group[0]) { // one notification per Apple update, not per CVE
		exploited := 0
		for _, f := range group {
			if f.KEV {
				exploited++
			}
		}
		n.Title = fmt.Sprintf("%s %s · fixes %d %s", icons[top], appleUpdate(group[0]), len(group), pluralWord(len(group), "vulnerability", "vulnerabilities"))
		if exploited > 0 {
			n.Title += fmt.Sprintf(" · %d actively exploited", exploited)
		}
		n.Body = "Install it in System Settings › Software Update."
		n.Buttons = []notify.Button{{ID: "fix:" + group[0].Server, Title: config.LocalLabel()}}
		return n
	}
	n.Title = icons[top] + " " + title(group[0])
	if group[0].Kind == findings.KindEarlyWarning { // no fix yet, so no buttons
		n.Title, n.Urgent = "🟡 Heads-up · "+title(group[0]), false
	}
	if kev {
		n.Title += " · actively exploited"
	}
	if group[0].Kind == findings.KindEarlyWarning {
		n.Body = "Not confirmed by your distro yet · may affect " + plural(len(servers), "server")
		if score := slices.MaxFunc(group, func(a, b *findings.Finding) int { return cmp.Compare(a.Score, b.Score) }).Score; score > 0 {
			n.Body += fmt.Sprintf(" · CVSS %.1f", score)
		}
		n.Body += " · no fix yet. Click for details."
		return n
	}
	if group[0].Kind != findings.KindVulnerability {
		n.Body = group[0].Summary
		if group[0].Kind == findings.KindReboot {
			n.Buttons = []notify.Button{{ID: "fix:" + group[0].Server, Title: "Open SSH to restart"}}
		}
		return n
	}

	affected := plural(len(servers), "server") + " affected"
	if fixed > 0 {
		affected = fmt.Sprintf("%d of %d servers fixed", fixed, fixed+len(servers))
	}
	switch {
	case proOnly:
		n.Body = affected + " · fix needs Ubuntu Pro"
	case fix:
		n.Body = affected + " · fix available"
	default:
		n.Body = affected + " · no fix yet"
	}

	d.mu.Lock()
	clicked := maps.Clone(d.clicked[key]) // fix() writes the inner map; a nil map reads as empty
	d.mu.Unlock()
	shown := min(len(servers), max(1, cfg.Notifications.MaxButtons-1))
	if len(servers) == 1 {
		shown = 1
	}
	for _, s := range servers[:shown] {
		label := serverLabel(s)
		if clicked[s] {
			label += " ✓"
		}
		n.Buttons = append(n.Buttons, notify.Button{ID: "fix:" + s, Title: label})
	}
	if len(servers) > 1 {
		n.Buttons = append(n.Buttons, notify.Button{ID: "all", Title: "All servers…"})
	}
	return n
}

func title(f *findings.Finding) string {
	switch f.Kind {
	case findings.KindReboot:
		return serverLabel(f.Server) + " needs a restart"
	case findings.KindEndOfLife:
		return serverLabel(f.Server) + ": " + f.Installed + " support ended"
	case findings.KindUpdates:
		return serverLabel(f.Server) + ": " + f.Installed + " packages"
	}
	return f.CVE + " · " + f.Source
}

// serverLabel is how notifications name a server; this computer is "This Mac".
func serverLabel(server string) string {
	if server == config.LocalName() {
		return config.LocalLabel()
	}
	return server
}

// isApple reports a vulnerability on this Mac, found in Apple's notes.
func isApple(f *findings.Finding) bool {
	return f.Kind == findings.KindVulnerability && f.Server == config.LocalName() && (f.Source == "macos" || f.Source == "safari")
}

// appleUpdate names the update that fixes an Apple finding, e.g. "macOS 15.8.2".
func appleUpdate(f *findings.Finding) string {
	if f.Source == "safari" {
		return "Safari " + f.Fixed
	}
	return "macOS " + f.Fixed
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// groupKey: one notification per CVE (early warnings separately), per Apple
// update on this Mac, or per server for restarts, end of support and updates.
func groupKey(f *findings.Finding) string {
	switch {
	case isApple(f):
		return "apple:" + f.Source + "-" + f.Fixed
	case f.Kind == findings.KindVulnerability:
		return "cve:" + f.CVE
	case f.Kind == findings.KindEarlyWarning:
		return string(f.Kind) + ":" + f.CVE
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
