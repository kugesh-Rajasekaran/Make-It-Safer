package findings

import (
	"slices"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// rebootGrace is how long a pending kernel reboot stays "normal".
const rebootGrace = 3 * 24 * time.Hour

// Classify decides a finding's priority from the rules (docs/design.md §4.4):
//
//	urgent: actively exploited, or severity ≥ 9 with a fix, or OS out of support
//	high:   severity ≥ min_severity, or EPSS ≥ min_epss, or a reboot pending > 3 days,
//	        or an early warning (shown once, never reminded: see ReminderDue)
//	normal: other vulnerabilities with a fix
//	silent: no fix and not urgent (unless rules.unfixed is "all"), or ignored
//
// End-of-life findings keep the priority they were created with.
func Classify(f *Finding, r config.Rules, now time.Time) Priority {
	if slices.Contains(r.Ignore.CVEs, f.CVE) || slices.Contains(r.Ignore.Packages, f.Source) {
		return Silent
	}
	switch f.Kind {
	case KindEndOfLife:
		return f.Priority
	case KindReboot:
		if now.Sub(f.FirstSeen) > rebootGrace {
			return High
		}
		return Normal
	case KindEarlyWarning:
		return High
	case KindUpdates: // no CVE data: shown in the weekly summary, never alone
		return Normal
	}

	score := f.Score
	if score == 0 {
		score = scoreFromDistro(f.DistroPriority)
	}
	switch {
	case f.KEV && r.AlertWhen.ActivelyExploited:
		return Urgent
	case f.HasFix() && score >= 9:
		return Urgent
	case !f.HasFix() && r.Unfixed != config.UnfixedAll:
		return Silent
	case score >= r.AlertWhen.MinSeverity || (f.EPSS > 0 && f.EPSS >= r.AlertWhen.MinEPSS):
		return High
	default:
		return Normal
	}
}

// scoreFromDistro approximates a CVSS score from Ubuntu priority or Debian
// urgency when no CVSS score is published.
func scoreFromDistro(p string) float64 {
	switch p {
	case "critical":
		return 9.0
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default: // negligible, unimportant, not yet assigned, unknown
		return 0
	}
}

// ReminderDue reports whether an open finding should be shown again.
func ReminderDue(f *Finding, r config.Rules, now time.Time) bool {
	if !f.Open() || f.State == StateAccepted || f.Priority == Silent {
		return false
	}
	if f.State == StateSnoozed {
		return !now.Before(f.SnoozedUntil)
	}
	if f.NotifiedAt.IsZero() {
		return true
	}
	if f.Kind == KindEarlyWarning {
		return false // nothing to do until the distro confirms it; that alert follows
	}
	every := time.Duration(r.Remind.Normal)
	switch f.Priority {
	case Urgent:
		every = time.Duration(r.Remind.Urgent)
	case High:
		every = time.Duration(r.Remind.High)
	}
	return now.Sub(f.NotifiedAt) >= every
}
