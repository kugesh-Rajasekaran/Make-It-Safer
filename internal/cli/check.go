package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

var icons = map[findings.Priority]string{findings.Urgent: "🔴", findings.High: "🟠", findings.Normal: "🟡", findings.Silent: "⚪"}

func (a *app) checkCmd() *cobra.Command {
	var noRefresh bool
	cmd := &cobra.Command{
		Use:   "check [server...]",
		Short: "Check your servers (and this computer) now: refresh package lists and match them",
		Long: `Logs in to each server as the read-only mis user to refresh its package
list (asks for your passphrase) and reads this computer's directly, then
matches all lists against the latest vulnerability data. With --no-refresh it
only matches the saved lists.`,
		RunE: func(_ *cobra.Command, names []string) error {
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			servers, err := pick(cfg, names, true)
			if err != nil {
				return err
			}
			needKey := !noRefresh && slices.ContainsFunc(servers, func(s config.Server) bool { return !s.Local })
			// The background service checks with its unlocked key, without asking again.
			if daemon.Running(paths) {
				var res engine.Result
				err := a.withSpinner("Checking "+describe(servers), func() error {
					return daemon.Call(paths, daemon.Request{Op: daemon.OpCheck, Servers: names, Refresh: !noRefresh}, &res, 30*time.Minute)
				})
				if err == nil {
					return a.emit(&res, func(w io.Writer) { printCheck(w, &res) })
				}
				if !apperr.Is(err, apperr.VaultLocked) {
					return err
				}
			}
			var signer ssh.Signer
			if needKey {
				key, err := a.unlockKey(paths)
				if err != nil {
					return err
				}
				defer key.Destroy()
				signer = key.Signer()
			}
			var res *engine.Result
			err = a.withSpinner("Checking "+describe(servers), func() (err error) {
				res, err = engine.New(paths, cfg, version, a.log).Check(context.Background(), !noRefresh, signer, servers)
				return err
			})
			if err != nil {
				return err
			}
			return a.emit(res, func(w io.Writer) { printCheck(w, res) })
		},
	}
	cmd.Flags().BoolVar(&noRefresh, "no-refresh", false, "don't log in to servers; match the saved package lists only")
	return cmd
}

func printCheck(w io.Writer, res *engine.Result) {
	for _, s := range res.Servers {
		label := s.Server
		if s.OS != "" {
			label += " (" + s.OS + ")"
		}
		switch {
		case s.Code != "" && len(s.Open) == 0:
			_, _ = fmt.Fprintf(w, "%s: ✗ %s [%s]\n", label, s.Error, s.Code)
		default:
			_, _ = fmt.Fprintf(w, "%s: %s\n", label, counts(s.Open))
			if s.Code != "" {
				_, _ = fmt.Fprintf(w, "    ✗ %s [%s]\n", s.Error, s.Code)
			}
		}
	}
	changed := slices.Concat(res.Changes.New, res.Changes.Reopened, res.Changes.Escalated)
	changed = slices.DeleteFunc(changed, func(f *findings.Finding) bool { return f.Priority == findings.Silent })
	if len(changed) > 0 {
		_, _ = fmt.Fprintln(w, "\nNew or more urgent:")
		sortFindings(changed)
		const shown = 20 // most urgent first; a Mac's first check can find hundreds
		for _, f := range changed[:min(len(changed), shown)] {
			_, _ = fmt.Fprintln(w, "  "+line(f))
		}
		if len(changed) > shown {
			_, _ = fmt.Fprintf(w, "  … and %d more\n", len(changed)-shown)
		}
	}
	if len(res.Changes.Resolved) > 0 {
		_, _ = fmt.Fprintln(w, "\nFixed since last check:")
		for _, f := range res.Changes.Resolved {
			_, _ = fmt.Fprintf(w, "  ✅ %s on %s\n", subject(f), f.Server)
		}
	}
	for _, warn := range res.Warnings {
		_, _ = fmt.Fprintf(w, "\n⚠ %s\n", clean(warn))
	}
	_, _ = fmt.Fprintln(w, "\nSee everything open: mis findings")
}

func counts(open map[string]int) string {
	var parts []string
	for _, p := range []findings.Priority{findings.Urgent, findings.High, findings.Normal} {
		if n := open[p.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, p))
		}
	}
	if len(parts) == 0 {
		return "✓ nothing to fix"
	}
	if n := open[findings.Silent.String()]; n > 0 {
		parts = append(parts, fmt.Sprintf("(+%d without a fix yet)", n))
	}
	return strings.Join(parts, ", ")
}

func subject(f *findings.Finding) string {
	switch f.Kind {
	case findings.KindReboot:
		return "restart needed"
	case findings.KindEndOfLife:
		return f.Installed + " end of support"
	}
	return f.CVE + " (" + f.Source + ")"
}

// line formats one finding on one line.
func line(f *findings.Finding) string {
	icon, label := icons[f.Priority], f.Priority.String()
	if f.Kind == findings.KindEarlyWarning {
		icon, label = "🟡", "early"
	}
	s := fmt.Sprintf("%s %-6s %-14s %s", icon, label, f.Server, subject(f))
	switch {
	case f.Kind == findings.KindEarlyWarning:
		s += "  unconfirmed: your distro hasn't assessed it yet"
		if f.Score > 0 {
			s += fmt.Sprintf(" · CVSS %.1f", f.Score)
		}
	case f.Kind != findings.KindVulnerability:
		s += " — " + clean(f.Summary)
	case f.HasFix():
		s += fmt.Sprintf("  %s → %s", f.Installed, f.Fixed)
	default:
		s += "  no fix yet"
	}
	var tags []string
	if f.KEV {
		tags = append(tags, "actively exploited")
	}
	if f.ProOnly {
		tags = append(tags, "fix needs Ubuntu Pro")
	}
	if f.State == findings.StateSnoozed {
		tags = append(tags, "snoozed until "+f.SnoozedUntil.Format("2006-01-02"))
	}
	if len(tags) > 0 {
		s += "  (" + strings.Join(tags, ", ") + ")"
	}
	return s
}

func sortFindings(fs []*findings.Finding) {
	slices.SortFunc(fs, func(x, y *findings.Finding) int {
		return cmp.Or(cmp.Compare(y.Priority, x.Priority), cmp.Compare(x.Server, y.Server), cmp.Compare(subject(x), subject(y)))
	})
}

func (a *app) findingsCmd() *cobra.Command {
	var server string
	var all bool
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List what's open on your servers, most urgent first",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			st, err := findings.Load(paths)
			if err != nil {
				return err
			}
			var shown []*findings.Finding
			hidden := 0
			for _, f := range st.Findings {
				if !f.Open() || (server != "" && f.Server != server) {
					continue
				}
				if !all && (f.Priority == findings.Silent || f.State == findings.StateAccepted) {
					hidden++
					continue
				}
				shown = append(shown, f)
			}
			sortFindings(shown)
			return a.emit(shown, func(w io.Writer) {
				if len(shown) == 0 {
					_, _ = fmt.Fprintln(w, "✓ Nothing to fix.")
				}
				for _, f := range shown {
					_, _ = fmt.Fprintln(w, line(f))
				}
				if hidden > 0 {
					_, _ = fmt.Fprintf(w, "\n%d more without a fix yet or accepted (show them with --all)\n", hidden)
				}
			})
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "only this server")
	cmd.Flags().BoolVar(&all, "all", false, "include findings without a fix and accepted ones")
	return cmd
}

func (a *app) showCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <CVE-…>",
		Short: "Show a vulnerability: what it is, which servers have it, and the fix",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			st, err := findings.Load(paths)
			if err != nil {
				return err
			}
			cve := strings.ToUpper(args[0])
			matches := slices.DeleteFunc(slices.Clone(st.Findings), func(f *findings.Finding) bool { return f.CVE != cve })
			if len(matches) == 0 {
				return apperr.New(apperr.FindingsNotFound, cve+" doesn't affect any of your servers (as of the last check)")
			}
			sortFindings(matches)
			return a.emit(matches, func(w io.Writer) {
				f := matches[0]
				_, _ = fmt.Fprintf(w, "%s %s\n", cve, clean(f.Summary))
				if f.Score > 0 {
					_, _ = fmt.Fprintf(w, "Severity: CVSS %.1f", f.Score)
				} else {
					_, _ = fmt.Fprintf(w, "Severity: %s (distro rating)", cmp.Or(f.DistroPriority, "unknown"))
				}
				if f.EPSS > 0 {
					_, _ = fmt.Fprintf(w, " · EPSS %.0f%%", f.EPSS*100)
				}
				if f.KEV {
					_, _ = fmt.Fprint(w, " · actively exploited (CISA KEV)")
				}
				_, _ = fmt.Fprintf(w, "\n\nServers:\n")
				early := false
				for _, m := range matches {
					state, fixed := string(m.State), cmp.Or(m.Fixed, "no fix yet")
					if !m.Open() {
						state = cmp.Or(m.Resolution, "fixed") + " " + m.ResolvedAt.Local().Format("2006-01-02")
					}
					if m.Kind == findings.KindEarlyWarning {
						early, fixed, state = true, "not assessed by your distro yet", "early warning, "+state
					}
					_, _ = fmt.Fprintf(w, "  %s  %s %s → %s  [%s]\n", m.Server, m.Source, m.Installed, fixed, state)
				}
				if early {
					_, _ = fmt.Fprintln(w, "\nEarly warnings come from the CVE List before your distro has assessed the CVE.\n"+
						"They're matched by product name, so they may not apply. The distro's verdict replaces them.")
				}
				_, _ = fmt.Fprintf(w, "\nMore: https://www.cve.org/CVERecord?id=%s", cve)
				if slices.ContainsFunc(matches, func(m *findings.Finding) bool { return m.Source != "macos" && m.Source != "safari" }) {
					_, _ = fmt.Fprintf(w, " · https://ubuntu.com/security/%s · https://security-tracker.debian.org/tracker/%s", cve, cve)
				} else {
					_, _ = fmt.Fprint(w, " · https://support.apple.com/en-us/100100")
				}
				_, _ = fmt.Fprintln(w)
			})
		},
	}
}

func (a *app) ackCmd() *cobra.Command {
	var server, until, reason string
	cmd := &cobra.Command{
		Use:   "ack <CVE-…>",
		Short: "Acknowledge a vulnerability: snooze it until a date, or accept the risk",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			var snoozeUntil time.Time
			if until != "" {
				if snoozeUntil, err = time.ParseInLocation("2006-01-02", until, time.Local); err != nil {
					return apperr.Wrap(apperr.CLIUsage, err, "--until must be a date like 2026-12-31")
				}
			}
			cve, now, changed := strings.ToUpper(args[0]), time.Now(), 0
			err = findings.Update(paths, func(st *findings.Store) error {
				for _, f := range st.Findings {
					if f.CVE != cve || !f.Open() || (server != "" && f.Server != server) {
						continue
					}
					to := findings.StateAccepted
					if !snoozeUntil.IsZero() {
						to = findings.StateSnoozed
					}
					if f.State == to {
						continue
					}
					if err := f.Transition(to, now); err != nil {
						return err
					}
					f.SnoozedUntil, f.AckReason = snoozeUntil, reason
					changed++
				}
				return nil
			})
			if err != nil {
				return err
			}
			if changed == 0 {
				return apperr.New(apperr.FindingsNotFound, "no open finding for "+cve+" to acknowledge")
			}
			return a.emit(map[string]int{"acknowledged": changed}, func(w io.Writer) {
				if snoozeUntil.IsZero() {
					_, _ = fmt.Fprintf(w, "✓ %s accepted on %d server(s). It reopens if it gets more urgent.\n", cve, changed)
				} else {
					_, _ = fmt.Fprintf(w, "✓ %s snoozed until %s on %d server(s).\n", cve, until, changed)
				}
			})
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "only on this server")
	cmd.Flags().StringVar(&until, "until", "", "snooze until this date (YYYY-MM-DD); without it the risk is accepted")
	cmd.Flags().StringVar(&reason, "reason", "", "why, for your future self")
	return cmd
}

// describe names what a check covers: "this Mac and web-1", or "4 servers".
func describe(servers []config.Server) string {
	names := make([]string, 0, len(servers))
	for _, s := range servers {
		if s.Local {
			names = append(names, lower(config.LocalLabel()))
		} else {
			names = append(names, s.Name)
		}
	}
	switch {
	case len(names) > 3:
		return fmt.Sprintf("%d servers", len(names))
	case len(names) > 1:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	case len(names) == 1:
		return names[0]
	}
	return "nothing"
}
