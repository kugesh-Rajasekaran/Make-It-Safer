package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// parseCVE checks a CVE ID given on the command line. An empty or odd
// argument must not match findings that have no CVE (restarts, end of
// support, Homebrew updates).
func parseCVE(arg string) (string, error) {
	cve := strings.ToUpper(strings.TrimSpace(arg))
	if !config.IsCVE(cve) {
		return "", apperr.New(apperr.CLIUsage, fmt.Sprintf("%q is not a CVE ID like CVE-2024-6387", arg))
	}
	return cve, nil
}

func (a *app) ackCmd() *cobra.Command {
	var server, until, reason string
	cmd := &cobra.Command{
		Use:   "ack <CVE-…>",
		Short: "Acknowledge a vulnerability: snooze it until a date, or accept the risk",
		Long: `Snoozes a vulnerability until a date (--until), or accepts the risk without
one. Running it again with another date moves the snooze; an accepted risk can
be snoozed instead.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cve, err := parseCVE(args[0])
			if err != nil {
				return err
			}
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			if server != "" {
				if _, err := pick(cfg, []string{server}, true); err != nil {
					return err
				}
			}
			now := time.Now()
			var snoozeUntil time.Time
			if until != "" {
				if snoozeUntil, err = time.ParseInLocation("2006-01-02", until, time.Local); err != nil {
					return apperr.Wrap(apperr.CLIUsage, err, "--until must be a date like 2026-12-31")
				}
				if !snoozeUntil.After(now) { // the day starts at midnight: today is already over
					return apperr.New(apperr.CLIUsage, "--until must be a date after today, like 2026-12-31")
				}
			}
			changed, already := 0, 0
			err = findings.Update(paths, func(st *findings.Store) error {
				for _, f := range st.Findings {
					if f.CVE != cve || !f.Open() || (server != "" && f.Server != server) {
						continue
					}
					to := findings.StateAccepted
					if !snoozeUntil.IsZero() {
						to = findings.StateSnoozed
					}
					if f.State == to && f.SnoozedUntil.Equal(snoozeUntil) {
						already++
						continue
					}
					if f.State != to {
						if err := f.Transition(to, now); err != nil {
							return err
						}
						f.AckReason = reason
					} else if reason != "" { // a snooze moved to a new date keeps its reason
						f.AckReason = reason
					}
					f.SnoozedUntil = snoozeUntil
					changed++
				}
				return nil
			})
			if err != nil {
				return err
			}
			if changed == 0 && already == 0 {
				return apperr.New(apperr.FindingsNotFound, "no open finding for "+cve+" to acknowledge")
			}
			return a.emit(map[string]int{"acknowledged": changed, "already": already}, func(w io.Writer) {
				switch {
				case changed == 0 && snoozeUntil.IsZero():
					_, _ = fmt.Fprintf(w, "%s is already accepted on %d server(s); nothing changed.\n", cve, already)
				case changed == 0:
					_, _ = fmt.Fprintf(w, "%s is already snoozed until %s on %d server(s); nothing changed.\n", cve, until, already)
				case snoozeUntil.IsZero():
					_, _ = fmt.Fprintf(w, "✓ %s accepted on %d server(s). It reopens if it gets more urgent.\n", cve, changed)
				default:
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
