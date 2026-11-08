package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/doctor"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/keyring"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/termlaunch"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

func (a *app) doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check that Make-It-Safer can do its job, and say how to fix what can't",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			var status *daemon.Status
			var s daemon.Status
			if err := daemon.Call(paths, daemon.Request{Op: daemon.OpStatus}, &s, 10*time.Second); err == nil {
				status = &s
			}
			st, err := findings.Load(paths)
			if err != nil {
				return err
			}
			userHome, _ := os.UserHomeDir()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			results := []doctor.Result{
				doctor.Files(paths),
				doctor.NotSynced(paths.Home, userHome),
				doctor.Service(daemon.ServiceState(paths), status),
			}
			if keyring.Available() {
				results = append(results, doctor.AutoUnlock(vault.AutoUnlockEnabled(paths.AutoKey), status))
			}
			results = append(results,
				doctor.Notifications(status),
				doctor.Terminal(termlaunch.Launcher{Terminal: cfg.Terminal}),
			)
			if runtime.GOOS == "linux" {
				out, _ := exec.CommandContext(ctx, "systemctl", "--user", "show-environment").Output()
				results = append(results, doctor.Desktop(strings.Split(string(out), "\n")))
			}
			var reachable doctor.Result
			_ = a.withSpinner("Checking the data sources", func() error {
				reachable = doctor.Reachable(ctx, feeds.New(version), doctor.Sources)
				return nil
			})
			results = append(results, reachable,
				doctor.Servers(cfg.Checked(), st.Checked, time.Now()),
				doctor.Data(status, time.Now()),
			)

			human := func(w io.Writer) { printDoctor(w, results) }
			if slices.ContainsFunc(results, func(r doctor.Result) bool { return r.Level == doctor.Fail }) {
				return a.emitFailed(results, human, apperr.New(apperr.DoctorFailed, "some checks failed (marked ✗ above)"))
			}
			return a.emit(results, human)
		},
	}
}

func printDoctor(w io.Writer, results []doctor.Result) {
	marks := map[doctor.Level]string{doctor.OK: "✓", doctor.Warn: "⚠", doctor.Fail: "✗"}
	for _, r := range results {
		_, _ = fmt.Fprintf(w, "%s %s: %s\n", marks[r.Level], r.Name, clean(r.Detail))
		if r.Fix != "" && r.Level != doctor.OK {
			_, _ = fmt.Fprintf(w, "    → %s\n", r.Fix)
		}
	}
}
