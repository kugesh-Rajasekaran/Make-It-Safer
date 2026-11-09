package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

func (a *app) daemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "daemon",
		Short:  "Run the background service (started by launchd or systemd)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, err := config.DefaultPaths()
			if err != nil {
				return err
			}
			// Before the notifier: it takes over the helper's socket, which a
			// second daemon must not do to the one that is running.
			if daemon.Running(paths) {
				return apperr.New(apperr.DaemonAlreadyRunning, "the background service is already running")
			}
			log := slog.New(slog.NewTextHandler(a.stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			n := a.desktop(ctx, paths, log)
			defer func() { _ = n.Close() }()
			return daemon.New(paths, version, log, n).Run(ctx)
		},
	}
}

func (a *app) unlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the background service with your passphrase",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			if !daemon.Running(paths) {
				return apperr.New(apperr.DaemonNotRunning, "the background service is not running; start it with: mis service install")
			}
			_ = vault.Harden()
			pass, err := vault.ReadPassphrase(a.stdin, a.stderr, "Passphrase: ")
			if err != nil {
				return err
			}
			a.say("Unlocking…\n")
			if err := daemon.Call(paths, daemon.Request{Op: daemon.OpUnlock, Passphrase: pass}, nil, 2*time.Minute); err != nil {
				return err
			}
			return a.emit(map[string]bool{"locked": false}, func(w io.Writer) {
				_, _ = fmt.Fprintln(w, "✓ Unlocked. Make-It-Safer is checking your servers now.")
			})
		},
	}
}

func (a *app) lockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Wipe the key from the background service's memory",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			if err := daemon.Call(paths, daemon.Request{Op: daemon.OpLock}, nil, 10*time.Second); err != nil {
				return err
			}
			return a.emit(map[string]bool{"locked": true}, func(w io.Writer) {
				_, _ = fmt.Fprintln(w, "✓ Locked. Checks of saved package lists continue; run mis unlock to refresh them.")
			})
		},
	}
}

type statusView struct {
	Service *daemon.Status `json:"service"` // nil when not running
	Servers []serverStatus `json:"servers"`
}

type serverStatus struct {
	Name    string         `json:"name"`
	Checked *time.Time     `json:"checked,omitempty"`
	Open    map[string]int `json:"open"`
}

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the background service runs and what's open per server",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			view := statusView{Servers: []serverStatus{}}
			var s daemon.Status
			if err := daemon.Call(paths, daemon.Request{Op: daemon.OpStatus}, &s, 10*time.Second); err == nil {
				view.Service = &s
			} else if !apperr.Is(err, apperr.DaemonNotRunning) {
				return err
			}
			st, err := findings.Load(paths)
			if err != nil {
				return err
			}
			for _, srv := range cfg.Checked() {
				row := serverStatus{Name: srv.Name, Open: map[string]int{}}
				if t, ok := st.Checked[srv.Name]; ok {
					row.Checked = &t
				}
				for _, f := range st.Findings {
					if f.Server == srv.Name && f.Open() && f.State != findings.StateAccepted {
						row.Open[f.Priority.String()]++
					}
				}
				view.Servers = append(view.Servers, row)
			}
			return a.emit(view, func(w io.Writer) { printStatus(w, view) })
		},
	}
}

func printStatus(w io.Writer, v statusView) {
	switch {
	case v.Service == nil:
		_, _ = fmt.Fprintln(w, "Background service: not running (start it with: mis service install)")
	case v.Service.Locked:
		_, _ = fmt.Fprintln(w, "Background service: running · 🔒 LOCKED (run: mis unlock)")
	case v.Service.AutoUnlock:
		_, _ = fmt.Fprintln(w, "Background service: running · unlocked · unlocks itself at login")
	default:
		_, _ = fmt.Fprintln(w, "Background service: running · unlocked")
	}
	if v.Service != nil {
		_, _ = fmt.Fprintf(w, "Notifications: %s\n", v.Service.Notifier)
		if j := v.Service.Jobs["match"]; j != nil && !j.LastOK.IsZero() {
			_, _ = fmt.Fprintf(w, "Last check: %s ago", time.Since(j.LastOK).Round(time.Minute))
			if j.LastError != "" {
				_, _ = fmt.Fprintf(w, " · last attempt failed: %s", clean(j.LastError))
			}
			_, _ = fmt.Fprintln(w)
		}
	}
	_, _ = fmt.Fprintln(w)
	if len(v.Servers) == 0 {
		_, _ = fmt.Fprintln(w, "No servers yet. Add one with: mis server add")
	}
	for _, s := range v.Servers {
		when := "never checked"
		if s.Checked != nil {
			when = "checked " + s.Checked.Local().Format("2006-01-02 15:04")
		}
		_, _ = fmt.Fprintf(w, "%-20s %s  (%s)\n", s.Name, counts(s.Open), when)
	}
}

func (a *app) serviceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Install or control the background service", Args: cobra.NoArgs}
	cmd.AddCommand(&cobra.Command{
		Use: "install", Short: "Install the background service and start it at every login", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			info, err := daemon.InstallService(paths)
			if err != nil {
				return err
			}
			return a.emit(info, func(w io.Writer) {
				_, _ = fmt.Fprintf(w, "✓ Background service installed (%s).\n  It starts at every login, locked. Unlock it now with: mis unlock\n", info.File)
			})
		},
	}, &cobra.Command{
		Use: "uninstall", Short: "Stop and remove the background service", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			// Only the paths are needed, so this works when config.yaml is
			// missing or broken: the service can still be removed.
			paths, err := config.DefaultPaths()
			if err != nil {
				return err
			}
			if err := a.uninstallService(paths); err != nil {
				return err
			}
			return a.emit(map[string]bool{"installed": false}, func(w io.Writer) {
				_, _ = fmt.Fprintln(w, "✓ Background service removed.")
			})
		},
	}, &cobra.Command{
		Use: "status", Short: "Show whether the background service is installed and active", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			info := daemon.ServiceState(paths)
			return a.emit(info, func(w io.Writer) {
				_, _ = fmt.Fprintf(w, "Installed: %v (%s)\nActive: %v\n", info.Installed, info.File, info.Active)
			})
		},
	}, &cobra.Command{
		Use: "logs", Short: "Show the background service's recent log", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			logs, err := daemon.ServiceLogs(paths, 100)
			if err != nil {
				return err
			}
			return a.emit(map[string]string{"logs": logs}, func(w io.Writer) { _, _ = io.WriteString(w, clean(strings.TrimRight(logs, "\n"))+"\n") })
		},
	})
	return cmd
}
