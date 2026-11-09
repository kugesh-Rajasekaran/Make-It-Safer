package cli

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/setup"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
)

func (a *app) serverRemoveCmd() *cobra.Command {
	var forget, yes bool
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a server: delete its mis user, then forget it",
		Long: `Deletes the mis user, the collector and the sshd settings from the server
through your own ssh login, then forgets the server here: its settings, pinned
host key, package list and findings. With --forget the server itself is not
contacted.

For this computer (` + config.LocalName() + `) there is nothing to delete: it is simply no longer checked.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error { return a.runServerRemove(args[0], forget, yes) },
	}
	cmd.Flags().BoolVar(&forget, "forget", false, "only forget the server here; don't connect to it")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation")
	return cmd
}

func (a *app) runServerRemove(name string, forget, yes bool) error {
	paths, cfg, err := a.setup()
	if err != nil {
		return err
	}
	s, ok := cfg.Server(name)
	if !ok {
		return apperr.New(apperr.ServerNotFound, "no server named "+name+"; see: mis server list")
	}
	if s.Local {
		return a.removeThisComputer(paths, cfg)
	}
	if !forget {
		a.say("This removes the mis user, the collector and the sshd settings from %s, through `ssh %s`.\n", s.Name, s.AdminSSH)
		if !yes {
			if ok, err := a.confirm("Continue?", true); err != nil {
				return err
			} else if !ok {
				return apperr.New(apperr.CLIInputAborted, "cancelled; nothing was changed")
			}
		}
		if err := setup.RunAsAdmin(context.Background(), s, setup.TeardownScript(), a.stdin, a.stderr, a.stderr); err != nil {
			return apperr.Wrap(apperr.SetupFailed, err, "removal failed; to only forget the server here, run: mis server remove "+s.Name+" --forget")
		}
	}
	cfg.Servers = slices.DeleteFunc(cfg.Servers, func(x config.Server) bool { return x.Name == s.Name })
	if err := cfg.Save(paths.Config); err != nil {
		return err
	}
	if err := (sshx.HostKeys{Path: paths.KnownHosts}).Unpin(sshx.TargetOf(s)); err != nil {
		return err
	}
	if err := forgetServerState(paths, s.Name); err != nil {
		return err
	}
	return a.emit(map[string]string{"removed": s.Name}, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "✓ %s removed.\n", s.Name)
	})
}

// removeThisComputer stops checking this computer. There is no remote user to
// delete, so nothing is asked and nothing is contacted.
func (a *app) removeThisComputer(paths config.Paths, cfg *config.Config) error {
	cfg.ThisComputer = false
	if err := cfg.Save(paths.Config); err != nil {
		return err
	}
	if err := forgetServerState(paths, config.LocalName()); err != nil {
		return err
	}
	return a.emit(map[string]string{"removed": config.LocalName()}, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "✓ %s is no longer checked. To check it again: mis config set this_computer yes\n", config.LocalLabel())
	})
}

// forgetServerState drops what is stored about a server outside config.yaml:
// its package list and its findings (so that a server added again under the
// same name starts fresh).
func forgetServerState(paths config.Paths, name string) error {
	if err := inventory.Remove(paths, name); err != nil {
		return err
	}
	return findings.Update(paths, func(st *findings.Store) error {
		st.Forget(name)
		return nil
	})
}
