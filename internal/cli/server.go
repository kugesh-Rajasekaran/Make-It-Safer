package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/setup"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

func (a *app) serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Add, list, verify and remove servers",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(a.serverAddCmd(), a.serverListCmd(), a.serverVerifyCmd(), a.serverRemoveCmd(), a.serverScriptCmd())
	return cmd
}

type addOptions struct {
	host, admin, fingerprint string
	port                     int
	yes                      bool
}

func (a *app) serverAddCmd() *cobra.Command {
	var o addOptions
	cmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Set up a server: create its read-only mis user and verify it",
		Long: `Sets up a server through your own ssh login (Make-It-Safer never sees it):
it creates a read-only "mis" user that can only run the collector, then
proves the restrictions from the outside and reads the package list.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			return a.runServerAdd(name, o)
		},
	}
	cmd.Flags().StringVar(&o.host, "host", "", "IP address or hostname")
	cmd.Flags().IntVar(&o.port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&o.admin, "admin", "", "your own login, as typed after ssh (user@host or an ~/.ssh/config alias)")
	cmd.Flags().StringVar(&o.fingerprint, "fingerprint", "", "expected SSH host key fingerprint (SHA256:…), to skip the question")
	cmd.Flags().BoolVarP(&o.yes, "yes", "y", false, "don't ask before running the setup script")
	return cmd
}

func (a *app) runServerAdd(name string, o addOptions) error {
	reports, err := a.addServer(name, o)
	if err != nil {
		return err
	}
	return a.printReports(reports)
}

// addServer sets up one server and verifies it. The server is saved once
// its setup script ran, even if a later check fails.
func (a *app) addServer(name string, o addOptions) ([]*setup.Report, error) {
	ctx := context.Background()
	paths, cfg, err := a.setup()
	if err != nil {
		return nil, err
	}
	pub, err := vault.PublicKeyFromFile(paths.KeyFile)
	if err != nil {
		return nil, err
	}

	s := config.Server{Name: name, Host: o.host, Port: o.port, AdminSSH: o.admin}
	if s.Name == "" {
		if s.Name, err = a.ask("Name for this server (e.g. ovh-web-1)", ""); err != nil {
			return nil, err
		}
	}
	if _, exists := cfg.Server(s.Name); exists {
		return nil, apperr.New(apperr.ServerExists, s.Name+" is already set up; check it with: mis server verify "+s.Name)
	}
	if s.Host == "" {
		if s.Host, err = a.ask("IP address or hostname", ""); err != nil {
			return nil, err
		}
	}
	if s.AdminSSH == "" {
		if s.AdminSSH, err = a.ask("Your own login, as you'd type after `ssh`", "root@"+s.Host); err != nil {
			return nil, err
		}
	}
	if err := s.Validate(); err != nil {
		return nil, apperr.Wrap(apperr.ConfigInvalid, err, "invalid server")
	}

	// 1. Pin the host key, after you've confirmed it.
	t := sshx.TargetOf(s)
	key, err := sshx.FetchHostKey(ctx, t)
	if err != nil {
		return nil, err
	}
	fp := sshx.Fingerprint(key)
	switch {
	case o.fingerprint != "":
		if o.fingerprint != fp {
			return nil, apperr.New(apperr.ServerHostKeyRejected, fmt.Sprintf("host key is %s, not the expected %s; nothing was changed", fp, o.fingerprint))
		}
	case sshx.UserKnownHost(t, key) == "match":
		a.say("✓ Host key %s matches your ~/.ssh/known_hosts\n", fp)
	case sshx.UserKnownHost(t, key) == "mismatch":
		return nil, apperr.New(apperr.ServerHostKeyMismatch, fmt.Sprintf(
			"%s presents host key %s, which differs from your ~/.ssh/known_hosts; someone may be intercepting the connection. Nothing was changed", s.Host, fp))
	default:
		a.say("Host key fingerprint of %s:\n    %s\nCompare it with your provider's console, or run on the server:\n    ssh-keygen -lf /etc/ssh/ssh_host_%s_key.pub\n",
			s.Host, fp, hostKeyFile(key.Type()))
		ok, err := a.confirm("Does it match?", false)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, apperr.New(apperr.ServerHostKeyRejected, "host key not confirmed; nothing was changed")
		}
	}

	// 2. Run the setup script through your own ssh login.
	script, err := setup.Script(pub)
	if err != nil {
		return nil, err
	}
	a.say("\nThe setup script, run through `ssh %s`:\n", s.AdminSSH)
	for _, line := range setup.Summary {
		a.say("  • %s\n", line)
	}
	if !o.yes {
		if show, err := a.confirm("Show the full script first?", false); err != nil {
			return nil, err
		} else if show {
			a.say("\n%s\n", script)
		}
		if run, err := a.confirm("Run it now?", true); err != nil {
			return nil, err
		} else if !run {
			return nil, apperr.New(apperr.CLIInputAborted, "cancelled; nothing was changed. You can also run it yourself: mis server setup-script")
		}
	}
	if err := setup.RunAsAdmin(ctx, s, script, a.stdin, a.stderr, a.stderr); err != nil {
		return nil, err
	}

	// 3. Remember the server, then prove the restrictions from the outside.
	hk := sshx.HostKeys{Path: paths.KnownHosts}
	if err := hk.Pin(t, key); err != nil {
		return nil, err
	}
	cfg.Servers = append(cfg.Servers, s)
	if err := cfg.Save(paths.Config); err != nil {
		return nil, err
	}
	a.say("\n✓ %s is set up. Checking it from the outside…\n", s.Name)
	return a.verifyServers(ctx, paths, []config.Server{s})
}

func (a *app) serverVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify [name...]",
		Short: "Prove that each server only lets Make-It-Safer read package lists",
		RunE: func(_ *cobra.Command, names []string) error {
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			servers, err := pick(cfg, names, false)
			if err != nil {
				return err
			}
			reports, err := a.verifyServers(context.Background(), paths, servers)
			if err != nil {
				return err
			}
			return a.printReports(reports)
		},
	}
}

// verifyServers unlocks the key once and verifies each server, saving the
// package lists it reads on the way.
func (a *app) verifyServers(ctx context.Context, paths config.Paths, servers []config.Server) ([]*setup.Report, error) {
	key := a.unlocked
	if key == nil {
		var err error
		if key, err = a.unlockKey(paths); err != nil {
			return nil, err
		}
		defer key.Destroy()
	}
	hk := sshx.HostKeys{Path: paths.KnownHosts}
	var reports []*setup.Report
	for _, s := range servers {
		r, err := setup.Verify(ctx, sshx.TargetOf(s), hk, key.Signer(), time.Now())
		if err != nil {
			r = &setup.Report{Server: s.Name, Checks: []setup.Check{{Name: "Log in as mis", Detail: apperr.MessageOf(err)}}}
		}
		if r.Inventory != nil {
			if err := inventory.Save(paths, s.Name, r.Inventory); err != nil {
				return nil, err
			}
		}
		reports = append(reports, r)
	}
	return reports, nil
}

func (a *app) printReports(reports []*setup.Report) error {
	human := func(w io.Writer) { writeReports(w, reports) }
	if slices.ContainsFunc(reports, func(r *setup.Report) bool { return !r.OK }) {
		return a.emitFailed(reports, human, apperr.New(apperr.SetupVerifyFailed, "some checks failed (marked ✗ above)"))
	}
	return a.emit(reports, human)
}

func writeReports(w io.Writer, reports []*setup.Report) {
	for _, r := range reports {
		_, _ = fmt.Fprintf(w, "\n%s", r.Server)
		if r.OS != "" {
			_, _ = fmt.Fprintf(w, " · %s · %d packages", r.OS, r.Packages)
		}
		_, _ = fmt.Fprintln(w)
		for _, c := range r.Checks {
			mark := "✓"
			if !c.OK {
				mark = "✗"
			}
			line := "  " + mark + " " + c.Name
			if c.Detail != "" {
				line += " — " + clean(c.Detail)
			}
			_, _ = fmt.Fprintln(w, line)
		}
	}
}

type serverRow struct {
	config.Server
	OS          string     `json:"os,omitempty"`
	Packages    int        `json:"packages,omitempty"`
	CollectedAt *time.Time `json:"collected_at,omitempty"`
}

func (a *app) serverListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your servers",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			rows := []serverRow{}
			for _, s := range cfg.Servers {
				row := serverRow{Server: s}
				if inv, err := inventory.Load(paths, s.Name); err == nil {
					row.OS, row.Packages, row.CollectedAt = inv.OSID+" "+inv.OSVersion, len(inv.Packages), &inv.CollectedAt
				}
				rows = append(rows, row)
			}
			return a.emit(rows, func(w io.Writer) {
				if len(rows) == 0 {
					_, _ = fmt.Fprintln(w, "No servers yet. Add one with: mis server add")
					return
				}
				for _, r := range rows {
					checked := "never checked"
					if r.CollectedAt != nil {
						checked = fmt.Sprintf("%s, %d packages, checked %s", r.OS, r.Packages, r.CollectedAt.Local().Format("2006-01-02 15:04"))
					}
					_, _ = fmt.Fprintf(w, "%-20s %s:%d  admin %s  (%s)\n", r.Name, r.Host, r.Port, r.AdminSSH, checked)
				}
			})
		},
	}
}

func (a *app) serverRemoveCmd() *cobra.Command {
	var forget, yes bool
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a server: delete its mis user, then forget it",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			s, ok := cfg.Server(args[0])
			if !ok {
				return apperr.New(apperr.ServerNotFound, "no server named "+args[0]+"; see: mis server list")
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
			if err := inventory.Remove(paths, s.Name); err != nil {
				return err
			}
			return a.emit(map[string]string{"removed": s.Name}, func(w io.Writer) {
				_, _ = fmt.Fprintf(w, "✓ %s removed.\n", s.Name)
			})
		},
	}
	cmd.Flags().BoolVar(&forget, "forget", false, "only forget the server here; don't connect to it")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation")
	return cmd
}

func (a *app) serverScriptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup-script",
		Short: "Print the setup script, to run it on a server yourself (as root)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			pub, err := vault.PublicKeyFromFile(paths.KeyFile)
			if err != nil {
				return err
			}
			script, err := setup.Script(pub)
			if err != nil {
				return err
			}
			return a.emit(map[string]string{"script": script}, func(w io.Writer) { _, _ = io.WriteString(w, script) })
		},
	}
}

// pick returns the named servers, or all of them when names is empty. With
// withThisComputer, this computer counts too (when this_computer is on).
func pick(cfg *config.Config, names []string, withThisComputer bool) ([]config.Server, error) {
	all := cfg.Servers
	if withThisComputer {
		all = cfg.Checked()
	}
	if len(names) == 0 {
		if len(all) == 0 {
			return nil, apperr.New(apperr.ServerNotFound, "no servers yet; add one with: mis server add")
		}
		return all, nil
	}
	var out []config.Server
	for _, n := range names {
		i := slices.IndexFunc(all, func(s config.Server) bool { return s.Name == n })
		if i < 0 {
			return nil, apperr.New(apperr.ServerNotFound, "no server named "+strconv.Quote(n)+"; see: mis server list")
		}
		out = append(out, all[i])
	}
	return out, nil
}

func hostKeyFile(keyType string) string {
	switch keyType {
	case "ssh-ed25519":
		return "ed25519"
	case "ssh-rsa":
		return "rsa"
	default:
		return "ecdsa"
	}
}
