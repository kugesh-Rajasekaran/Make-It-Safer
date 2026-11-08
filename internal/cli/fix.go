package cli

import (
	"fmt"
	"io"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
)

// openFix asks the background service to open the fix (so it can follow up
// and update the notification), or opens it directly when it isn't running.
func (a *app) openFix(paths config.Paths, cfg *config.Config, server, cve string) error {
	err := daemon.Call(paths, daemon.Request{Op: daemon.OpFix, Server: server, CVE: cve}, nil, 30*time.Second)
	if !apperr.Is(err, apperr.DaemonNotRunning) {
		return err
	}
	key := ""
	if cve != "" {
		key = "cve:" + cve
	}
	return daemon.OpenFix(paths, cfg, server, key)
}

func (a *app) fixCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fix <server> [CVE-…]",
		Short: "Open an SSH session to a server with the fix typed in (same as a notification button)",
		Long: `Opens your terminal with an SSH session using your own admin login. The
update command is typed in for you; press Enter to run it, edit it first,
or press Ctrl-C to skip. Without a CVE, everything fixable on the server
is combined into one command.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			cve := ""
			if len(args) == 2 {
				cve = strings.ToUpper(args[1])
			}
			if err := a.openFix(paths, cfg, args[0], cve); err != nil {
				return err
			}
			return a.emit(map[string]string{"opened": args[0]}, func(w io.Writer) {
				switch {
				case args[0] != config.LocalName():
					_, _ = fmt.Fprintf(w, "✓ Opened an SSH session to %s in your terminal.\n", args[0])
				case runtime.GOOS == "darwin":
					_, _ = fmt.Fprintln(w, "✓ Opened System Settings › Software Update.")
				default:
					_, _ = fmt.Fprintln(w, "✓ Opened the fix for this computer in your terminal.")
				}
			})
		},
	}
}

func (a *app) pickCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pick <CVE-…>",
		Short: "Choose servers affected by a vulnerability and open their fixes, one by one",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			paths, cfg, err := a.setup()
			if err != nil {
				return err
			}
			cve := strings.ToUpper(args[0])
			opened := map[string]bool{}
			for {
				st, err := findings.Load(paths)
				if err != nil {
					return err
				}
				var servers []string
				for _, f := range st.Findings {
					if f.CVE == cve && f.Open() && !slices.Contains(servers, f.Server) {
						servers = append(servers, f.Server)
					}
				}
				slices.Sort(servers)
				if len(servers) == 0 {
					a.say("✓ No server is affected by %s anymore.\n", cve)
					return nil
				}
				a.say("\n%s is open on:\n", cve)
				for i, s := range servers {
					mark := ""
					if opened[s] {
						mark = "  ✓ opened"
					}
					a.say("  %d) %s%s\n", i+1, s, mark)
				}
				answer, err := a.ask("Open which server? (number, q to quit)", "")
				if err != nil || answer == "q" || answer == "" {
					return nil
				}
				n, err := strconv.Atoi(answer)
				if err != nil || n < 1 || n > len(servers) {
					a.say("Please type a number from the list.\n")
					continue
				}
				if err := a.openFix(paths, cfg, servers[n-1], cve); err != nil {
					a.say("✗ %s\n", apperr.MessageOf(err))
					continue
				}
				opened[servers[n-1]] = true
			}
		},
	}
}

func (a *app) notifyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "notify", Short: "Desktop notifications", Args: cobra.NoArgs}
	cmd.AddCommand(&cobra.Command{
		Use:   "setup",
		Short: "Allow notifications (opens System Settings on macOS), then show a test",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			if !daemon.Running(paths) {
				return apperr.New(apperr.DaemonNotRunning, "the background service is not running; start it with: mis service install")
			}
			ready, err := a.setUpNotifications(paths)
			if err != nil {
				return err
			}
			return a.emit(map[string]bool{"ready": ready}, func(io.Writer) {})
		},
	}, &cobra.Command{
		Use: "test", Short: "Show a test notification with buttons", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := a.setup()
			if err != nil {
				return err
			}
			if err := daemon.Call(paths, daemon.Request{Op: daemon.OpNotify}, nil, 10*time.Second); err != nil {
				return err
			}
			return a.emit(map[string]bool{"sent": true}, func(w io.Writer) {
				_, _ = fmt.Fprintln(w, "✓ Test notification sent. Click a button: your terminal should open with mis status.")
			})
		},
	})
	return cmd
}
