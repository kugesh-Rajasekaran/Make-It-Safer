package daemon

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/fixcmd"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/termlaunch"
)

// After a fix button, the server's package list is refreshed this often,
// this many times, so the ✅ appears without waiting for the next check.
const (
	followUpEvery = 10 * time.Minute
	followUps     = 6
)

// OpenFix opens your terminal with an SSH session to server, logged in with
// your own admin login, and the fix typed in. key selects the findings: a
// notification group ("cve:CVE-…", "reboot:<server>"), or "" for everything
// fixable on the server. For this computer there's no SSH: a Mac opens
// System Settings › Software Update, Linux a local terminal with the fix.
func OpenFix(paths config.Paths, cfg *config.Config, server, key string) error {
	s, ok := cfg.Server(server)
	if !ok {
		return apperr.New(apperr.ServerNotFound, "no server named "+server)
	}
	inv, err := inventory.Load(paths, server)
	if err != nil {
		return err
	}
	if s.Local && inv.IsMac() {
		return openSoftwareUpdate()
	}
	st, err := findings.Load(paths)
	if err != nil {
		return err
	}
	var fs []*findings.Finding
	for _, f := range st.Findings {
		if f.Server != server || !f.Open() {
			continue
		}
		if (key == "" && (f.HasFix() || f.Kind == findings.KindReboot)) || (key != "" && groupKey(f) == key) {
			fs = append(fs, f)
		}
	}
	if len(fs) == 0 {
		return apperr.New(apperr.FixNothingToDo, "nothing open to fix on "+server)
	}
	cmd, err := fixcmd.Build(inv, fs)
	if err != nil {
		return err
	}
	script := termlaunch.RemoteScript(termlaunch.Banner(server, fs, cmd), cmd)
	launcher := termlaunch.Launcher{Terminal: cfg.Terminal, TempDir: paths.Temp}
	if s.Local {
		return launcher.Open(termlaunch.LocalFixLauncher(script))
	}
	return launcher.Open(termlaunch.FixLauncher(s, termlaunch.RemoteCommand(script)))
}

// softwareUpdateURL opens System Settings › General › Software Update.
const softwareUpdateURL = "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"

// openSoftwareUpdate is a variable so tests can replace it.
var openSoftwareUpdate = func() error {
	if err := exec.Command("/usr/bin/open", softwareUpdateURL).Run(); err != nil {
		return apperr.Wrap(apperr.TerminalFailed, err, "cannot open System Settings › Software Update")
	}
	return nil
}

// fix opens the fix for one server, marks its button ✓ and checks the
// server again over the next hour.
func (d *Daemon) fix(server, key string) error {
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		return err
	}
	if err := OpenFix(d.paths, cfg, server, key); err != nil {
		return err
	}
	if key != "" {
		d.markClicked(key, server)
		d.reshow(key, cfg)
	}
	d.followUp(server)
	return nil
}

// markClicked remembers that a group's fix button was used for server.
func (d *Daemon) markClicked(key, server string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.clicked[key] == nil {
		d.clicked[key] = map[string]bool{}
	}
	d.clicked[key][server] = true
}

// reshow shows a group's notification again (macOS closes it on a click).
func (d *Daemon) reshow(key string, cfg *config.Config) {
	st, err := findings.Load(d.paths)
	if err != nil {
		return
	}
	group := slices.DeleteFunc(slices.Clone(st.Findings), func(f *findings.Finding) bool { return !f.Open() || groupKey(f) != key })
	if len(group) > 0 {
		n := d.groupNotification(key, group, fixedServers(st, key, d.now()), cfg)
		n.Sound = false
		_ = d.notifier.Show(n)
	}
}

// followUp refreshes a server's package list a few times after a fix.
func (d *Daemon) followUp(server string) {
	go func() {
		for range followUps {
			select {
			case <-d.ctx.Done():
				return
			case <-time.After(d.followUpEvery):
			}
			cfg, err := config.Load(d.paths.Config)
			if err != nil {
				continue
			}
			s, ok := cfg.Server(server)
			if !ok {
				return
			}
			var signer ssh.Signer // this computer is read without the key
			if !s.Local {
				key := d.currentKey()
				if key == nil {
					continue
				}
				signer = key.Signer()
			}
			eng := d.newEngine(cfg)
			if failed := eng.Refresh(d.ctx, signer, []config.Server{s}); len(failed) > 0 {
				d.refreshFailed(failed)
				continue
			}
			res, err := eng.Match(d.ctx, cfg.Checked())
			if err != nil {
				continue
			}
			d.alert(res)
		}
	}()
}

// onClick reacts to a click on a notification or one of its buttons.
func (d *Daemon) onClick(ev notify.Event) {
	id := ev.NotificationID
	var err error
	switch {
	case id == lockNoticeID:
		err = d.openLocal("unlock")
	case id == summaryID || id == staleID:
		err = d.openLocal("findings")
	case id == "test":
		err = d.openLocal("status")
	case strings.HasPrefix(id, "baseline:"):
		err = d.openLocal("findings", "--server", strings.TrimPrefix(id, "baseline:"))
	case strings.HasPrefix(id, "cve:"):
		if server, ok := strings.CutPrefix(ev.Action, "fix:"); ok {
			err = d.fix(server, id)
		} else {
			err = d.openLocal("pick", strings.TrimPrefix(id, "cve:"))
		}
	case strings.HasPrefix(id, "apple:"):
		// One notification per Apple update: the button and the notification
		// itself both open Software Update on this Mac.
		err = d.fix(config.LocalName(), id)
	case strings.HasPrefix(id, string(findings.KindReboot)+":"):
		err = d.fix(strings.TrimPrefix(id, string(findings.KindReboot)+":"), id)
	case strings.HasPrefix(id, hostKeyPrefix):
		err = d.openLocal("server", "verify", strings.TrimPrefix(id, hostKeyPrefix))
	case strings.HasPrefix(id, string(findings.KindEarlyWarning)+":"):
		err = d.openLocal("show", strings.TrimPrefix(id, string(findings.KindEarlyWarning)+":"))
	case strings.HasPrefix(id, string(findings.KindEndOfLife)+":"):
		err = d.openLocal("findings", "--server", strings.TrimPrefix(id, string(findings.KindEndOfLife)+":"))
	}
	if err != nil {
		d.log.Warn("click", "status", "error", "id", id, "action", ev.Action, "error", err)
		_ = d.notifier.Show(notify.Notification{ID: "error", Title: "Make-It-Safer couldn't do that", Body: apperr.MessageOf(err)})
	}
}

// openLocal opens your terminal running a mis command.
func (d *Daemon) openLocal(args ...string) error {
	mis, err := os.Executable()
	if err != nil {
		return apperr.Wrap(apperr.TerminalFailed, err, "cannot find the mis binary")
	}
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		return err
	}
	launcher := termlaunch.Launcher{Terminal: cfg.Terminal, TempDir: d.paths.Temp}
	return launcher.Open(termlaunch.LocalLauncher(mis, args...))
}

// notifyTest shows a sample notification with buttons.
func (d *Daemon) notifyTest() error {
	return d.notifier.Show(notify.Notification{
		ID: "test", Title: "Make-It-Safer test notification",
		Body:    "Click a button: your terminal should open with mis status.",
		Buttons: []notify.Button{{ID: "test:a", Title: "Button A"}, {ID: "test:b", Title: "Button B"}},
		Sound:   true,
	})
}

// fixedServers counts servers where a group was fixed in the last week.
func fixedServers(st *findings.Store, key string, now time.Time) int {
	var servers []string
	for _, f := range st.Findings {
		if !f.Open() && groupKey(f) == key && now.Sub(f.ResolvedAt) < 7*24*time.Hour && !slices.Contains(servers, f.Server) {
			servers = append(servers, f.Server)
		}
	}
	return len(servers)
}
