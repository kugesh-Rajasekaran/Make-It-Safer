// Package doctor checks that Make-It-Safer can do its job on this computer:
// private files, a running and unlocked background service, notifications,
// the terminal, the data sources, and recent checks of every server.
//
// Each check is a function of plain inputs, so each can be tested alone.
// The CLI gathers the inputs (mis doctor).
package doctor

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/apple"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/eol"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/epss"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/kev"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/osv"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/termlaunch"
)

// Level says how serious a result is.
type Level string

// Levels.
const (
	OK   Level = "ok"
	Warn Level = "warn"
	Fail Level = "fail"
)

// Result is the outcome of one check.
type Result struct {
	Name   string `json:"name"`
	Level  Level  `json:"level"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"` // what to do about it
}

// Files checks that the Make-It-Safer folder and its files are private.
func Files(paths config.Paths) Result {
	if err := paths.CheckPermissions(); err != nil {
		return Result{Name: "Files", Level: Fail, Detail: apperr.MessageOf(err), Fix: "chmod 700 " + paths.Home + ", and chmod 600 each file in it"}
	}
	return Result{Name: "Files", Level: OK, Detail: paths.Home + " is private"}
}

// syncedFolders are parts of paths that cloud services copy.
var syncedFolders = []struct{ part, service string }{
	{"/Library/Mobile Documents/", "iCloud Drive"},
	{"/Library/CloudStorage/", "a cloud storage app"},
	{"/Dropbox/", "Dropbox"}, {"/OneDrive/", "OneDrive"}, {"/Google Drive/", "Google Drive"},
	{"/Nextcloud/", "Nextcloud"}, {"/ownCloud/", "ownCloud"}, {"/MEGA/", "MEGA"}, {"/Sync/", "Syncthing"},
}

// NotSynced checks that the folder (with your encrypted key) isn't copied
// to a cloud service. userHome is your home directory.
func NotSynced(home, userHome string) Result {
	r := Result{Name: "Not synced"}
	p := filepath.Clean(home) + "/"
	for _, f := range syncedFolders {
		if strings.Contains(p, f.part) {
			r.Level, r.Detail = Fail, home+" is in a folder synced by "+f.service
			r.Fix = "move it to a local folder (set MIS_HOME), or stop syncing that folder"
			return r
		}
	}
	for _, dir := range []string{"Desktop", "Documents"} {
		if strings.HasPrefix(p, filepath.Join(userHome, dir)+"/") {
			r.Level, r.Detail = Warn, home+" is in ~/"+dir+", which iCloud syncs when \"Desktop & Documents Folders\" is on"
			r.Fix = "move it to a local folder (set MIS_HOME), or make sure that sync is off"
			return r
		}
	}
	r.Level, r.Detail = OK, "not in a synced folder"
	return r
}

// Service checks that the background service is installed, running and
// unlocked. status is nil when it doesn't answer.
func Service(info *daemon.ServiceInfo, status *daemon.Status) Result {
	r := Result{Name: "Background service"}
	switch {
	case status == nil && (info == nil || !info.Installed):
		r.Level, r.Detail, r.Fix = Fail, "not installed", "mis service install"
	case status == nil:
		r.Level, r.Detail, r.Fix = Fail, "installed but not running", "mis service install (it restarts it), and see: mis service logs"
	case status.Locked:
		r.Level, r.Detail, r.Fix = Warn, "running, but locked: it can't refresh package lists", "mis unlock"
	default:
		r.Level, r.Detail = OK, "running and unlocked (version "+status.Version+")"
	}
	return r
}

// AutoUnlock reports whether the background service unlocks itself when you
// log in (macOS Keychain, ADR 0002). enabled means key.auto exists.
func AutoUnlock(enabled bool, status *daemon.Status) Result {
	r := Result{Name: "Auto-unlock"}
	switch {
	case !enabled:
		r.Level, r.Detail = OK, "off: after each restart, run mis unlock (or turn it on: mis auto-unlock on)"
	case status != nil && status.Locked:
		r.Level, r.Detail = Warn, "on, but the background service is locked (after mis lock, or if your Keychain refused it)"
		r.Fix = "mis unlock; if this happens after every restart: mis auto-unlock on, and click Always Allow when macOS asks"
	default:
		r.Level, r.Detail = OK, "on: it unlocks itself when you log in"
	}
	return r
}

// Notifications checks that notifications show and stay on screen.
func Notifications(status *daemon.Status) Result {
	r := Result{Name: "Notifications"}
	switch {
	case status == nil:
		r.Level, r.Detail = Warn, "unknown while the background service isn't running"
	case !status.Ready:
		r.Level, r.Detail, r.Fix = Fail, status.Notifier, "mis notify setup"
	default:
		r.Level, r.Detail = OK, status.Notifier
	}
	return r
}

// Terminal checks that the configured terminal app can be opened.
func Terminal(l termlaunch.Launcher) Result {
	if err := l.Available(); err != nil {
		return Result{Name: "Terminal", Level: Fail, Detail: apperr.MessageOf(err), Fix: "install it, or set terminal.app in config.yaml"}
	}
	return Result{Name: "Terminal", Level: OK, Detail: "fix sessions open in " + l.Terminal.App}
}

// Desktop checks (on Linux) that the background service sees your desktop
// session, which it needs to open terminals. env is its environment, from
// systemctl --user show-environment.
func Desktop(env []string) Result {
	if slices.ContainsFunc(env, func(kv string) bool {
		return strings.HasPrefix(kv, "DISPLAY=") || strings.HasPrefix(kv, "WAYLAND_DISPLAY=")
	}) {
		return Result{Name: "Desktop session", Level: OK, Detail: "the background service can open windows"}
	}
	return Result{Name: "Desktop session", Level: Warn,
		Detail: "the background service doesn't see your desktop (no DISPLAY or WAYLAND_DISPLAY), so it can't open terminals",
		Fix:    "systemctl --user import-environment DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS, then: mis service install"}
}

// Dialogs checks (on Linux) that zenity is installed: it shows the dialog a
// click on a notification opens.
func Dialogs(zenity bool) Result {
	if zenity {
		return Result{Name: "Dialogs", Level: OK, Detail: "a click on a notification opens its details (zenity)"}
	}
	return Result{Name: "Dialogs", Level: Warn, Detail: "zenity isn't installed, so a click on a notification opens the terminal instead",
		Fix: "sudo apt install zenity"}
}

// Source is a data source and a small address to try it with.
type Source struct {
	Name string
	URL  string
	Head bool // a HEAD request is enough
}

// Sources are the data sources Make-It-Safer uses (docs/design.md §4.9).
var Sources = []Source{
	{"OSV.dev", osv.DefaultAPI + "/v1/vulns/UBUNTU-CVE-2024-6387", false},
	{"OSV.dev data files", "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/modified_id.csv", true},
	{"CVE List", cvelist.DefaultBase + "/cves/delta.json", true},
	{"CISA KEV", kev.DefaultURL, true},
	{"EPSS", epss.DefaultAPI + "?cve=CVE-2024-6387", false},
	{"endoflife.date", eol.DefaultAPI + "/ubuntu.json", true},
}

// AppleSource is Apple's security notes, which only a Mac that checks itself uses.
var AppleSource = Source{"Apple security notes", apple.IndexURL, false}

// SourcesFor lists the data sources to try on an OS: Apple's security notes
// count only on a Mac that checks itself (this_computer is on).
func SourcesFor(goos string, thisComputer bool) []Source {
	if goos == "darwin" && thisComputer {
		return append(slices.Clone(Sources), AppleSource)
	}
	return Sources
}

// Reachable checks that every data source answers.
func Reachable(ctx context.Context, fc *feeds.Client, sources []Source) Result {
	var failed, hosts []string
	for _, s := range sources {
		var err error
		if s.Head {
			_, err = fc.Head(ctx, s.URL)
		} else {
			_, err = fc.Get(ctx, s.URL, "")
		}
		if err != nil {
			failed = append(failed, s.Name+": "+apperr.MessageOf(err))
		}
		if u, err := url.Parse(s.URL); err == nil && !slices.Contains(hosts, u.Host) {
			hosts = append(hosts, u.Host)
		}
	}
	if len(failed) > 0 {
		return Result{Name: "Data sources", Level: Fail, Detail: strings.Join(failed, "; "),
			Fix: "check your internet connection or firewall; Make-It-Safer only connects to " + strings.Join(hosts, ", ")}
	}
	return Result{Name: "Data sources", Level: OK, Detail: fmt.Sprintf("all %d answer", len(sources))}
}

// Servers checks that every server's package list was read recently: not
// longer ago than limit (config.Schedule.ListStaleAfter). refreshed maps
// server names to when their list was read. A server can be matched often
// (against the list it has) and still have an old list. This computer is
// read again at every match, so it is left out.
func Servers(servers []config.Server, refreshed map[string]time.Time, limit time.Duration, now time.Time) Result {
	r := Result{Name: "Servers"}
	if len(servers) == 0 {
		r.Level, r.Detail, r.Fix = Warn, "no servers yet", "mis server add"
		return r
	}
	var stale []string
	remote := 0
	for _, s := range servers {
		if s.Local {
			continue
		}
		remote++
		t, ok := refreshed[s.Name]
		switch {
		case !ok:
			stale = append(stale, s.Name+": no package list yet")
		case now.Sub(t) > limit:
			stale = append(stale, fmt.Sprintf("%s: package list is %s old", s.Name, now.Sub(t).Round(time.Hour)))
		}
	}
	if len(stale) > 0 {
		r.Level, r.Detail, r.Fix = Warn, strings.Join(stale, "; "), "unlock the background service (mis unlock), or run: mis check"
		return r
	}
	if remote == 0 { // only this computer, which is read directly on every check
		r.Level, r.Detail = OK, "no servers; only this computer is checked"
		return r
	}
	r.Level, r.Detail = OK, fmt.Sprintf("all %d package lists read recently", remote)
	return r
}

// Data checks that the vulnerability data is current: the last successful
// match and the early-warning job.
func Data(status *daemon.Status, now time.Time) Result {
	r := Result{Name: "Vulnerability data"}
	if status == nil {
		r.Level, r.Detail = Warn, "unknown while the background service isn't running"
		return r
	}
	match, early := status.Jobs["match"], status.Jobs["early"]
	switch {
	case match == nil || match.LastOK.IsZero():
		r.Level, r.Detail = Warn, "no successful check yet"
	case now.Sub(match.LastOK) > 24*time.Hour:
		r.Level, r.Detail = Fail, fmt.Sprintf("the last successful check was %s ago", now.Sub(match.LastOK).Round(time.Hour))
		if match.LastError != "" {
			r.Detail += " (" + match.LastError + ")"
		}
		r.Fix = "see: mis service logs"
	case early != nil && early.LastError != "" && now.Sub(early.LastOK) > time.Hour:
		r.Level, r.Detail, r.Fix = Warn, "early warnings are failing: "+early.LastError, "see: mis service logs"
	default:
		r.Level, r.Detail = OK, fmt.Sprintf("last check %s ago", now.Sub(match.LastOK).Round(time.Minute))
	}
	return r
}
