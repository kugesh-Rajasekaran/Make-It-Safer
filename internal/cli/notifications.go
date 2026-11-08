package cli

import (
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
)

// notificationSettingsURL opens System Settings › Notifications at the
// helper app's page.
const notificationSettingsURL = "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=com.makeitsafer.notifier"

// setUpNotifications makes sure notifications show and stay on screen, then
// shows a test notification. On macOS only you can allow them, so it opens
// System Settings at the right page, waits for you, and checks again until
// they're allowed in the Alerts style, or you skip. It needs the background
// service. It reports whether notifications are ready.
func (a *app) setUpNotifications(paths config.Paths) (bool, error) {
	if runtime.GOOS == "darwin" {
		ready, err := a.allowNotifications(paths)
		if err != nil || !ready {
			return false, err
		}
	}
	if err := daemon.Call(paths, daemon.Request{Op: daemon.OpNotify}, nil, 10*time.Second); err != nil {
		a.say("✗ %s\n  Try again later: mis notify setup\n", apperr.MessageOf(err))
		return false, nil
	}
	seen, err := a.confirm("A test notification with two buttons should be on your screen. Do you see it?", true)
	if err != nil {
		return false, err
	}
	if !seen {
		if runtime.GOOS == "darwin" {
			a.say("Check that Focus (Do Not Disturb) is off, then try: mis notify test\n")
		} else {
			a.say("Your desktop needs a notification service (GNOME, KDE and most have one). See: mis doctor\n")
		}
		return false, nil
	}
	a.say("✓ Notifications work. Click a button: your terminal opens with mis status.\n")
	return true, nil
}

// allowNotifications loops: check, and if they aren't allowed in the Alerts
// style, open System Settings and wait for Enter.
func (a *app) allowNotifications(paths config.Paths) (bool, error) {
	for {
		status, err := notifierStatus(paths)
		if err != nil {
			a.say("✗ %s\n  Try again later: mis notify setup\n", apperr.MessageOf(err))
			return false, nil
		}
		if status.Ready {
			a.say("✓ Notifications are allowed and stay on screen (Alerts).\n")
			return true, nil
		}
		a.say("Now: %s\n", strings.TrimPrefix(status.Notifier, "macOS: "))
		a.say("Opening System Settings › Notifications › Make-It-Safer Notifier. There:\n" +
			"  1. Turn on \"Allow notifications\"\n" +
			"  2. Choose \"Alerts\" (they stay on screen until you act)\n")
		_ = exec.Command("/usr/bin/open", notificationSettingsURL).Run() // if it can't open, the steps above still apply
		answer, err := a.ask(`Press Enter when done (or type "skip")`, "")
		if err != nil {
			return false, err
		}
		if strings.EqualFold(strings.TrimSpace(answer), "skip") {
			a.say("Later: mis notify setup\n")
			return false, nil
		}
	}
}

// notifierStatus asks the background service, which asks the helper app,
// how notifications are set right now. A helper that is still starting gets
// a few seconds.
func notifierStatus(paths config.Paths) (*daemon.Status, error) {
	var s daemon.Status
	for range 5 {
		if err := daemon.Call(paths, daemon.Request{Op: daemon.OpStatus}, &s, 10*time.Second); err != nil {
			return nil, err
		}
		if s.Notifier != "macOS helper app not connected yet" {
			break
		}
		time.Sleep(time.Second)
	}
	return &s, nil
}
