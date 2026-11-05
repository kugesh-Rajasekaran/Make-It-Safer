package daemon

import (
	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
)

// onClick reacts to a notification click. Opening terminals arrives with the
// fix flow (milestone M5); until then clicks are only logged.
func (d *Daemon) onClick(ev notify.Event) {
	d.log.Info("notification clicked", "id", ev.NotificationID, "action", ev.Action)
}

// fix opens a terminal with the fix for a server (milestone M5).
func (d *Daemon) fix(server, cve string) error {
	return apperr.New(apperr.DaemonBadRequest, "fixing from notifications isn't available yet")
}

// notifyTest shows a sample notification with buttons.
func (d *Daemon) notifyTest() error {
	return d.notifier.Show(notify.Notification{
		ID: "test", Title: "Make-It-Safer test notification",
		Body:    "Click a button: it should open your terminal.",
		Buttons: []notify.Button{{ID: "test:a", Title: "Button A"}, {ID: "test:b", Title: "Button B"}},
	})
}
