// Package notify shows desktop notifications: through a small helper app on
// macOS and D-Bus on Linux. Notifications carry buttons, and a click can open
// a Dialog with the details; clicks come back as events.
package notify

import (
	"log/slog"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/explain"
)

// Button is an action on a notification, e.g. one per affected server.
type Button struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Notification is one desktop notification. Showing one with the same ID
// again replaces it.
type Notification struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Body    string   `json:"body"`
	Buttons []Button `json:"buttons,omitempty"`
	Urgent  bool     `json:"urgent,omitempty"`
	Sound   bool     `json:"sound,omitempty"`
}

// Default is the Action of a click on the notification itself.
const Default = "default"

// Event is a click on a notification or one of its buttons, or on a button
// of the notification's Dialog.
type Event struct {
	NotificationID string `json:"id"`
	Action         string `json:"action"` // a Button.ID, or Default
	FromDialog     bool   `json:"fromDialog,omitempty"`
}

// Dialog is the window a click on a notification opens: what it is about,
// the fix, and a row per server it affects, each with its button. Showing
// one with the same ID again updates it. All its text is shown as plain
// text.
type Dialog struct {
	ID      string         `json:"id"` // the notification's: button clicks come back as its Events
	Title   string         `json:"title"`
	Verdict string         `json:"verdict"` // e.g. "Act now"
	Level   string         `json:"level"`   // the verdict's colour: urgent, high, normal or silent
	Facts   []explain.Fact `json:"facts,omitempty"`
	Fix     string         `json:"fix,omitempty"`     // what the buttons do
	Command string         `json:"command,omitempty"` // what they type in, when it's the same on every row
	Rows    []Row          `json:"rows,omitempty"`
	Refresh bool           `json:"refresh,omitempty"` // after one of its buttons: macOS updates it behind what the button opened; zenity, closed by the button, reopens
}

// Row is one server in a Dialog.
type Row struct {
	Name    string  `json:"name"`
	Detail  string  `json:"detail,omitempty"`  // e.g. "openssl 3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5"
	Command string  `json:"command,omitempty"` // when rows need different commands
	Button  *Button `json:"button,omitempty"`  // nil: nothing to do here
	Opened  bool    `json:"opened,omitempty"`  // the button was used: shown with ✓
}

// Dialoger is a Notifier that can open a Dialog: the macOS helper app, and
// zenity on Linux.
type Dialoger interface {
	ShowDialog(d Dialog) error
}

// Notifier shows notifications and reports clicks.
type Notifier interface {
	Show(n Notification) error
	Remove(id string) error
	Events() <-chan Event
	Describe() string // for mis status, e.g. "macOS (Alerts style)"
	Ready() bool      // notifications appear on screen and stay there
	Close() error
}

// Rechecker is a Notifier that can ask again whether notifications are
// allowed (the macOS helper: you may have changed it in System Settings).
type Rechecker interface {
	Recheck(timeout time.Duration)
}

// Log is a Notifier that only writes to the log. It's used when there is
// no desktop session, and in tests.
type Log struct {
	L      *slog.Logger
	events chan Event
}

// NewLog returns a log-only notifier.
func NewLog(l *slog.Logger) *Log { return &Log{L: l, events: make(chan Event)} }

// Show logs the notification.
func (n *Log) Show(x Notification) error {
	titles := make([]string, len(x.Buttons))
	for i, b := range x.Buttons {
		titles[i] = b.Title
	}
	n.L.Info("notification", "id", x.ID, "title", x.Title, "body", x.Body, "buttons", strings.Join(titles, ", "))
	return nil
}

// Remove logs the removal.
func (n *Log) Remove(id string) error { n.L.Info("notification removed", "id", id); return nil }

// Events never fires.
func (n *Log) Events() <-chan Event { return n.events }

// Describe says notifications go to the log.
func (n *Log) Describe() string { return "log only (no desktop notifications)" }

// Ready is false: nothing appears on screen.
func (n *Log) Ready() bool { return false }

// Close does nothing.
func (n *Log) Close() error { return nil }
