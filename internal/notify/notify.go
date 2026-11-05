// Package notify shows desktop notifications: through a small helper app on
// macOS and D-Bus on Linux. Notifications carry buttons; clicks come back as
// events.
package notify

import (
	"log/slog"
	"strings"
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

// Event is a click on a notification or one of its buttons.
type Event struct {
	NotificationID string `json:"id"`
	Action         string `json:"action"` // a Button.ID, or Default
}

// Notifier shows notifications and reports clicks.
type Notifier interface {
	Show(n Notification) error
	Remove(id string) error
	Events() <-chan Event
	Describe() string // for mis status, e.g. "macOS (Alerts style)"
	Close() error
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

// Close does nothing.
func (n *Log) Close() error { return nil }
