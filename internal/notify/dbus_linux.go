package notify

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

const (
	busName   = "org.freedesktop.Notifications"
	busPath   = dbus.ObjectPath("/org/freedesktop/Notifications")
	busPrefix = busName + "."
)

// callTimeout bounds a call to the notification server: the daemon shows
// notifications while holding its findings lock, so a server that never
// answers must not hold it for the bus's own (minutes-long) timeout.
// It is a variable so tests can shorten it.
var callTimeout = 10 * time.Second

// DBus shows freedesktop notifications (GNOME, KDE, …). Notifications are
// "resident" so clicking a button doesn't close them, and showing one again
// replaces it in place.
type DBus struct {
	log    *slog.Logger
	conn   *dbus.Conn
	obj    dbus.BusObject
	caps   []string
	server string
	events chan Event

	mu    sync.Mutex
	ids   map[string]uint32 // our ID → the notification server's ID
	back  map[uint32]string
	owner string // unique bus name of the notification server; only its signals count
}

// NewDBus connects to the session bus.
func NewDBus(ctx context.Context, log *slog.Logger) (*DBus, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, apperr.Wrap(apperr.NotifyUnavailable, err, "no D-Bus session")
	}
	d := &DBus{log: log, conn: conn, obj: conn.Object(busName, busPath), events: make(chan Event, 16),
		ids: map[string]uint32{}, back: map[uint32]string{}}
	if err := d.obj.Call(busPrefix+"GetCapabilities", 0).Store(&d.caps); err != nil {
		_ = conn.Close()
		return nil, apperr.Wrap(apperr.NotifyUnavailable, err, "no notification server on the session bus")
	}
	var name, vendor, version, spec string
	if d.obj.Call(busPrefix+"GetServerInformation", 0).Store(&name, &vendor, &version, &spec) == nil {
		d.server = name
	}
	if err := conn.AddMatchSignal(dbus.WithMatchObjectPath(busPath), dbus.WithMatchInterface(busName)); err != nil {
		_ = conn.Close()
		return nil, apperr.Wrap(apperr.NotifyUnavailable, err, "cannot listen for notification clicks")
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	go d.listen(ctx, signals)
	return d, nil
}

func (d *DBus) listen(ctx context.Context, signals chan *dbus.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-signals:
			if !ok {
				return
			}
			d.handle(s)
		}
	}
}

func (d *DBus) handle(s *dbus.Signal) {
	switch s.Name {
	case busPrefix + "ActionInvoked":
		d.mu.Lock()
		owner := d.owner
		d.mu.Unlock()
		if len(s.Body) < 2 || s.Sender != owner {
			return // another program on the bus can't click for you
		}
		id, _ := s.Body[0].(uint32)
		action, _ := s.Body[1].(string)
		d.mu.Lock()
		ours, known := d.back[id]
		d.mu.Unlock()
		if known {
			d.events <- Event{NotificationID: ours, Action: action}
		}
	case busPrefix + "NotificationClosed":
		if len(s.Body) < 1 {
			return
		}
		id, _ := s.Body[0].(uint32)
		d.mu.Lock()
		if ours, ok := d.back[id]; ok {
			delete(d.ids, ours)
			delete(d.back, id)
		}
		d.mu.Unlock()
	}
}

// markup escapes what a notification server that reads body markup would
// otherwise take as tags or entities.
var markup = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// bodyText is the body as the server should get it: escaped when it reads
// markup (feed text such as CISA's description can contain < and &).
func bodyText(caps []string, body string) string {
	if slices.Contains(caps, "body-markup") {
		return markup.Replace(body)
	}
	return body
}

// Show shows or replaces a notification.
func (d *DBus) Show(n Notification) error {
	actions := []string{Default, "Open"} // a click on the notification itself
	if slices.Contains(d.caps, "actions") {
		for _, b := range n.Buttons {
			actions = append(actions, b.ID, b.Title)
		}
	}
	urgency := byte(1)
	if n.Urgent {
		urgency = 2 // critical: stays until dismissed
	}
	hints := map[string]dbus.Variant{
		"urgency":  dbus.MakeVariant(urgency),
		"resident": dbus.MakeVariant(true), // keep it open after a button click
	}
	if !n.Sound {
		hints["suppress-sound"] = dbus.MakeVariant(true)
	}
	d.mu.Lock()
	replaces := d.ids[n.ID]
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var id uint32
	err := d.obj.CallWithContext(ctx, busPrefix+"Notify", 0, "Make-It-Safer", replaces, "dialog-warning", n.Title, bodyText(d.caps, n.Body), actions, hints, int32(0)).Store(&id)
	if err != nil {
		return apperr.Wrap(apperr.NotifyUnavailable, err, "cannot show a notification")
	}
	var owner string // it changes when the notification server restarts
	if err := d.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, busName).Store(&owner); err != nil {
		return apperr.Wrap(apperr.NotifyUnavailable, err, "cannot find the notification server")
	}
	d.mu.Lock()
	d.owner = owner
	if old, ok := d.ids[n.ID]; ok {
		delete(d.back, old)
	}
	d.ids[n.ID], d.back[id] = id, n.ID
	d.mu.Unlock()
	return nil
}

// Remove closes a notification.
func (d *DBus) Remove(id string) error {
	d.mu.Lock()
	sid, ok := d.ids[id]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return d.obj.CallWithContext(ctx, busPrefix+"CloseNotification", 0, sid).Err
}

// Events reports clicks.
func (d *DBus) Events() <-chan Event { return d.events }

// Describe names the notification server and warns when buttons won't work.
func (d *DBus) Describe() string {
	s := "Linux desktop notifications (" + d.server + ")"
	if !slices.Contains(d.caps, "actions") {
		s += "; this desktop doesn't support buttons, so click the notification itself"
	}
	return s
}

// Ready is true: a notification server answered (resident notifications
// stay where the desktop supports them).
func (d *DBus) Ready() bool { return true }

// Close disconnects from the bus.
func (d *DBus) Close() error { return d.conn.Close() }
