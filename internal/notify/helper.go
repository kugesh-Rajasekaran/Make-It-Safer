package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// message is one line between the daemon and the macOS helper app.
//
//	daemon → helper: {"op":"show", id, title, body, buttons, urgent, sound} | {"op":"remove", id}
//	helper → daemon: {"op":"action", id, action} | {"op":"settings", authorized, alertStyle}
type message struct {
	Op         string   `json:"op"`
	ID         string   `json:"id,omitempty"`
	Title      string   `json:"title,omitempty"`
	Body       string   `json:"body,omitempty"`
	Buttons    []Button `json:"buttons,omitempty"`
	Urgent     bool     `json:"urgent,omitempty"`
	Sound      bool     `json:"sound,omitempty"`
	Action     string   `json:"action,omitempty"`
	Authorized bool     `json:"authorized,omitempty"`
	AlertStyle string   `json:"alertStyle,omitempty"`
}

// Helper talks to the macOS helper app ("Make-It-Safer Notifier.app") over a
// Unix socket that only the same user can use. Notifications shown while the
// helper isn't connected are queued and sent when it connects.
type Helper struct {
	log    *slog.Logger
	launch func() error
	events chan Event
	l      *net.UnixListener

	mu         sync.Mutex
	conn       net.Conn
	pending    []message
	launched   time.Time
	authorized bool
	alertStyle string
}

// NewHelper listens on socketPath and starts the helper app with launch.
func NewHelper(ctx context.Context, socketPath string, launch func() error, log *slog.Logger) (*Helper, error) {
	_ = os.Remove(socketPath)
	old := syscall.Umask(0o077)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, apperr.Wrap(apperr.NotifyUnavailable, err, "cannot open "+socketPath)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = l.Close()
		return nil, apperr.Wrap(apperr.NotifyUnavailable, err, "cannot protect "+socketPath)
	}
	h := &Helper{log: log, launch: launch, events: make(chan Event, 16), l: l}
	go h.accept(ctx)
	h.relaunch()
	return h, nil
}

func (h *Helper) accept(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = h.l.Close()
	}()
	for {
		conn, err := h.l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}
		if uid, err := config.PeerUID(conn); err != nil || uid != os.Getuid() {
			_ = conn.Close()
			continue
		}
		h.mu.Lock()
		if h.conn != nil {
			_ = h.conn.Close() // a newer helper replaces the old one
		}
		h.conn = conn
		pending := h.pending
		h.pending = nil
		h.mu.Unlock()
		h.log.Info("notifier", "status", "helper connected")
		for _, m := range pending {
			h.send(m)
		}
		go h.read(conn)
	}
}

func (h *Helper) read(conn net.Conn) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		var m message
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		switch m.Op {
		case "action":
			h.events <- Event{NotificationID: m.ID, Action: m.Action}
		case "settings":
			h.mu.Lock()
			h.authorized, h.alertStyle = m.Authorized, m.AlertStyle
			h.mu.Unlock()
		}
	}
	h.mu.Lock()
	if h.conn == conn {
		h.conn = nil
	}
	h.mu.Unlock()
}

// send writes a message, or queues it (latest per ID) while disconnected.
func (h *Helper) send(m message) {
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	h.mu.Lock()
	conn := h.conn
	if conn == nil {
		for i, p := range h.pending {
			if p.ID == m.ID {
				h.pending = append(h.pending[:i], h.pending[i+1:]...)
				break
			}
		}
		h.pending = append(h.pending, m)
		h.mu.Unlock()
		h.relaunch()
		return
	}
	h.mu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(append(data, '\n')); err != nil {
		h.log.Warn("notifier", "status", "error", "error", err)
	}
}

// relaunch starts the helper app, at most once a minute.
func (h *Helper) relaunch() {
	h.mu.Lock()
	if h.conn != nil || time.Since(h.launched) < time.Minute {
		h.mu.Unlock()
		return
	}
	h.launched = time.Now()
	h.mu.Unlock()
	if err := h.launch(); err != nil {
		h.log.Warn("notifier", "status", "cannot start the helper app", "error", err)
	}
}

// Show sends a notification to the helper app.
func (h *Helper) Show(n Notification) error {
	h.send(message{Op: "show", ID: n.ID, Title: n.Title, Body: n.Body, Buttons: n.Buttons, Urgent: n.Urgent, Sound: n.Sound})
	return nil
}

// Remove takes a notification away.
func (h *Helper) Remove(id string) error {
	h.send(message{Op: "remove", ID: id})
	return nil
}

// Events reports clicks.
func (h *Helper) Events() <-chan Event { return h.events }

// Describe says whether the helper is connected and how macOS shows its notifications.
func (h *Helper) Describe() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.conn == nil:
		return "macOS helper app not connected yet"
	case !h.authorized:
		return "macOS: notifications not allowed; allow them in System Settings › Notifications › Make-It-Safer Notifier"
	case h.alertStyle != "alert":
		return "macOS: " + h.alertStyle + " style; choose Alerts in System Settings › Notifications › Make-It-Safer Notifier so they stay on screen"
	}
	return "macOS (Alerts style)"
}

// Ready reports whether the helper is connected, allowed to notify and set
// to the Alerts style.
func (h *Helper) Ready() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conn != nil && h.authorized && h.alertStyle == "alert"
}

// Close stops listening.
func (h *Helper) Close() error {
	h.mu.Lock()
	if h.conn != nil {
		_ = h.conn.Close()
	}
	h.mu.Unlock()
	return h.l.Close()
}
