package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHelperProtocol(t *testing.T) {
	dir, err := os.MkdirTemp("", "mis")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "notify.sock")
	var launches atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := NewHelper(ctx, sock, func() error { launches.Add(1); return nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if info, err := os.Stat(sock); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, %v", info.Mode().Perm(), err)
	}
	if launches.Load() != 1 || !strings.Contains(h.Describe(), "not connected") {
		t.Fatalf("helper should be launched at start: %d, %q", launches.Load(), h.Describe())
	}

	// Shown while the helper isn't connected: queued, latest per ID.
	_ = h.Show(Notification{ID: "cve:CVE-1", Title: "old"})
	_ = h.Show(Notification{ID: "cve:CVE-1", Title: "new", Buttons: []Button{{ID: "fix:web", Title: "web"}}})
	_ = h.Remove("lock")
	if err := h.ShowDialog(Dialog{ID: "cve:CVE-1"}); err == nil {
		t.Fatal("a dialog needs the helper connected: no window popping up later")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	var got []message
	for range 2 {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := r.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var m message
		_ = json.Unmarshal(line, &m)
		got = append(got, m)
	}
	if got[0].Op != "show" || got[0].Title != "new" || got[0].Buttons[0].ID != "fix:web" || got[1].Op != "remove" {
		t.Fatalf("queued messages = %+v", got)
	}

	_, _ = conn.Write([]byte(`{"op":"settings","authorized":true,"alertStyle":"alert"}` + "\n" + `{"op":"action","id":"cve:CVE-1","action":"fix:web"}` + "\n"))
	select {
	case ev := <-h.Events():
		if ev.NotificationID != "cve:CVE-1" || ev.Action != "fix:web" {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no click event")
	}
	if d := h.Describe(); d != "macOS (Alerts style)" {
		t.Fatalf("Describe() = %q", d)
	}

	// A dialog goes to the helper; its buttons come back marked as such.
	if err := h.ShowDialog(Dialog{ID: "cve:CVE-1", Title: "CVE-1 · openssh"}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := r.ReadBytes('\n')
	var m message
	if err != nil || json.Unmarshal(line, &m) != nil || m.Op != "dialog" || m.Dialog == nil || m.Dialog.Title != "CVE-1 · openssh" {
		t.Fatalf("dialog message = %s, %v", line, err)
	}
	_, _ = conn.Write([]byte(`{"op":"action","id":"cve:CVE-1","action":"fix:web","fromDialog":true}` + "\n"))
	if ev := <-h.Events(); !ev.FromDialog || ev.Action != "fix:web" {
		t.Fatalf("dialog click = %+v", ev)
	}

	// Recheck asks the helper for the current settings and waits for them:
	// here you switched to Banners in System Settings.
	go func() {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := r.ReadBytes('\n')
		var m message
		if err == nil && json.Unmarshal(line, &m) == nil && m.Op == "settings" {
			_, _ = conn.Write([]byte(`{"op":"settings","authorized":true,"alertStyle":"banner"}` + "\n"))
		}
	}()
	h.Recheck(5 * time.Second)
	if h.Ready() || !strings.Contains(h.Describe(), "banner style") {
		t.Fatalf("after Recheck: ready %v, %q", h.Ready(), h.Describe())
	}

	// A helper that doesn't answer doesn't hang the caller.
	start := time.Now()
	h.Recheck(100 * time.Millisecond)
	if time.Since(start) > 2*time.Second {
		t.Fatal("Recheck waited too long")
	}
}

// When the daemon stops reading from the helper (a line over the limit), it
// must close the connection too: the helper reconnects when it sees the end,
// and until then neither side would do anything.
func TestHelperClosesAConnectionItStopsReading(t *testing.T) {
	dir, err := os.MkdirTemp("", "mis")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "notify.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &logBuffer{}
	h, err := NewHelper(ctx, sock, func() error { return nil }, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(`{"op":"settings","authorized":true,"alertStyle":"alert"}` + "\n"))
	for range 100 { // wait until the daemon has taken the connection
		if h.Ready() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !h.Ready() {
		t.Fatal("the helper never counted as connected")
	}

	_, _ = conn.Write([]byte(strings.Repeat("x", 70000) + "\n")) // more than a message can be
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the daemon stopped reading but kept the connection open")
	}
	if err == nil {
		t.Fatal("expected the connection to end, but read data")
	}
	if !strings.Contains(h.Describe(), "not connected") {
		t.Fatalf("Describe() = %q", h.Describe())
	}
	if !strings.Contains(logs.String(), "helper connection closed") { // this one is worth a line in the log
		t.Fatalf("the oversize line wasn't logged:\n%s", logs.String())
	}
}

// logBuffer is a log destination safe for the helper's goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A newer helper replacing the old one, and the daemon stopping, are normal:
// they close the connection themselves and must not be logged as warnings.
func TestHelperReplacementAndShutdownAreNotWarnings(t *testing.T) {
	dir, err := os.MkdirTemp("", "mis")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "notify.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &logBuffer{}
	h, err := NewHelper(ctx, sock, func() error { return nil }, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}

	ended := func(conn net.Conn) { // wait for the daemon to close it
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("expected the connection to end")
		} else if ne := net.Error(nil); errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("the connection stayed open")
		}
	}
	first, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, _ = first.Write([]byte(`{"op":"settings","authorized":true,"alertStyle":"alert"}` + "\n"))
	for range 100 {
		if h.Ready() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	second, err := net.Dial("unix", sock) // a newer helper: the first is closed
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ended(first)
	time.Sleep(100 * time.Millisecond) // the daemon's side of the first connection finishes
	_ = h.Close()                      // shutdown closes the second
	ended(second)
	time.Sleep(300 * time.Millisecond)

	if out := logs.String(); strings.Contains(out, "helper connection closed") {
		t.Fatalf("a normal close was logged as a warning:\n%s", out)
	}
}
