package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
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
}
