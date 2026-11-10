package notify

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// fakeServer is a notification server on a private session bus.
type fakeServer struct {
	mu       sync.Mutex
	next     uint32
	actions  []string
	hints    map[string]dbus.Variant
	replaces []uint32
	closed   []uint32
	hang     chan struct{} // when set, Notify doesn't answer until it is closed
}

func (f *fakeServer) Notify(_ string, replaces uint32, _, _, _ string, actions []string, hints map[string]dbus.Variant, _ int32) (uint32, *dbus.Error) {
	f.mu.Lock()
	hang := f.hang
	f.mu.Unlock()
	if hang != nil {
		<-hang
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions, f.hints, f.replaces = actions, hints, append(f.replaces, replaces)
	if replaces != 0 {
		return replaces, nil
	}
	f.next++
	return f.next, nil
}

func (f *fakeServer) CloseNotification(id uint32) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, id)
	return nil
}

func (f *fakeServer) GetCapabilities() ([]string, *dbus.Error) {
	return []string{"actions", "body", "persistence"}, nil
}

func (f *fakeServer) GetServerInformation() (string, string, string, string, *dbus.Error) {
	return "fake-shell", "test", "1", "1.2", nil
}

func startBus(t *testing.T) (*fakeServer, *dbus.Conn) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start dbus-daemon: ", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", strings.TrimSpace(addr))

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	srv := &fakeServer{}
	if err := conn.Export(srv, busPath, busName); err != nil {
		t.Fatal(err)
	}
	if reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("RequestName: %v %v", reply, err)
	}
	return srv, conn
}

func TestDBusNotifier(t *testing.T) {
	srv, bus := startBus(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := NewDBus(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !strings.Contains(d.Describe(), "fake-shell") {
		t.Fatalf("Describe() = %q", d.Describe())
	}

	n := Notification{ID: "cve:CVE-1", Title: "t", Body: "b", Urgent: true, Buttons: []Button{{ID: "fix:web", Title: "web"}, {ID: "all", Title: "All servers…"}}}
	if err := d.Show(n); err != nil {
		t.Fatal(err)
	}
	if err := d.Show(n); err != nil { // shown again: replaced in place
		t.Fatal(err)
	}
	srv.mu.Lock()
	actions, hints, replaces := srv.actions, srv.hints, srv.replaces
	srv.mu.Unlock()
	if strings.Join(actions, "|") != "default|Open|fix:web|web|all|All servers…" {
		t.Fatalf("actions = %v", actions)
	}
	if hints["resident"].Value() != true || hints["urgency"].Value() != byte(2) {
		t.Fatalf("hints = %v", hints)
	}
	if len(replaces) != 2 || replaces[0] != 0 || replaces[1] != 1 {
		t.Fatalf("replaces = %v", replaces)
	}

	// Another program on the bus sends a fake click first: it is ignored.
	other, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if err := other.Emit(busPath, busPrefix+"ActionInvoked", uint32(1), "fix:spoofed"); err != nil {
		t.Fatal(err)
	}
	if err := bus.Emit(busPath, busPrefix+"ActionInvoked", uint32(1), "fix:web"); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-d.Events():
		if ev.NotificationID != "cve:CVE-1" || ev.Action != "fix:web" {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no click event")
	}
	select {
	case ev := <-d.Events():
		t.Fatalf("unexpected event %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}

	if err := d.Remove("cve:CVE-1"); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	closed := srv.closed
	srv.mu.Unlock()
	if len(closed) != 1 || closed[0] != 1 {
		t.Fatalf("closed = %v", closed)
	}
}

// The daemon shows notifications while it holds its findings lock, so a
// notification server that stops answering must make Show fail, not wait.
func TestShowGivesUpOnASilentServer(t *testing.T) {
	srv, _ := startBus(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := NewDBus(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	hang := make(chan struct{})
	defer close(hang)
	srv.mu.Lock()
	srv.hang = hang
	srv.mu.Unlock()
	defer func(orig time.Duration) { callTimeout = orig }(callTimeout)
	callTimeout = 200 * time.Millisecond

	start := time.Now()
	err = d.Show(Notification{ID: "cve:CVE-1", Title: "t", Body: "b"})
	if err == nil {
		t.Fatal("Show succeeded although the server never answered")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("Show waited %s for a silent server", took)
	}
}

func TestBodyTextEscapesMarkup(t *testing.T) {
	body := "Example <b>Server</b> & co"
	if got := bodyText([]string{"actions", "body-markup"}, body); got != "Example &lt;b&gt;Server&lt;/b&gt; &amp; co" {
		t.Errorf("with markup: %q", got)
	}
	if got := bodyText([]string{"actions"}, body); got != body {
		t.Errorf("without markup the text is shown as is: %q", got)
	}
}
