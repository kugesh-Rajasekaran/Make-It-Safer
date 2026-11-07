//go:build linux

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/secret"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// pty is a pseudo-terminal: the wizard gets the terminal side, the test
// types on the other side and reads what the wizard shows.
type pty struct {
	t      *testing.T
	master *os.File
	tty    *os.File
	mu     sync.Mutex
	out    bytes.Buffer
	seen   int
}

func openPTY(t *testing.T) *pty {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals here: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	tty, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := &pty{t: t, master: master, tty: tty}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			p.mu.Lock()
			p.out.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = tty.Close(); _ = master.Close() })
	return p
}

// expect waits for text after what was already matched.
func (p *pty) expect(text string) {
	p.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		p.mu.Lock()
		i := strings.Index(p.out.String()[p.seen:], text)
		if i >= 0 {
			p.seen += i + len(text)
		}
		shown := p.out.String()
		p.mu.Unlock()
		if i >= 0 {
			return
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("waited for %q; the terminal shows:\n%s", text, shown)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (p *pty) send(s string) {
	if _, err := p.master.Write([]byte(s)); err != nil {
		p.t.Fatal(err)
	}
}

// fakeService answers on the background service's socket.
type fakeService struct {
	mu       sync.Mutex
	requests []daemon.Request
}

func (f *fakeService) start(t *testing.T, paths config.Paths) {
	l, err := net.Listen("unix", paths.Socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			var req daemon.Request
			if line, err := bufio.NewReader(conn).ReadBytes('\n'); err == nil && json.Unmarshal(line, &req) == nil {
				f.mu.Lock()
				f.requests = append(f.requests, req)
				f.mu.Unlock()
				_, _ = conn.Write([]byte(`{"ok":true}` + "\n"))
			}
			_ = conn.Close()
		}
	}()
}

// TestInitWizard runs all of mis init through a terminal: passphrase,
// terminal, alerts, no server, background service, notification test.
func TestInitWizard(t *testing.T) {
	dir, err := os.MkdirTemp("", "mis") // short: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv(config.EnvHome, filepath.Join(dir, "h"))
	bin := filepath.Join(dir, "bin") // a terminal app, so "default" is available
	if err := os.MkdirAll(bin, 0o700); err != nil || os.WriteFile(filepath.Join(bin, "xterm"), []byte("#!/bin/sh\n"), 0o700) != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("TERMINAL", "")
	paths, err := config.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}

	p := openPTY(t)
	var stdout bytes.Buffer
	a := newApp([]string{"init"}, p.tty, &stdout, p.tty)
	a.kdf = func() vault.Params { return vault.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1} }
	service := &fakeService{}
	a.installService = func(paths config.Paths) (*daemon.ServiceInfo, error) {
		service.start(t, paths)
		return &daemon.ServiceInfo{Installed: true, Active: true}, nil
	}
	done := make(chan int)
	go func() { done <- a.execute([]string{"init"}) }()

	const pass = "glacier rhubarb tandem quiver lantern 77"
	p.expect("New passphrase: ")
	p.send("short\r")
	p.expect("use at least 8 characters (this one has 5). Please try another one.")
	p.expect("New passphrase: ")
	p.send(pass + "\r")
	p.expect("Type it again to confirm: ")
	p.send(pass + "\r")
	p.expect("✓ Key created")
	p.expect("Terminal app [default]: ")
	p.send("\n")
	p.expect("from CVSS [7.0]: ")
	p.send("6.5\n")
	p.expect(`Early warnings from CVSS (or "off") [9.0]: `)
	p.send("11\n")
	p.expect("Please type a number from 0 to 10.")
	p.send("8\n")
	p.expect("Play a sound with alerts? (Y/n): ")
	p.send("n\n")
	p.expect("Add a server now? (Y/n): ")
	p.send("n\n")
	p.expect("Install and start it now? (Y/n): ")
	p.send("\n")
	p.expect("✓ Running and unlocked.")
	p.expect("Do you see it? (Y/n): ")
	p.send("\n")

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d; output:\n%s", code, p.out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("mis init didn't finish")
	}
	if !strings.Contains(stdout.String(), "Make-It-Safer is set up") || !strings.Contains(stdout.String(), "Add a server: mis server add") {
		t.Errorf("result:\n%s", stdout.String())
	}
	p.mu.Lock()
	shown := p.out.String()
	p.mu.Unlock()
	if strings.Contains(shown, "rhubarb") {
		t.Fatal("the passphrase was shown on the terminal")
	}

	cfg, err := config.Load(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Rules
	if cfg.Terminal.App != "default" || r.AlertWhen.MinSeverity != 6.5 || !r.EarlyWarning.Enabled || r.EarlyWarning.MinSeverity != 8 || cfg.Notifications.Sound {
		t.Errorf("saved config: terminal %+v, rules %+v, sound %v", cfg.Terminal, r, cfg.Notifications.Sound)
	}
	key, err := vault.Unlock(paths.KeyFile, secret.Bytes(pass))
	if err != nil {
		t.Fatalf("the key doesn't open with the passphrase: %v", err)
	}
	key.Destroy()

	service.mu.Lock()
	defer service.mu.Unlock()
	var ops []string
	for _, req := range service.requests {
		ops = append(ops, req.Op)
		if req.Op == daemon.OpUnlock && string(req.Passphrase) != pass {
			t.Error("the service was unlocked with the wrong passphrase")
		}
	}
	if strings.Join(ops, ",") != "unlock,notify-test" {
		t.Errorf("service calls = %v", ops)
	}
}
