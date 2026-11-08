package sshx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// testServer is an in-process SSH server that behaves like a set-up server:
// every exec runs the "collector" (returns output), and the restrictions can
// be switched off to check that the probes notice.
type testServer struct {
	target        Target
	hostKey       ssh.PublicKey
	output        []byte
	allowPTY      bool
	allowForward  bool
	offerPassword bool
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startServer(t *testing.T, client ssh.Signer, configure func(*testServer)) *testServer {
	t.Helper()
	host := newSigner(t)
	srv := &testServer{hostKey: host.PublicKey(), output: []byte("mis-collect 1\n")}
	if configure != nil {
		configure(srv)
	}
	conf := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == User && bytes.Equal(key.Marshal(), client.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	if srv.offerPassword {
		conf.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			t.Error("a password was sent to the server")
			return nil, errors.New("denied")
		}
	}
	conf.AddHostKey(host)

	l, err := net.Listen("tcp", "127.0.0.1:0")
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
			go srv.serve(conn, conf)
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	srv.target = Target{Name: "test", Host: "127.0.0.1", Port: addr.Port}
	return srv
}

func (srv *testServer) serve(conn net.Conn, conf *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, conf)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go func() {
		for req := range reqs {
			if req.Type == "tcpip-forward" && srv.allowForward {
				_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{40000})) // the port "allocated" for :0
				continue
			}
			_ = req.Reply(false, nil)
		}
	}()
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, reqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go srv.session(ch, reqs)
		case "direct-tcpip":
			if !srv.allowForward {
				_ = nc.Reject(ssh.Prohibited, "forwarding disabled")
				continue
			}
			ch, _, err := nc.Accept()
			if err == nil {
				_ = ch.Close()
			}
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "no")
		}
	}
}

func (srv *testServer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(srv.allowPTY, nil)
		case "exec": // like ForceCommand: whatever was asked, run the collector
			_ = req.Reply(true, nil)
			_, _ = ch.Write(srv.output)
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func pinned(t *testing.T, srv *testServer, key ssh.PublicKey) HostKeys {
	t.Helper()
	hk := HostKeys{Path: filepath.Join(t.TempDir(), "known_hosts")}
	if err := hk.Pin(srv.target, key); err != nil {
		t.Fatal(err)
	}
	return hk
}

func TestFetchPinLookupUnpin(t *testing.T) {
	client := newSigner(t)
	srv := startServer(t, client, nil)
	ctx := context.Background()

	key, err := FetchHostKey(ctx, srv.target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Marshal(), srv.hostKey.Marshal()) {
		t.Fatal("fetched a different host key")
	}
	hk := pinned(t, srv, key)
	other := Target{Name: "other", Host: "10.0.0.1", Port: 22}
	if err := hk.Pin(other, newSigner(t).PublicKey()); err != nil {
		t.Fatal(err)
	}
	if got, err := hk.Lookup(srv.target); err != nil || !bytes.Equal(got.Marshal(), key.Marshal()) {
		t.Fatalf("Lookup() = %v, %v", got, err)
	}
	if err := hk.Unpin(srv.target); err != nil {
		t.Fatal(err)
	}
	if _, err := hk.Lookup(srv.target); !apperr.Is(err, apperr.ServerHostKeyUnknown) {
		t.Fatalf("Lookup after Unpin = %v", err)
	}
	if _, err := hk.Lookup(other); err != nil {
		t.Fatalf("Unpin removed another server's key: %v", err)
	}
}

func TestDialAndCollect(t *testing.T) {
	client := newSigner(t)
	srv := startServer(t, client, nil)
	c, err := Dial(context.Background(), srv.target, pinned(t, srv, srv.hostKey), client)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	out, err := c.Collect(context.Background())
	if err != nil || string(out) != "mis-collect 1\n" {
		t.Fatalf("Collect() = %q, %v", out, err)
	}
}

func TestDialRefuses(t *testing.T) {
	client := newSigner(t)
	srv := startServer(t, client, nil)
	ctx := context.Background()

	if _, err := Dial(ctx, srv.target, pinned(t, srv, newSigner(t).PublicKey()), client); !apperr.Is(err, apperr.ServerHostKeyMismatch) {
		t.Fatalf("changed host key: Dial() = %v", err)
	}
	empty := HostKeys{Path: filepath.Join(t.TempDir(), "known_hosts")}
	if _, err := Dial(ctx, srv.target, empty, client); !apperr.Is(err, apperr.ServerHostKeyUnknown) {
		t.Fatalf("unpinned host: Dial() = %v", err)
	}
	if _, err := Dial(ctx, srv.target, pinned(t, srv, srv.hostKey), newSigner(t)); !apperr.Is(err, apperr.ServerAuthFailed) {
		t.Fatalf("wrong client key: Dial() = %v", err)
	}
	closed := Target{Name: "down", Host: "127.0.0.1", Port: freePort(t)}
	if _, err := Dial(ctx, closed, pinned(t, &testServer{target: closed}, srv.hostKey), client); !apperr.Is(err, apperr.ServerUnreachable) {
		t.Fatalf("closed port: Dial() = %v", err)
	}
}

func TestOutputIsCapped(t *testing.T) {
	client := newSigner(t)
	srv := startServer(t, client, func(s *testServer) { s.output = bytes.Repeat([]byte("x"), MaxOutput+10) })
	c, err := Dial(context.Background(), srv.target, pinned(t, srv, srv.hostKey), client)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Collect(context.Background()); !apperr.Is(err, apperr.InventoryTooLarge) {
		t.Fatalf("Collect() = %v, want %s", err, apperr.InventoryTooLarge)
	}
}

func TestRestrictionProbes(t *testing.T) {
	for _, open := range []bool{false, true} {
		t.Run("open="+strconv.FormatBool(open), func(t *testing.T) {
			client := newSigner(t)
			srv := startServer(t, client, func(s *testServer) {
				s.allowPTY, s.allowForward, s.offerPassword = open, open, open
			})
			hk := pinned(t, srv, srv.hostKey)
			c, err := Dial(context.Background(), srv.target, hk, client)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.PTYAllowed() != open || c.LocalForwardAllowed() != open || c.RemoteForwardAllowed() != open {
				t.Fatalf("probes disagree with the server (want %v)", open)
			}
			offered, err := PasswordOffered(context.Background(), srv.target, hk)
			if err != nil || offered != open {
				t.Fatalf("PasswordOffered() = %v, %v; want %v", offered, err, open)
			}
		})
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
