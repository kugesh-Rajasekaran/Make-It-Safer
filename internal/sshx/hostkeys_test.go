package sshx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

func newECDSAKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestUserKnownHost(t *testing.T) {
	target := Target{Name: "web", Host: "203.0.113.10", Port: 22}
	ed := newSigner(t).PublicKey()
	otherEd := newSigner(t).PublicKey()
	ec := newECDSAKey(t)
	line := func(k ssh.PublicKey) string {
		return knownhosts.Line([]string{knownhosts.Normalize(target.Addr())}, k) + "\n"
	}

	cases := []struct {
		name  string
		file  *string // contents of ~/.ssh/known_hosts; nil = no file
		shown ssh.PublicKey
		want  string
	}{
		{"no known_hosts file", nil, ed, "unknown"},
		{"empty known_hosts", ptr(""), ed, "unknown"},
		{"same key", ptr(line(ed)), ed, "match"},
		{"same-type different key", ptr(line(otherEd)), ed, "mismatch"},
		{"other key type only", ptr(line(ec)), ed, "unknown"},
		{"other key type and same-type different key", ptr(line(ec) + line(otherEd)), ed, "mismatch"},
		{"other key type and same key", ptr(line(ec) + line(ed)), ed, "match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			if tc.file != nil {
				if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(*tc.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := UserKnownHost(target, tc.shown); got != tc.want {
				t.Fatalf("UserKnownHost() = %q, want %q", got, tc.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// silentServer accepts connections and never answers, like a mistyped port
// that reaches something other than sshd.
func silentServer(t *testing.T) Target {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-done
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return Target{Name: "silent", Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}
}

func setDialTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := dialTimeout
	dialTimeout = d
	t.Cleanup(func() { dialTimeout = old })
}

// handshakes are the calls that talk to a server before any login.
func handshakes(t *testing.T, target Target) map[string]func(context.Context) error {
	hk := pinned(t, &testServer{target: target}, newSigner(t).PublicKey())
	return map[string]func(context.Context) error{
		"FetchHostKey": func(ctx context.Context) error {
			_, err := FetchHostKey(ctx, target)
			return err
		},
		"PasswordOffered": func(ctx context.Context) error {
			_, err := PasswordOffered(ctx, target, hk)
			return err
		},
	}
}

// Neither call may hang on a server that accepts the connection and then
// says nothing: they give up after the timeout, or when ctx ends.
func TestHandshakeGivesUpOnSilentServer(t *testing.T) {
	target := silentServer(t)
	for name, call := range handshakes(t, target) {
		t.Run(name+"/timeout", func(t *testing.T) {
			setDialTimeout(t, 300*time.Millisecond)
			start := time.Now()
			if err := call(context.Background()); !apperr.Is(err, apperr.ServerUnreachable) {
				t.Fatalf("err = %v, want %s", err, apperr.ServerUnreachable)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("took %v with a 300ms timeout", d)
			}
		})
		t.Run(name+"/cancel", func(t *testing.T) {
			setDialTimeout(t, time.Minute)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			if err := call(ctx); !apperr.Is(err, apperr.ServerUnreachable) {
				t.Fatalf("err = %v, want %s", err, apperr.ServerUnreachable)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("took %v after the context ended", d)
			}
		})
	}
}
