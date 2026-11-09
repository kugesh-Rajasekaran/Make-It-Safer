// Package sshx is Make-It-Safer's SSH client. It logs in as the read-only
// "mis" user, accepts only pinned host keys, and runs the collector.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// User is the read-only account Make-It-Safer logs in as.
const User = "mis"

// dialTimeout bounds connecting and the SSH handshake. A variable so tests
// can shorten it.
var dialTimeout = 15 * time.Second

// Target is a server as the SSH client sees it.
type Target struct {
	Name string
	Host string
	Port int
}

// TargetOf converts a configured server.
func TargetOf(s config.Server) Target { return Target{Name: s.Name, Host: s.Host, Port: s.Port} }

// Addr is host:port.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// preferredAlgorithms makes servers present their Ed25519 host key when they have one.
var preferredAlgorithms = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// FetchHostKey connects without logging in and returns the server's host key.
func FetchHostKey(ctx context.Context, t Target) (ssh.PublicKey, error) {
	var key ssh.PublicKey
	errGotKey := errors.New("host key received")
	conf := &ssh.ClientConfig{
		User:              User,
		HostKeyAlgorithms: preferredAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errGotKey // stop before authenticating
		},
		Timeout: dialTimeout,
	}
	conn, err := dial(ctx, t)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := bound(ctx, conn)
	defer stop()
	if _, _, _, err := ssh.NewClientConn(conn, t.Addr(), conf); key == nil {
		return nil, apperr.Wrap(apperr.ServerUnreachable, err, "cannot read the SSH host key of "+t.Addr())
	}
	return key, nil
}

// Fingerprint returns the SHA256 fingerprint shown by `ssh-keygen -l`.
func Fingerprint(key ssh.PublicKey) string { return ssh.FingerprintSHA256(key) }

// UserKnownHost checks key against your own ~/.ssh/known_hosts: it returns
// "match", "mismatch" or "unknown".
func UserKnownHost(t Target, key ssh.PublicKey) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown"
	}
	cb, err := knownhosts.New(home + "/.ssh/known_hosts")
	if err != nil {
		return "unknown"
	}
	addr := &net.TCPAddr{IP: net.ParseIP(t.Host), Port: t.Port}
	err = cb(t.Addr(), addr, key)
	var keyErr *knownhosts.KeyError
	switch {
	case err == nil:
		return "match"
	case errors.As(err, &keyErr) && sameTypeKnown(keyErr.Want, key):
		return "mismatch"
	default:
		return "unknown"
	}
}

// sameTypeKnown reports whether known_hosts holds a key of the same type as
// key under a different value. An entry of another type (say ECDSA while the
// server presented Ed25519) says nothing about this key: it is not a mismatch.
func sameTypeKnown(want []knownhosts.KnownKey, key ssh.PublicKey) bool {
	return slices.ContainsFunc(want, func(w knownhosts.KnownKey) bool { return w.Key.Type() == key.Type() })
}

// HostKeys is Make-It-Safer's own known_hosts file of pinned host keys.
type HostKeys struct{ Path string }

// Pin stores the host key for a server, replacing any earlier one.
func (h HostKeys) Pin(t Target, key ssh.PublicKey) error {
	lines, err := h.otherLines(t)
	if err != nil {
		return err
	}
	lines = append(lines, knownhosts.Line([]string{knownhosts.Normalize(t.Addr())}, key))
	return config.WriteFileAtomic(h.Path, []byte(strings.Join(lines, "\n")+"\n"))
}

// Unpin forgets a server's host key.
func (h HostKeys) Unpin(t Target) error {
	lines, err := h.otherLines(t)
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(h.Path, []byte(strings.Join(lines, "\n")+"\n"))
}

// Lookup returns the pinned host key for a server.
func (h HostKeys) Lookup(t Target) (ssh.PublicKey, error) {
	data, err := h.read()
	if err != nil {
		return nil, err
	}
	want := knownhosts.Normalize(t.Addr())
	for rest := data; len(rest) > 0; {
		_, hosts, key, _, next, err := ssh.ParseKnownHosts(rest)
		if err != nil {
			break
		}
		rest = next
		for _, host := range hosts {
			if host == want {
				return key, nil
			}
		}
	}
	return nil, apperr.New(apperr.ServerHostKeyUnknown, fmt.Sprintf("no pinned host key for %s; set it up with: mis server add", t.Name))
}

// callback accepts only the pinned key and returns the algorithms to ask for.
func (h HostKeys) callback(t Target) (ssh.HostKeyCallback, []string, error) {
	pinned, err := h.Lookup(t)
	if err != nil {
		return nil, nil, err
	}
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), pinned.Marshal()) {
			return nil
		}
		return apperr.New(apperr.ServerHostKeyMismatch, fmt.Sprintf(
			"the SSH host key of %s changed (now %s, pinned %s). This can mean someone is intercepting the connection. "+
				"If you reinstalled the server, run: mis server remove %s --forget, then mis server add",
			t.Name, Fingerprint(key), Fingerprint(pinned), t.Name))
	}
	algorithms := []string{pinned.Type()}
	if pinned.Type() == ssh.KeyAlgoRSA {
		algorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return cb, algorithms, nil
}

func (h HostKeys) read() ([]byte, error) {
	data, err := os.ReadFile(h.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read "+h.Path)
	}
	return data, nil
}

// otherLines returns the file's lines except those for t.
func (h HostKeys) otherLines(t Target) ([]string, error) {
	data, err := h.read()
	if err != nil {
		return nil, err
	}
	prefix := knownhosts.Normalize(t.Addr()) + " "
	var keep []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" && !strings.HasPrefix(line, prefix) {
			keep = append(keep, line)
		}
	}
	return keep, nil
}

// bound limits the SSH handshake on conn to dialTimeout and ends it when ctx
// is done. ClientConfig.Timeout only covers the TCP dial, so without this a
// server that accepts the connection and never answers would block forever.
func bound(ctx context.Context, conn net.Conn) (stop func() bool) {
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	return context.AfterFunc(ctx, func() { _ = conn.Close() })
}

func dial(ctx context.Context, t Target) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", t.Addr())
	if err != nil {
		return nil, apperr.Wrap(apperr.ServerUnreachable, err, "cannot reach "+t.Name+" ("+t.Addr()+")")
	}
	return conn, nil
}
