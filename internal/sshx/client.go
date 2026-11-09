package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// MaxOutput caps what a server may send back; the inventory parser has the
// same limit.
const MaxOutput = 4 << 20

// commandTimeout bounds one collector run.
const commandTimeout = 2 * time.Minute

// Client is a logged-in connection as the "mis" user.
type Client struct {
	c      *ssh.Client
	target Target
}

// Dial logs in as "mis" with the given key, accepting only the pinned host key.
func Dial(ctx context.Context, t Target, hk HostKeys, signer ssh.Signer) (*Client, error) {
	cb, algorithms, err := hk.callback(t)
	if err != nil {
		return nil, err
	}
	conf := &ssh.ClientConfig{
		User:              User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: algorithms,
		Timeout:           dialTimeout,
	}
	conn, err := dial(ctx, t)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, t.Addr(), conf)
	if err != nil {
		_ = conn.Close()
		return nil, loginError(t, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &Client{c: ssh.NewClient(c, chans, reqs), target: t}, nil
}

func loginError(t Target, err error) error {
	var e *apperr.Error
	if errors.As(err, &e) { // host key mismatch from our callback
		return e
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return apperr.Wrap(apperr.ServerAuthFailed, err, fmt.Sprintf(
			"%s refused the Make-It-Safer key; is the server set up? check with: mis server verify %s", t.Name, t.Name))
	}
	return apperr.Wrap(apperr.ServerUnreachable, err, "cannot log in to "+t.Name)
}

// Close ends the connection.
func (c *Client) Close() error { return c.c.Close() }

// Collect runs the collector and returns its raw output. The server forces
// the collector whatever command is requested.
func (c *Client) Collect(ctx context.Context) ([]byte, error) {
	return c.Run(ctx, "collect")
}

// Run requests cmd and returns at most MaxOutput bytes of output.
func (c *Client) Run(ctx context.Context, cmd string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	s, err := c.c.NewSession()
	if err != nil {
		return nil, apperr.Wrap(apperr.ServerCommandFailed, err, "cannot open a session on "+c.target.Name)
	}
	defer func() { _ = s.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()

	out, err := s.StdoutPipe()
	if err != nil {
		return nil, apperr.Wrap(apperr.ServerCommandFailed, err, "cannot read from "+c.target.Name)
	}
	if err := s.Start(cmd); err != nil {
		return nil, apperr.Wrap(apperr.ServerCommandFailed, err, "cannot run the collector on "+c.target.Name)
	}
	data, err := io.ReadAll(io.LimitReader(out, MaxOutput+1))
	if err != nil {
		return nil, apperr.Wrap(apperr.ServerCommandFailed, err, "reading from "+c.target.Name+" failed")
	}
	if len(data) > MaxOutput {
		return nil, apperr.New(apperr.InventoryTooLarge, c.target.Name+" sent more output than allowed")
	}
	// A run that ends without a clean exit (dropped connection, non-zero or
	// signalled exit) may have been cut off mid-list; the output has no end
	// marker, so a truncated list must never be mistaken for a full one.
	if err := s.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, apperr.Wrap(apperr.ServerCommandFailed, ctx.Err(), "the collector on "+c.target.Name+" timed out")
		}
		return nil, apperr.Wrap(apperr.ServerCommandFailed, err, "the collector on "+c.target.Name+" did not finish cleanly")
	}
	return data, nil
}

// PTYAllowed reports whether the server lets "mis" open a terminal.
func (c *Client) PTYAllowed() bool {
	s, err := c.c.NewSession()
	if err != nil {
		return false
	}
	defer func() { _ = s.Close() }()
	return s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}) == nil
}

// LocalForwardAllowed reports whether "mis" can tunnel to the server's own
// ports. Only an "administratively prohibited" refusal counts as blocked: a
// "connection failed" means the server tried, so forwarding is allowed.
func (c *Client) LocalForwardAllowed() bool {
	conn, err := c.c.Dial("tcp", "127.0.0.1:22")
	if err == nil {
		_ = conn.Close()
		return true
	}
	var oce *ssh.OpenChannelError
	return !errors.As(err, &oce) || oce.Reason != ssh.Prohibited
}

// RemoteForwardAllowed reports whether "mis" can open a listening port on the server.
func (c *Client) RemoteForwardAllowed() bool {
	l, err := c.c.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// PasswordOffered reports whether the server would accept a password (or
// keyboard-interactive) login for "mis". No password is ever sent: the
// callbacks record the offer and abort.
func PasswordOffered(ctx context.Context, t Target, hk HostKeys) (bool, error) {
	cb, algorithms, err := hk.callback(t)
	if err != nil {
		return false, err
	}
	offered := false
	errProbe := errors.New("probe only")
	conf := &ssh.ClientConfig{
		User: User,
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (string, error) { offered = true; return "", errProbe }),
			ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
				offered = true
				return nil, errProbe
			}),
		},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: algorithms,
		Timeout:           dialTimeout,
	}
	conn, err := dial(ctx, t)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	stop := bound(ctx, conn)
	defer stop()
	c, _, _, err := ssh.NewClientConn(conn, t.Addr(), conf)
	if err == nil { // logged in without any credentials: worst case
		_ = c.Close()
		return true, nil
	}
	var e *apperr.Error
	if errors.As(err, &e) {
		return false, e
	}
	var ne net.Error
	if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) { // no answer is not "no password offered"
		return false, apperr.Wrap(apperr.ServerUnreachable, err, "no answer from "+t.Name+" ("+t.Addr()+")")
	}
	return offered, nil
}
