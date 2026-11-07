// Package daemon is Make-It-Safer's background service. It runs at login,
// holds the unlocked key in locked memory, runs checks on a schedule and
// shows notifications. The CLI talks to it over a Unix socket that only the
// same user can use.
package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
)

// Operations the daemon understands.
const (
	OpStatus     = "status"
	OpUnlock     = "unlock"
	OpAutoUnlock = "auto-unlock" // unlock with the key in your Keychain (ADR 0002)
	OpLock       = "lock"
	OpCheck      = "check"
	OpFix        = "fix"         // open a terminal with the fix for a server (M5)
	OpNotify     = "notify-test" // show a test notification (M5)
)

// Request is one call. Each connection carries exactly one.
type Request struct {
	Op         string   `json:"op"`
	Passphrase []byte   `json:"passphrase,omitempty"` // unlock only; wiped as soon as it's used
	Servers    []string `json:"servers,omitempty"`    // check
	Refresh    bool     `json:"refresh,omitempty"`    // check: log in to refresh package lists
	Server     string   `json:"server,omitempty"`     // fix
	CVE        string   `json:"cve,omitempty"`        // fix
}

// Response answers a request.
type Response struct {
	OK    bool            `json:"ok"`
	Error *ErrorBody      `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// ErrorBody carries an apperr code across the socket.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Status is the answer to OpStatus.
type Status struct {
	Version    string               `json:"version"`
	Locked     bool                 `json:"locked"`
	AutoUnlock bool                 `json:"auto_unlock"` // unlocks itself when you log in
	Started    time.Time            `json:"started"`
	Notifier   string               `json:"notifier"`
	Ready      bool                 `json:"notifier_ready"` // notifications show and stay on screen
	Jobs       map[string]*JobState `json:"jobs"`
}

// CheckResult is the answer to OpCheck.
type CheckResult = engine.Result

const maxRequest = 64 << 10

// ErrNotRunning means no daemon answered on the socket.
var ErrNotRunning = errors.New("the background service is not running")

// Call sends one request to the daemon and decodes its data into out (if
// not nil). timeout bounds the whole exchange.
func Call(paths config.Paths, req Request, out any, timeout time.Duration) error {
	conn, err := net.DialTimeout("unix", paths.Socket, 2*time.Second)
	if err != nil {
		return apperr.Wrap(apperr.DaemonNotRunning, ErrNotRunning, "the background service is not running; start it with: mis service install")
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	data, err := json.Marshal(req)
	clear(req.Passphrase)
	if err != nil {
		return apperr.Wrap(apperr.DaemonBadRequest, err, "cannot encode the request")
	}
	_, err = conn.Write(append(data, '\n'))
	clear(data)
	if err != nil {
		return apperr.Wrap(apperr.DaemonFailed, err, "cannot talk to the background service")
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return apperr.Wrap(apperr.DaemonFailed, err, "no answer from the background service")
	}
	if !resp.OK {
		if resp.Error == nil {
			return apperr.New(apperr.DaemonFailed, "the background service failed")
		}
		return apperr.New(resp.Error.Code, resp.Error.Message)
	}
	if out != nil && len(resp.Data) > 0 {
		if err := json.Unmarshal(resp.Data, out); err != nil {
			return apperr.Wrap(apperr.DaemonFailed, err, "unexpected answer from the background service")
		}
	}
	return nil
}

// Running reports whether a daemon answers on the socket.
func Running(paths config.Paths) bool {
	conn, err := net.DialTimeout("unix", paths.Socket, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
