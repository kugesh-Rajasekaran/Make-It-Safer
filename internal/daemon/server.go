package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// listen opens the socket with owner-only permissions. A stale socket from a
// crashed daemon is replaced; a live one means another daemon is running.
func listen(path string) (*net.UnixListener, error) {
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = conn.Close()
		return nil, apperr.New(apperr.DaemonAlreadyRunning, "the background service is already running")
	}
	_ = os.Remove(path)
	old := syscall.Umask(0o077) // the socket is created 0600 from the start
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, apperr.Wrap(apperr.DaemonFailed, err, "cannot open "+path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, apperr.Wrap(apperr.DaemonFailed, err, "cannot protect "+path)
	}
	return l, nil
}

// serve accepts connections until ctx ends. Only processes of the same user
// may talk to the daemon.
func (d *Daemon) serve(ctx context.Context, l *net.UnixListener) {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			d.log.Warn("accept", "status", "error", "error", err)
			continue
		}
		go d.handle(ctx, conn)
	}
}

func (d *Daemon) handle(ctx context.Context, conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()
	if uid, err := config.PeerUID(conn); err != nil || uid != os.Getuid() {
		d.log.Warn("connection refused", "reason", "different user or unknown peer")
		writeResponse(conn, nil, apperr.New(apperr.DaemonPeerRejected, "only your own user can talk to the background service"))
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequest)).ReadBytes('\n')
	var req Request
	if err == nil {
		err = json.Unmarshal(line, &req)
	}
	clear(line) // may hold a passphrase
	if err != nil {
		writeResponse(conn, nil, apperr.Wrap(apperr.DaemonBadRequest, err, "invalid request"))
		return
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Minute)) // checks can take a while
	data, err := d.dispatch(ctx, req)
	clear(req.Passphrase)
	writeResponse(conn, data, err)
}

func writeResponse(conn net.Conn, data any, err error) {
	resp := Response{OK: err == nil}
	if err != nil {
		resp.Error = &ErrorBody{Code: apperr.CodeOf(err), Message: apperr.MessageOf(err)}
	} else if data != nil {
		raw, merr := json.Marshal(data)
		if merr != nil {
			resp = Response{Error: &ErrorBody{Code: apperr.DaemonFailed, Message: "cannot encode the answer"}}
		}
		resp.Data = raw
	}
	out, _ := json.Marshal(resp)
	_, _ = conn.Write(append(out, '\n'))
}
