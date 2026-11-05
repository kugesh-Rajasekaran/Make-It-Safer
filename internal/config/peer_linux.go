package config

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the user ID of the process on the other end of the socket.
func PeerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid, cerr := -1, error(nil)
	err = raw.Control(func(fd uintptr) {
		var cred *unix.Ucred
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if cerr == nil {
			uid = int(cred.Uid)
		}
	})
	if err != nil {
		return -1, err
	}
	return uid, cerr
}
