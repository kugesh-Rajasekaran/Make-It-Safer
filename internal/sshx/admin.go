package sshx

import (
	"strconv"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// AdminArgs returns the arguments for your own ssh client to log in with
// your admin login and run remoteCommand in a terminal. Make-It-Safer never
// sees the admin credentials: ssh asks for them itself.
//
// A port is only added for user@host logins; an ~/.ssh/config alias brings
// its own settings. Config validation guarantees nothing here starts with
// "-", and "--" ends ssh's options anyway.
func AdminArgs(s config.Server, remoteCommand string) []string {
	args := []string{"-t"}
	if strings.Contains(s.AdminSSH, "@") && s.Port != 22 {
		args = append(args, "-p", strconv.Itoa(s.Port))
	}
	return append(args, "--", s.AdminSSH, remoteCommand)
}

// AdminIsRoot reports whether the admin login is root (so sudo isn't needed).
func AdminIsRoot(s config.Server) bool {
	return strings.HasPrefix(s.AdminSSH, "root@") || s.AdminSSH == "root"
}
