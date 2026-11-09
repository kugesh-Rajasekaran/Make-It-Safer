// Package setup renders the scripts that create and remove the read-only
// "mis" user on a server, runs them through your own ssh client, and
// verifies from the outside that the server only lets Make-It-Safer read
// package lists.
package setup

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"text/template"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
	"github.com/kugesh-rajasekaran/make-it-safer/server"
)

// Summary says in plain words what the setup script does.
var Summary = []string{
	`creates a user "mis" with no password, no sudo and no groups`,
	"installs your Make-It-Safer public key as its only key",
	"installs the read-only collector at /usr/local/lib/mis/collect",
	`tells sshd that "mis" may only run the collector: no shell, no terminal, no forwarding`,
	"checks the result, proves root's and your admin login's SSH settings are unchanged, and rolls back on any error or if the session drops",
}

var (
	keyLinePattern = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+=* make-it-safer$`)
	setupTemplate  = template.Must(template.New("setup").Option("missingkey=error").Parse(server.SetupTemplate))
)

// Script returns the setup script that installs pub as the only key of "mis".
func Script(pub ssh.PublicKey) (string, error) {
	line := strings.TrimSpace(vault.AuthorizedKey(pub))
	if !keyLinePattern.MatchString(line) { // keeps the values safe inside the script's quotes
		return "", apperr.New(apperr.SetupInvalidKey, "only the Ed25519 key created by mis init can be installed")
	}
	var buf bytes.Buffer
	err := setupTemplate.Execute(&buf, struct{ PublicKey, Collector string }{
		PublicKey: line,
		Collector: base64.StdEncoding.EncodeToString([]byte(server.Collector)),
	})
	if err != nil {
		return "", apperr.Wrap(apperr.SetupFailed, err, "cannot render the setup script")
	}
	return buf.String(), nil
}

// TeardownScript removes everything Script added.
func TeardownScript() string { return server.Teardown }

// RemoteCommand wraps a script so it runs as root on the server, through
// sudo when the login isn't root. The script travels base64-encoded and is
// piped into sh, so it works whatever your login shell is; sudo asks for
// its password on the terminal.
func RemoteCommand(script string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	return "printf %s " + b64 + ` | base64 -d | sh -c 'if [ "$(id -u)" -eq 0 ]; then exec sh; else exec sudo sh; fi'`
}

// RunAsAdmin runs a script on the server through your own ssh client and
// admin login, attached to your terminal (for ssh and sudo prompts).
func RunAsAdmin(ctx context.Context, s config.Server, script string, stdin *os.File, stdout, stderr io.Writer) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return apperr.Wrap(apperr.SetupSSHMissing, err, "the ssh client was not found; install OpenSSH")
	}
	cmd := exec.CommandContext(ctx, sshPath, sshx.AdminArgs(s, RemoteCommand(script))...) //nolint:gosec // validated server fields after "--"; the script is ours
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return apperr.Wrap(apperr.SetupFailed, err, "the script stopped on "+s.Name+" (see its output above); if it stopped part-way, run it again, it is safe to repeat")
		}
		return apperr.Wrap(apperr.SetupFailed, err, "cannot run ssh")
	}
	return nil
}
