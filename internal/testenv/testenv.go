//go:build integration

// Package testenv starts throwaway Ubuntu and Debian SSH servers in Docker
// for integration tests. Nothing here touches a real server.
package testenv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
)

// Images are the distros Make-It-Safer supports. Set MIS_TEST_IMAGES (comma
// separated) to run a subset, e.g. where Debian mirrors aren't reachable.
var Images = func() []string {
	if v := os.Getenv("MIS_TEST_IMAGES"); v != "" {
		return strings.Split(v, ",")
	}
	return []string{"ubuntu:22.04", "ubuntu:24.04", "debian:12", "debian:13"}
}()

// dockerfile builds an SSH server with an "admin" user that may sudo without
// a password (the stand-in for your own admin login).
const dockerfile = `ARG BASE
FROM ${BASE}
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends openssh-server sudo apt-utils >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash admin \
 && echo 'admin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/admin \
 && install -d -o admin -g admin -m 700 /home/admin/.ssh
CMD ["/usr/sbin/sshd", "-D", "-e"]
`

// Server is a running throwaway SSH server.
type Server struct {
	Target    sshx.Target
	HostKey   ssh.PublicKey
	Admin     ssh.Signer
	container string
}

var buildLocks sync.Map

// Start builds (cached) and runs an SSH server for base, e.g. "ubuntu:24.04".
func Start(t *testing.T, base string) *Server {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("Docker is not available")
	}
	image := "mis-it-" + strings.NewReplacer(":", "-", "/", "-").Replace(base)
	mu, _ := buildLocks.LoadOrStore(image, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	build := exec.Command("docker", "build", "-q", "--network", "host", "-t", image, "--build-arg", "BASE="+base, "-")
	build.Stdin = strings.NewReader(dockerfile)
	out, err := build.CombinedOutput()
	mu.(*sync.Mutex).Unlock()
	if err != nil {
		t.Fatalf("docker build %s: %v\n%s", base, err, out)
	}

	id := strings.TrimSpace(must(t, "docker", "run", "-d", "-p", "127.0.0.1::22", image))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Admin: admin, container: id}
	if _, err := s.ExecInput(string(ssh.MarshalAuthorizedKey(admin.PublicKey())),
		"sh", "-c", "cat > /home/admin/.ssh/authorized_keys && chown admin:admin /home/admin/.ssh/authorized_keys && chmod 600 /home/admin/.ssh/authorized_keys"); err != nil {
		t.Fatal(err)
	}
	hostKeyLine, err := s.Exec("cat", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		t.Fatal(err)
	}
	if s.HostKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(hostKeyLine)); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(strings.Split(must(t, "docker", "port", id, "22/tcp"), "\n")[0]))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	s.Target = sshx.Target{Name: image, Host: host, Port: p}

	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := sshx.FetchHostKey(context.Background(), s.Target); err == nil {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd in %s did not start", base)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// WaitReady waits until sshd accepts connections again (it restarts briefly
// when setup reloads it).
func (s *Server) WaitReady() {
	for range 50 {
		if _, err := sshx.FetchHostKey(context.Background(), s.Target); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// AdminRun runs a command over SSH as the admin user, like your own login.
func (s *Server) AdminRun(cmd string) (string, error) {
	s.WaitReady()
	conf := &ssh.ClientConfig{
		User:              "admin",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(s.Admin)},
		HostKeyCallback:   ssh.FixedHostKey(s.HostKey),
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           15 * time.Second,
	}
	c, err := ssh.Dial("tcp", s.Target.Addr(), conf)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	session, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()
	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

// Terminal is an interactive SSH session with a terminal, logged in as the
// admin user, like the window a fix button opens.
type Terminal struct {
	session *ssh.Session
	client  *ssh.Client
	stdin   io.WriteCloser
	mu      sync.Mutex
	out     bytes.Buffer
}

// AdminTerminal runs command over SSH as admin, with a terminal attached.
func (s *Server) AdminTerminal(t *testing.T, command string) *Terminal {
	t.Helper()
	s.WaitReady()
	client, err := ssh.Dial("tcp", s.Target.Addr(), &ssh.ClientConfig{
		User: "admin", Auth: []ssh.AuthMethod{ssh.PublicKeys(s.Admin)},
		HostKeyCallback: ssh.FixedHostKey(s.HostKey), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, Timeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestPty("xterm", 40, 200, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatal(err)
	}
	term := &Terminal{session: session, client: client}
	if term.stdin, err = session.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	session.Stdout, session.Stderr = term, term
	if err := session.Start(command); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close(); _ = client.Close() })
	return term
}

func (tm *Terminal) Write(p []byte) (int, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.out.Write(p)
}

// Output returns everything shown so far.
func (tm *Terminal) Output() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.out.String()
}

// WaitFor waits until text appears on the terminal.
func (tm *Terminal) WaitFor(t *testing.T, text string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !strings.Contains(tm.Output(), text) {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %q; the terminal shows:\n%s", text, tm.Output())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Type sends keystrokes.
func (tm *Terminal) Type(s string) { _, _ = tm.stdin.Write([]byte(s)) }

// Exec runs a command as root inside the container.
func (s *Server) Exec(args ...string) (string, error) { return s.ExecInput("", args...) }

// ExecInput runs a command as root inside the container with stdin.
func (s *Server) ExecInput(stdin string, args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"exec", "-i", s.container}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func must(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// NewKey returns a fresh Ed25519 signer, like the one `mis init` creates.
func NewKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(fmt.Errorf("signer: %w", err))
	}
	return s
}
