//go:build integration

package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/fixcmd"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/setup"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/termlaunch"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/testenv"
)

// installDummy builds and installs a tiny Debian package "openssh-dummy"
// built from source "openssh", so the fake data can call it vulnerable.
func installDummy(t *testing.T, srv *testenv.Server, version string) {
	t.Helper()
	script := fmt.Sprintf(`set -e
umask 022
d=$(mktemp -d)
chmod 0755 "$d"
mkdir -p "$d/DEBIAN"
printf 'Package: openssh-dummy\nSource: openssh\nVersion: %[1]s\nArchitecture: all\nMaintainer: test <test@example.org>\nDescription: test package\n' > "$d/DEBIAN/control"
dpkg-deb --build "$d" /tmp/dummy.deb >/dev/null
dpkg -i /tmp/dummy.deb >/dev/null`, version)
	if out, err := srv.Exec("sh", "-c", script); err != nil {
		t.Fatalf("installing the dummy package: %v\n%s", err, out)
	}
}

// TestCheckFindsAndResolves: a real server with an "old" package is found
// vulnerable; after upgrading it, the finding is resolved.
func TestCheckFindsAndResolves(t *testing.T) {
	srv := testenv.Start(t, testenv.Images[len(testenv.Images)-1])
	misKey := testenv.NewKey(t)
	script, err := setup.Script(misKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := srv.AdminRun(setup.RemoteCommand(script)); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	installDummy(t, srv, "1:9.6p1-3ubuntu13.5")

	// Fake data says openssh is fixed in 1:9.6p1-3ubuntu13.8.
	e, paths := newEngine(t, &fakeData{fixed: "1:9.6p1-3ubuntu13.8"})
	hk := sshx.HostKeys{Path: filepath.Join(paths.Home, "known_hosts")}
	if err := hk.Pin(srv.Target, srv.HostKey); err != nil {
		t.Fatal(err)
	}
	e.Paths.KnownHosts = hk.Path
	server := config.Server{Name: "it", Host: srv.Target.Host, Port: srv.Target.Port, AdminSSH: "admin@" + srv.Target.Host}
	srv.WaitReady()

	// The fake data only knows Ubuntu 24.04; skip if the image is another release.
	res, err := e.Check(context.Background(), misKey, []config.Server{server})
	if err != nil {
		t.Fatal(err)
	}
	if res.Servers[0].OS != "ubuntu 24.04" {
		t.Skipf("fake data covers Ubuntu 24.04, image is %s", res.Servers[0].OS)
	}
	st, _ := findings.Load(paths)
	f := st.Find("it/vulnerability/CVE-2024-6387/openssh")
	if f == nil || !f.Open() || f.Fixed != "1:9.6p1-3ubuntu13.8" {
		t.Fatalf("expected an open finding with the fix, got %+v (result %+v)", f, res)
	}

	installDummy(t, srv, "1:9.6p1-3ubuntu13.8") // the "upgrade"
	if _, err := e.Check(context.Background(), misKey, []config.Server{server}); err != nil {
		t.Fatal(err)
	}
	st, _ = findings.Load(paths)
	if f := st.Find("it/vulnerability/CVE-2024-6387/openssh"); f == nil || f.Open() {
		t.Fatalf("finding should be resolved after the upgrade: %+v", f)
	}
}

// TestFixFlow is the whole fix button, minus the GUI: the update command is
// typed into a real SSH terminal, Enter runs it, and the next check marks
// the vulnerability fixed.
func TestFixFlow(t *testing.T) {
	srv := testenv.Start(t, testenv.Images[len(testenv.Images)-1])
	misKey := testenv.NewKey(t)
	script, _ := setup.Script(misKey.PublicKey())
	if out, err := srv.AdminRun(setup.RemoteCommand(script)); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	installDummy(t, srv, "1:9.6p1-3ubuntu13.5")
	// A local apt repository holding the fixed version, and nothing else.
	repo := `set -e
umask 022
d=$(mktemp -d)
chmod 0755 "$d"
mkdir -p "$d/DEBIAN" /srv/repo
printf 'Package: openssh-dummy\nSource: openssh\nVersion: 1:9.6p1-3ubuntu13.8\nArchitecture: all\nMaintainer: test <test@example.org>\nDescription: test package\n' > "$d/DEBIAN/control"
dpkg-deb --build "$d" /srv/repo/openssh-dummy.deb >/dev/null
cd /srv/repo && apt-ftparchive packages . > Packages
mkdir -p /root/apt-sources && mv /etc/apt/sources.list.d/* /root/apt-sources/ 2>/dev/null || true
: > /etc/apt/sources.list
echo 'deb [trusted=yes] file:/srv/repo ./' > /etc/apt/sources.list.d/mis-test.list`
	if out, err := srv.Exec("sh", "-c", repo); err != nil {
		t.Fatalf("local repository: %v\n%s", err, out)
	}

	e, paths := newEngine(t, &fakeData{fixed: "1:9.6p1-3ubuntu13.8"})
	hk := sshx.HostKeys{Path: filepath.Join(paths.Home, "known_hosts")}
	_ = hk.Pin(srv.Target, srv.HostKey)
	e.Paths.KnownHosts = hk.Path
	server := config.Server{Name: "it", Host: srv.Target.Host, Port: srv.Target.Port, AdminSSH: "admin@" + srv.Target.Host}
	srv.WaitReady()
	if res, err := e.Check(context.Background(), misKey, []config.Server{server}); err != nil || res.Servers[0].OS != "ubuntu 24.04" {
		t.Skipf("needs Ubuntu 24.04 (fake data): %v %+v", err, res)
	}

	inv, _ := inventory.Load(paths, "it")
	st, _ := findings.Load(paths)
	f := st.Find("it/vulnerability/CVE-2024-6387/openssh")
	cmd, err := fixcmd.Build(inv, []*findings.Finding{f})
	// Every installed package built from openssh is upgraded together.
	if err != nil || !strings.HasPrefix(cmd.Sudo, "sudo apt-get update && sudo apt-get install --only-upgrade ") || !slices.Contains(cmd.Packages, "openssh-dummy") {
		t.Fatalf("fix command = %+v, %v", cmd, err)
	}
	remote := termlaunch.RemoteCommand(termlaunch.RemoteScript(termlaunch.Banner("it", []*findings.Finding{f}, cmd), cmd))

	// Ctrl-C skips to a normal shell without running anything.
	skip := srv.AdminTerminal(t, remote)
	skip.WaitFor(t, cmd.Sudo, 30*time.Second)
	time.Sleep(200 * time.Millisecond)
	skip.Type("\x03")
	time.Sleep(300 * time.Millisecond) // like a person: wait for the shell, then type
	skip.Type("echo skipped-$((40+2))\r")
	skip.WaitFor(t, "skipped-42", 30*time.Second)
	if strings.Contains(skip.Output(), "Reading package lists") {
		t.Fatalf("Ctrl-C ran the command:\n%s", skip.Output())
	}

	term := srv.AdminTerminal(t, remote)
	term.WaitFor(t, cmd.Sudo, 30*time.Second) // typed in, waiting for Enter
	if strings.Contains(term.Output(), "Setting up") {
		t.Fatal("the command ran before Enter")
	}
	term.Type("\r")
	term.WaitFor(t, "Do you want to continue?", 2*time.Minute) // apt still asks you
	term.Type("y\r")
	term.WaitFor(t, "Setting up openssh-dummy (1:9.6p1-3ubuntu13.8)", 2*time.Minute)
	term.Type("exit\r")

	if _, err := e.Check(context.Background(), misKey, []config.Server{server}); err != nil {
		t.Fatal(err)
	}
	st, _ = findings.Load(paths)
	if f := st.Find("it/vulnerability/CVE-2024-6387/openssh"); f.Open() {
		t.Fatalf("still open after the fix: %+v", f)
	}
}
