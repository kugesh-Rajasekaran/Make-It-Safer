//go:build integration

package setup

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/testenv"
)

// TestSetupVerifyTeardown runs the real scripts on every supported distro:
// set up, prove the restrictions, set up again, then remove everything.
func TestSetupVerifyTeardown(t *testing.T) {
	for _, base := range testenv.Images {
		t.Run(base, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			srv := testenv.Start(t, base)
			misKey := testenv.NewKey(t)
			script, err := Script(misKey.PublicKey())
			if err != nil {
				t.Fatal(err)
			}

			for run := 1; run <= 2; run++ { // the second run proves it is safe to repeat
				if out, err := srv.AdminRun(RemoteCommand(script)); err != nil || !strings.Contains(out, "mis-setup: done") {
					t.Fatalf("setup run %d failed: %v\n%s", run, err, out)
				}
			}

			hk := sshx.HostKeys{Path: filepath.Join(t.TempDir(), "known_hosts")}
			if err := hk.Pin(srv.Target, srv.HostKey); err != nil {
				t.Fatal(err)
			}
			srv.WaitReady()
			report, err := Verify(ctx, srv.Target, hk, misKey, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if !report.OK {
				t.Fatalf("verify failed: %+v", report.Checks)
			}
			wantOS := strings.Replace(strings.Split(base, ":")[0]+" "+strings.Split(base, ":")[1], ":", " ", 1)
			if report.OS != wantOS || report.Packages < 50 {
				t.Fatalf("inventory: OS %q, %d packages", report.OS, report.Packages)
			}
			if _, err := srv.Exec("test", "-e", "/tmp/mis-was-here"); err == nil {
				t.Fatal("the command mis asked for actually ran; only the collector may run")
			}
			if out, err := srv.AdminRun("id -un"); err != nil || strings.TrimSpace(out) != "admin" {
				t.Fatalf("admin login broken after setup: %v %q", err, out)
			}

			if out, err := srv.AdminRun(RemoteCommand(TeardownScript())); err != nil || !strings.Contains(out, "mis-teardown: done") {
				t.Fatalf("teardown failed: %v\n%s", err, out)
			}
			if _, err := srv.Exec("id", "mis"); err == nil {
				t.Fatal("the mis user still exists after teardown")
			}
			srv.WaitReady()
			if _, err := sshx.Dial(ctx, srv.Target, hk, misKey); !apperr.Is(err, apperr.ServerAuthFailed) {
				t.Fatalf("login as mis after teardown = %v", err)
			}
		})
	}
}

// TestSetupWithoutDropInDirectory covers sshd_config files that don't
// include sshd_config.d: the settings go into a marked block instead.
func TestSetupWithoutDropInDirectory(t *testing.T) {
	srv := testenv.Start(t, testenv.Images[len(testenv.Images)-1])
	if out, err := srv.Exec("sed", "-i", `/^Include \/etc\/ssh\/sshd_config.d/d`, "/etc/ssh/sshd_config"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	misKey := testenv.NewKey(t)
	script, _ := Script(misKey.PublicKey())
	if out, err := srv.AdminRun(RemoteCommand(script)); err != nil {
		t.Fatalf("setup failed: %v\n%s", err, out)
	}
	if out, _ := srv.Exec("grep", "-c", "BEGIN make-it-safer", "/etc/ssh/sshd_config"); strings.TrimSpace(out) != "1" {
		t.Fatal("marked block not added to sshd_config")
	}
	hk := sshx.HostKeys{Path: filepath.Join(t.TempDir(), "known_hosts")}
	_ = hk.Pin(srv.Target, srv.HostKey)
	srv.WaitReady()
	if report, err := Verify(context.Background(), srv.Target, hk, misKey, time.Now()); err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
	if out, err := srv.AdminRun(RemoteCommand(TeardownScript())); err != nil {
		t.Fatalf("teardown failed: %v\n%s", err, out)
	}
	if out, _ := srv.Exec("grep", "-c", "make-it-safer", "/etc/ssh/sshd_config"); strings.TrimSpace(out) != "0" {
		t.Fatal("marked block left in sshd_config")
	}
}

// TestSetupRefusesAndRollsBack checks that setup changes nothing when it
// can't finish safely.
func TestSetupRefusesAndRollsBack(t *testing.T) {
	cases := map[string]struct {
		prepare string // run as root before setup
		message string
	}{
		"someone else's mis user":  {"useradd mis", "already exists"},
		"AllowUsers excludes mis":  {"echo 'AllowUsers admin' >> /etc/ssh/sshd_config", "AllowUsers"},
		"AllowUsers lookalike":     {"echo 'AllowUsers admin mis-admin' >> /etc/ssh/sshd_config", "AllowUsers"},
		"AllowGroups excludes mis": {"echo 'AllowGroups wheel' >> /etc/ssh/sshd_config", "AllowGroups"},
		"DenyGroups blocks mis":    {"echo 'DenyGroups mi*' >> /etc/ssh/sshd_config", "DenyGroups"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := testenv.Start(t, testenv.Images[0])
			if out, err := srv.Exec("sh", "-c", tc.prepare); err != nil {
				t.Fatalf("%v %s", err, out)
			}
			before, _ := srv.Exec("getent", "passwd", "mis")
			script, _ := Script(testenv.NewKey(t).PublicKey())
			out, err := srv.AdminRun(RemoteCommand(script))
			if err == nil || !strings.Contains(out, tc.message) {
				t.Fatalf("setup should fail mentioning %q: %v\n%s", tc.message, err, out)
			}
			if _, err := srv.Exec("test", "-e", "/etc/ssh/sshd_config.d/50-mis.conf"); err == nil {
				t.Fatal("sshd drop-in left behind")
			}
			if after, _ := srv.Exec("getent", "passwd", "mis"); after != before {
				t.Fatalf("mis user changed: %q → %q", before, after)
			}
		})
	}
}
