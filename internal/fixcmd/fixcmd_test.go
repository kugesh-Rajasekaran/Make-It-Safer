package fixcmd

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
)

func inv(pkgs ...inventory.Package) *inventory.Inventory {
	return &inventory.Inventory{OSID: "ubuntu", OSVersion: "24.04", Kernel: "6.8.0-49-generic", Packages: pkgs}
}

func pkg(name, source string) inventory.Package {
	return inventory.Package{Name: name, Version: "1", Source: source, SourceVersion: "1"}
}

func vuln(cve, source string, fixed string) *findings.Finding {
	return &findings.Finding{Kind: findings.KindVulnerability, CVE: cve, Source: source, Fixed: fixed}
}

func TestBuild(t *testing.T) {
	server := inv(
		pkg("openssh-server", "openssh"), pkg("openssh-client", "openssh"), pkg("libssl3t64", "openssl"),
		pkg("linux-image-6.8.0-49-generic", "linux-signed"), pkg("linux-generic", "linux-meta"),
		pkg("linux-image-generic", "linux-meta"), pkg("linux-firmware", "linux-firmware"),
	)
	cases := []struct {
		name     string
		findings []*findings.Finding
		sudo     string
		root     string
		note     string
	}{
		{"one package source", []*findings.Finding{vuln("CVE-2024-6387", "openssh", "1:9.6p1-3ubuntu13.8")},
			"sudo apt-get update && sudo apt-get install --only-upgrade openssh-client openssh-server",
			"apt-get update && apt-get install --only-upgrade openssh-client openssh-server", ""},
		{"several CVEs, combined", []*findings.Finding{vuln("CVE-1", "openssh", "2"), vuln("CVE-2", "openssl", "3"), vuln("CVE-3", "openssh", "2")},
			"sudo apt-get update && sudo apt-get install --only-upgrade libssl3t64 openssh-client openssh-server", "", ""},
		{"kernel upgrades the meta-packages", []*findings.Finding{vuln("CVE-4", "linux-signed", "6.8.0-51.52")},
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-generic linux-image-generic", "", "Restart afterwards"},
		{"no fix yet", []*findings.Finding{vuln("CVE-5", "openssh", "")}, "", "", "no fix yet"},
		{"restart only", []*findings.Finding{{Kind: findings.KindReboot}}, "sudo reboot", "reboot", "restarts the server"},
		{"ubuntu pro", []*findings.Finding{{Kind: findings.KindVulnerability, CVE: "CVE-6", Source: "openssl", Fixed: "3+esm1", ProOnly: true}},
			"sudo apt-get update && sudo apt-get install --only-upgrade libssl3t64", "", "Ubuntu Pro"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := Build(server, tc.findings)
			if err != nil {
				t.Fatal(err)
			}
			if cmd.Sudo != tc.sudo || (tc.root != "" && cmd.Root != tc.root) {
				t.Fatalf("got sudo %q, root %q", cmd.Sudo, cmd.Root)
			}
			if tc.note != "" && !strings.Contains(strings.Join(cmd.Notes, "\n"), tc.note) {
				t.Fatalf("notes %q lack %q", cmd.Notes, tc.note)
			}
		})
	}
}

// A compromised server could report hostile package names; they must never
// reach the command.
func TestBuildRejectsHostilePackageNames(t *testing.T) {
	for _, name := range []string{"x;rm -rf /", "$(curl evil)", "-oProxy", "a b", "pkg`id`", "UPPER", "x\nreboot"} {
		server := inv(pkg(name, "openssh"))
		if _, err := Build(server, []*findings.Finding{vuln("CVE-1", "openssh", "2")}); !apperr.Is(err, apperr.FixInvalidPackage) {
			t.Errorf("package %q: Build() = %v", name, err)
		}
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"openssh-server":      "openssh-server",
		"libc6:i386":          "libc6:i386",
		"it's":                `'it'\''s'`,
		"$(id)":               "'$(id)'",
		"two words; and more": "'two words; and more'",
	} {
		got := Quote(in)
		if got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
		out, err := exec.Command("sh", "-c", "printf %s "+got).Output()
		if err != nil || string(out) != in {
			t.Errorf("Quote(%q) did not survive the shell: %q, %v", in, out, err)
		}
	}
}
