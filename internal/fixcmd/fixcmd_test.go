package fixcmd

import (
	"os/exec"
	"slices"
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

// Meta-packages may carry a release or series number; a kernel's own
// packages carry its full version and are never the thing to upgrade.
func TestKernelMetas(t *testing.T) {
	cases := []struct {
		name      string
		installed []string
		want      []string
	}{
		{"Ubuntu GA", []string{"linux-generic", "linux-image-generic", "linux-headers-generic", "linux-virtual", "linux-image-virtual"},
			[]string{"linux-generic", "linux-image-generic", "linux-headers-generic", "linux-virtual", "linux-image-virtual"}},
		{"Ubuntu HWE", []string{"linux-generic-hwe-22.04", "linux-image-generic-hwe-22.04", "linux-headers-generic-hwe-22.04", "linux-virtual-hwe-24.04", "linux-image-virtual-hwe-24.04"},
			[]string{"linux-generic-hwe-22.04", "linux-image-generic-hwe-22.04", "linux-headers-generic-hwe-22.04", "linux-virtual-hwe-24.04", "linux-image-virtual-hwe-24.04"}},
		{"Ubuntu OEM", []string{"linux-oem-22.04b", "linux-image-oem-24.04", "linux-oem-24.04"},
			[]string{"linux-oem-22.04b", "linux-image-oem-24.04", "linux-oem-24.04"}},
		{"Ubuntu cloud LTS", []string{"linux-image-aws-lts-22.04", "linux-azure-lts-22.04", "linux-image-azure-fde-lts-22.04"},
			[]string{"linux-image-aws-lts-22.04", "linux-azure-lts-22.04", "linux-image-azure-fde-lts-22.04"}},
		{"series meta", []string{"linux-generic-6.8", "linux-image-virtual-6.14"}, []string{"linux-generic-6.8", "linux-image-virtual-6.14"}},
		{"Debian", []string{"linux-image-amd64", "linux-image-cloud-amd64", "linux-image-rt-arm64"},
			[]string{"linux-image-amd64", "linux-image-cloud-amd64", "linux-image-rt-arm64"}},
		{"GA and HWE together", []string{"linux-generic", "linux-image-generic", "linux-generic-hwe-22.04", "linux-image-generic-hwe-22.04"},
			[]string{"linux-generic", "linux-image-generic", "linux-generic-hwe-22.04", "linux-image-generic-hwe-22.04"}},
		{"real kernel packages", []string{
			"linux-image-6.8.0-49-generic", "linux-modules-6.8.0-49-generic", "linux-modules-extra-6.8.0-49-generic", "linux-headers-6.8.0-49",
			"linux-headers-6.8.0-49-generic", "linux-tools-6.8.0-49", "linux-hwe-6.8-headers-6.8.0-49", "linux-image-6.1.0-18-amd64", "linux-headers-6.1.0-18-common"}, nil},
		{"build helpers and non-kernel linux packages", []string{
			"linux-kbuild-6.1", "linux-config-6.1", "linux-source-6.1", "linux-doc-6.1", "linux-perf-6.1", "linux-compiler-gcc-12-x86", "linux-support-6.1.0-18",
			"linux-base", "linux-firmware", "linux-libc-dev", "linux-tools-common", "linux-doc", "linux-source", "linux-image-generic:amd64", "libc6", "openssh-server"}, nil},
		{"kept next to the real kernel", []string{"linux-image-6.8.0-49-generic", "linux-generic-hwe-22.04", "linux-kbuild-6.1"}, []string{"linux-generic-hwe-22.04"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pkgs []inventory.Package
			for _, n := range tc.installed {
				pkgs = append(pkgs, pkg(n, "linux-meta"))
			}
			got := kernelMetas(inv(pkgs...))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("kernelMetas() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildKernelFixWithVersionedMetas(t *testing.T) {
	cases := []struct {
		name      string
		installed []string
		source    string
		want      string
	}{
		{"HWE only", []string{"linux-image-6.8.0-49-generic", "linux-generic-hwe-22.04", "linux-image-generic-hwe-22.04", "linux-headers-generic-hwe-22.04"}, "linux-signed-hwe-6.8",
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-generic-hwe-22.04 linux-headers-generic-hwe-22.04 linux-image-generic-hwe-22.04"},
		{"OEM only", []string{"linux-image-6.8.0-1005-oem", "linux-oem-24.04", "linux-image-oem-24.04"}, "linux-signed-oem-6.8",
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-image-oem-24.04 linux-oem-24.04"},
		{"cloud LTS only", []string{"linux-image-6.8.0-1010-azure", "linux-azure-lts-22.04", "linux-image-azure-lts-22.04"}, "linux-signed-azure",
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-azure-lts-22.04 linux-image-azure-lts-22.04"},
		{"GA and HWE both installed", []string{"linux-image-6.8.0-49-generic", "linux-generic", "linux-image-generic", "linux-generic-hwe-22.04", "linux-image-generic-hwe-22.04"}, "linux-signed-hwe-6.8",
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-generic linux-generic-hwe-22.04 linux-image-generic linux-image-generic-hwe-22.04"},
		{"Debian", []string{"linux-image-6.1.0-18-amd64", "linux-image-amd64", "linux-kbuild-6.1", "linux-config-6.1"}, "linux-signed-amd64",
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-image-amd64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pkgs []inventory.Package
			for _, n := range tc.installed {
				pkgs = append(pkgs, pkg(n, tc.source))
			}
			cmd, err := Build(inv(pkgs...), []*findings.Finding{vuln("CVE-2026-0001", tc.source, "6.8.0-51.52")})
			if err != nil {
				t.Fatal(err)
			}
			if cmd.Sudo != tc.want {
				t.Fatalf("Build() = %q\nwant %q", cmd.Sudo, tc.want)
			}
			if !strings.Contains(strings.Join(cmd.Notes, "\n"), "Restart afterwards") {
				t.Fatalf("no restart note: %q", cmd.Notes)
			}
		})
	}
}
