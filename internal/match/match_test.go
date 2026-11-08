package match

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
)

// A typical Ubuntu server's source packages (part of them).
var server = []string{
	"apt", "bash", "curl", "git", "glibc", "openssh", "openssl", "patch", "rsync", "sudo",
	"xz-utils", "file", "tar", "screen", "linux-base", "linux-firmware",
}

// TestRealRecords uses real CVE records (testdata) and what they must match.
func TestRealRecords(t *testing.T) {
	for _, tc := range []struct {
		id        string
		installed []string
		want      []string
		why       string
	}{
		{"CVE-2024-6387", server, []string{"openssh"}, "Red Hat CNA: packageName"},
		{"CVE-2024-3094", server, []string{"xz-utils"}, "alias xz → xz-utils"},
		{"CVE-2023-4911", server, []string{"glibc"}, "packageName glibc"},
		{"CVE-2023-38545", server, []string{"curl"}, "vendor curl, product curl"},
		{"CVE-2021-41773", append(slices.Clone(server), "apache2"), []string{"apache2"}, "alias Apache HTTP Server"},
		{"CVE-2021-41773", server, nil, "apache2 not installed"},
		{"CVE-2024-1086", append(slices.Clone(server), "linux-signed-amd64", "linux"), []string{Kernel}, "kernel, from any kernel source"},
		{"CVE-2024-1086", server, nil, "no kernel installed (a container)"},
		{"CVE-2026-109518", server, []string{"apt"}, "vendor Debian"},
		{"CVE-2026-119741", server, []string{"rsync"}, "vendor RsyncProject names rsync"},
		{"CVE-2026-100407", server, nil, "Git for Windows is not git"},
		{"CVE-2026-121565", server, nil, "Tanium's Patch is not GNU patch"},
	} {
		data, err := os.ReadFile("testdata/" + tc.id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		r, err := cvelist.Parse(data, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if got := Sources(r.Products, tc.installed); !slices.Equal(got, tc.want) {
			t.Errorf("%s (%s): got %v, want %v", tc.id, tc.why, got, tc.want)
		}
	}
}

func TestSources(t *testing.T) {
	type P = cvelist.Product
	for _, tc := range []struct {
		name      string
		products  []P
		installed []string
		want      []string
	}{
		{"Drupal module is not file", []P{{Vendor: "Drupal", Product: "File Force Download"}}, server, nil},
		{"Drupal module, vendor named after it", []P{{Vendor: "File Force Download project", Product: "File Force Download"}}, server, nil},
		{"npm tar is not tar", []P{{Vendor: "isaacs", Product: "node-tar", Package: "tar", CollectionURL: "https://www.npmjs.com/package/tar"}}, append(slices.Clone(server), "node-tar"), nil},
		{"PyPI requests is not Debian's", []P{{Package: "requests", CollectionURL: "https://pypi.org/project/requests"}}, []string{"requests"}, nil},
		{"WordPress plugin", []P{{Vendor: "Redis", Product: "Redis Object Cache plugin"}}, []string{"redis"}, nil},
		{"placeholders", []P{{Vendor: "n/a", Product: "n/a"}}, server, nil},
		{"unknown vendor, generic name", []P{{Vendor: "Acme Corp", Product: "Screen"}}, server, nil},
		{"vendor names the product", []P{{Vendor: "sudo_project", Product: "sudo"}}, server, []string{"sudo"}},
		{"no vendor", []P{{Package: "OpenSSL", CollectionURL: "https://github.com/openssl/openssl"}}, server, []string{"openssl"}},
		{"PostgreSQL, versioned source", []P{{Vendor: "PostgreSQL", Product: "PostgreSQL"}}, []string{"postgresql-16", "postgresql-common"}, []string{"postgresql-16"}},
		{"CPython", []P{{Vendor: "Python Software Foundation", Product: "CPython"}}, []string{"python3.12", "python3-defaults"}, []string{"python3.12"}},
		{"ISC BIND 9", []P{{Vendor: "ISC", Product: "BIND 9"}}, []string{"bind9"}, []string{"bind9"}},
		{"CISA CPE names", []P{{Vendor: "apache", Product: "http_server"}}, []string{"apache2"}, []string{"apache2"}},
		{"kernel.org", []P{{Vendor: "Linux", Product: "Linux"}}, []string{"linux-hwe-6.8"}, []string{Kernel}},
		{"Android kernel is not Linux's alias", []P{{Vendor: "Google", Product: "Android", Package: "kernel"}}, []string{"linux"}, nil},
		{"hostile text", []P{{Vendor: "x", Product: "openssh; rm -rf /"}}, server, nil},
		{"two products", []P{{Vendor: "curl", Product: "curl"}, {Vendor: "OpenSSL", Product: "OpenSSL"}}, server, []string{"curl", "openssl"}},
	} {
		if got := Sources(tc.products, tc.installed); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestUsable(t *testing.T) {
	if Usable([]cvelist.Product{{Vendor: "n/a", Product: "n/a"}}) || Usable(nil) {
		t.Error("placeholders count as usable")
	}
	if !Usable([]cvelist.Product{{Vendor: "n/a", Product: "n/a"}, {Vendor: "curl", Product: "curl"}}) {
		t.Error("a real product doesn't count")
	}
}

func TestNorm(t *testing.T) {
	for in, want := range map[string]string{"XZ Utils": "xz utils", "xz-utils": "xz utils", " Apache  HTTP_Server ": "apache http server", "n/a": "n a", "Ünïcode": "n code"} {
		if got := norm(in); got != want {
			t.Errorf("norm(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzSources(f *testing.F) {
	f.Add("OpenBSD", "OpenSSH", "openssh", "https://www.openssh.com/")
	f.Add("Linux", "Kernel", "kernel", "")
	f.Fuzz(func(t *testing.T, vendor, product, pkg, collection string) {
		installed := []string{"openssh", "linux-signed-amd64", "glibc", "xz-utils"}
		for _, s := range Sources([]cvelist.Product{{Vendor: vendor, Product: product, Package: pkg, CollectionURL: collection}}, installed) {
			if s != Kernel && !slices.Contains(installed, s) {
				t.Fatalf("returned %q, which isn't installed", s)
			}
			if strings.ContainsAny(s, " ;$`") {
				t.Fatalf("unsafe name %q", s)
			}
		}
	})
}
