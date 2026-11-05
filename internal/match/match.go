// Package match finds which installed source packages a new CVE may be
// about, from the vendor, product and package names in its CVE record.
//
// It is only used for early warnings, before the distros have assessed a
// CVE: names are matched exactly (after normalising case and punctuation)
// or through a curated alias table, never fuzzily. A bare product name only
// counts when its vendor is plausible (see vendorOK). Entries from language
// registries, CMS plugins and other operating systems are skipped.
// Confirmed findings always come from distro data (OSV), not from here.
package match

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds/cvelist"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
)

// Kernel is the source reported for the Linux kernel, whichever kernel
// packages (linux-signed-amd64, linux-aws, …) are installed.
const Kernel = "linux"

// aliases maps a normalised product, package or "vendor product" name to
// the Debian/Ubuntu source packages it means: exact names, or patterns
// (anchored regular expressions) for versioned sources. "kernel" means any
// kernel source.
var aliases = map[string][]string{
	"linux linux":        {"kernel"}, // kernel.org: vendor Linux, product Linux
	"linux kernel":       {"kernel"}, // vendor Linux, product Kernel
	"linux linux kernel": {"kernel"}, // CISA: linux/linux_kernel
	"red hat kernel":     {"kernel"}, // Red Hat's package name
	"apache http server": {"apache2"},
	"httpd":              {"apache2"},
	"apache tomcat":      {`tomcat[0-9]+`},
	"glibc":              {"glibc"},
	"gnu c library":      {"glibc"},
	"xz":                 {"xz-utils"},
	"libcurl":            {"curl"},
	"bind":               {"bind9"},
	"bind 9":             {"bind9"},
	"isc bind":           {"bind9"},
	"isc bind 9":         {"bind9"},
	"exim":               {"exim4"},
	"polkit":             {"policykit-1", "polkit"},
	"linux pam":          {"pam"},
	"mit kerberos":       {"krb5"},
	"mit kerberos 5":     {"krb5"},
	"kerberos 5":         {"krb5"},
	"gnutls":             {"gnutls28"},
	"gnupg":              {"gnupg2"},
	"libgcrypt":          {"libgcrypt20"},
	"libexpat":           {"expat"},
	"libtiff":            {"tiff"},
	"libpng":             {"libpng1.6"},
	"sqlite":             {"sqlite3"},
	"grub":               {"grub2"},
	"gnu grub":           {"grub2"},
	"grub2":              {"grub2"},
	"cyrus sasl":         {"cyrus-sasl2"},
	"node js":            {"nodejs"},
	"postgresql":         {`postgresql-[0-9]+`},
	"mysql":              {`mysql-[0-9.]+`},
	"mysql server":       {`mysql-[0-9.]+`},
	"oracle mysql":       {`mysql-[0-9.]+`},
	"mariadb":            {"mariadb", `mariadb-[0-9.]+`},
	"python":             {`python3\.[0-9]+`},
	"cpython":            {`python3\.[0-9]+`},
	"php":                {`php[0-9.]+`},
	"openjdk":            {`openjdk-[0-9]+`},
	"ruby":               {`ruby[0-9.]+`},
	"docker":             {"docker.io"},
	"moby":               {"docker.io"},
	"nginx open source":  {"nginx"},
	"f5 nginx":           {"nginx"},
}

// Vendors whose bare product names can be trusted: upstream projects and
// distros of software Ubuntu and Debian ship (normalised; CISA's CPE vendor
// names included). Any other vendor must name the product itself, like
// "RsyncProject" for rsync.
var knownVendors = []string{
	"debian", "ubuntu", "canonical", "canonical ltd", "red hat", "redhat",
	"gnu", "the gnu c library", "free software foundation", "openbsd", "the openbsd project",
	"apache", "apache software foundation", "the apache software foundation",
	"isc", "internet systems consortium", "linux", "kernel org", "the linux foundation",
	"mozilla", "python", "python software foundation", "php", "php group", "the php group",
	"openssl", "openssl project", "postgresql", "the postgresql global development group",
	"oracle", "mariadb", "mariadb foundation", "redis", "f5", "nginx", "haxx", "samba",
	"tukaani", "systemd", "freedesktop", "freedesktop org", "x org", "x org foundation",
	"gnome", "kde", "nodejs", "openjs foundation", "docker", "mit", "libssh", "libssh2",
	"qemu", "xen", "xen project", "vim", "git", "git project", "exim", "dovecot", "postfix",
}

// Registries of language packages and CMS plugins: their package names
// are not distro packages, even when they look the same (npm "tar").
var registryHosts = []string{
	"npmjs.com", "npmjs.org", "pypi.org", "pypi.python.org", "rubygems.org", "crates.io",
	"pkg.go.dev", "proxy.golang.org", "maven.org", "maven.apache.org", "sonatype.com",
	"nuget.org", "packagist.org", "hex.pm", "pub.dev", "cocoapods.org",
	"wordpress.org", "drupal.org", "joomla.org", "catalog.redhat.com",
}

// Words that mark an add-on for other software, or software for another
// operating system ("Git for Windows").
var skipWords = []string{
	"plugin", "plugins", "theme", "themes", "extension", "extensions", "addon", "addons",
	"wordpress", "drupal", "joomla", "woocommerce", "windows", "macos", "android", "ios",
}

var patterns = map[string]*regexp.Regexp{}

func init() {
	for _, targets := range aliases {
		for _, t := range targets {
			if strings.ContainsAny(t, `[\+`) {
				patterns[t] = regexp.MustCompile(`^(?:` + t + `)$`)
			}
		}
	}
}

// Sources returns the installed source packages the products name, sorted.
// The kernel is reported as Kernel.
func Sources(products []cvelist.Product, installed []string) []string {
	var out []string
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	byName := map[string][]string{} // normalised source name → sources
	for _, src := range installed {
		byName[norm(src)] = append(byName[norm(src)], src)
	}
	for _, p := range products {
		if !usable(p) {
			continue
		}
		for _, n := range names(p) {
			if !n.withVendor && !vendorOK(p.Vendor, n.name) {
				continue
			}
			for _, src := range byName[n.name] { // exact name
				add(src)
			}
			for _, target := range aliases[n.name] {
				for _, src := range installed {
					if matches(target, src) {
						if inventory.IsKernelSource(src) {
							src = Kernel
						}
						add(src)
					}
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// Usable reports whether any product could be matched at all (records
// often name it only later, when CISA adds it).
func Usable(products []cvelist.Product) bool {
	return slices.ContainsFunc(products, usable)
}

type name struct {
	name       string
	withVendor bool // includes the vendor, like "apache http server"
}

// names are the normalised names to look up for one product.
func names(p cvelist.Product) []name {
	var out []name
	for i, n := range []string{p.Product, p.Package, p.Vendor + " " + p.Product, p.Vendor + " " + p.Package} {
		n = norm(n)
		if len(n) < 2 || placeholder(n) || slices.ContainsFunc(out, func(o name) bool { return o.name == n }) {
			continue
		}
		if i >= 2 && (placeholder(norm(p.Vendor)) || n == norm(p.Product) || n == norm(p.Package)) {
			continue // no vendor to add
		}
		out = append(out, name{name: n, withVendor: i >= 2})
	}
	return out
}

// vendorOK reports whether a bare product name from this vendor can be
// trusted: no vendor given, a known one, or one that names the product
// ("sudo_project", "RsyncProject"). It rejects "Tanium" for "Patch".
func vendorOK(vendor, product string) bool {
	v := norm(vendor)
	if placeholder(v) || slices.Contains(knownVendors, v) {
		return true
	}
	return strings.Contains(strings.ReplaceAll(v, " ", ""), strings.ReplaceAll(product, " ", ""))
}

func usable(p cvelist.Product) bool {
	if placeholder(norm(p.Product)) && placeholder(norm(p.Package)) {
		return false
	}
	if u, err := url.Parse(p.CollectionURL); err == nil && u.Host != "" {
		host := strings.ToLower(u.Host)
		for _, r := range registryHosts {
			if host == r || strings.HasSuffix(host, "."+r) {
				return false
			}
		}
	}
	words := strings.Fields(norm(p.Vendor) + " " + norm(p.Product) + " " + norm(p.Package))
	return !slices.ContainsFunc(words, func(w string) bool { return slices.Contains(skipWords, w) })
}

// placeholder reports names that say nothing ("n/a", "unknown").
func placeholder(n string) bool {
	switch n {
	case "", "n a", "na", "unknown", "unspecified", "not applicable", "none":
		return true
	}
	return false
}

func matches(target, src string) bool {
	switch {
	case target == "kernel":
		return inventory.IsKernelSource(src)
	case patterns[target] != nil:
		return patterns[target].MatchString(src)
	default:
		return target == src
	}
}

// norm lowercases s and turns every run of other characters into one
// space: "XZ Utils" and "xz-utils" both become "xz utils".
func norm(s string) string {
	var b strings.Builder
	gap := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if gap && b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteRune(r)
			gap = false
		} else {
			gap = true
		}
	}
	return b.String()
}
