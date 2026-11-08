// Package inventory parses what the collector prints on a server and stores
// the last result per server.
//
// Collector output comes from a machine that could be compromised, so the
// parser is strict: a size limit, a fixed format, and a pattern for every
// field. Anything unexpected rejects the whole inventory.
package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Limits on collector output.
const (
	MaxBytes    = 4 << 20
	MaxPackages = 20000
	header      = "mis-collect 1"
)

// Inventory is what a server (or this computer) reported.
type Inventory struct {
	CollectedAt    time.Time `json:"collected_at"`
	OSID           string    `json:"os_id"`      // ubuntu, debian, macos
	OSVersion      string    `json:"os_version"` // 24.04, 12, 15.7.7
	Kernel         string    `json:"kernel"`     // running kernel (uname -r)
	Arch           string    `json:"arch"`       // dpkg architecture
	RebootRequired bool      `json:"reboot_required"`
	Groups         []string  `json:"groups"` // groups of the mis user
	Packages       []Package `json:"packages"`
	Mac            *Mac      `json:"mac,omitempty"` // this computer, when it's a Mac
}

// Mac is what a Mac reports instead of a package list.
type Mac struct {
	Safari   string        `json:"safari,omitempty"` // installed Safari version
	Updates  []AppleUpdate `json:"updates"`          // pending, from softwareupdate --list
	Homebrew []BrewPackage `json:"homebrew"`         // outdated Homebrew packages
}

// AppleUpdate is one update Apple offers for this Mac.
type AppleUpdate struct {
	Label   string `json:"label"` // softwareupdate's ID, e.g. "macOS Sequoia 15.8.2-24H232"
	Title   string `json:"title"` // e.g. "macOS Sequoia 15.8.2"
	Version string `json:"version"`
	Restart bool   `json:"restart"`
}

// BrewPackage is one outdated Homebrew package.
type BrewPackage struct {
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Current   string `json:"current"`
}

// IsMac reports whether this is a Mac's inventory.
func (inv *Inventory) IsMac() bool { return inv.OSID == "macos" && inv.Mac != nil }

// Package is one installed binary package and the source it was built from.
// Distros file vulnerabilities under the source package name.
type Package struct {
	Name          string `json:"name"` // binary package, without the native :arch suffix
	Version       string `json:"version"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
}

// Supported reports whether Make-It-Safer can check this OS.
func (inv *Inventory) Supported() bool {
	return inv.OSID == "ubuntu" || inv.OSID == "debian"
}

// Sources returns each installed source package once, with its version.
func (inv *Inventory) Sources() []Package {
	seen := map[string]bool{}
	var out []Package
	for _, p := range inv.Packages {
		key := p.Source + "\x00" + p.SourceVersion
		if !seen[key] {
			seen[key] = true
			out = append(out, Package{Source: p.Source, SourceVersion: p.SourceVersion})
		}
	}
	return out
}

// Binaries returns the installed binary packages built from source.
func (inv *Inventory) Binaries(source string) []Package {
	var out []Package
	for _, p := range inv.Packages {
		if p.Source == source {
			out = append(out, p)
		}
	}
	return out
}

// Kernel sources whose packages are not the kernel itself.
var notKernel = map[string]bool{"linux-firmware": true, "linux-base": true, "linux-atm": true, "linux-sound-base": true}

// IsKernelSource reports whether a source package builds the Linux kernel
// (linux, linux-signed-amd64, linux-hwe-6.8, linux-aws, …).
func IsKernelSource(source string) bool {
	return source == "linux" || (strings.HasPrefix(source, "linux-") && !notKernel[source])
}

var (
	osIDPattern      = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)
	osVersionPattern = regexp.MustCompile(`^[0-9]{1,4}(\.[0-9]{1,4})?$`)
	kernelPattern    = regexp.MustCompile(`^[A-Za-z0-9._+~-]{1,128}$`)
	archPattern      = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	groupPattern     = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	statusPattern    = regexp.MustCompile(`^[uihrp][ncHUFWti][ R]?$`)
	binaryPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9-]{1,32})?$`)
	sourcePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)
	versionPattern   = regexp.MustCompile(`^[A-Za-z0-9.+~:-]{1,128}$`)
)

// Parse validates collector output and returns the inventory.
func Parse(data []byte, collectedAt time.Time) (*Inventory, error) {
	if len(data) > MaxBytes {
		return nil, apperr.New(apperr.InventoryTooLarge, fmt.Sprintf("the server sent more than %d bytes", MaxBytes))
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[0] != header {
		return nil, invalid(1, "this is not Make-It-Safer collector output; is the server set up? run: mis server verify")
	}

	inv := &Inventory{CollectedAt: collectedAt.UTC()}
	seen := map[string]bool{}
	for i, line := range lines[1:] {
		n := i + 2
		if rest, ok := strings.CutPrefix(line, "pkg\t"); ok {
			p, err := parsePackage(rest)
			if err != nil {
				return nil, invalid(n, err.Error())
			}
			if p != nil {
				inv.Packages = append(inv.Packages, *p)
			}
			if len(inv.Packages) > MaxPackages {
				return nil, apperr.New(apperr.InventoryTooLarge, fmt.Sprintf("more than %d packages", MaxPackages))
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return nil, invalid(n, "unexpected line")
		}
		seen[key] = true
		if err := inv.set(key, value); err != nil {
			return nil, invalid(n, err.Error())
		}
	}

	if inv.OSID == "" || inv.OSVersion == "" || inv.Kernel == "" || len(inv.Packages) == 0 {
		return nil, invalid(len(lines), "incomplete output (missing OS, kernel or packages)")
	}
	for i := range inv.Packages { // "libc6:amd64" → "libc6" on an amd64 server
		inv.Packages[i].Name = strings.TrimSuffix(inv.Packages[i].Name, ":"+inv.Arch)
	}
	return inv, nil
}

func (inv *Inventory) set(key, value string) error {
	bad := fmt.Errorf("invalid %s", key)
	switch key {
	case "os-id":
		inv.OSID = value
		if !osIDPattern.MatchString(value) {
			return bad
		}
	case "os-version":
		inv.OSVersion = value
		if !osVersionPattern.MatchString(value) {
			return bad
		}
	case "kernel":
		inv.Kernel = value
		if !kernelPattern.MatchString(value) {
			return bad
		}
	case "arch":
		inv.Arch = value
		if value != "" && !archPattern.MatchString(value) {
			return bad
		}
	case "reboot-required":
		inv.RebootRequired = value == "yes"
		if value != "yes" && value != "no" {
			return bad
		}
	case "groups":
		inv.Groups = strings.Fields(value)
		if slices.ContainsFunc(inv.Groups, func(g string) bool { return !groupPattern.MatchString(g) }) {
			return bad
		}
	default:
		return fmt.Errorf("unknown field %q", key)
	}
	return nil
}

// parsePackage parses "status\tbinary\tversion\tsource\tsourceVersion".
// It returns nil for packages that aren't installed (removed, config-files).
func parsePackage(s string) (*Package, error) {
	f := strings.Split(s, "\t")
	if len(f) != 5 {
		return nil, errors.New("malformed package line")
	}
	if !statusPattern.MatchString(f[0]) || !binaryPattern.MatchString(f[1]) || !versionPattern.MatchString(f[2]) ||
		!sourcePattern.MatchString(f[3]) || !versionPattern.MatchString(f[4]) {
		return nil, errors.New("invalid package fields")
	}
	if state := f[0][1]; state == 'n' || state == 'c' { // not installed / config files only
		return nil, nil
	}
	return &Package{Name: f[1], Version: f[2], Source: f[3], SourceVersion: f[4]}, nil
}

func invalid(line int, msg string) error {
	return apperr.New(apperr.InventoryInvalid, fmt.Sprintf("collector output line %d: %s", line, msg))
}

// Save stores a server's inventory in the state directory.
func Save(paths config.Paths, server string, inv *Inventory) error {
	data, err := json.MarshalIndent(inv, "", " ")
	if err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot encode the inventory")
	}
	return config.WriteFileAtomic(path(paths, server), data)
}

// Load returns a server's last inventory, or an INVENTORY_NOT_FOUND error.
func Load(paths config.Paths, server string) (*Inventory, error) {
	data, err := os.ReadFile(path(paths, server))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, apperr.New(apperr.InventoryNotFound, "no package list for "+server+" yet; run: mis check "+server)
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read the inventory of "+server)
	}
	var inv Inventory
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&inv); err != nil {
		return nil, apperr.Wrap(apperr.InventoryInvalid, err, "the saved inventory of "+server+" is damaged")
	}
	return &inv, nil
}

// Remove deletes a server's saved inventory.
func Remove(paths config.Paths, server string) error {
	if err := os.Remove(path(paths, server)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot remove the inventory of "+server)
	}
	return nil
}

func path(paths config.Paths, server string) string {
	return filepath.Join(paths.Inventory, server+".json")
}
