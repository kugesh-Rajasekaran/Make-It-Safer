// Package fixcmd builds the update command typed into your SSH session.
// It is the only place commands are built, and it only uses package names
// your own server reported, after validating them. Text from vulnerability
// feeds never ends up in a command.
package fixcmd

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/findings"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
)

// Command is a fix, in two forms: for a normal login (with sudo) and for root.
type Command struct {
	Sudo     string   `json:"sudo,omitempty"`
	Root     string   `json:"root,omitempty"`
	Packages []string `json:"packages,omitempty"`
	Notes    []string `json:"notes,omitempty"` // shown above the command
}

// Empty reports whether there is nothing to run.
func (c *Command) Empty() bool { return c.Root == "" }

var (
	packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9-]{1,32})?$`)
	safeToken      = regexp.MustCompile(`^[A-Za-z0-9+.:_/=-]+$`)
	versioned      = regexp.MustCompile(`[0-9]+\.[0-9]+`)
)

// Kernel meta-packages and others that never pull in a new kernel.
var notMeta = map[string]bool{
	"linux-base": true, "linux-firmware": true, "linux-libc-dev": true, "linux-tools-common": true,
	"linux-sound-base": true, "linux-doc": true, "linux-source": true,
}

// Build returns the fix for some of a server's findings.
func Build(inv *inventory.Inventory, fs []*findings.Finding) (*Command, error) {
	cmd := &Command{}
	reboot := false
	var packages []string
	for _, f := range fs {
		switch f.Kind {
		case findings.KindReboot:
			reboot = true
		case findings.KindEndOfLife:
			cmd.Notes = append(cmd.Notes, "No package update fixes this: upgrade the server to a supported release.")
		case findings.KindVulnerability:
			if !f.HasFix() {
				cmd.Notes = append(cmd.Notes, fmt.Sprintf("%s has no fix yet; nothing to install for it.", f.CVE))
				continue
			}
			pkgs := names(inv.Binaries(f.Source))
			if inventory.IsKernelSource(f.Source) {
				if metas := kernelMetas(inv); len(metas) > 0 {
					pkgs = metas
				}
				reboot = true
			}
			packages = append(packages, pkgs...)
			if f.ProOnly {
				cmd.Notes = append(cmd.Notes, fmt.Sprintf("The fix for %s comes from Ubuntu Pro. If this server isn't attached yet: sudo pro attach <token>", f.CVE))
			}
		}
	}

	slices.Sort(packages)
	packages = slices.Compact(packages)
	for _, p := range packages {
		if !packagePattern.MatchString(p) {
			return nil, apperr.New(apperr.FixInvalidPackage, fmt.Sprintf("refusing to build a command with the package name %q", p))
		}
	}
	cmd.Packages = packages

	var steps []string
	if len(packages) > 0 {
		steps = append(steps, "apt-get update", "apt-get install --only-upgrade "+quoteAll(packages))
	}
	switch {
	case reboot && len(steps) > 0:
		cmd.Notes = append(cmd.Notes, "Restart afterwards so the new kernel runs: sudo reboot")
	case reboot:
		steps = append(steps, "reboot")
		cmd.Notes = append(cmd.Notes, "This restarts the server.")
	}
	if len(steps) > 0 {
		cmd.Root = strings.Join(steps, " && ")
		sudo := make([]string, len(steps))
		for i, s := range steps {
			sudo[i] = "sudo " + s
		}
		cmd.Sudo = strings.Join(sudo, " && ")
	}
	cmd.Notes = slices.Compact(cmd.Notes)
	return cmd, nil
}

func names(ps []inventory.Package) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

// kernelMetas returns the installed kernel meta-packages (linux-generic,
// linux-image-amd64, …). Upgrading them installs the newest kernel.
func kernelMetas(inv *inventory.Inventory) []string {
	var out []string
	for _, p := range inv.Packages {
		if strings.HasPrefix(p.Name, "linux-") && !versioned.MatchString(p.Name) && !notMeta[p.Name] && !strings.Contains(p.Name, ":") {
			out = append(out, p.Name)
		}
	}
	return out
}

// Quote makes s safe as one shell word: plain tokens stay as they are,
// anything else is single-quoted.
func Quote(s string) string {
	if safeToken.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func quoteAll(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = Quote(s)
	}
	return strings.Join(q, " ")
}
