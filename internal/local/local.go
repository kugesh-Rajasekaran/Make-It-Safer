// Package local reads this computer's inventory, so Make-It-Safer can check
// the computer it runs on too:
//   - Linux (Ubuntu, Debian): the same collector as on servers, run directly.
//   - macOS: the macOS and Safari versions, the updates Apple offers
//     (softwareupdate --list) and outdated Homebrew packages.
//
// It only reads. If any part can't be read the whole collection fails, so a
// missing answer never looks like "nothing to update".
package local

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/server"
)

// Collect reads this computer's inventory.
func Collect(ctx context.Context, now time.Time) (*inventory.Inventory, error) {
	switch runtime.GOOS {
	case "darwin":
		return collectMac(ctx, now)
	case "linux":
		out, err := run(ctx, time.Minute, nil, server.Collector, "/bin/sh", "-s")
		if err != nil {
			return nil, err
		}
		return inventory.Parse(out, now)
	}
	return nil, apperr.New(apperr.ServerUnsupportedOS, "checking this computer needs macOS, Ubuntu or Debian")
}

// brewPaths are where Homebrew lives (Apple silicon, then Intel). The
// background service's PATH doesn't include them.
var brewPaths = []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"}

func collectMac(ctx context.Context, now time.Time) (*inventory.Inventory, error) {
	version, err := run(ctx, 10*time.Second, nil, "", "/usr/bin/sw_vers", "-productVersion")
	if err != nil {
		return nil, err
	}
	kernel, err := run(ctx, 10*time.Second, nil, "", "/usr/bin/uname", "-r")
	if err != nil {
		return nil, err
	}
	arch, err := run(ctx, 10*time.Second, nil, "", "/usr/bin/uname", "-m")
	if err != nil {
		return nil, err
	}
	inv := &inventory.Inventory{CollectedAt: now, OSID: "macos", OSVersion: clean(version), Kernel: clean(kernel), Arch: clean(arch), Mac: &inventory.Mac{}}
	if !versionPattern.MatchString(inv.OSVersion) {
		return nil, apperr.New(apperr.InventoryInvalid, fmt.Sprintf("unexpected macOS version %q", inv.OSVersion))
	}
	if safari, err := run(ctx, 10*time.Second, nil, "", "/usr/bin/plutil", "-extract", "CFBundleShortVersionString", "raw", "-o", "-",
		"/Applications/Safari.app/Contents/Info.plist"); err == nil && versionPattern.MatchString(clean(safari)) {
		inv.Mac.Safari = clean(safari)
	}

	updates, err := run(ctx, 3*time.Minute, nil, "", "/usr/sbin/softwareupdate", "--list")
	if err != nil {
		return nil, err
	}
	inv.Mac.Updates = ParseSoftwareUpdate(updates)

	for _, brew := range brewPaths {
		if _, err := os.Stat(brew); err != nil {
			continue
		}
		env := []string{"HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1", "HOMEBREW_NO_ENV_HINTS=1"}
		out, err := run(ctx, 2*time.Minute, env, "", brew, "outdated", "--json=v2")
		if err != nil {
			return nil, err
		}
		if inv.Mac.Homebrew, err = ParseBrewOutdated(out); err != nil {
			return nil, err
		}
		break
	}
	return inv, nil
}

const maxOutput = 4 << 20

// run runs a command with a timeout and returns its standard output.
func run(ctx context.Context, timeout time.Duration, env []string, stdin, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed system tools, no outside input
	cmd.Env = append(os.Environ(), env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, apperr.Wrap(apperr.ServerCommandFailed, err, fmt.Sprintf("cannot read this computer: %s failed %s", name, msg))
	}
	if out.Len() > maxOutput {
		return nil, apperr.New(apperr.InventoryTooLarge, name+" printed more than allowed")
	}
	return out.Bytes(), nil
}

var (
	versionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)
	textPattern    = regexp.MustCompile(`^[A-Za-z0-9 ._+()-]{1,120}$`)
	brewPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9@+._/-]{0,100}$`)
	brewVersion    = regexp.MustCompile(`^[A-Za-z0-9._+,:-]{1,64}$`)
)

func clean(b []byte) string { return strings.TrimSpace(string(b)) }

// ParseSoftwareUpdate reads `softwareupdate --list`:
//
//   - Label: macOS Sequoia 15.8.2-24H232
//     Title: macOS Sequoia 15.8.2, Version: 15.8.2, Size: 2269625KiB, Recommended: YES, Action: restart,
//
// Entries that don't look like that are skipped.
func ParseSoftwareUpdate(out []byte) []inventory.AppleUpdate {
	var updates []inventory.AppleUpdate
	label := ""
	for line := range strings.Lines(string(out)) {
		line = strings.TrimSpace(line)
		if l, ok := strings.CutPrefix(line, "* Label: "); ok {
			label = l
			continue
		}
		if !strings.HasPrefix(line, "Title: ") || label == "" {
			continue
		}
		u := inventory.AppleUpdate{Label: label}
		for part := range strings.SplitSeq(line, ",") {
			key, value, _ := strings.Cut(strings.TrimSpace(part), ": ")
			switch key {
			case "Title":
				u.Title = value
			case "Version":
				u.Version = value
			case "Action":
				u.Restart = value == "restart"
			}
		}
		if textPattern.MatchString(u.Label) && textPattern.MatchString(u.Title) && versionPattern.MatchString(u.Version) {
			updates = append(updates, u)
		}
		label = ""
	}
	return updates
}

// ParseBrewOutdated reads `brew outdated --json=v2` (formulae and casks).
func ParseBrewOutdated(out []byte) ([]inventory.BrewPackage, error) {
	var v struct {
		Formulae []brewEntry `json:"formulae"`
		Casks    []brewEntry `json:"casks"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, apperr.Wrap(apperr.InventoryInvalid, err, "unexpected output from brew outdated")
	}
	var pkgs []inventory.BrewPackage
	for _, e := range append(v.Formulae, v.Casks...) {
		installed := strings.Join(e.Installed, ", ")
		if !brewPattern.MatchString(e.Name) || !brewVersion.MatchString(e.Current) || (installed != "" && !brewVersion.MatchString(strings.ReplaceAll(installed, " ", ""))) {
			continue
		}
		pkgs = append(pkgs, inventory.BrewPackage{Name: e.Name, Installed: installed, Current: e.Current})
	}
	return pkgs, nil
}

type brewEntry struct {
	Name      string   `json:"name"`
	Installed []string `json:"installed_versions"`
	Current   string   `json:"current_version"`
}
