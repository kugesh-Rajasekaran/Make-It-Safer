// Package config holds Make-It-Safer's on-disk layout, its configuration
// schema, and the file helpers (atomic writes, locking, permission checks)
// the other packages share.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// EnvHome overrides the Make-It-Safer home directory. It is used by tests and
// to run separate profiles. It never holds secrets.
const EnvHome = "MIS_HOME"

// Paths is the on-disk layout. Everything lives under Home (mode 0700).
type Paths struct {
	Home       string // base directory
	Config     string // config.yaml
	KeyFile    string // key.enc: the encrypted private key
	PublicKey  string // key.pub: the public key installed on servers
	KnownHosts string // pinned server host keys
	State      string // state/
	Inventory  string // state/inventory/<server>.json
	Cache      string // state/cache/: feed data
	Temp       string // tmp/: short-lived launcher scripts
	Socket     string // mis.sock: CLI ↔ daemon
	Logs       string // daemon logs
}

// DefaultPaths returns the layout for this user and OS:
//   - macOS: ~/Library/Application Support/MakeItSafer (logs in ~/Library/Logs/MakeItSafer)
//   - Linux: $XDG_CONFIG_HOME/mis, usually ~/.config/mis
func DefaultPaths() (Paths, error) {
	if h := os.Getenv(EnvHome); h != "" {
		abs, err := filepath.Abs(h)
		if err != nil {
			return Paths{}, apperr.Wrap(apperr.ConfigUnreadable, err, "invalid "+EnvHome)
		}
		return PathsAt(abs), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot find your home directory")
	}
	if runtime.GOOS == "darwin" {
		p := PathsAt(filepath.Join(home, "Library", "Application Support", "MakeItSafer"))
		p.Logs = filepath.Join(home, "Library", "Logs", "MakeItSafer")
		return p, nil
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" || !filepath.IsAbs(base) {
		base = filepath.Join(home, ".config")
	}
	return PathsAt(filepath.Join(base, "mis")), nil
}

// PathsAt returns the layout rooted at home.
func PathsAt(home string) Paths {
	state := filepath.Join(home, "state")
	return Paths{
		Home:       home,
		Config:     filepath.Join(home, "config.yaml"),
		KeyFile:    filepath.Join(home, "key.enc"),
		PublicKey:  filepath.Join(home, "key.pub"),
		KnownHosts: filepath.Join(home, "known_hosts"),
		State:      state,
		Inventory:  filepath.Join(state, "inventory"),
		Cache:      filepath.Join(state, "cache"),
		Temp:       filepath.Join(home, "tmp"),
		Socket:     filepath.Join(home, "mis.sock"),
		Logs:       filepath.Join(home, "logs"),
	}
}

// Ensure creates the directory layout with owner-only permissions.
func (p Paths) Ensure() error {
	for _, dir := range []string{p.Home, p.State, p.Inventory, p.Cache, p.Temp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot create "+dir)
		}
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // directories need the execute bit; 0700 is owner-only
			return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot protect "+dir)
		}
	}
	return nil
}

// CheckPermissions refuses to continue when another user could read or
// change Make-It-Safer's files.
func (p Paths) CheckPermissions() error {
	for _, path := range []string{p.Home, p.State, p.Inventory, p.Cache, p.Temp, p.Config, p.KeyFile, p.KnownHosts} {
		if err := CheckPrivate(path); err != nil {
			return err
		}
	}
	return nil
}

// Initialized reports whether `mis init` has created the configuration.
func (p Paths) Initialized() bool {
	_, err := os.Stat(p.Config)
	return err == nil
}

// RequireInitialized returns a helpful error when `mis init` hasn't run yet.
func (p Paths) RequireInitialized() error {
	if !p.Initialized() {
		return apperr.New(apperr.ConfigNotInitialized, fmt.Sprintf("Make-It-Safer isn't set up yet (no %s); run: mis init", p.Config))
	}
	return p.CheckPermissions()
}
