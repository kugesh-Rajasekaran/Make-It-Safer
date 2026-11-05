package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

const unitName = "mis.service"

func unitFile() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot find your home directory")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user", unitName), nil
}

// InstallService installs the systemd user unit and starts it. It then
// starts with every graphical login.
func InstallService(paths config.Paths) (*ServiceInfo, error) {
	v, err := valuesFor(paths)
	if err != nil {
		return nil, err
	}
	content, err := renderSystemdUnit(v)
	if err != nil {
		return nil, err
	}
	file, err := unitFile()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil { //nolint:gosec // standard systemd user directory, no secrets
		return nil, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot create "+filepath.Dir(file))
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil { //nolint:gosec // systemd needs to read it; it holds no secrets
		return nil, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot write "+file)
	}
	if _, err := run("systemctl", "--user", "daemon-reload"); err != nil {
		return nil, err
	}
	if _, err := run("systemctl", "--user", "enable", "--now", unitName); err != nil {
		return nil, err
	}
	return ServiceState(paths), nil
}

// UninstallService stops the unit and removes it.
func UninstallService(paths config.Paths) error {
	file, err := unitFile()
	if err != nil {
		return err
	}
	_, _ = run("systemctl", "--user", "disable", "--now", unitName)
	if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
		return apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot remove "+file)
	}
	_, _ = run("systemctl", "--user", "daemon-reload")
	return nil
}

// ServiceState reports whether the unit is installed and running.
func ServiceState(paths config.Paths) *ServiceInfo {
	file, _ := unitFile()
	_, statErr := os.Stat(file)
	out, _ := run("systemctl", "--user", "is-active", unitName)
	return &ServiceInfo{File: file, Installed: statErr == nil, Active: strings.TrimSpace(out) == "active"}
}

// ServiceLogs returns the last lines of the daemon's journal.
func ServiceLogs(paths config.Paths, lines int) (string, error) {
	return run("journalctl", "--user", "-u", unitName, "-n", strconv.Itoa(lines), "--no-pager")
}
