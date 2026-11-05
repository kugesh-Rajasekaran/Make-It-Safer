package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

func agentFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot find your home directory")
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchLabel+".plist"), nil
}

func guiDomain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

// InstallService installs the LaunchAgent and starts it. It then starts at
// every login.
func InstallService(paths config.Paths) (*ServiceInfo, error) {
	v, err := valuesFor(paths)
	if err != nil {
		return nil, err
	}
	content, err := renderLaunchAgent(v)
	if err != nil {
		return nil, err
	}
	file, err := agentFile()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil { //nolint:gosec // ~/Library/LaunchAgents is a standard, non-secret directory
		return nil, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot create "+filepath.Dir(file))
	}
	if err := os.MkdirAll(paths.Logs, 0o700); err != nil {
		return nil, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot create "+paths.Logs)
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil { //nolint:gosec // launchd needs to read it; it holds no secrets
		return nil, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot write "+file)
	}
	_, _ = run("launchctl", "bootout", guiDomain()+"/"+launchLabel) // not loaded yet is fine
	if _, err := run("launchctl", "bootstrap", guiDomain(), file); err != nil {
		return nil, err
	}
	return ServiceState(paths), nil
}

// UninstallService stops the LaunchAgent and removes it.
func UninstallService(paths config.Paths) error {
	file, err := agentFile()
	if err != nil {
		return err
	}
	_, _ = run("launchctl", "bootout", guiDomain()+"/"+launchLabel)
	if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
		return apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot remove "+file)
	}
	return nil
}

// ServiceState reports whether the LaunchAgent is installed and loaded.
func ServiceState(paths config.Paths) *ServiceInfo {
	file, _ := agentFile()
	_, statErr := os.Stat(file)
	_, runErr := run("launchctl", "print", guiDomain()+"/"+launchLabel)
	return &ServiceInfo{File: file, Installed: statErr == nil, Active: runErr == nil}
}

// ServiceLogs returns the last lines of the daemon log.
func ServiceLogs(paths config.Paths, lines int) (string, error) {
	data, err := os.ReadFile(filepath.Join(paths.Logs, "daemon.log"))
	if err != nil {
		return "", apperr.Wrap(apperr.ConfigUnreadable, err, "no daemon log yet")
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	return strings.Join(all[max(0, len(all)-lines):], "\n") + "\n", nil
}
